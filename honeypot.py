#!/usr/bin/env python3
"""
SSH honeypot - port 2222.

WHAT THIS PROCESS DOES
----------------------
It speaks enough SSH to look like a real OpenSSH server, records every
connection and credential attempt as one JSON line, and then rejects the
login.  It never creates a shell, never runs a command, never opens a file
on behalf of the client, and never forwards a port.

ISOLATION MODEL (enforced in code AND in the deployment notes)
--------------------------------------------------------------
1. The process must run as a dedicated, unprivileged account.  It refuses to
   start as root (Linux/macOS) or with an elevated Administrator token
   (Windows).  See README.md for creating the account.
2. Every SSH channel request is denied in HoneypotServer.check_channel_*:
   no shell, no exec, no subsystem/SFTP, no PTY, no X11, no agent forwarding,
   no direct-tcpip.  Even if authentication somehow succeeded, there is no
   code path that gives the client a shell or a file handle.
3. The only file this process writes is <log-dir>/events.jsonl, opened in
   append mode.  The host key is read-only and is generated once by
   `python honeypot.py --init` (run separately, before dropping privileges).
4. The only listener is the SSH socket on the configured port (2222 by
   default).  The dashboard and WebSocket server are separate processes /
   ports and are bound to localhost by default.
5. Deployment hardening (systemd sandbox on Linux, ACLs + a standard local
   user on Windows, firewall rules) is in README.md and deploy/.
6. Paramiko is the only third-party component parsing attacker input.  Keep
   it patched.  For exposure to the public internet, run this inside a
   dedicated VM or container as an additional layer; the code itself still
   never grants host access.

The log format is one JSON object per line (JSONL), for example:
{"id":"...","ts":"2026-10-31T12:34:56.789Z","event":"auth_attempt",
 "connection_id":"...","src_ip":"203.0.113.7","src_port":51515,
 "client_version":"SSH-2.0-OpenSSH_9.6","username":"root",
 "auth_type":"password","password":"hunter2","key_type":null,
 "key_fingerprint":null}
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import socket
import socketserver
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import paramiko

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_LOG_DIR = Path(os.environ.get("HONEYPOT_LOG_DIR", BASE_DIR / "logs"))
DEFAULT_STATE_DIR = Path(os.environ.get("HONEYPOT_STATE_DIR", BASE_DIR / "state"))
DEFAULT_BANNER = os.environ.get(
    "HONEYPOT_BANNER", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
)

MAX_FIELD_CHARS = 512          # keep a hostile client from writing a huge log line
MAX_CONNECTIONS = 64           # concurrent sockets, so a flood cannot exhaust the host
MAX_AUTH_ATTEMPTS = 20         # per TCP connection, then we hang up
CONNECTION_TTL = 120           # seconds a connection may stay open
SOCKET_TIMEOUT = 30            # seconds of silence before Paramiko gives up


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def clip(value) -> str | None:
    """Bound every attacker-controlled field before it reaches the log."""
    if value is None:
        return None
    return str(value)[:MAX_FIELD_CHARS]


def fingerprint_sha256(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


class EventLog:
    """Append-only JSONL writer.

    This is the *only* writable path used by the running honeypot.  The file
    is created 0600 and each event is flushed+fsynced so the dashboard sees it
    immediately.
    """

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.Lock()
        self._fh = open(self.path, "a", encoding="utf-8", newline="\n")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass  # Windows ACLs are configured separately; see README.md

    def write(self, event: dict) -> None:
        line = json.dumps(event, ensure_ascii=True, separators=(",", ":"))
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
            try:
                os.fsync(self._fh.fileno())
            except OSError:
                pass

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.close()
            except OSError:
                pass


class HoneypotServer(paramiko.ServerInterface):
    """Paramiko server policy: reject everything, log the attempt."""

    def __init__(
        self,
        src_ip: str,
        src_port: int,
        connection_id: str,
        log: EventLog,
    ):
        self.src_ip = src_ip
        self.src_port = src_port
        self.connection_id = connection_id
        self.log = log
        self.transport: paramiko.Transport | None = None
        self.attempts = 0
        self.should_close = False
        self._seen_keys: set[str] = set()
        self._ki_username: str | None = None

    # ---- logging helpers -------------------------------------------------
    def _event(self, username, auth_type, password=None, key=None) -> None:
        self.attempts += 1
        if self.attempts > MAX_AUTH_ATTEMPTS:
            self.should_close = True

        event = {
            "id": uuid.uuid4().hex,
            "ts": utc_now(),
            "event": "auth_attempt",
            "connection_id": self.connection_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "client_version": clip(getattr(self.transport, "remote_version", None)),
            "username": clip(username),
            "auth_type": auth_type,
            "password": clip(password),
            "key_type": key.get_name() if key is not None else None,
            "key_fingerprint": fingerprint_sha256(key) if key is not None else None,
            "key_bits": key.get_bits() if key is not None else None,
        }
        self.log.write(event)

    # ---- authentication: always fail, but record what was offered -------
    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey,keyboard-interactive"

    def check_auth_password(self, username: str, password: str) -> int:
        self._event(username, "password", password=password)
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        fp = fingerprint_sha256(key)
        # Paramiko may offer the same key twice (query + signed request), so
        # dedupe per (username, key), not per key alone.
        key_id = f"{username}:{fp}"
        if key_id not in self._seen_keys:
            self._seen_keys.add(key_id)
            self._event(username, "publickey", key=key)
        return paramiko.AUTH_FAILED

    def check_auth_interactive(self, username: str, submethods: str):
        self._ki_username = username
        return paramiko.InteractiveQuery(
            "Password authentication", "", ("Password: ", False)
        )

    def check_auth_interactive_response(self, responses) -> int:
        password = responses[0] if responses else ""
        self._event(self._ki_username, "keyboard-interactive", password=password)
        return paramiko.AUTH_FAILED

    # ---- channels: deny every kind, including shell and exec ------------
    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel) -> bool:
        return False

    def check_channel_exec_request(self, channel, command) -> bool:
        return False

    def check_channel_subsystem_request(self, channel, name) -> bool:
        return False

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ) -> bool:
        return False

    def check_channel_window_change_request(
        self, channel, width, height, pixelwidth, pixelheight
    ) -> bool:
        return False

    def check_channel_x11_request(
        self, channel, single_connection, auth_protocol, auth_cookie, screen_number
    ) -> bool:
        return False

    def check_channel_forward_agent_request(self, channel) -> bool:
        return False

    def check_port_forward_request(self, address, port) -> bool:
        return False

    def check_channel_direct_tcpip_request(self, chanid, origin, destination) -> int:
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class HoneypotTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    # On Windows SO_REUSEADDR lets two processes bind the same port.  That
    # would silently share 2222 with another service, so use exclusive bind
    # there and fail loudly instead.  Linux/macOS keep the usual restart
    # behaviour.
    allow_reuse_address = os.name != "nt"
    request_queue_size = 64

    def server_bind(self):
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if os.name == "nt" and exclusive is not None:
            self.socket.setsockopt(socket.SOL_SOCKET, exclusive, 1)
        super().server_bind()

    def __init__(self, address, handler, log: EventLog, host_key, banner: str):
        self.log = log
        self.host_key = host_key
        self.banner = banner
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, handler)


class HoneypotHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        if not self.server.slots.acquire(blocking=False):
            # Too many concurrent connections: drop this one immediately.
            try:
                self.request.close()
            except OSError:
                pass
            return
        try:
            self._run()
        finally:
            self.server.slots.release()

    def _run(self) -> None:
        try:
            peer = self.request.getpeername()
        except OSError:
            return

        src_ip = str(peer[0])
        if src_ip.startswith("::ffff:"):
            src_ip = src_ip[7:]
        src_port = int(peer[1])
        connection_id = uuid.uuid4().hex[:12]

        self.server.log.write(
            {
                "id": uuid.uuid4().hex,
                "ts": utc_now(),
                "event": "connection",
                "connection_id": connection_id,
                "src_ip": src_ip,
                "src_port": src_port,
            }
        )

        transport = None
        try:
            self.request.settimeout(SOCKET_TIMEOUT)

            # Paramiko sends its own banner at start_server(), so set the
            # realistic banner before starting the transport thread.
            transport = paramiko.Transport(self.request)
            transport.local_version = self.server.banner
            transport.add_server_key(self.server.host_key)

            policy = HoneypotServer(
                src_ip=src_ip,
                src_port=src_port,
                connection_id=connection_id,
                log=self.server.log,
            )
            policy.transport = transport
            transport.start_server(server=policy)

            # The transport thread handles authentication.  This thread only
            # waits; it never reads or writes application data.
            deadline = time.monotonic() + CONNECTION_TTL
            while transport.is_active() and time.monotonic() < deadline:
                if policy.should_close:
                    break
                time.sleep(0.25)
        except (paramiko.SSHException, OSError, EOFError):
            pass
        finally:
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass
            try:
                self.request.close()
            except OSError:
                pass


def init_host_key(state_dir: Path) -> int:
    """Generate the server host key once.  This is a setup command, not the
    long-running honeypot, so it is allowed to write to the state directory."""
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    key_path = state_dir / "host_rsa.key"
    if key_path.exists():
        print(f"[init] host key already exists: {key_path}")
        return 0
    print("[init] generating 2048-bit RSA host key (a few seconds)...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(key_path))
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    print(f"[init] wrote {key_path}")
    print("[init] keep this file read-only for the honeypot account")
    return 0


def load_host_key(state_dir: Path):
    key_path = state_dir / "host_rsa.key"
    if not key_path.exists():
        raise SystemExit(
            f"Host key not found: {key_path}\n"
            "Run this once first:  python honeypot.py --init"
        )
    return paramiko.RSAKey.from_private_key_file(str(key_path))


def refuse_privileged() -> None:
    """A honeypot that can read the whole host is not isolated."""
    if os.name == "nt":
        try:
            import ctypes

            if ctypes.windll.shell32.IsUserAnAdmin():
                raise SystemExit(
                    "Refusing to run with an Administrator token.\n"
                    "Run this from a normal terminal as a standard local user "
                    "(see README.md, 'Isolation')."
                )
        except AttributeError:
            pass
        return

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise SystemExit(
            "Refusing to run as root.\n"
            "Create the unprivileged 'honeypot' account and use the systemd "
            "unit in deploy/ (see README.md, 'Isolation')."
        )


def validate_banner(banner: str) -> None:
    if not banner.startswith("SSH-2.0-"):
        raise SystemExit("Banner must start with 'SSH-2.0-'")
    if "\r" in banner or "\n" in banner or len(banner) > 200:
        raise SystemExit("Banner must be a single line under 200 characters")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SSH honeypot (rejects all logins)")
    p.add_argument("--init", action="store_true", help="generate host key and exit")
    p.add_argument("--host", default="0.0.0.0", help="bind address (default 0.0.0.0)")
    p.add_argument("--port", type=int, default=2222, help="SSH port (default 2222)")
    p.add_argument("--log-dir", default=str(DEFAULT_LOG_DIR))
    p.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR))
    p.add_argument("--banner", default=DEFAULT_BANNER)
    return p.parse_args()


def main() -> int:
    args = parse_args()
    log_dir = Path(args.log_dir).resolve()
    state_dir = Path(args.state_dir).resolve()

    if args.init:
        return init_host_key(state_dir)

    validate_banner(args.banner)
    refuse_privileged()
    host_key = load_host_key(state_dir)
    log = EventLog(log_dir / "events.jsonl")

    # The only listening socket this process creates.  There is deliberately
    # no HTTP listener, no shell, and no command execution anywhere below.
    try:
        server = HoneypotTCPServer(
            (args.host, args.port),
            HoneypotHandler,
            log=log,
            host_key=host_key,
            banner=args.banner,
        )
    except OSError as exc:
        print(
            f"[honeypot] cannot bind {args.host}:{args.port}: {exc}",
            file=sys.stderr,
        )
        print(
            "[honeypot] another process owns that port. Stop it or use "
            "--port 2223 (then update the dashboard's test commands).",
            file=sys.stderr,
        )
        log.close()
        return 1

    print(f"[honeypot] listening on {args.host}:{args.port}")
    print(f"[honeypot] banner: {args.banner}")
    print(f"[honeypot] events: {log_dir / 'events.jsonl'}")
    print("[honeypot] all logins are rejected; no shell/exec/SFTP is enabled")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\n[honeypot] stopping")
    finally:
        server.server_close()
        log.close()
    return 0


if __name__ == "__main__":
    # Paramiko can be noisy about malformed clients; keep stderr clean.
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    sys.exit(main())
