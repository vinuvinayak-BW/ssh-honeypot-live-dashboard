#!/usr/bin/env python3
"""
Live dashboard server for the SSH honeypot.

Responsibilities
----------------
* Tail logs/events.jsonl as it is appended by honeypot.py.
* Enrich auth attempts with latitude/longitude (MaxMind GeoLite2 if a local
  database is supplied, otherwise the free ip-api.com service).
* Keep aggregate statistics for newly opened dashboards.
* Broadcast every event to all connected WebSocket clients on port 8765.
* Serve the single-page dashboard on port 8080 (separate port, localhost by
  default).

This process only *reads* the honeypot log.  It never writes to it and never
talks to the SSH port.  Both listeners bind to 127.0.0.1 by default: the
dashboard is an operator view, not a public service.  See README.md for
hosting it safely behind TLS + authentication or an SSH tunnel.
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import http.server
import ipaddress
import json
import os
import socket
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import websockets
from websockets.exceptions import ConnectionClosed

from connectors import ConnectorManager, ExternalEventStore
from enrichment import (
    DShieldBlocklistWorker,
    GeoEnricher,
    RedisBlocklistStore,
    redact_url,
)

BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_DIR = BASE_DIR / "dashboard"
DEFAULT_LOG = BASE_DIR / "logs" / "events.jsonl"
DEFAULT_GEOIP_DB = Path(
    os.environ.get("GEOIP_DB", BASE_DIR / "GeoLite2-City.mmdb")
)
DEFAULT_REDIS_URL = os.environ.get(
    "HONEYPOT_REDIS_URL", "redis://127.0.0.1:6379/0"
)

SERIES_MINUTES = 30
RECENT_EVENTS = 100


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def minute_key(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


def normalize_ip(value) -> str:
    ip = str(value or "").strip()
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    return ip


def classify_ip(ip: str) -> str:
    """Return 'public', 'private', or 'invalid' without any network call."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    return "public" if addr.is_global else "private"


class LogTailer:
    """Follow an append-only JSONL file, surviving truncation/rotation."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._fh = None
        self._ident = None
        self._buf = b""

    def _open(self) -> None:
        self._fh = open(self.path, "rb")
        st = os.fstat(self._fh.fileno())
        self._ident = (st.st_dev, st.st_ino)

    def _close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
        self._fh = None
        self._ident = None
        self._buf = b""

    def _parse(self, raw: bytes) -> dict | None:
        raw = raw.strip()
        if not raw:
            return None
        try:
            event = json.loads(raw.decode("utf-8", errors="replace"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return event if isinstance(event, dict) else None

    def read_history(self) -> list[dict]:
        """Read everything currently in the file and leave the handle at EOF.

        Using the same open handle for history and for following avoids a
        race where an event is appended between the two operations.
        """
        try:
            self._open()
        except (FileNotFoundError, PermissionError):
            return []

        data = self._fh.read()
        lines = data.split(b"\n")
        self._buf = lines.pop() if lines else b""
        events = []
        for line in lines:
            event = self._parse(line)
            if event is not None:
                events.append(event)
        return events

    async def follow(self):
        while True:
            if self._fh is None:
                try:
                    self._open()
                except (FileNotFoundError, PermissionError):
                    await asyncio.sleep(1.0)
                    continue

            chunk = self._fh.read(65536)
            if chunk:
                self._buf += chunk
                while b"\n" in self._buf:
                    line, self._buf = self._buf.split(b"\n", 1)
                    event = self._parse(line)
                    if event is not None:
                        yield event
                continue

            await asyncio.sleep(0.2)
            self._check_rotation()

    def _check_rotation(self) -> None:
        try:
            st = os.stat(self.path)
        except OSError:
            self._close()
            return
        ident = (st.st_dev, st.st_ino)
        if self._ident is not None and ident != self._ident:
            self._close()
            return
        if self._fh is not None and st.st_size < self._fh.tell():
            # Truncated in place.
            self._fh.seek(0)
            self._buf = b""

    def close(self) -> None:
        self._close()


class State:
    """Aggregates + recent events, rebuilt from the log on startup."""

    def __init__(self):
        self.connections = 0
        self.attempts = 0
        self.ips: set[str] = set()
        self.usernames: set[str] = set()
        self.user_counts: collections.Counter[str] = collections.Counter()
        self.minutes: collections.Counter[str] = collections.Counter()
        self.location_counts: collections.Counter[tuple[str, str]] = collections.Counter()
        self.location_points: dict[tuple[str, str], list[float]] = {}
        self.recent: collections.deque[dict] = collections.deque(maxlen=RECENT_EVENTS)
        self.external_attempts = 0
        self.source_counts: collections.Counter[str] = collections.Counter()
        self.sources: dict[str, dict] = {}

    def apply(self, event: dict) -> None:
        ip = normalize_ip(event.get("src_ip"))
        if ip:
            self.ips.add(ip)

        kind = event.get("event")
        if kind == "connection":
            self.connections += 1
        elif kind == "auth_attempt":
            if event.get("external"):
                self.external_attempts += 1
                self.source_counts[str(event.get("source_id") or "external")] += 1
            else:
                self.attempts += 1
                username = event.get("username")
                if username is not None:
                    self.user_counts[str(username)] += 1
                    if username:
                        self.usernames.add(str(username))
                self.minutes[self._minute_for(event)] += 1
            geo = event.get("geo") or {}
            country = geo.get("country")
            region = geo.get("region")
            if country:
                country_key = ("country", str(country))
                self.location_counts[country_key] += 1
                self._add_location_point(country_key, geo)
            if country and region:
                region_name = str(region)
                region_key = ("state", f"{region_name}, {country}")
                self.location_counts[region_key] += 1
                self._add_location_point(region_key, geo)

        self.recent.appendleft(event)
        self._prune_minutes()

    def _add_location_point(self, key: tuple[str, str], geo: dict) -> None:
        lat, lon = geo.get("lat"), geo.get("lon")
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            point = self.location_points.setdefault(key, [0.0, 0.0, 0.0])
            point[0] += float(lat)
            point[1] += float(lon)
            point[2] += 1

    def location_rankings(self) -> dict:
        result = {"countries": [], "states": []}
        for (kind, name), count in self.location_counts.most_common():
            item = {"name": name, "count": count}
            point = self.location_points.get((kind, name))
            if point and point[2]:
                item["lat"] = point[0] / point[2]
                item["lon"] = point[1] / point[2]
            result["countries" if kind == "country" else "states"].append(item)
        return result

    def update_source(self, info: dict) -> None:
        """Register or refresh one external connector's status."""
        source_id = str(info.get("id") or "")
        if source_id:
            self.sources[source_id] = dict(info)

    def _source_rows(self) -> list[dict]:
        rows = []
        for source_id, info in self.sources.items():
            row = dict(info)
            row["events"] = self.source_counts.get(source_id, 0)
            rows.append(row)
        return sorted(rows, key=lambda item: str(item.get("name") or "").lower())

    @staticmethod
    def _minute_for(event: dict) -> str:
        """Bucket an event by its own timestamp, not by server start time.

        Without this, replaying yesterday's log at startup would put every
        historical attempt into the current minute and draw a fake spike.
        """
        raw = event.get("ts")
        try:
            when = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            return minute_key(when)
        except (TypeError, ValueError):
            return minute_key(utc_now())

    def _prune_minutes(self) -> None:
        if len(self.minutes) < 180:
            return
        cutoff = minute_key(utc_now() - timedelta(hours=2))
        for key in [k for k in self.minutes if k < cutoff]:
            del self.minutes[key]

    def stats(self) -> dict:
        now = utc_now().replace(second=0, microsecond=0)
        series = []
        for i in range(SERIES_MINUTES - 1, -1, -1):
            key = minute_key(now - timedelta(minutes=i))
            series.append({"t": key, "count": self.minutes.get(key, 0)})

        return {
            "connections": self.connections,
            "attempts": self.attempts,
            "unique_ips": len(self.ips),
            "unique_usernames": len(self.usernames),
            "top_usernames": [
                {"username": username, "count": count}
                for username, count in self.user_counts.most_common(10)
            ],
            "series": series,
            "location_rankings": self.location_rankings(),
            "external_attempts": self.external_attempts,
            "sources": self._source_rows(),
        }


class Hub:
    """WebSocket fan-out plus the snapshot sent to each new client."""

    def __init__(self, state: State, allowed_origins: set[str]):
        self.state = state
        self.allowed_origins = allowed_origins
        self.clients: set = set()

    async def handler(self, websocket) -> None:
        # WebSockets are not covered by CORS.  Without an Origin check, any
        # website the operator visits could open ws://127.0.0.1:8765 and read
        # the attack feed (including attempted passwords).  Browsers always
        # send Origin; command-line clients usually do not, so allow those.
        origin = websocket.request_headers.get("Origin")
        if origin is not None and origin not in self.allowed_origins:
            print(f"[ws] rejected origin: {origin}", flush=True)
            await websocket.close(code=1008, reason="origin not allowed")
            return

        self.clients.add(websocket)
        try:
            snapshot = {
                "type": "snapshot",
                "stats": self.state.stats(),
                "recent": list(self.state.recent),
            }
            await websocket.send(json.dumps(snapshot))
            async for _ in websocket:
                # The dashboard is read-only; ignore anything it sends.
                pass
        except ConnectionClosed:
            pass
        finally:
            self.clients.discard(websocket)

    async def broadcast(self, payload: dict) -> None:
        if not self.clients:
            return
        message = json.dumps(payload)
        clients = list(self.clients)
        results = await asyncio.gather(
            *(self._send(client, message) for client in clients),
            return_exceptions=True,
        )
        for client, result in zip(clients, results):
            if isinstance(result, Exception):
                self.clients.discard(client)

    @staticmethod
    async def _send(client, message: str) -> None:
        await asyncio.wait_for(client.send(message), timeout=2.0)


async def process_event(
    event: dict,
    state: State,
    geo: GeoEnricher,
    hub: Hub,
    store: ExternalEventStore | None = None,
    blocklist: DShieldBlocklistWorker | None = None,
) -> None:
    if event.get("event") == "auth_attempt":
        src_ip = event.get("src_ip", "")
        status, location = await geo.lookup(src_ip)
        event["geo"] = location
        event["geo_status"] = status
        if blocklist is not None:
            event["dshield_listed"] = blocklist.is_listed(src_ip)
    else:
        event["geo"] = None
        event["geo_status"] = "n/a"

    state.apply(event)
    if store is not None and event.get("external"):
        # Persist after enrichment so a restart does not repeat geolocation.
        await asyncio.to_thread(store.append, event)
    await hub.broadcast({"type": "event", "event": event, "stats": state.stats()})


class DashboardRequestHandler(http.server.SimpleHTTPRequestHandler):
    webhook_manager: ConnectorManager | None = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DASHBOARD_DIR), **kwargs)

    def list_directory(self, path):
        self.send_error(404, "Not found")
        return None

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        """Push-based external events: POST /api/ingest[/source-id]."""
        path = urllib.parse.urlparse(self.path).path.rstrip("/")
        if path != "/api/ingest" and not path.startswith("/api/ingest/"):
            self.send_error(404, "Not found")
            return

        manager = self.webhook_manager
        if manager is None:
            self.send_json(503, {"error": "external sources are disabled"})
            return

        source_id = path[len("/api/ingest/"):] if path.startswith("/api/ingest/") else None
        auth = self.headers.get("Authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not token:
            token = self.headers.get("X-Honeypot-Token", "").strip()
        source = manager.find_webhook(token, source_id)
        if source is None:
            self.send_json(401, {"error": "invalid or missing token"})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > 262144:
            self.send_json(413, {"error": "body must be 1..262144 bytes"})
            return

        try:
            self.connection.settimeout(10)
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode("utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            self.send_json(400, {"error": "invalid JSON"})
            return

        if isinstance(payload, dict) and isinstance(payload.get("events"), list):
            records = payload["events"]
        elif isinstance(payload, list):
            records = payload
        elif isinstance(payload, dict):
            records = [payload]
        else:
            self.send_json(400, {"error": "expected an object or an array"})
            return

        events, error = source.accept(token, records)
        if error:
            self.send_json(401 if error == "invalid token" else 503, {"error": error})
            return
        queued = manager.enqueue_threadsafe(events)
        self.send_json(202, {"accepted": queued, "source": source.id})

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def log_message(self, fmt, *args):
        print("[http] " + (fmt % args), flush=True)


class DashboardHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if os.name == "nt" and exclusive is not None:
            self.socket.setsockopt(socket.SOL_SOCKET, exclusive, 1)
        super().server_bind()


def start_dashboard_http(
    host: str, port: int, webhook_manager: ConnectorManager | None = None
) -> DashboardHTTPServer:
    if not (DASHBOARD_DIR / "index.html").exists():
        raise SystemExit(f"Dashboard not found: {DASHBOARD_DIR / 'index.html'}")

    class Handler(DashboardRequestHandler):
        pass

    Handler.webhook_manager = webhook_manager
    httpd = DashboardHTTPServer((host, port), Handler)
    thread = threading.Thread(
        target=httpd.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True
    )
    thread.start()
    return httpd


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SSH honeypot live dashboard server")
    p.add_argument("--log", default=str(DEFAULT_LOG), help="honeypot JSONL log")
    p.add_argument("--ws-host", default="127.0.0.1")
    p.add_argument("--ws-port", type=int, default=8765)
    p.add_argument("--http-host", default="127.0.0.1")
    p.add_argument("--http-port", type=int, default=8080)
    p.add_argument("--geoip-db", default=str(DEFAULT_GEOIP_DB))
    p.add_argument(
        "--sources",
        default=str(BASE_DIR / "sources.json"),
        help="external connector config (default: sources.json)",
    )
    p.add_argument(
        "--no-external",
        action="store_true",
        help="disable all external data sources and the webhook",
    )
    p.add_argument("--no-http", action="store_true", help="do not serve the dashboard")
    p.add_argument(
        "--allow-origin",
        action="append",
        default=[],
        metavar="ORIGIN",
        help="extra browser Origin allowed to open the WebSocket "
        "(for example https://honeypot.example.com)",
    )
    p.add_argument(
        "--redis-url",
        default=DEFAULT_REDIS_URL,
        help="Redis URL for the DShield blocklist cache "
        "(default: HONEYPOT_REDIS_URL or redis://127.0.0.1:6379/0)",
    )
    p.add_argument(
        "--redis-key",
        default="honeypot:dshield:ssh",
        help="Redis key prefix for the blocklist set and metadata hash",
    )
    p.add_argument(
        "--redis-ca-cert",
        default=None,
        help="PEM CA bundle for a private Redis TLS certificate",
    )
    p.add_argument(
        "--redis-insecure",
        action="store_true",
        help="disable Redis TLS certificate verification (testing only)",
    )
    p.add_argument(
        "--dshield-interval",
        type=int,
        default=4 * 60 * 60,
        help="seconds between DShield blocklist refreshes (default: 14400 = 4h)",
    )
    p.add_argument(
        "--no-blocklist",
        action="store_true",
        help="do not run the DShield blocklist worker",
    )
    args = p.parse_args()
    if args.dshield_interval < 300:
        p.error("--dshield-interval must be >= 300 seconds")
    return args


def build_allowed_origins(http_host: str, http_port: int, extra: list[str]) -> set[str]:
    hosts = {"127.0.0.1", "localhost", "::1"}
    if http_host not in {"", "0.0.0.0", "::"}:
        hosts.add(http_host)

    def origin_host(host: str) -> str:
        # Browsers write IPv6 origins as http://[::1]:8080.
        if ":" in host and not host.startswith("["):
            return f"[{host}]"
        return host

    origins = {f"http://{origin_host(host)}:{http_port}" for host in hosts}
    origins.update(extra)
    return origins


async def run(args: argparse.Namespace) -> None:
    log_path = Path(args.log).resolve()
    state = State()
    tailer = LogTailer(log_path)
    history = tailer.read_history()

    geo = GeoEnricher(Path(args.geoip_db))
    await geo.start()

    blocklist = None
    if not args.no_blocklist:
        try:
            store = RedisBlocklistStore(
                args.redis_url,
                key=args.redis_key,
                ttl=max(2 * args.dshield_interval, 8 * 60 * 60),
                username=os.environ.get("HONEYPOT_REDIS_USERNAME") or None,
                password=os.environ.get("HONEYPOT_REDIS_PASSWORD") or None,
                ca_cert=args.redis_ca_cert,
                insecure=args.redis_insecure,
            )
            blocklist = DShieldBlocklistWorker(
                store,
                interval=args.dshield_interval,
            )
            await blocklist.start()
        except Exception as exc:
            print(f"[blocklist] disabled: {exc}", flush=True)
            blocklist = None

    external_store = ExternalEventStore(log_path.parent / "external_events.jsonl")
    external_history = external_store.load()

    combined = history + external_history
    combined.sort(key=lambda event: str(event.get("ts") or ""))
    for event in combined:
        if event.get("event") == "auth_attempt":
            if not event.get("geo"):
                status, location = await geo.lookup(event.get("src_ip", ""))
                event["geo"] = location
                event["geo_status"] = status
            if blocklist is not None:
                event["dshield_listed"] = blocklist.is_listed(
                    event.get("src_ip", "")
                )
        state.apply(event)

    hub = Hub(
        state,
        build_allowed_origins(args.http_host, args.http_port, args.allow_origin),
    )

    manager = None
    if not args.no_external:
        manager = ConnectorManager(
            Path(args.sources).resolve(),
            submit=lambda event: process_event(
                event, state, geo, hub, external_store, blocklist
            ),
            status_cb=state.update_source,
            seed_events=external_history,
        ).load()

    httpd = None
    if not args.no_http:
        try:
            httpd = start_dashboard_http(args.http_host, args.http_port, manager)
        except OSError as exc:
            print(
                f"[server] cannot bind http://{args.http_host}:{args.http_port}: {exc}",
                flush=True,
            )
            print(
                "[server] stop the other service or use --http-port 8090 "
                "(and open http://127.0.0.1:8090).",
                flush=True,
            )
            if manager is not None:
                await manager.stop()
            if blocklist is not None:
                await blocklist.stop()
            tailer.close()
            await geo.close()
            return

    if manager is not None:
        await manager.start()

    print(f"[server] log: {log_path} ({len(history)} historical events)", flush=True)
    print(f"[server] external events: {len(external_history)}", flush=True)
    print(f"[server] websocket: ws://{args.ws_host}:{args.ws_port}", flush=True)
    if httpd is not None:
        print(
            f"[server] dashboard: http://{args.http_host}:{args.http_port}",
            flush=True,
        )
    if manager is not None:
        active = [source for source in manager.sources if source.enabled]
        print(
            f"[sources] {len(active)} active / {len(manager.sources)} configured "
            f"({Path(args.sources).name})",
            flush=True,
        )
        for source in manager.sources:
            print(
                f"[sources]   {source.id}: {source.type} "
                f"{'enabled' if source.enabled else 'disabled'}"
                + (f" -> {source.status.get('url')}" if source.status.get("url") else ""),
                flush=True,
            )
    print(f"[geo] lookup: {geo.source}", flush=True)
    if blocklist is not None:
        snapshot = blocklist.snapshot()
        print(
            f"[blocklist] DShield: {snapshot['count']} IP(s), "
            f"updated {snapshot['updated_at'] or 'pending'}; "
            f"Redis {redact_url(args.redis_url)}",
            flush=True,
        )
        print(
            f"[blocklist] refresh every {args.dshield_interval // 3600}h",
            flush=True,
        )
    else:
        print("[blocklist] disabled", flush=True)
    print("[server] waiting for new events...", flush=True)

    try:
        async with websockets.serve(
            hub.handler,
            args.ws_host,
            args.ws_port,
            ping_interval=20,
            ping_timeout=20,
        ):
            async for event in tailer.follow():
                await process_event(
                    event, state, geo, hub, external_store, blocklist
                )
    except OSError as exc:
        print(
            f"[server] cannot bind ws://{args.ws_host}:{args.ws_port}: {exc}",
            flush=True,
        )
        print(
            "[server] stop the other service or use --ws-port 8775 "
            "(and open the dashboard with ?ws=ws://127.0.0.1:8775).",
            flush=True,
        )
    finally:
        if manager is not None:
            await manager.stop()
        if blocklist is not None:
            await blocklist.stop()
        tailer.close()
        await geo.close()
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()


def main() -> int:
    args = parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n[server] stopping", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
