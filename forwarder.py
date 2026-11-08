#!/usr/bin/env python3
"""
Forward local honeypot JSONL events to a centralized Elasticsearch or
ClickHouse instance over TLS.

This process is optional.  It does not listen on any port.  It tails the same
JSONL files the dashboard reads, batches complete lines, and POSTs them to a
remote backend.  A byte-offset checkpoint lets it resume after a restart.

Design goals
------------
* Standard library only: no new runtime dependency beyond Python itself.
* TLS certificate verification is on by default.  A private CA and client
  certificates (mTLS) are supported.
* Credentials come from environment variables, never from the command line
  (where they would be visible in the process list).
* At-least-once delivery: the checkpoint advances only after the backend
  accepts a batch.  Elasticsearch uses the event id as ``_id``, so a retry
  overwrites instead of duplicating.  ClickHouse uses ReplacingMergeTree, so
  duplicate ids converge.
* Bounded memory: at most ``--batch-size`` events are held at once.  If the
  backend is down, the forwarder retries and leaves the rest in the local log
  instead of growing an unbounded in-memory queue.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_LOG = BASE_DIR / "logs" / "events.jsonl"
DEFAULT_STATE_DIR = BASE_DIR / "state"
DEFAULT_BATCH = 500
DEFAULT_FLUSH = 2.0
DEFAULT_POLL = 0.5
DEFAULT_READ_BYTES = 4 * 1024 * 1024
DEFAULT_TIMEOUT = 15.0
MAX_RETRY_DELAY = 60.0
MAX_TEXT_CHARS = 4096


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_ts(value) -> datetime:
    try:
        when = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return utc_now()
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc)


def clickhouse_ts(value) -> str:
    """ClickHouse DateTime64(3, 'UTC') accepts 'YYYY-MM-DD HH:MM:SS.sss'."""
    when = parse_ts(value)
    return when.strftime("%Y-%m-%d %H:%M:%S.") + f"{when.microsecond // 1000:03d}"


def text(value) -> str:
    if value is None:
        return ""
    return str(value)[:MAX_TEXT_CHARS]


def int_or_none(value):
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def float_or_none(value):
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def event_id(event: dict) -> str:
    """Use the honeypot id, or a deterministic hash for id-less records.

    A deterministic fallback keeps retries idempotent even if the local log
    contains an event without an ``id`` field.
    """
    value = event.get("id")
    if value:
        return str(value)
    canonical = json.dumps(
        event, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def env_value(name: str | None) -> str | None:
    if not name:
        return None
    value = os.environ.get(name, "")
    return value or None


def add_query(url: str, **params: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query.update(params)
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), parsed.fragment)
    )


def validate_http_url(url: str, allow_plaintext: bool) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("--url must be an absolute http:// or https:// URL")
    if parsed.scheme == "http" and not allow_plaintext:
        raise ValueError(
            "refusing plaintext HTTP; use https:// or pass --allow-plaintext "
            "for a local test backend"
        )


class BackendError(RuntimeError):
    def __init__(self, message: str, *, permanent: bool = False):
        super().__init__(message)
        self.permanent = permanent


def http_post(
    url: str,
    body: bytes,
    headers: dict[str, str],
    context: ssl.SSLContext | None,
    timeout: float,
) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return response.status, response.read(65536)
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", "replace")[:500]
        permanent = 400 <= exc.code < 500 and exc.code not in (408, 429)
        raise BackendError(f"HTTP {exc.code}: {detail}", permanent=permanent) from exc
    except urllib.error.URLError as exc:
        raise BackendError(f"connection failed: {exc.reason}") from exc
    except TimeoutError as exc:
        raise BackendError("request timed out") from exc


# ---------------------------------------------------------------------------
# backends
# ---------------------------------------------------------------------------
class ElasticsearchBackend:
    """Bulk-index events into daily indices such as ssh-honeypot-2026-11-02."""

    name = "elasticsearch"

    def __init__(
        self,
        url: str,
        index_prefix: str,
        *,
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        context: ssl.SSLContext | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        allow_plaintext: bool = False,
    ):
        validate_http_url(url, allow_plaintext)
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", index_prefix or ""):
            raise ValueError(
                "index prefix must start with a lowercase letter or digit and "
                "contain only lowercase letters, digits, '.', '_' or '-'"
            )
        if username and not password:
            raise ValueError("username was set but password is missing")
        self.url = url.rstrip("/")
        self.index_prefix = index_prefix
        self.api_key = api_key
        self.username = username
        self.password = password
        self.context = context
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/x-ndjson",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        elif self.username:
            token = base64.b64encode(
                f"{self.username}:{self.password or ''}".encode("utf-8")
            ).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
        return headers

    def build(self, events: list[dict]) -> bytes:
        lines: list[str] = []
        for event in events:
            ts = parse_ts(event.get("ts")).isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            )
            day = ts[:10]
            doc = dict(event)
            doc["id"] = event_id(event)
            doc["@timestamp"] = ts
            doc["ingested_at"] = utc_now_iso()
            action = {
                "index": {
                    "_index": f"{self.index_prefix}-{day}",
                    "_id": doc["id"],
                }
            }
            lines.append(json.dumps(action, separators=(",", ":"), ensure_ascii=True))
            lines.append(json.dumps(doc, separators=(",", ":"), ensure_ascii=True))
        return ("\n".join(lines) + "\n").encode("utf-8")

    def send(self, events: list[dict]) -> None:
        url = add_query(
            self.url + "/_bulk",
            filter_path="errors,items.*.error,items.*.status",
        )
        status, raw = http_post(
            url, self.build(events), self._headers(), self.context, self.timeout
        )
        if status >= 300:
            raise BackendError(f"unexpected Elasticsearch status {status}")
        try:
            payload = json.loads(raw.decode("utf-8", "replace") or "{}")
        except json.JSONDecodeError:
            payload = {}
        if payload.get("errors"):
            items = payload.get("items") or []
            errors = [
                item.get("index", {})
                for item in items
                if isinstance(item, dict) and item.get("index", {}).get("error")
            ]
            retryable = bool(errors) and all(
                error.get("status") in (429, 503) for error in errors
            )
            if retryable:
                raise BackendError(
                    f"Elasticsearch rejected {len(errors)} document(s) with 429/503"
                )
            print(
                f"[forwarder] warning: Elasticsearch rejected {len(errors)} "
                f"document(s); first error: {errors[:1]}",
                file=sys.stderr,
                flush=True,
            )


def flatten_event(event: dict) -> dict:
    """Map an event to the flat columns used by deploy/clickhouse-schema.sql."""
    geo = event.get("geo") or {}
    if not isinstance(geo, dict):
        geo = {}
    return {
        "id": event_id(event),
        "ts": clickhouse_ts(event.get("ts")),
        "event": text(event.get("event")),
        "connection_id": text(event.get("connection_id")),
        "src_ip": text(event.get("src_ip")),
        "src_port": int_or_none(event.get("src_port")) or 0,
        "client_version": text(event.get("client_version")),
        "username": text(event.get("username")),
        "auth_type": text(event.get("auth_type")),
        "password": text(event.get("password")),
        "key_type": text(event.get("key_type")),
        "key_bits": int_or_none(event.get("key_bits")),
        "key_fingerprint": text(event.get("key_fingerprint")),
        "external": bool(event.get("external")),
        "dshield_listed": bool(event.get("dshield_listed")),
        "source_id": text(event.get("source_id")),
        "source_name": text(event.get("source_name")),
        "source_url": text(event.get("source_url")),
        "external_id": text(event.get("external_id")),
        "reports": int_or_none(event.get("reports")),
        "targets": int_or_none(event.get("targets")),
        "rank": int_or_none(event.get("rank")),
        "severity": text(event.get("severity")),
        "category": text(event.get("category")),
        "first_seen": text(event.get("first_seen")),
        "last_seen": text(event.get("last_seen")),
        "geo_lat": float_or_none(geo.get("lat")),
        "geo_lon": float_or_none(geo.get("lon")),
        "geo_city": text(geo.get("city")),
        "geo_country": text(geo.get("country")),
        "geo_country_code": text(geo.get("country_code")),
        "geo_region": text(geo.get("region")),
        "geo_source": text(geo.get("source")),
        "geo_status": text(event.get("geo_status")),
    }


class ClickHouseBackend:
    """Insert events through the ClickHouse HTTP interface (JSONEachRow)."""

    name = "clickhouse"

    def __init__(
        self,
        url: str,
        database: str,
        table: str,
        *,
        username: str | None = None,
        password: str | None = None,
        context: ssl.SSLContext | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        allow_plaintext: bool = False,
    ):
        validate_http_url(url, allow_plaintext)
        for label, value in (("database", database), ("table", table)):
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value or ""):
                raise ValueError(f"invalid ClickHouse {label} name: {value!r}")
        self.url = url.rstrip("/")
        self.database = database
        self.table = table
        self.username = username
        self.password = password
        self.context = context
        self.timeout = timeout

    def build(self, events: list[dict]) -> bytes:
        rows = [
            json.dumps(flatten_event(event), separators=(",", ":"), ensure_ascii=True)
            for event in events
        ]
        return ("\n".join(rows) + "\n").encode("utf-8")

    def send(self, events: list[dict]) -> None:
        query = (
            f"INSERT INTO {self.database}.{self.table} FORMAT JSONEachRow"
        )
        url = add_query(self.url + "/", query=query)
        headers = {"Content-Type": "application/x-ndjson"}
        if self.username:
            headers["X-ClickHouse-User"] = self.username
        if self.password:
            headers["X-ClickHouse-Key"] = self.password
        status, raw = http_post(
            url, self.build(events), headers, self.context, self.timeout
        )
        if status >= 300:
            detail = raw.decode("utf-8", "replace")[:500]
            raise BackendError(f"unexpected ClickHouse status {status}: {detail}")


# ---------------------------------------------------------------------------
# checkpoint + JSONL follower
# ---------------------------------------------------------------------------
class Checkpoint:
    """Atomic byte-offset checkpoint, one entry per source file."""

    VERSION = 1

    def __init__(self, path: Path | str, backend: str):
        self.path = Path(path)
        self.backend = backend
        self.files: dict[str, dict] = {}
        self.dirty = False
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"[forwarder] cannot read checkpoint {self.path}: {exc}", flush=True)
            return
        if not isinstance(data, dict):
            return
        stored = data.get("backend")
        if stored not in (None, self.backend):
            raise SystemExit(
                f"checkpoint {self.path} belongs to backend {stored!r}, not "
                f"{self.backend!r}; use a different --checkpoint or delete it"
            )
        files = data.get("files")
        if isinstance(files, dict):
            self.files = files

    def get(self, path: Path) -> dict | None:
        value = self.files.get(str(path))
        return value if isinstance(value, dict) else None

    def update(self, path: Path, dev: int, ino: int, offset: int) -> None:
        key = str(path)
        current = self.files.get(key)
        if current == {"dev": int(dev), "ino": int(ino), "offset": int(offset)}:
            return
        self.files[key] = {"dev": int(dev), "ino": int(ino), "offset": int(offset)}
        self.dirty = True

    def save(self) -> None:
        if not self.dirty:
            return
        payload = {
            "version": self.VERSION,
            "backend": self.backend,
            "updated": utc_now_iso(),
            "files": self.files,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            with tmp.open("w", encoding="utf-8", newline="\n") as fh:
                json.dump(payload, fh, ensure_ascii=True, separators=(",", ":"))
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
            self.dirty = False
        except OSError as exc:
            print(f"[forwarder] cannot write checkpoint {self.path}: {exc}", flush=True)


class JsonlFollower:
    """Read complete JSONL lines from a byte offset, surviving rotation."""

    def __init__(self, path: Path | str, checkpoint: Checkpoint, from_start: bool):
        self.path = Path(path).resolve()
        self.checkpoint = checkpoint
        self.from_start = from_start
        self.offset: int | None = None
        self.ident: tuple[int, int] | None = None
        self._init_cursor()

    def _stat(self):
        try:
            return self.path.stat()
        except OSError:
            return None

    def _init_cursor(self) -> None:
        st = self._stat()
        if st is None:
            self.offset = 0
            self.ident = None
            return
        ident = (int(st.st_dev), int(st.st_ino))
        saved = self.checkpoint.get(self.path)
        if saved:
            self.offset = int(saved.get("offset", 0))
            saved_ident = (saved.get("dev"), saved.get("ino"))
            if saved_ident != ident or st.st_size < self.offset:
                self.offset = 0
        else:
            self.offset = 0 if self.from_start else int(st.st_size)
        self.ident = ident
        self.checkpoint.update(self.path, ident[0], ident[1], self.offset)

    def read_batch(self, limit: int, max_bytes: int = DEFAULT_READ_BYTES) -> list[dict]:
        if limit <= 0:
            return []
        st = self._stat()
        if st is None:
            return []
        ident = (int(st.st_dev), int(st.st_ino))
        if self.offset is None or self.ident != ident or st.st_size < self.offset:
            if self.ident is not None:
                print(
                    f"[forwarder] {self.path.name}: rotated or truncated; "
                    "restarting at byte 0",
                    flush=True,
                )
            self.offset = 0
            self.ident = ident
            self.checkpoint.update(self.path, ident[0], ident[1], 0)

        try:
            with self.path.open("rb") as fh:
                fh.seek(self.offset)
                data = fh.read(max_bytes)
        except OSError as exc:
            print(f"[forwarder] cannot read {self.path}: {exc}", flush=True)
            return []
        if not data:
            return []

        last_newline = data.rfind(b"\n")
        if last_newline < 0:
            # A partial line is normal while the honeypot is writing.  A line
            # larger than the read window is corruption; skip it rather than
            # stalling the pipeline forever.
            if len(data) >= max_bytes:
                print(
                    f"[forwarder] {self.path.name}: skipping an oversized line "
                    f"(> {max_bytes} bytes)",
                    file=sys.stderr,
                    flush=True,
                )
                self.offset += len(data)
                self.checkpoint.update(self.path, ident[0], ident[1], self.offset)
            return []

        complete = data[: last_newline + 1]
        events: list[dict] = []
        consumed = 0
        for raw in complete.splitlines(keepends=True):
            if len(events) >= limit:
                break
            consumed += len(raw)
            line = raw.strip()
            if not line:
                continue
            try:
                event = json.loads(line.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                print(
                    f"[forwarder] {self.path.name}: skipping invalid JSON line",
                    file=sys.stderr,
                    flush=True,
                )
                continue
            if isinstance(event, dict):
                events.append(event)

        self.offset += consumed
        self.checkpoint.update(self.path, ident[0], ident[1], self.offset)
        return events


# ---------------------------------------------------------------------------
# CLI and main loop
# ---------------------------------------------------------------------------
def build_ssl_context(args: argparse.Namespace) -> ssl.SSLContext:
    if args.insecure:
        print(
            "[forwarder] WARNING: TLS certificate verification is disabled",
            file=sys.stderr,
            flush=True,
        )
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        try:
            context = ssl.create_default_context(cafile=args.ca_cert)
        except (OSError, ssl.SSLError) as exc:
            raise SystemExit(f"cannot load CA certificate: {exc}") from exc
    if args.client_cert:
        try:
            context.load_cert_chain(args.client_cert, args.client_key)
        except (OSError, ssl.SSLError) as exc:
            raise SystemExit(f"cannot load client certificate: {exc}") from exc
    return context


def build_backend(args: argparse.Namespace, context: ssl.SSLContext):
    if args.backend == "elasticsearch":
        api_key_env = args.api_key_env or "HONEYPOT_ES_API_KEY"
        user_env = args.username_env or "HONEYPOT_ES_USER"
        pass_env = args.password_env or "HONEYPOT_ES_PASSWORD"
        api_key = env_value(api_key_env)
        username = env_value(user_env)
        password = env_value(pass_env)
        if not api_key and not username:
            print(
                f"[forwarder] no credentials in {api_key_env} or {user_env}; "
                "continuing without authentication",
                flush=True,
            )
        return ElasticsearchBackend(
            args.url,
            args.index_prefix,
            api_key=api_key,
            username=username,
            password=password,
            context=context,
            timeout=args.timeout,
            allow_plaintext=args.allow_plaintext,
        )

    user_env = args.username_env or "HONEYPOT_CH_USER"
    pass_env = args.password_env or "HONEYPOT_CH_PASSWORD"
    username = env_value(user_env)
    password = env_value(pass_env)
    if not username:
        print(
            f"[forwarder] no username in {user_env}; using the ClickHouse "
            "server default",
            flush=True,
        )
    return ClickHouseBackend(
        args.url,
        args.database,
        args.table,
        username=username,
        password=password,
        context=context,
        timeout=args.timeout,
        allow_plaintext=args.allow_plaintext,
    )


def collect_logs(args: argparse.Namespace) -> list[Path]:
    paths = [Path(p).resolve() for p in (args.log or [str(DEFAULT_LOG)])]
    if args.include_external:
        paths.append((BASE_DIR / "logs" / "external_events.jsonl").resolve())
    unique: list[Path] = []
    for path in paths:
        if path not in unique:
            unique.append(path)
    return unique


def deliver(backend, events: list[dict], args: argparse.Namespace) -> None:
    """Send one batch, retrying transient failures with capped backoff."""
    delay = 1.0
    while True:
        try:
            backend.send(events)
            return
        except BackendError as exc:
            if exc.permanent:
                raise SystemExit(f"[forwarder] permanent backend error: {exc}") from exc
            print(
                f"[forwarder] send failed: {exc}; retrying in {delay:.0f}s",
                file=sys.stderr,
                flush=True,
            )
        except Exception as exc:  # keep the pipeline alive on transient faults
            print(
                f"[forwarder] send failed: {exc}; retrying in {delay:.0f}s",
                file=sys.stderr,
                flush=True,
            )
        time.sleep(min(delay, MAX_RETRY_DELAY))
        delay = min(delay * 2, MAX_RETRY_DELAY)


def run(args: argparse.Namespace) -> None:
    context = build_ssl_context(args)
    backend = build_backend(args, context)
    checkpoint = Checkpoint(args.checkpoint, args.backend)
    logs = collect_logs(args)
    followers = [
        JsonlFollower(path, checkpoint, args.start == "beginning") for path in logs
    ]

    print(f"[forwarder] backend: {args.backend} {args.url}", flush=True)
    print(f"[forwarder] logs: {', '.join(str(path) for path in logs)}", flush=True)
    print(f"[forwarder] checkpoint: {checkpoint.path}", flush=True)
    if urllib.parse.urlsplit(args.url).scheme == "http":
        tls = "plaintext (allowed for testing)"
    elif args.insecure:
        tls = "verification disabled"
    elif args.ca_cert:
        tls = "custom CA"
    else:
        tls = "system CA"
    print(f"[forwarder] TLS: {tls}", flush=True)
    if args.client_cert:
        print("[forwarder] client certificate: enabled", flush=True)

    buffer: list[dict] = []
    first_buffered: float | None = None
    sent = 0
    batches = 0

    try:
        while True:
            added = 0
            for follower in followers:
                while len(buffer) < args.batch_size:
                    events = follower.read_batch(
                        args.batch_size - len(buffer), args.read_bytes
                    )
                    if not events:
                        break
                    buffer.extend(events)
                    added += len(events)

            now = time.monotonic()
            if buffer and first_buffered is None:
                first_buffered = now
            due = bool(buffer) and (
                len(buffer) >= args.batch_size
                or (
                    first_buffered is not None
                    and now - first_buffered >= args.flush_interval
                )
            )

            if due:
                deliver(backend, buffer, args)
                sent += len(buffer)
                batches += 1
                checkpoint.save()
                if args.verbose or batches % 10 == 0:
                    print(
                        f"[forwarder] sent {sent} event(s) in {batches} batch(es)",
                        flush=True,
                    )
                buffer.clear()
                first_buffered = None
            elif not buffer:
                # Persist progress made by skipping invalid lines.
                checkpoint.save()

            if args.once and added == 0 and not buffer:
                break
            if not due:
                time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        print("\n[forwarder] stopping", flush=True)
        if buffer:
            print(
                f"[forwarder] {len(buffer)} event(s) were not acknowledged; "
                "checkpoint was not advanced",
                flush=True,
            )
    finally:
        # Never persist an offset that covers events still sitting in buffer.
        if not buffer:
            checkpoint.save()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Forward honeypot JSONL events to Elasticsearch or "
        "ClickHouse over TLS"
    )
    p.add_argument("--backend", choices=("elasticsearch", "clickhouse"), required=True)
    p.add_argument("--url", required=True, help="https://host:9200 or https://host:8443")
    p.add_argument(
        "--log",
        action="append",
        default=None,
        help="JSONL file to ship (repeatable; default logs/events.jsonl)",
    )
    p.add_argument(
        "--include-external",
        action="store_true",
        help="also ship logs/external_events.jsonl",
    )
    p.add_argument(
        "--checkpoint",
        default=None,
        help="offset checkpoint (default state/forwarder-<backend>.json)",
    )
    p.add_argument(
        "--start",
        choices=("beginning", "end"),
        default="beginning",
        help="where to start when no checkpoint exists (default: beginning)",
    )
    p.add_argument("--batch-size", type=int, default=DEFAULT_BATCH)
    p.add_argument("--flush-interval", type=float, default=DEFAULT_FLUSH)
    p.add_argument("--poll-interval", type=float, default=DEFAULT_POLL)
    p.add_argument("--read-bytes", type=int, default=DEFAULT_READ_BYTES)
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--once", action="store_true", help="ship the current backlog and exit")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--index-prefix", default="ssh-honeypot")
    p.add_argument("--database", default="ssh_honeypot")
    p.add_argument("--table", default="events")
    p.add_argument(
        "--api-key-env",
        default=None,
        help="env var holding an Elasticsearch API key "
        "(default HONEYPOT_ES_API_KEY)",
    )
    p.add_argument(
        "--username-env",
        default=None,
        help="env var holding the username "
        "(default HONEYPOT_ES_USER or HONEYPOT_CH_USER)",
    )
    p.add_argument(
        "--password-env",
        default=None,
        help="env var holding the password "
        "(default HONEYPOT_ES_PASSWORD or HONEYPOT_CH_PASSWORD)",
    )
    p.add_argument("--ca-cert", default=None, help="PEM CA bundle for a private CA")
    p.add_argument("--client-cert", default=None, help="PEM client certificate for mTLS")
    p.add_argument("--client-key", default=None, help="PEM client key for mTLS")
    p.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS certificate verification (not recommended)",
    )
    p.add_argument(
        "--allow-plaintext",
        action="store_true",
        help="allow http:// for a local test backend only",
    )
    args = p.parse_args()

    if args.batch_size < 1:
        p.error("--batch-size must be >= 1")
    if args.flush_interval < 0:
        p.error("--flush-interval must be >= 0")
    if args.poll_interval < 0.05:
        p.error("--poll-interval must be >= 0.05")
    if args.read_bytes < 1024:
        p.error("--read-bytes must be >= 1024")
    if args.timeout <= 0:
        p.error("--timeout must be > 0")
    if args.client_key and not args.client_cert:
        p.error("--client-key requires --client-cert")
    if not args.checkpoint:
        args.checkpoint = str(DEFAULT_STATE_DIR / f"forwarder-{args.backend}.json")
    return args


def main() -> int:
    args = parse_args()
    try:
        run(args)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"[forwarder] fatal: {exc}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
