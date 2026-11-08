#!/usr/bin/env python3
"""
Pluggable real-world attack-data connectors.

The honeypot itself only sees traffic that reaches its own SSH port.  This
module adds a small, source-agnostic pipeline for *external* observations:

    [ JSON feed / DShield / webhook ] -> normalize -> geo-enrich -> dashboard

Nothing here is tied to one vendor.  A connector is configured in
``sources.json`` and emits the same event shape as ``honeypot.py`` so the
existing State, WebSocket, map, ranking and search code work unchanged.

External events are marked with ``external: true`` and ``source_id`` /
``source_name``.  They are kept in a separate JSONL file
(``logs/external_events.jsonl``) so the honeypot log remains the authoritative
record of traffic that actually hit this sensor.

No third-party packages are required.
"""

from __future__ import annotations

import asyncio
import collections
import hmac
import ipaddress
import json
import os
import re
import threading
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

MAX_FIELD_CHARS = 512
DEFAULT_INTERVAL = 300
DEFAULT_TIMEOUT = 10
MAX_EVENTS_PER_POLL = 100
DEDUP_LIMIT = 20000
MAX_WEBHOOK_BYTES = 262144

_IP_KEYS = ("src_ip", "source_ip", "source", "ip", "ipv4", "remote_ip", "attacker_ip")
_TS_KEYS = ("ts", "timestamp", "time", "date", "created_at", "lastseen", "last_seen")
_USER_KEYS = ("username", "user", "account", "login")
_AUTH_KEYS = ("auth_type", "auth", "protocol", "service")
_PASSWORD_KEYS = ("password", "secret", "credential")
_CLIENT_KEYS = ("client_version", "client", "user_agent", "agent")

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat(timespec="milliseconds").replace("+00:00", "Z")


def normalize_ip(value) -> str:
    ip = str(value or "").strip()
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    return ip


def clip(value) -> str | None:
    if value is None:
        return None
    return str(value)[:MAX_FIELD_CHARS]


def normalize_ts(value) -> str:
    """Return an ISO-8601 UTC timestamp with a trailing Z.

    Accepts ISO strings, epoch seconds and epoch milliseconds.  Bad input is
    replaced with the current time rather than dropping the observation.
    """
    if value is None or value == "":
        return utc_now_iso()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        if number > 1e12:  # milliseconds
            number /= 1000.0
        try:
            when = datetime.fromtimestamp(number, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return utc_now_iso()
        return when.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    text = str(value).strip()
    try:
        when = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return utc_now_iso()
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def get_path(obj: Any, path: str | None) -> Any:
    """Read ``a.b[0].c`` style paths from nested dict/list data."""
    if not path:
        return None
    current = obj
    for part in re.split(r"\.|\[|\]", str(path)):
        if not part:
            continue
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None
        if current is None:
            return None
    return current


def _first(record: dict, keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = record.get(key)
        if value is not None and value != "":
            return value
    return None


def normalize_record(
    record: dict,
    *,
    source_id: str,
    source_name: str,
    source_url: str = "",
    mapping: dict[str, str] | None = None,
) -> dict | None:
    """Turn one arbitrary record into the dashboard event schema.

    Returns ``None`` when the record has no usable source IP.  The mapping
    argument maps target fields (``src_ip``, ``ts``, ``username``, ...) to
    source paths, so a feed does not need to use our names.
    """
    if not isinstance(record, dict):
        return None
    mapping = mapping or {}

    def pick(target: str, fallback: tuple[str, ...]) -> Any:
        path = mapping.get(target)
        if path:
            value = get_path(record, path)
            if value is not None:
                return value
        return _first(record, fallback)

    ip = normalize_ip(pick("src_ip", _IP_KEYS))
    if not ip:
        return None
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None

    username = clip(pick("username", _USER_KEYS))
    if username is None:
        username = "(external)"
    auth_type = clip(pick("auth_type", _AUTH_KEYS)) or "external"
    password = clip(pick("password", _PASSWORD_KEYS))
    client_version = clip(pick("client_version", _CLIENT_KEYS))
    if not client_version:
        client_version = f"external:{source_name}"

    src_port = pick("src_port", ("src_port", "source_port", "port"))
    try:
        src_port = int(src_port) if src_port is not None else 0
    except (TypeError, ValueError):
        src_port = 0

    event = {
        "id": uuid.uuid4().hex,
        "ts": normalize_ts(pick("ts", _TS_KEYS)),
        "event": "auth_attempt",
        "connection_id": f"ext-{source_id}",
        "src_ip": ip,
        "src_port": src_port,
        "client_version": client_version,
        "username": username,
        "auth_type": auth_type,
        "password": password,
        "key_type": None,
        "key_fingerprint": None,
        "key_bits": None,
        "external": True,
        "source_id": source_id,
        "source_name": source_name,
        "source_url": source_url,
    }

    # Keep a few useful, bounded fields when the feed provides them.
    for key in ("reports", "targets", "rank", "severity", "category", "first_seen", "last_seen"):
        if key in record:
            value = record[key]
            if isinstance(value, (int, float, bool)):
                event[key] = value
            elif isinstance(value, str):
                event[key] = clip(value)

    external_id = record.get("id") or record.get("event_id") or record.get("external_id")
    if external_id is not None:
        event["external_id"] = clip(external_id)
    return event


def event_key(event: dict) -> str:
    """Stable key used to avoid re-emitting the same external observation."""
    source = str(event.get("source_id") or "external")
    external_id = event.get("external_id")
    if external_id:
        return f"{source}:id:{external_id}"
    day = str(event.get("ts") or "")[:10]
    return f"{source}:ip:{event.get('src_ip', '')}:{day}"


def extract_records(payload: Any, records_path: str | None = None) -> list:
    """Find the list of records in a JSON feed payload."""
    if records_path:
        value = get_path(payload, records_path)
    elif isinstance(payload, list):
        value = payload
    elif isinstance(payload, dict):
        value = None
        for key in ("events", "data", "results", "items", "records", "indicators"):
            candidate = payload.get(key)
            if isinstance(candidate, list):
                value = candidate
                break
        if value is None:
            value = [payload]
    else:
        value = []
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        return []
    return value[:MAX_EVENTS_PER_POLL]


def expand_env(value: Any) -> Any:
    """Recursively replace ``${VAR}`` with environment values."""
    if isinstance(value, str):
        return _ENV_PATTERN.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {key: expand_env(item) for key, item in value.items()}
    if isinstance(value, list):
        return [expand_env(item) for item in value]
    return value


def load_sources_config(path: Path | str) -> list[dict]:
    """Load ``sources.json``.  Missing file means no external sources."""
    path = Path(path)
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[sources] cannot read {path}: {exc}", flush=True)
        return []
    payload = expand_env(payload)
    if isinstance(payload, dict):
        payload = payload.get("sources", [])
    if not isinstance(payload, list):
        print(f"[sources] {path} must contain a list or an object with 'sources'", flush=True)
        return []
    sources = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        if not item.get("id") or not item.get("type"):
            print(f"[sources] skipping entry without id/type: {item!r}", flush=True)
            continue
        sources.append(item)
    return sources


class Deduplicator:
    """Bounded, thread-safe set of recent event keys."""

    def __init__(self, limit: int = DEDUP_LIMIT):
        self._limit = limit
        self._keys: set[str] = set()
        self._order: collections.deque[str] = collections.deque()
        self._lock = threading.Lock()

    def add(self, key: str) -> bool:
        if not key:
            return True
        with self._lock:
            if key in self._keys:
                return False
            self._keys.add(key)
            self._order.append(key)
            while len(self._order) > self._limit:
                old = self._order.popleft()
                self._keys.discard(old)
            return True

    def seed(self, key: str) -> None:
        self.add(key)


class ExternalEventStore:
    """Append-only JSONL store for external observations.

    This is separate from the honeypot's ``events.jsonl``.  The server writes
    here; the honeypot process still writes only its own log.
    """

    def __init__(self, path: Path | str, max_load: int = 5000,
                 max_bytes: int = 5_000_000):
        self.path = Path(path)
        self.max_load = max_load
        self.max_bytes = max_bytes
        self._lock = threading.Lock()

    def append(self, event: dict) -> None:
        line = json.dumps(event, ensure_ascii=True, separators=(",", ":")) + "\n"
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size > self.max_bytes:
                    backup = self.path.with_suffix(self.path.suffix + ".1")
                    try:
                        backup.unlink()
                    except FileNotFoundError:
                        pass
                    self.path.replace(backup)
                with self.path.open("a", encoding="utf-8", newline="\n") as fh:
                    fh.write(line)
                    fh.flush()
            except OSError as exc:
                print(f"[sources] cannot write {self.path}: {exc}", flush=True)

    def load(self) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            with self.path.open("r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()[-self.max_load:]
        except OSError:
            return []
        events = []
        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and event.get("event") == "auth_attempt":
                events.append(event)
        return events


# ---------------------------------------------------------------------------
# connectors
# ---------------------------------------------------------------------------
class BaseSource:
    type = "base"

    def __init__(
        self,
        config: dict,
        submit: Callable[[dict], Awaitable[None]],
        dedup: Deduplicator,
        status_cb: Callable[[dict], None],
    ):
        self.config = config
        self.id = str(config["id"])
        self.name = str(config.get("name") or self.id)
        self.enabled = bool(config.get("enabled", True))
        self.interval = max(10, int(config.get("interval", DEFAULT_INTERVAL)))
        self.submit = submit
        self.dedup = dedup
        self.status_cb = status_cb
        self.status = {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "enabled": self.enabled,
            "status": "starting" if self.enabled else "disabled",
            "last_poll": None,
            "last_event": None,
            "count": 0,
            "error": None,
            "url": "",
            "interval": self.interval,
        }
        self._publish()

    def _publish(self, **fields) -> None:
        self.status.update(fields)
        try:
            self.status_cb(dict(self.status))
        except Exception as exc:
            print(f"[sources] status update failed: {exc}", flush=True)

    async def run(self) -> None:
        if not self.enabled:
            return
        while True:
            try:
                await self.poll_once()
                self._publish(status="ok", last_poll=utc_now_iso(), error=None)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # keep the connector alive on transient errors
                self._publish(
                    status="error",
                    last_poll=utc_now_iso(),
                    error=str(exc)[:300],
                )
                print(f"[sources] {self.id}: {exc}", flush=True)
            await asyncio.sleep(self.interval)

    async def poll_once(self) -> None:
        raise NotImplementedError

    async def emit(self, event: dict | None) -> bool:
        if not event:
            return False
        if not self.dedup.add(event_key(event)):
            return False
        await self.submit(event)
        self._publish(
            count=int(self.status.get("count") or 0) + 1,
            last_event=event.get("ts"),
            status="ok",
            error=None,
        )
        return True


class JsonFeedSource(BaseSource):
    """Poll any HTTP(S) JSON feed and map its records into event fields."""

    type = "json_feed"

    def __init__(self, config, submit, dedup, status_cb):
        super().__init__(config, submit, dedup, status_cb)
        self.url = str(config.get("url") or "")
        self.headers = {
            str(key): str(value)
            for key, value in (config.get("headers") or {}).items()
            if value not in (None, "")
        }
        self.records_path = config.get("records_path")
        self.mapping = dict(config.get("mapping") or {})
        self.timeout = float(config.get("timeout", DEFAULT_TIMEOUT))
        self._publish(url=self.url)

    async def poll_once(self) -> None:
        if not self.url:
            raise ValueError("json_feed requires a url")
        payload = await asyncio.to_thread(self._fetch)
        records = extract_records(payload, self.records_path)
        for record in records:
            event = normalize_record(
                record,
                source_id=self.id,
                source_name=self.name,
                source_url=self.url,
                mapping=self.mapping,
            )
            await self.emit(event)

    def _fetch(self) -> Any:
        headers = {
            "User-Agent": "ssh-honeypot-connector/1.0 (+https://github.com/)",
            "Accept": "application/json",
        }
        headers.update(self.headers)
        request = urllib.request.Request(self.url, headers=headers)
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            raw = response.read(2_000_000)
        return json.loads(raw.decode("utf-8", errors="replace"))


class DShieldSource(BaseSource):
    """SANS ISC / DShield public feed.

    ``feed: "openbl_ssh"`` (default) returns SSH brute-force source IPs.
    ``feed: "topips"`` returns the top attacking IPs across all protocols.
    No API key is required.  The API asks for a descriptive User-Agent and
    polite polling; see https://isc.sans.edu/api/.
    """

    type = "dshield"

    def __init__(self, config, submit, dedup, status_cb):
        super().__init__(config, submit, dedup, status_cb)
        self.feed = str(config.get("feed") or "openbl_ssh").strip().lower()
        self.limit = max(1, min(100, int(config.get("limit", 25))))
        if self.feed == "topips":
            self.url = f"https://isc.sans.edu/api/topips/records/{self.limit}?json"
        else:
            self.feed = "openbl_ssh"
            self.url = "https://isc.sans.edu/api/threatlist/openbl_ssh?json"
        self._publish(url=self.url)

    async def poll_once(self) -> None:
        payload = await asyncio.to_thread(self._fetch)
        if not isinstance(payload, list):
            raise ValueError("unexpected DShield payload (expected a JSON array)")
        now = utc_now_iso()
        for record in payload[: self.limit]:
            if not isinstance(record, dict):
                continue
            if self.feed == "topips":
                event = normalize_record(
                    {
                        "src_ip": record.get("source"),
                        "ts": now,
                        "username": "(dshield)",
                        "auth_type": "external",
                        "client_version": f"SANS ISC DShield top {self.limit}",
                        "reports": record.get("reports"),
                        "targets": record.get("targets"),
                        "rank": record.get("rank"),
                        "id": f"topips:{record.get('source')}:{now[:10]}",
                    },
                    source_id=self.id,
                    source_name=self.name,
                    source_url=self.url,
                )
            else:
                last_seen = record.get("lastseen") or record.get("last_seen") or now[:10]
                event = normalize_record(
                    {
                        "src_ip": record.get("ipv4") or record.get("ip"),
                        "ts": last_seen,
                        "username": "(dshield-ssh)",
                        "auth_type": "external",
                        "client_version": "SANS ISC openbl_ssh",
                        "first_seen": record.get("date"),
                        "last_seen": last_seen,
                        "id": f"openbl_ssh:{record.get('ipv4') or record.get('ip')}:{last_seen}",
                    },
                    source_id=self.id,
                    source_name=self.name,
                    source_url=self.url,
                )
            await self.emit(event)

    def _fetch(self) -> Any:
        request = urllib.request.Request(
            self.url,
            headers={
                "User-Agent": "ssh-honeypot-connector/1.0 (operator dashboard)",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT) as response:
            raw = response.read(2_000_000)
        return json.loads(raw.decode("utf-8", errors="replace"))


class WebhookSource(BaseSource):
    """Push-based source.  The HTTP handler calls :meth:`accept`."""

    type = "webhook"

    def __init__(self, config, submit, dedup, status_cb):
        super().__init__(config, submit, dedup, status_cb)
        token = config.get("token")
        if not token and config.get("token_env"):
            token = os.environ.get(str(config["token_env"]), "")
        self.token = str(token or "")
        self.mapping = dict(config.get("mapping") or {})
        if not self.token:
            self.enabled = False
            self._publish(
                status="disabled",
                enabled=False,
                error="missing token (set token_env)",
            )
        self._publish(url="/api/ingest")

    def accept(self, token: str, records: list) -> tuple[list[dict], str | None]:
        """Validate and normalize records.  Called from the HTTP thread.

        Deduplication is thread-safe; the actual submit happens on the
        asyncio event loop via ConnectorManager.enqueue_threadsafe().
        """
        if not self.enabled:
            return [], "webhook disabled"
        if not self.token or not token or not hmac.compare_digest(self.token, token):
            return [], "invalid token"
        events = []
        for record in records[:MAX_EVENTS_PER_POLL]:
            event = normalize_record(
                record,
                source_id=self.id,
                source_name=self.name,
                mapping=self.mapping,
            )
            if event and self.dedup.add(event_key(event)):
                events.append(event)
        return events, None


_SOURCE_TYPES = {
    "json_feed": JsonFeedSource,
    "dshield": DShieldSource,
    "webhook": WebhookSource,
}


class ConnectorManager:
    """Owns configured sources and the webhook inbox."""

    def __init__(
        self,
        config_path: Path | str,
        submit: Callable[[dict], Awaitable[None]],
        status_cb: Callable[[dict], None],
        seed_events: list[dict] | None = None,
    ):
        self.config_path = Path(config_path)
        self.submit = submit
        self.status_cb = status_cb
        self.dedup = Deduplicator()
        self.sources: list[BaseSource] = []
        self.webhooks: dict[str, WebhookSource] = {}
        self._seed_events = seed_events or []
        self._tasks: list[asyncio.Task] = []
        self._consumer: asyncio.Task | None = None
        self._queue: asyncio.Queue | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    def load(self) -> "ConnectorManager":
        for event in self._seed_events:
            self.dedup.seed(event_key(event))
        for config in load_sources_config(self.config_path):
            kind = str(config.get("type") or "").strip().lower()
            cls = _SOURCE_TYPES.get(kind)
            if cls is None:
                print(
                    f"[sources] unknown type {kind!r} for {config.get('id')!r}; "
                    "use json_feed, dshield or webhook",
                    flush=True,
                )
                continue
            try:
                source = cls(config, self.submit, self.dedup, self.status_cb)
            except Exception as exc:
                print(f"[sources] cannot load {config.get('id')}: {exc}", flush=True)
                continue
            self.sources.append(source)
            if isinstance(source, WebhookSource) and source.enabled:
                self.webhooks[source.id] = source
        return self

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._queue = asyncio.Queue()
        self._consumer = asyncio.create_task(self._consume())
        for source in self.sources:
            if isinstance(source, WebhookSource):
                # Push sources never poll; they are ready as soon as the
                # HTTP handler can accept requests.
                if source.enabled:
                    source._publish(status="ok", error=None)
                continue
            if source.enabled:
                self._tasks.append(asyncio.create_task(source.run()))
        for source in self.sources:
            self.status_cb(dict(source.status))

    async def _consume(self) -> None:
        assert self._queue is not None
        while True:
            event = await self._queue.get()
            try:
                await self.submit(event)
                source = next(
                    (item for item in self.sources
                     if item.id == event.get("source_id")),
                    None,
                )
                if source is not None:
                    source._publish(
                        count=int(source.status.get("count") or 0) + 1,
                        last_event=event.get("ts"),
                        status="ok",
                        error=None,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                print(f"[sources] webhook submit failed: {exc}", flush=True)
            finally:
                self._queue.task_done()

    def enqueue_threadsafe(self, events: list[dict]) -> int:
        if self._loop is None or self._queue is None:
            return 0
        for event in events:
            self._loop.call_soon_threadsafe(self._queue.put_nowait, event)
        return len(events)

    def find_webhook(self, token: str, source_id: str | None = None) -> WebhookSource | None:
        candidates = (
            [self.webhooks[source_id]]
            if source_id and source_id in self.webhooks
            else list(self.webhooks.values())
        )
        for source in candidates:
            if source.token and token and hmac.compare_digest(source.token, token):
                return source
        return None

    async def stop(self) -> None:
        tasks = list(self._tasks)
        if self._consumer is not None:
            tasks.append(self._consumer)
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._tasks.clear()
        self._consumer = None
