#!/usr/bin/env python3
"""
Asynchronous enrichment for the SSH honeypot.

Two independent pieces live here:

* ``GeoEnricher`` wraps ``geoip2.database.Reader``.  The MaxMind reader is
  synchronous and does local file I/O, so every lookup is dispatched with
  ``asyncio.to_thread``.  The event loop is never blocked, and no attacker IP
  is sent to a third-party geolocation service.
* ``DShieldBlocklistWorker`` refreshes the SANS ISC ``openbl_ssh`` blocklist
  every four hours, stores it in Redis, and keeps an in-memory snapshot for
  O(1) membership checks.  Redis is a cache: if it is unavailable, the worker
  keeps working with the last snapshot it fetched.

Redis is optional.  ``redis.asyncio`` is imported lazily so the rest of the
server still starts (with in-memory blocklist data) when the package or the
server is missing.
"""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Awaitable, Callable

DEFAULT_DSHIELD_URL = "https://isc.sans.edu/api/threatlist/openbl_ssh?json"
DEFAULT_REFRESH_SECONDS = 4 * 60 * 60       # 4 hours
DEFAULT_REDIS_KEY = "honeypot:dshield:ssh"
DEFAULT_CACHE_SECONDS = 24 * 60 * 60
DEFAULT_FAILURE_SECONDS = 5 * 60
REDIS_CHUNK = 500


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
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


def utc_now_iso() -> str:
    from datetime import datetime, timezone

    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def redact_url(url: str) -> str:
    """Hide a password embedded in a Redis URL before logging it."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    netloc = parts.netloc
    if "@" in netloc:
        userinfo, host = netloc.rsplit("@", 1)
        if ":" in userinfo:
            userinfo = userinfo.split(":", 1)[0] + ":***"
        netloc = f"{userinfo}@{host}"
    return urllib.parse.urlunsplit(
        (parts.scheme, netloc, parts.path, parts.query, parts.fragment)
    )


def open_maxmind_reader(path: Path | str):
    """Import and open the MaxMind reader.

    Kept as a module-level function so tests can replace it without needing a
    real ``.mmdb`` file.  ``geoip2`` is a synchronous library; callers run this
    in a worker thread.
    """
    import geoip2.database  # optional dependency, declared in requirements.txt

    return geoip2.database.Reader(str(path))


# ---------------------------------------------------------------------------
# asynchronous MaxMind reader
# ---------------------------------------------------------------------------
class GeoEnricher:
    """Async facade over a local MaxMind GeoLite2 City database.

    ``geoip2`` has no async API.  Each cache miss is executed in a worker
    thread with ``asyncio.to_thread``; cache hits never leave the event loop.
    There is deliberately no ip-api.com fallback: if the database is missing,
    lookups return ``unavailable`` instead of sending attacker IPs to a third
    party.
    """

    def __init__(
        self,
        db_path: Path | str | None,
        *,
        success_ttl: float = DEFAULT_CACHE_SECONDS,
        failure_ttl: float = DEFAULT_FAILURE_SECONDS,
        max_cache: int = 20000,
    ):
        self.db_path = Path(db_path) if db_path else None
        self.source = "disabled"
        self._reader = None
        self._cache: dict[str, tuple[float, dict | None]] = {}
        self._success_ttl = float(success_ttl)
        self._failure_ttl = float(failure_ttl)
        self._max_cache = max(1000, int(max_cache))

    async def start(self) -> None:
        if self.db_path is None or not self.db_path.exists():
            self.source = f"disabled (database not found: {self.db_path})"
            print(f"[geo] {self.source}; map markers disabled", flush=True)
            return
        try:
            self._reader = await asyncio.to_thread(
                open_maxmind_reader, self.db_path
            )
            self.source = f"MaxMind ({self.db_path.name})"
        except Exception as exc:  # a bad/corrupt DB must not stop the feed
            self.source = f"disabled ({exc})"
            print(f"[geo] cannot open {self.db_path}: {exc}", flush=True)

    async def lookup(self, ip: str) -> tuple[str, dict | None]:
        """Return ``(status, geo)``; status is ok/private/invalid/unavailable."""
        ip = normalize_ip(ip)
        kind = classify_ip(ip)
        if kind != "public":
            return kind, None
        if self._reader is None:
            return "unavailable", None

        cached = self._cache.get(ip)
        now = time.monotonic()
        if cached is not None and cached[0] > now:
            return ("ok" if cached[1] else "unavailable"), cached[1]

        data = await asyncio.to_thread(self._lookup_sync, ip)
        ttl = self._success_ttl if data else self._failure_ttl
        self._cache[ip] = (now + ttl, data)
        if len(self._cache) > self._max_cache:
            # Bound memory on a busy sensor; drop the oldest entries.
            for key in list(self._cache)[: self._max_cache // 4]:
                self._cache.pop(key, None)
        return ("ok" if data else "unavailable"), data

    def _lookup_sync(self, ip: str) -> dict | None:
        reader = self._reader
        if reader is None:
            return None
        try:
            record = reader.city(ip)
        except Exception:
            return None
        lat = record.location.latitude
        lon = record.location.longitude
        if lat is None or lon is None:
            return None
        return {
            "lat": float(lat),
            "lon": float(lon),
            "city": record.city.name,
            "country": record.country.name,
            "country_code": record.country.iso_code,
            "region": (
                record.subdivisions.most_specific.name
                if record.subdivisions
                else None
            ),
            "source": "maxmind",
        }

    async def close(self) -> None:
        reader = self._reader
        self._reader = None
        if reader is not None:
            try:
                await asyncio.to_thread(reader.close)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Redis-backed DShield blocklist
# ---------------------------------------------------------------------------
class RedisBlocklistStore:
    """Small Redis adapter used by :class:`DShieldBlocklistWorker`.

    Keys
    ----
    ``<key>``       Redis SET of blocklisted IPs
    ``<key>:meta``  Redis HASH with ``updated_at``, ``count``, ``source_url``
                    and ``feed``.

    Both keys expire after ``ttl`` seconds (two refresh intervals by default),
    so a dead worker does not leave a stale blocklist around forever.
    """

    def __init__(
        self,
        url: str,
        *,
        key: str = DEFAULT_REDIS_KEY,
        ttl: int = DEFAULT_REFRESH_SECONDS * 2,
        username: str | None = None,
        password: str | None = None,
        ca_cert: str | None = None,
        insecure: bool = False,
        client=None,
    ):
        self.url = url
        self.key = key
        self.meta_key = f"{key}:meta"
        self.ttl = max(60, int(ttl))
        if client is not None:
            self._client = client
            return

        try:
            import redis.asyncio as redis  # optional dependency
        except ImportError as exc:
            raise RuntimeError(
                "the 'redis' package is required for the DShield blocklist "
                "cache; run: pip install -r requirements.txt"
            ) from exc

        kwargs: dict[str, Any] = {
            "decode_responses": True,
            "socket_connect_timeout": 3.0,
            "socket_timeout": 5.0,
        }
        if username:
            kwargs["username"] = username
        if password:
            kwargs["password"] = password
        if ca_cert:
            kwargs["ssl_ca_certs"] = ca_cert
        if insecure:
            kwargs["ssl_cert_reqs"] = "none"
        self._client = redis.from_url(url, **kwargs)

    async def replace(self, ips: set[str], meta: dict[str, Any]) -> None:
        pipe = self._client.pipeline(transaction=True)
        pipe.delete(self.key)
        values = sorted(ips)
        for start in range(0, len(values), REDIS_CHUNK):
            pipe.sadd(self.key, *values[start : start + REDIS_CHUNK])
        pipe.hset(
            self.meta_key,
            mapping={str(k): str(v) for k, v in meta.items()},
        )
        pipe.expire(self.key, self.ttl)
        pipe.expire(self.meta_key, self.ttl)
        await pipe.execute()

    async def load(self) -> tuple[set[str], dict[str, str]]:
        pipe = self._client.pipeline(transaction=False)
        pipe.smembers(self.key)
        pipe.hgetall(self.meta_key)
        members, meta = await pipe.execute()
        return {str(item) for item in (members or [])}, dict(meta or {})

    async def ping(self) -> bool:
        return bool(await self._client.ping())

    async def close(self) -> None:
        closer = getattr(self._client, "aclose", None)
        if closer is not None:
            await closer()
        else:  # redis-py < 5 compatibility
            await self._client.close()


class DShieldBlocklistWorker:
    """Refresh the DShield SSH blocklist every ``interval`` seconds."""

    def __init__(
        self,
        store: RedisBlocklistStore,
        *,
        url: str = DEFAULT_DSHIELD_URL,
        interval: int = DEFAULT_REFRESH_SECONDS,
        timeout: float = 10.0,
        on_update: Callable[[dict], Awaitable[None] | None] | None = None,
    ):
        self.store = store
        self.url = url
        self.interval = max(300, int(interval))
        self.timeout = max(1.0, float(timeout))
        self.on_update = on_update
        self._ips: frozenset[str] = frozenset()
        self._meta: dict[str, str] = {}
        self._last_error: str | None = None
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        await self.load_cached()
        self._task = asyncio.create_task(self._run(), name="dshield-blocklist")

    async def load_cached(self) -> None:
        """Load the last snapshot from Redis so restarts are warm."""
        try:
            ips, meta = await self.store.load()
        except Exception as exc:
            print(
                f"[blocklist] cannot read Redis cache: {exc}; "
                "using in-memory data only",
                flush=True,
            )
            return
        self._meta = dict(meta)
        if ips:
            self._ips = frozenset(ips)
            updated = meta.get("updated_at") or "unknown"
            print(
                f"[blocklist] loaded {len(ips)} cached DShield IP(s) "
                f"(updated {updated})",
                flush=True,
            )

    async def _run(self) -> None:
        while True:
            delay = self.interval
            try:
                await self.refresh_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._last_error = str(exc)[:300]
                delay = min(300, self.interval)
                print(
                    f"[blocklist] refresh failed: {exc}; "
                    f"retrying in {delay}s",
                    flush=True,
                )
            await asyncio.sleep(delay)

    async def refresh_once(self) -> dict:
        payload = await asyncio.to_thread(self._fetch_sync)
        if not isinstance(payload, list):
            raise ValueError("unexpected DShield payload (expected a JSON array)")

        ips: set[str] = set()
        for record in payload:
            if not isinstance(record, dict):
                continue
            ip = normalize_ip(record.get("ipv4") or record.get("ip"))
            if not ip:
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            ips.add(ip)

        if not ips:
            raise ValueError(
                "DShield feed contained no valid IPs; keeping the previous snapshot"
            )

        meta = {
            "updated_at": utc_now_iso(),
            "count": str(len(ips)),
            "source_url": self.url,
            "feed": "openbl_ssh",
        }
        try:
            await self.store.replace(ips, meta)
        except Exception as exc:
            # The in-memory snapshot is still useful; Redis may come back.
            print(
                f"[blocklist] Redis write failed: {exc}; "
                "keeping the in-memory snapshot",
                flush=True,
            )

        self._ips = frozenset(ips)
        self._meta = meta
        self._last_error = None
        print(
            f"[blocklist] refreshed {len(ips)} DShield IP(s); "
            f"next refresh in {self.interval // 3600}h",
            flush=True,
        )
        snapshot = self.snapshot()
        if self.on_update is not None:
            result = self.on_update(snapshot)
            if inspect.isawaitable(result):
                await result
        return snapshot

    def _fetch_sync(self) -> Any:
        request = urllib.request.Request(
            self.url,
            headers={
                "User-Agent": "ssh-honeypot-enrichment/1.0 (operator dashboard)",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            raw = response.read(2_000_000)
        return json.loads(raw.decode("utf-8", errors="replace"))

    def is_listed(self, ip: str) -> bool:
        ip = normalize_ip(ip)
        return bool(ip) and ip in self._ips

    def snapshot(self) -> dict:
        return {
            "count": len(self._ips),
            "updated_at": self._meta.get("updated_at"),
            "source_url": self._meta.get("source_url") or self.url,
            "last_error": self._last_error,
        }

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        try:
            await self.store.close()
        except Exception:
            pass
