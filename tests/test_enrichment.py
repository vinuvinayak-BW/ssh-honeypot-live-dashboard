import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from enrichment import (
    DShieldBlocklistWorker,
    GeoEnricher,
    RedisBlocklistStore,
    classify_ip,
    normalize_ip,
    redact_url,
)


def fake_record():
    return SimpleNamespace(
        location=SimpleNamespace(latitude=1.5, longitude=2.5),
        city=SimpleNamespace(name="Test City"),
        country=SimpleNamespace(name="Testland", iso_code="TL"),
        subdivisions=SimpleNamespace(
            most_specific=SimpleNamespace(name="Test Region")
        ),
    )


class FakeReader:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []
        self.closed = False

    def city(self, ip):
        self.calls.append(ip)
        if self.fail:
            raise ValueError("not in database")
        return fake_record()

    def close(self):
        self.closed = True


class HelperTests(unittest.TestCase):
    def test_normalize_and_classify(self):
        self.assertEqual(normalize_ip("::ffff:8.8.8.8"), "8.8.8.8")
        self.assertEqual(classify_ip("8.8.8.8"), "public")
        self.assertEqual(classify_ip("127.0.0.1"), "private")
        self.assertEqual(classify_ip("not-an-ip"), "invalid")

    def test_redact_url(self):
        self.assertEqual(
            redact_url("redis://user:secret@example.com:6379/0"),
            "redis://user:***@example.com:6379/0",
        )
        self.assertEqual(
            redact_url("redis://example.com:6379/0"),
            "redis://example.com:6379/0",
        )


class GeoEnricherTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_database_is_unavailable(self):
        geo = GeoEnricher(Path("does-not-exist.mmdb"))
        await geo.start()
        self.assertIn("disabled", geo.source)
        self.assertEqual(await geo.lookup("8.8.8.8"), ("unavailable", None))
        await geo.close()

    async def test_private_and_invalid_ips_do_not_touch_reader(self):
        geo = GeoEnricher(None)
        await geo.start()
        self.assertEqual(await geo.lookup("127.0.0.1"), ("private", None))
        self.assertEqual(await geo.lookup("not-an-ip"), ("invalid", None))
        await geo.close()

    async def test_maxmind_lookup_and_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "GeoLite2-City.mmdb"
            db.write_bytes(b"fake database")
            reader = FakeReader()
            with patch("enrichment.open_maxmind_reader", return_value=reader):
                geo = GeoEnricher(db)
                await geo.start()
                self.assertEqual(geo.source, "MaxMind (GeoLite2-City.mmdb)")

                status, data = await geo.lookup("8.8.8.8")
                self.assertEqual(status, "ok")
                self.assertEqual(data["lat"], 1.5)
                self.assertEqual(data["lon"], 2.5)
                self.assertEqual(data["city"], "Test City")
                self.assertEqual(data["country"], "Testland")
                self.assertEqual(data["country_code"], "TL")
                self.assertEqual(data["region"], "Test Region")
                self.assertEqual(data["source"], "maxmind")

                await geo.lookup("8.8.8.8")
                self.assertEqual(len(reader.calls), 1)
                await geo.close()
                self.assertTrue(reader.closed)

    async def test_missing_record_is_cached_as_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "GeoLite2-City.mmdb"
            db.write_bytes(b"fake database")
            reader = FakeReader(fail=True)
            with patch("enrichment.open_maxmind_reader", return_value=reader):
                geo = GeoEnricher(db)
                await geo.start()
                self.assertEqual(
                    await geo.lookup("8.8.8.8"), ("unavailable", None)
                )
                self.assertEqual(
                    await geo.lookup("8.8.8.8"), ("unavailable", None)
                )
                self.assertEqual(len(reader.calls), 1)
                await geo.close()


class FakeStore:
    def __init__(self, ips=None, meta=None):
        self.ips = set(ips or [])
        self.meta = dict(meta or {})
        self.fail_load = False
        self.fail_replace = False
        self.closed = False
        self.replaced = []

    async def load(self):
        if self.fail_load:
            raise RuntimeError("redis is down")
        return set(self.ips), dict(self.meta)

    async def replace(self, ips, meta):
        if self.fail_replace:
            raise RuntimeError("redis is down")
        self.ips = set(ips)
        self.meta = dict(meta)
        self.replaced.append((set(ips), dict(meta)))

    async def close(self):
        self.closed = True


class BlocklistWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def test_refresh_stores_valid_ips_and_marks_listed(self):
        store = FakeStore()
        worker = DShieldBlocklistWorker(store)
        worker._fetch_sync = lambda: [
            {"ipv4": "8.8.8.8"},
            {"ip": "1.1.1.1"},
            {"ipv4": "not-an-ip"},
            {"unexpected": "record"},
            "not a dict",
        ]

        snapshot = await worker.refresh_once()

        self.assertEqual(store.ips, {"8.8.8.8", "1.1.1.1"})
        self.assertEqual(store.meta["count"], "2")
        self.assertEqual(snapshot["count"], 2)
        self.assertTrue(worker.is_listed("8.8.8.8"))
        self.assertTrue(worker.is_listed("1.1.1.1"))
        self.assertFalse(worker.is_listed("9.9.9.9"))
        await worker.stop()
        self.assertTrue(store.closed)

    async def test_empty_feed_keeps_previous_snapshot(self):
        store = FakeStore()
        worker = DShieldBlocklistWorker(store)
        worker._fetch_sync = lambda: [{"ipv4": "8.8.8.8"}]
        await worker.refresh_once()

        worker._fetch_sync = lambda: []
        with self.assertRaises(ValueError):
            await worker.refresh_once()

        self.assertTrue(worker.is_listed("8.8.8.8"))
        self.assertEqual(store.ips, {"8.8.8.8"})
        await worker.stop()

    async def test_redis_write_failure_still_updates_memory(self):
        store = FakeStore()
        store.fail_replace = True
        worker = DShieldBlocklistWorker(store)
        worker._fetch_sync = lambda: [{"ipv4": "8.8.8.8"}]

        await worker.refresh_once()

        self.assertTrue(worker.is_listed("8.8.8.8"))
        self.assertEqual(worker.snapshot()["count"], 1)
        await worker.stop()

    async def test_load_cached_snapshot(self):
        store = FakeStore(
            {"8.8.8.8"},
            {"updated_at": "2026-11-02T00:00:00.000Z", "count": "1"},
        )
        worker = DShieldBlocklistWorker(store)

        await worker.load_cached()

        self.assertTrue(worker.is_listed("8.8.8.8"))
        self.assertEqual(
            worker.snapshot()["updated_at"], "2026-11-02T00:00:00.000Z"
        )
        await worker.stop()

    async def test_load_cached_failure_is_non_fatal(self):
        store = FakeStore()
        store.fail_load = True
        worker = DShieldBlocklistWorker(store)

        await worker.load_cached()

        self.assertFalse(worker.is_listed("8.8.8.8"))
        await worker.stop()


class FakePipe:
    def __init__(self, results):
        self.results = results
        self.calls = []

    def delete(self, *args):
        self.calls.append(("delete", args))

    def sadd(self, *args):
        self.calls.append(("sadd", args))

    def hset(self, *args, **kwargs):
        self.calls.append(("hset", args, kwargs))

    def expire(self, *args):
        self.calls.append(("expire", args))

    def smembers(self, *args):
        self.calls.append(("smembers", args))

    def hgetall(self, *args):
        self.calls.append(("hgetall", args))

    async def execute(self):
        return self.results


class FakeRedis:
    def __init__(self, results=None):
        self.results = results or []
        self.pipes = []
        self.closed = False

    def pipeline(self, transaction=True):
        pipe = FakePipe(self.results)
        self.pipes.append(pipe)
        return pipe

    async def aclose(self):
        self.closed = True


class RedisStoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_replace_writes_set_meta_and_ttl(self):
        client = FakeRedis()
        store = RedisBlocklistStore(
            "redis://localhost:6379/0",
            key="test:blocklist",
            ttl=120,
            client=client,
        )

        await store.replace({"b", "a"}, {"count": "2", "updated_at": "now"})

        calls = client.pipes[0].calls
        self.assertIn(("delete", ("test:blocklist",)), calls)
        self.assertIn(
            ("sadd", ("test:blocklist", "a", "b")),
            calls,
        )
        hset = next(call for call in calls if call[0] == "hset")
        self.assertEqual(hset[1], ("test:blocklist:meta",))
        self.assertEqual(hset[2]["mapping"]["count"], "2")
        self.assertIn(("expire", ("test:blocklist", 120)), calls)
        self.assertIn(("expire", ("test:blocklist:meta", 120)), calls)

    async def test_load_reads_set_and_meta(self):
        client = FakeRedis(
            results=[{"8.8.8.8", "1.1.1.1"}, {"updated_at": "now"}]
        )
        store = RedisBlocklistStore(
            "redis://localhost:6379/0",
            key="test:blocklist",
            client=client,
        )

        ips, meta = await store.load()

        self.assertEqual(ips, {"8.8.8.8", "1.1.1.1"})
        self.assertEqual(meta, {"updated_at": "now"})
        calls = client.pipes[0].calls
        self.assertIn(("smembers", ("test:blocklist",)), calls)
        self.assertIn(("hgetall", ("test:blocklist:meta",)), calls)

    async def test_close(self):
        client = FakeRedis()
        store = RedisBlocklistStore(
            "redis://localhost:6379/0", client=client
        )
        await store.close()
        self.assertTrue(client.closed)


class FakeGeo:
    async def lookup(self, ip):
        return "ok", {
            "lat": 1.0,
            "lon": 2.0,
            "country": "Testland",
            "region": "Test Region",
        }


class FakeHub:
    def __init__(self):
        self.messages = []

    async def broadcast(self, payload):
        self.messages.append(payload)


class FakeBlocklist:
    def is_listed(self, ip):
        return ip == "8.8.8.8"


class ProcessEventTests(unittest.IsolatedAsyncioTestCase):
    async def test_auth_attempt_gets_geo_and_blocklist(self):
        import server

        event = {
            "event": "auth_attempt",
            "src_ip": "8.8.8.8",
            "username": "root",
            "ts": "2026-11-02T10:00:00.000Z",
        }
        state = server.State()
        hub = FakeHub()

        await server.process_event(
            event, state, FakeGeo(), hub, None, FakeBlocklist()
        )

        self.assertEqual(event["geo_status"], "ok")
        self.assertTrue(event["dshield_listed"])
        self.assertEqual(state.attempts, 1)
        self.assertEqual(len(hub.messages), 1)

    async def test_blocklist_field_is_omitted_when_disabled(self):
        import server

        event = {
            "event": "auth_attempt",
            "src_ip": "8.8.8.8",
            "username": "root",
            "ts": "2026-11-02T10:00:00.000Z",
        }
        await server.process_event(
            event, server.State(), FakeGeo(), FakeHub(), None, None
        )

        self.assertNotIn("dshield_listed", event)


if __name__ == "__main__":
    unittest.main()
