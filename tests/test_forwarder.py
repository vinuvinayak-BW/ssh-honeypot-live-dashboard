import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from forwarder import (
    Checkpoint,
    ClickHouseBackend,
    ElasticsearchBackend,
    JsonlFollower,
    clickhouse_ts,
    event_id,
    flatten_event,
)

EVENT = {
    "id": "abc123",
    "ts": "2026-11-02T04:00:00.000Z",
    "event": "auth_attempt",
    "connection_id": "conn1",
    "src_ip": "203.0.113.7",
    "src_port": 2222,
    "client_version": "SSH-2.0-test",
    "username": "root",
    "auth_type": "password",
    "password": "hunter2",
    "key_type": None,
    "key_bits": None,
    "key_fingerprint": None,
    "external": True,
    "source_id": "dshield-ssh",
    "source_name": "DShield",
    "geo": {
        "lat": 1.5,
        "lon": 2.5,
        "city": "X",
        "country": "Y",
        "country_code": "YY",
        "region": "R",
        "source": "ip-api.com",
    },
    "geo_status": "ok",
}


class PayloadTests(unittest.TestCase):
    def test_elasticsearch_bulk_lines(self):
        backend = ElasticsearchBackend("https://es.example.com:9200", "ssh-honeypot")
        lines = backend.build([EVENT]).decode("utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        action = json.loads(lines[0])
        self.assertEqual(action["index"]["_index"], "ssh-honeypot-2026-11-02")
        self.assertEqual(action["index"]["_id"], "abc123")
        doc = json.loads(lines[1])
        self.assertEqual(doc["id"], "abc123")
        self.assertEqual(doc["@timestamp"], "2026-11-02T04:00:00.000Z")
        self.assertTrue(doc["ingested_at"].endswith("Z"))
        self.assertEqual(doc["geo"]["country"], "Y")

    def test_elasticsearch_requires_https_by_default(self):
        with self.assertRaises(ValueError):
            ElasticsearchBackend("http://es.example.com:9200", "ssh-honeypot")
        ElasticsearchBackend(
            "http://es.example.com:9200", "ssh-honeypot", allow_plaintext=True
        )

    def test_elasticsearch_rejects_bad_index_prefix(self):
        with self.assertRaises(ValueError):
            ElasticsearchBackend("https://es.example.com:9200", "SSH-Honeypot")

    def test_elasticsearch_requires_password_with_username(self):
        with self.assertRaises(ValueError):
            ElasticsearchBackend(
                "https://es.example.com:9200", "ssh-honeypot", username="elastic"
            )

    def test_clickhouse_row(self):
        backend = ClickHouseBackend(
            "https://ch.example.com:8443", "ssh_honeypot", "events"
        )
        row = json.loads(backend.build([EVENT]).decode("utf-8").splitlines()[0])
        self.assertEqual(row["id"], "abc123")
        self.assertEqual(row["ts"], "2026-11-02 04:00:00.000")
        self.assertEqual(row["src_ip"], "203.0.113.7")
        self.assertEqual(row["src_port"], 2222)
        self.assertEqual(row["geo_lat"], 1.5)
        self.assertTrue(row["external"])
        self.assertEqual(row["source_id"], "dshield-ssh")

    def test_clickhouse_rejects_bad_identifier(self):
        with self.assertRaises(ValueError):
            ClickHouseBackend("https://ch.example.com", "ssh_honeypot; DROP", "events")
        with self.assertRaises(ValueError):
            ClickHouseBackend("https://ch.example.com", "ssh_honeypot", "events; DROP")

    def test_clickhouse_timestamp(self):
        self.assertEqual(
            clickhouse_ts("2026-11-02T04:00:00.123Z"),
            "2026-11-02 04:00:00.123",
        )
        self.assertRegex(
            clickhouse_ts("not-a-date"), r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$"
        )

    def test_event_id_is_deterministic_without_id(self):
        event = {"src_ip": "203.0.113.7", "username": "root"}
        self.assertEqual(event_id(event), event_id(dict(event)))
        self.assertEqual(len(event_id(event)), 64)

    def test_flatten_defaults(self):
        row = flatten_event({"id": "x", "ts": "2026-11-02T04:00:00Z"})
        self.assertEqual(row["username"], "")
        self.assertEqual(row["src_port"], 0)
        self.assertIsNone(row["geo_lat"])
        self.assertFalse(row["external"])


class CheckpointTests(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkpoint.json"
            source = Path(tmp) / "events.jsonl"
            checkpoint = Checkpoint(path, "elasticsearch")
            checkpoint.update(source, 1, 2, 42)
            checkpoint.save()
            self.assertTrue(path.exists())
            self.assertFalse(path.with_name(path.name + ".tmp").exists())

            loaded = Checkpoint(path, "elasticsearch")
            self.assertEqual(loaded.get(source)["offset"], 42)

    def test_backend_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkpoint.json"
            checkpoint = Checkpoint(path, "elasticsearch")
            checkpoint.update(Path(tmp) / "events.jsonl", 1, 2, 3)
            checkpoint.save()
            with self.assertRaises(SystemExit):
                Checkpoint(path, "clickhouse")


class FollowerTests(unittest.TestCase):
    def _make(self, tmp, content, start="beginning"):
        path = Path(tmp) / "events.jsonl"
        path.write_bytes(content)
        checkpoint = Checkpoint(Path(tmp) / "checkpoint.json", "elasticsearch")
        follower = JsonlFollower(path, checkpoint, start == "beginning")
        return path, checkpoint, follower

    def test_partial_line_is_not_consumed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, checkpoint, follower = self._make(
                tmp, b'{"id":"1"}\n{"id":"2"}'
            )
            events = follower.read_batch(10)
            self.assertEqual([event["id"] for event in events], ["1"])
            self.assertEqual(checkpoint.get(path)["offset"], len(b'{"id":"1"}\n'))

            with path.open("ab") as fh:
                fh.write(b"\n")
            events = follower.read_batch(10)
            self.assertEqual([event["id"] for event in events], ["2"])

    def test_limit_and_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, follower = self._make(
                tmp, b'{"id":"1"}\n{"id":"2"}\n{"id":"3"}\n'
            )
            self.assertEqual(
                [event["id"] for event in follower.read_batch(2)], ["1", "2"]
            )
            self.assertEqual(
                [event["id"] for event in follower.read_batch(2)], ["3"]
            )

    def test_start_at_end_skips_existing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, _, follower = self._make(tmp, b'{"id":"old"}\n', start="end")
            self.assertEqual(follower.read_batch(10), [])
            with path.open("ab") as fh:
                fh.write(b'{"id":"new"}\n')
            self.assertEqual(
                [event["id"] for event in follower.read_batch(10)], ["new"]
            )

    def test_invalid_line_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, follower = self._make(tmp, b"not json\n{\"id\":\"ok\"}\n")
            self.assertEqual(
                [event["id"] for event in follower.read_batch(10)], ["ok"]
            )

    def test_truncated_file_restarts_at_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, _, follower = self._make(tmp, b'{"id":"old"}\n')
            self.assertEqual(
                [event["id"] for event in follower.read_batch(10)], ["old"]
            )
            path.write_bytes(b'{"id":"n"}\n')
            self.assertEqual(
                [event["id"] for event in follower.read_batch(10)], ["n"]
            )


class _CaptureHandler(BaseHTTPRequestHandler):
    body = b""
    path = ""
    headers = {}
    response = b'{"errors":false}'

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        type(self).body = self.rfile.read(length)
        type(self).path = self.path
        type(self).headers = {
            key.lower(): value for key, value in self.headers.items()
        }
        body = type(self).response
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class HttpTransportTests(unittest.TestCase):
    def _serve(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _CaptureHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def test_elasticsearch_bulk_request(self):
        _CaptureHandler.response = b'{"errors":false}'
        server = self._serve()
        try:
            backend = ElasticsearchBackend(
                f"http://127.0.0.1:{server.server_address[1]}",
                "ssh-honeypot",
                allow_plaintext=True,
            )
            backend.send([EVENT])
        finally:
            server.shutdown()
            server.server_close()
        self.assertTrue(_CaptureHandler.path.startswith("/_bulk"))
        self.assertEqual(_CaptureHandler.headers["content-type"], "application/x-ndjson")
        self.assertEqual(len(_CaptureHandler.body.splitlines()), 2)

    def test_clickhouse_insert_request(self):
        _CaptureHandler.response = b""
        server = self._serve()
        try:
            backend = ClickHouseBackend(
                f"http://127.0.0.1:{server.server_address[1]}",
                "ssh_honeypot",
                "events",
                username="honeypot",
                password="secret",
                allow_plaintext=True,
            )
            backend.send([EVENT])
        finally:
            server.shutdown()
            server.server_close()
        self.assertIn("query=INSERT", _CaptureHandler.path)
        self.assertEqual(_CaptureHandler.headers["x-clickhouse-user"], "honeypot")
        self.assertEqual(_CaptureHandler.headers["x-clickhouse-key"], "secret")
        self.assertEqual(len(_CaptureHandler.body.splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
