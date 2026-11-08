import json
import os
import tempfile
import unittest
from pathlib import Path

from connectors import (
    Deduplicator,
    event_key,
    expand_env,
    extract_records,
    load_sources_config,
    normalize_record,
    normalize_ts,
)


class NormalizeRecordTests(unittest.TestCase):
    def test_common_field_names(self):
        event = normalize_record(
            {
                "ip": "8.8.8.8",
                "timestamp": "2026-11-02T10:00:00Z",
                "user": "root",
                "auth_type": "password",
                "password": "hunter2",
                "client": "SSH-2.0-test",
                "reports": 12,
            },
            source_id="demo",
            source_name="Demo feed",
            source_url="https://example.com",
        )
        self.assertIsNotNone(event)
        self.assertEqual(event["src_ip"], "8.8.8.8")
        self.assertEqual(event["username"], "root")
        self.assertEqual(event["auth_type"], "password")
        self.assertEqual(event["password"], "hunter2")
        self.assertEqual(event["client_version"], "SSH-2.0-test")
        self.assertTrue(event["external"])
        self.assertEqual(event["source_id"], "demo")
        self.assertEqual(event["reports"], 12)
        self.assertEqual(event["ts"], "2026-11-02T10:00:00.000Z")

    def test_nested_mapping(self):
        event = normalize_record(
            {
                "indicators": [{"indicator": "1.1.1.1"}],
                "modified": "2026-11-02T10:00:00Z",
            },
            source_id="otx",
            source_name="OTX",
            mapping={"src_ip": "indicators[0].indicator", "ts": "modified"},
        )
        self.assertIsNotNone(event)
        self.assertEqual(event["src_ip"], "1.1.1.1")

    def test_invalid_ip_is_skipped(self):
        self.assertIsNone(
            normalize_record(
                {"ip": "not-an-ip"},
                source_id="demo",
                source_name="Demo",
            )
        )

    def test_missing_ip_is_skipped(self):
        self.assertIsNone(
            normalize_record(
                {"user": "root"},
                source_id="demo",
                source_name="Demo",
            )
        )

    def test_defaults_for_missing_fields(self):
        event = normalize_record(
            {"ip": "8.8.8.8"},
            source_id="demo",
            source_name="Demo",
        )
        self.assertIsNotNone(event)
        self.assertEqual(event["username"], "(external)")
        self.assertEqual(event["auth_type"], "external")
        self.assertEqual(event["client_version"], "external:Demo")


class TimestampTests(unittest.TestCase):
    def test_iso(self):
        self.assertEqual(normalize_ts("2026-11-02T10:00:00Z"), "2026-11-02T10:00:00.000Z")

    def test_epoch_seconds(self):
        self.assertEqual(normalize_ts(1762077600), "2025-11-02T10:00:00.000Z")

    def test_bad_value_falls_back(self):
        self.assertTrue(normalize_ts("not-a-date").endswith("Z"))


class ExtractRecordsTests(unittest.TestCase):
    def test_list_payload(self):
        self.assertEqual(extract_records([{"a": 1}]), [{"a": 1}])

    def test_events_key(self):
        self.assertEqual(extract_records({"events": [{"a": 1}]}), [{"a": 1}])

    def test_nested_path(self):
        payload = {"data": {"items": [{"a": 1}]}}
        self.assertEqual(extract_records(payload, "data.items"), [{"a": 1}])

    def test_single_object(self):
        self.assertEqual(extract_records({"ip": "8.8.8.8"}), [{"ip": "8.8.8.8"}])


class DedupTests(unittest.TestCase):
    def test_duplicate_is_rejected(self):
        dedup = Deduplicator()
        self.assertTrue(dedup.add("a"))
        self.assertFalse(dedup.add("a"))

    def test_event_key_uses_external_id(self):
        event = {
            "source_id": "dshield",
            "external_id": "openbl_ssh:1.2.3.4:2026-11-02",
            "src_ip": "1.2.3.4",
            "ts": "2026-11-02T00:00:00Z",
        }
        self.assertEqual(
            event_key(event),
            "dshield:id:openbl_ssh:1.2.3.4:2026-11-02",
        )


class ConfigTests(unittest.TestCase):
    def test_env_expansion(self):
        os.environ["HONEYPOT_TEST_TOKEN"] = "secret"
        self.assertEqual(expand_env("${HONEYPOT_TEST_TOKEN}"), "secret")

    def test_load_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sources.json"
            path.write_text(
                json.dumps(
                    {
                        "sources": [
                            {"id": "a", "type": "json_feed"},
                            {"id": "b", "type": "webhook"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            sources = load_sources_config(path)
            self.assertEqual([source["id"] for source in sources], ["a", "b"])

    def test_missing_file(self):
        self.assertEqual(load_sources_config(Path("does-not-exist.json")), [])


if __name__ == "__main__":
    unittest.main()
