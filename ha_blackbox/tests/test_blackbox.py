import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP))

from analyzer import Analyzer, LOG_PATTERNS, log_pattern_applies, SUPERVISOR_APP_WATCHDOG_RE
from config import Settings
from log_monitor import classify_log
from storage import Storage
from churn_analysis import classify_entity, summarize_groups, suspected_flap_source
from diagnostic_context import redact, redact_text, analyze_zigbee2mqtt, addon_context
from ai_export import build_ai_summary, build_file_index
from notifier import DirectNotifier
from event_monitor import HAEventMonitor


class ConfigTests(unittest.TestCase):
    def test_load_and_normalize(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "options.json"
            path.write_text(json.dumps({
                "sample_interval_seconds": 1,
                "persist_interval_seconds": 2,
                "excluded_apps": ["foo", ""],
            }))
            settings = Settings.load(str(path))
            self.assertEqual(settings.sample_interval_seconds, 2)
            self.assertEqual(settings.persist_interval_seconds, 5)
            self.assertEqual(settings.excluded_apps, ["foo"])

    def test_notification_secrets_are_masked_in_public_settings(self):
        settings = Settings(
            direct_critical_notifications=True,
            direct_notification_provider="ntfy",
            ntfy_topic="very-private-topic",
            ntfy_access_token="secret-token",
            ntfy_click_url="https://ha.example.test/blackbox",
        )
        settings._normalize()
        public = settings.public_dict()
        self.assertEqual(public["ntfy_topic"], "<configured>")
        self.assertEqual(public["ntfy_access_token"], "<configured>")
        self.assertEqual(public["ntfy_click_url"], "<configured>")
        self.assertEqual(public["direct_notification_provider"], "ntfy")

    def test_direct_notifier_configuration_status(self):
        settings = Settings(
            direct_critical_notifications=True,
            direct_notification_provider="ntfy",
            ntfy_server="https://ntfy.sh",
            ntfy_topic="private-topic",
        )
        settings._normalize()
        notifier = DirectNotifier(settings)
        self.assertTrue(notifier.configured())
        status = notifier.status()
        self.assertTrue(status["independent_of_core"])
        self.assertEqual(status["provider"], "ntfy")
        self.assertEqual(status["critical_priority"], 5)

    def test_ntfy_android_headers_use_max_priority_and_optional_click(self):
        settings = Settings(
            direct_critical_notifications=True,
            direct_notification_provider="ntfy",
            ntfy_server="https://ntfy.sh",
            ntfy_topic="private-topic",
            ntfy_click_url="https://ha.example.test/blackbox",
        )
        settings._normalize()
        notifier = DirectNotifier(settings)
        headers = notifier._ntfy_headers("HA Black Box – KRITISK", 5, "rotating_light,warning")
        self.assertEqual(headers["Priority"], "5")
        self.assertEqual(headers["Click"], "https://ha.example.test/blackbox")
        self.assertNotIn("private-topic", json.dumps(headers))

    def test_direct_notification_message_redacts_credentials(self):
        settings = Settings()
        notifier = DirectNotifier(settings)
        text = notifier._message({
            "summary": "camera failed rtsp://user:pw@192.168.1.2:554/stream?token=abc",
            "category": "camera",
            "confidence": 80,
            "evidence": ["Authorization: Bearer abc.def.ghi"],
        })
        self.assertNotIn("user:pw", text)
        self.assertNotIn("/stream", text)
        self.assertNotIn("abc.def.ghi", text)



class EventMonitorTests(unittest.TestCase):
    def test_status_exposes_reconnect_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "events.db"))
            mon = HAEventMonitor(db)
            mon.reconnect_attempts = 3
            mon.last_disconnect_reason = "test disconnect"
            mon.outage_since_ts = time.time() - 65
            status = mon.status()
            self.assertFalse(status["connected"])
            self.assertEqual(status["reconnect_attempts"], 3)
            self.assertGreaterEqual(status["outage_seconds"], 60)
            self.assertIn("test disconnect", status["last_disconnect_reason"])
            db.close()

    def test_registry_storage_fallback_supplies_navigation_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "events.db"))
            reg = Path(tmp) / "core.entity_registry"
            reg.write_text(json.dumps({
                "data": {
                    "entities": [{
                        "entity_id": "sensor.demo_rx",
                        "platform": "unifi",
                        "device_id": "device123",
                        "config_entry_id": "entry456",
                        "unique_id": "uniq",
                    }]
                }
            }))
            mon = HAEventMonitor(db, registry_path=str(reg))
            row = mon.enrich_rows([{"entity_id": "sensor.demo_rx", "changes": 3, "unavailable": 1}])[0]
            self.assertEqual(row["source_platform"], "unifi")
            self.assertEqual(row["device_id"], "device123")
            self.assertEqual(row["config_entry_id"], "entry456")
            self.assertEqual(mon.status()["entity_registry_source"], "storage")
            db.close()


class LogTests(unittest.TestCase):
    def test_log_classification(self):
        self.assertEqual(classify_log("2026 ERROR database is locked"), "error")
        self.assertEqual(classify_log("kernel: Out of memory: Killed process"), "warning")
        self.assertEqual(classify_log("normal startup line"), "info")

    def test_recorder_signature_does_not_match_sqlite_web_successfully(self):
        line = (
            "homeassistant app_a0d7b954_sqlite-web[567]: "
            "s6-rc: info: service sqlite-web successfully started"
        )
        matched = [category for category, _title, pattern, *_rest in LOG_PATTERNS if pattern.search(line)]
        self.assertNotIn("recorder_database", matched)


    def test_addon_watchdog_is_not_system_watchdog(self):
        line = "[2026-08-29 21:13:30] watchdog.doorbellcamera INFO : Restarting ffmpeg..."
        watchdog = next((category, pattern) for category, _title, pattern, *_rest in LOG_PATTERNS if category == "watchdog_restart")
        self.assertIsNotNone(watchdog[1].search(line))
        self.assertFalse(log_pattern_applies(watchdog[0], "addon:ccab4aaf_frigate-fa-beta"))
        self.assertTrue(log_pattern_applies(watchdog[0], "supervisor"))

    def test_supervisor_app_watchdog_signature_is_identified_separately(self):
        line = "Watchdog found app OpenThread Border Router exited with code 1, restarting..."
        match = SUPERVISOR_APP_WATCHDOG_RE.search(line)
        self.assertIsNotNone(match)
        self.assertEqual(match.group("name"), "OpenThread Border Router")
        self.assertEqual(match.group("code"), "1")

    def test_recorder_signature_matches_real_sqlite_failures(self):
        lines = [
            "homeassistant.components.recorder: database is locked",
            "sqlite3.DatabaseError: database disk image is malformed",
            "homeassistant.components.recorder: purge failed with database error",
        ]
        recorder_pattern = next(pattern for category, _title, pattern, *_rest in LOG_PATTERNS if category == "recorder_database")
        for line in lines:
            self.assertIsNotNone(recorder_pattern.search(line), line)


class EventCoverageTests(unittest.TestCase):
    def test_sse_fallback_event_is_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "events.db"))
            monitor = HAEventMonitor(db)
            monitor._mark_connected("sse")
            monitor._handle_sse_data(json.dumps({
                "event_type": "state_changed",
                "data": {
                    "entity_id": "sensor.demo",
                    "old_state": {"state": "1"},
                    "new_state": {"state": "2"},
                },
            }))
            self.assertTrue(monitor.connected)
            self.assertEqual(monitor.status()["transport"], "sse")
            self.assertTrue(monitor.status()["fallback_active"])
            self.assertEqual(monitor.rates()["state_changes_per_minute"], 1.0)
            db.close()

    def test_monitoring_issue_does_not_mark_home_assistant_unhealthy(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "health.db"))
            analyzer = Analyzer(Settings(), db, object())
            analyzer.ever_api_ok = True
            analyzer.ever_supervisor_ok = True
            analyzer.current_monitoring_issues = [{
                "category": "event_monitor_unavailable",
                "level": "warning",
            }]
            status = analyzer.status()
            self.assertEqual(status["health"], "healthy")
            self.assertEqual(status["data_quality"], "limited")
            db.close()

    def test_warning_incident_degrades_but_does_not_make_system_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "health.db"))
            analyzer = Analyzer(Settings(), db, object())
            analyzer.ever_api_ok = True
            analyzer.ever_supervisor_ok = True
            analyzer.active["addon_watchdog_restart"] = {
                "id": "warn1", "category": "addon_watchdog_restart", "title": "Add-on genstartet",
                "severity": "warning", "confidence": 90, "start_ts": time.time(),
            }
            status = analyzer.status()
            self.assertEqual(status["health"], "degraded")
            self.assertEqual(status["active_incidents"][0]["severity"], "warning")
            db.close()


class StorageTests(unittest.TestCase):
    def test_churn_and_incident_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "test.db"))
            now = time.time()
            bucket = int(now // 60) * 60
            db.save_minute_stats(
                bucket, 12, 2, 3, 1,
                {"sensor.a": (10, 0), "sensor.b": (2, 1)},
                {"automation.x": 2},
            )
            top = db.top_entities(now - 60, 10)
            self.assertEqual(top[0]["entity_id"], "sensor.a")
            self.assertEqual(top[0]["changes"], 10)
            flappers = db.top_flappers(now - 60, 10)
            self.assertEqual(flappers[0]["entity_id"], "sensor.b")
            self.assertEqual(flappers[0]["unavailable"], 1)
            db.save_minute_stats(
                bucket + 60, 9, 0, 0, 3,
                {"sensor.a_tx": (3, 1), "sensor.a_rx": (3, 1), "sensor.usw_uplink_mac": (3, 1)},
                {},
            )
            bursts = db.flap_bursts(now - 60, 10, 3)
            self.assertEqual(bursts[0]["entity_count"], 3)

            incident = {
                "id": "abc",
                "start_ts": now,
                "end_ts": None,
                "status": "open",
                "severity": "critical",
                "category": "test",
                "title": "Test",
                "confidence": 75,
                "summary": "Summary",
                "recommendation": "Recommendation",
                "evidence": ["one"],
                "context": {"samples": []},
                "acknowledged": False,
                "updated_ts": now,
            }
            db.save_incident(incident)
            loaded = db.get_incident("abc")
            self.assertEqual(loaded["evidence"], ["one"])
            self.assertFalse(loaded["acknowledged"])
            self.assertTrue(db.acknowledge_incident("abc"))
            self.assertTrue(db.get_incident("abc")["acknowledged"])
            self.assertEqual(db.close_open_incidents(now + 10), 1)
            closed = db.get_incident("abc")
            self.assertEqual(closed["status"], "closed")
            self.assertEqual(closed["end_ts"], now + 10)

            false_watchdog = dict(incident)
            false_watchdog.update({
                "id": "wd", "status": "closed", "end_ts": now + 1,
                "category": "watchdog_restart",
                "evidence": ["addon:frigate: watchdog.camera Restarting ffmpeg"],
            })
            db.save_incident(false_watchdog)
            self.assertEqual(db.suppress_legacy_addon_watchdog_incidents(), 1)
            self.assertNotIn("wd", [x["id"] for x in db.list_incidents(10)])
            self.assertEqual(db.get_incident("wd")["status"], "ignored")

            supervisor_app_watchdog = dict(incident)
            supervisor_app_watchdog.update({
                "id": "wdapp", "status": "closed", "end_ts": now + 1,
                "category": "watchdog_restart",
                "evidence": ["supervisor: Watchdog found app OpenThread Border Router exited with code 1, restarting..."],
            })
            db.save_incident(supervisor_app_watchdog)
            self.assertEqual(db.suppress_legacy_supervisor_app_watchdog_incidents(), 1)
            self.assertEqual(db.get_incident("wdapp")["status"], "ignored")

            false_recorder = dict(incident)
            false_recorder.update({
                "id": "recfalse", "status": "closed", "end_ts": now + 2,
                "category": "recorder_database",
                "evidence": [
                    "addon:a0d7b954_sqlite-web: s6-rc: info: service sqlite-web successfully started",
                    "addon:a0d7b954_sqlite-web: s6-rc: info: service nginx successfully started",
                ],
            })
            db.save_incident(false_recorder)
            self.assertEqual(db.suppress_legacy_false_recorder_incidents(), 1)
            self.assertNotIn("recfalse", [x["id"] for x in db.list_incidents(10)])
            self.assertEqual(db.get_incident("recfalse")["status"], "ignored")
            db.close()


class ChurnAnalysisTests(unittest.TestCase):
    def test_network_group_and_unifi_hint(self):
        rows = [
            {"entity_id": "sensor.siljes_tx", "changes": 50, "unavailable": 20},
            {"entity_id": "sensor.siljes_rx", "changes": 50, "unavailable": 20},
            {"entity_id": "sensor.usw_flex_mini_uplink_mac", "changes": 40, "unavailable": 20},
            {"entity_id": "sensor.uap_ac_lite_uplink_mac", "changes": 40, "unavailable": 20},
            {"entity_id": "sensor.chromecast_tx", "changes": 40, "unavailable": 20},
            {"entity_id": "sensor.chromecast_rx", "changes": 40, "unavailable": 20},
        ]
        groups = summarize_groups(rows, "unavailable", "changes")
        self.assertEqual(groups[0]["key"], "network")
        hint = suspected_flap_source(rows)
        self.assertIn("UniFi", hint["title"])
        self.assertGreaterEqual(hint["confidence"], 80)

    def test_watts_group(self):
        key, _label = classify_entity("sensor.watts_live_l3_strom")
        self.assertEqual(key, "watts")

    def test_exact_unifi_registry_beats_name_guessing(self):
        rows = [
            {"entity_id": "sensor.anything", "changes": 10, "unavailable": 5, "source_platform": "unifi"},
            {"entity_id": "sensor.other", "changes": 10, "unavailable": 5, "source_platform": "unifi"},
        ]
        groups = summarize_groups(rows, "unavailable", "changes")
        self.assertEqual(groups[0]["key"], "network")
        self.assertEqual(groups[0]["platforms"].get("unifi"), 2)
        hint = suspected_flap_source(rows)
        self.assertIn("UniFi-integrationen", hint["title"])
        self.assertGreaterEqual(hint["confidence"], 94)

    def test_group_keeps_config_entry_for_direct_integration_navigation(self):
        rows = [
            {"entity_id": "sensor.a", "changes": 10, "unavailable": 2, "source_platform": "unifi", "config_entry_id": "entry1"},
            {"entity_id": "sensor.b", "changes": 9, "unavailable": 2, "source_platform": "unifi", "config_entry_id": "entry1"},
        ]
        group = summarize_groups(rows, "changes", "unavailable")[0]
        self.assertEqual(group["config_entries"].get("entry1"), 2)

    def test_battery_entity_is_separate_group(self):
        key, _ = classify_entity({"entity_id": "sensor.button_battery", "battery_device": True})
        self.assertEqual(key, "battery")


class DiagnosticContextTests(unittest.TestCase):
    def test_redaction_drops_credentials_and_url_paths(self):
        value = {
            "password": "secret",
            "url": "rtsp://camera:pw@192.168.1.2:554/Streaming/Channels/101?token=abc",
            "nested": {"api_key": "123", "normal": "ok"},
        }
        safe = redact(value)
        self.assertEqual(safe["password"], "<redacted>")
        self.assertEqual(safe["nested"]["api_key"], "<redacted>")
        self.assertEqual(safe["nested"]["normal"], "ok")
        self.assertEqual(safe["url"], "rtsp://192.168.1.2:554")


    def test_freeform_log_redaction_removes_bearer_and_embedded_rtsp_path(self):
        text = "ffmpeg -i rtsp://camera:pw@192.168.1.2:554/Streaming/101?token=abc Authorization: Bearer abc.def.ghi"
        safe = redact_text(text)
        self.assertNotIn("camera:pw", safe)
        self.assertNotIn("Streaming/101", safe)
        self.assertNotIn("abc.def.ghi", safe)
        self.assertIn("rtsp://192.168.1.2:554", safe)

    def test_addon_context_never_exports_generic_secret_option_values(self):
        addons = [{"slug": "core_mosquitto", "name": "Mosquitto broker", "state": "started", "version": "1"}]
        details = {"core_mosquitto": {"options": {"logins": [{"username": "me", "password": "secret"}], "anonymous": False, "custom_secret": "do-not-export"}}}
        ctx = addon_context(addons, details)
        serialized = json.dumps(ctx)
        self.assertNotIn("do-not-export", serialized)
        self.assertNotIn("secret", serialized)
        self.assertEqual(ctx["core_mosquitto"]["safe_options"]["logins_count"], 1)

    def test_z2m_short_passive_timeout_is_flagged(self):
        ctx = {
            "found": True,
            "availability": {"enabled": True, "active": {"timeout": 10}, "passive": {"timeout": 30}},
            "availability_overrides": [],
        }
        findings = analyze_zigbee2mqtt(ctx)
        self.assertTrue(any(x["level"] == "warning" for x in findings))


class AIExportTests(unittest.TestCase):
    def test_ai_summary_has_self_contained_file_workflow(self):
        status = {"version": "0.1.8", "generated_ts": 1, "health": {"health": "observed", "warnings": [], "advisories": []}, "current": {"api_ok": True}}
        churn = {"entities": [], "flappers": [], "automations": [], "totals": {}, "analysis": {}}
        context = {"privacy": {}, "zigbee2mqtt": {"found": False}, "frigate": {"found": False}, "recorder": {"found": False}, "addons": {}, "automations": {"found": False}}
        summary = build_ai_summary(status, churn, context, [], [], [], 0, 0)
        self.assertEqual(summary["schema"], "ha-blackbox-ai-summary-v1")
        self.assertTrue(summary["recommended_ai_workflow"])
        self.assertIn("AI-START-HERE.md", build_file_index()["files"])


if __name__ == "__main__":
    unittest.main()
