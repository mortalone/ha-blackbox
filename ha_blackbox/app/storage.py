from __future__ import annotations

import csv
import io
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Iterable


class Storage:
    def __init__(self, path: str = "/data/blackbox.db") -> None:
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self._lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
            self.db.execute("PRAGMA temp_store=MEMORY")
            self.db.execute("PRAGMA busy_timeout=3000")
            self._init_schema()

    def _init_schema(self) -> None:
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS samples (
                ts REAL PRIMARY KEY,
                core_cpu REAL,
                core_memory_percent REAL,
                core_memory_usage INTEGER,
                core_blk_read_rate REAL,
                core_blk_write_rate REAL,
                supervisor_cpu REAL,
                supervisor_memory_percent REAL,
                disk_used_percent REAL,
                disk_free_gb REAL,
                disk_life_time REAL,
                api_ok INTEGER,
                api_latency_ms REAL,
                state_changes_per_minute REAL,
                automation_triggers_per_minute REAL,
                unavailable_per_minute REAL,
                psi_cpu REAL,
                psi_memory REAL,
                psi_io REAL,
                recorder_bytes INTEGER,
                recorder_growth_mb_hour REAL,
                addons_json TEXT,
                extra_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);

            CREATE TABLE IF NOT EXISTS minute_stats (
                bucket INTEGER PRIMARY KEY,
                state_changes INTEGER NOT NULL DEFAULT 0,
                automation_triggers INTEGER NOT NULL DEFAULT 0,
                service_calls INTEGER NOT NULL DEFAULT 0,
                unavailable_transitions INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS entity_churn (
                bucket INTEGER NOT NULL,
                entity_id TEXT NOT NULL,
                changes INTEGER NOT NULL DEFAULT 0,
                unavailable INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(bucket, entity_id)
            );
            CREATE INDEX IF NOT EXISTS idx_entity_churn_bucket ON entity_churn(bucket);

            CREATE TABLE IF NOT EXISTS automation_churn (
                bucket INTEGER NOT NULL,
                entity_id TEXT NOT NULL,
                triggers INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(bucket, entity_id)
            );
            CREATE INDEX IF NOT EXISTS idx_automation_churn_bucket ON automation_churn(bucket);

            CREATE TABLE IF NOT EXISTS important_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                source TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_important_logs_ts ON important_logs(ts);

            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                start_ts REAL NOT NULL,
                end_ts REAL,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                summary TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                context_json TEXT NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0,
                notified_ha INTEGER NOT NULL DEFAULT 0,
                updated_ts REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_incidents_start_ts ON incidents(start_ts DESC);

            CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        cols = {row["name"] for row in self.db.execute("PRAGMA table_info(incidents)").fetchall()}
        if "notified_ha" not in cols:
            self.db.execute("ALTER TABLE incidents ADD COLUMN notified_ha INTEGER NOT NULL DEFAULT 0")
        self.db.commit()

    def save_sample(self, sample: dict) -> None:
        columns = [
            "ts", "core_cpu", "core_memory_percent", "core_memory_usage",
            "core_blk_read_rate", "core_blk_write_rate", "supervisor_cpu",
            "supervisor_memory_percent", "disk_used_percent", "disk_free_gb",
            "disk_life_time", "api_ok", "api_latency_ms",
            "state_changes_per_minute", "automation_triggers_per_minute",
            "unavailable_per_minute", "psi_cpu", "psi_memory", "psi_io",
            "recorder_bytes", "recorder_growth_mb_hour", "addons_json", "extra_json",
        ]
        row = dict(sample)
        row["api_ok"] = 1 if row.get("api_ok") else 0
        row["addons_json"] = json.dumps(row.get("addons", {}), separators=(",", ":"))
        row["extra_json"] = json.dumps(row.get("extra", {}), separators=(",", ":"))
        values = [row.get(c) for c in columns]
        with self._lock:
            self.db.execute(
                f"INSERT OR REPLACE INTO samples ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
                values,
            )
            self.db.commit()

    def save_minute_stats(
        self,
        bucket: int,
        state_changes: int,
        automation_triggers: int,
        service_calls: int,
        unavailable_transitions: int,
        entity_counts: dict[str, tuple[int, int]],
        automation_counts: dict[str, int],
    ) -> None:
        with self._lock:
            self.db.execute(
                """INSERT OR REPLACE INTO minute_stats
                (bucket,state_changes,automation_triggers,service_calls,unavailable_transitions)
                VALUES (?,?,?,?,?)""",
                (bucket, state_changes, automation_triggers, service_calls, unavailable_transitions),
            )
            self.db.executemany(
                """INSERT OR REPLACE INTO entity_churn(bucket,entity_id,changes,unavailable)
                VALUES (?,?,?,?)""",
                [(bucket, entity, counts[0], counts[1]) for entity, counts in entity_counts.items()],
            )
            self.db.executemany(
                """INSERT OR REPLACE INTO automation_churn(bucket,entity_id,triggers)
                VALUES (?,?,?)""",
                [(bucket, entity, count) for entity, count in automation_counts.items()],
            )
            self.db.commit()

    def save_important_log(self, entry: dict) -> None:
        with self._lock:
            self.db.execute(
                "INSERT INTO important_logs(ts,source,level,message) VALUES (?,?,?,?)",
                (entry["ts"], entry["source"], entry["level"], entry["message"][:12000]),
            )
            self.db.commit()

    def save_incident(self, incident: dict) -> None:
        with self._lock:
            self.db.execute(
                """INSERT INTO incidents
                (id,start_ts,end_ts,status,severity,category,title,confidence,summary,recommendation,
                 evidence_json,context_json,acknowledged,notified_ha,updated_ts)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  end_ts=excluded.end_ts,status=excluded.status,severity=excluded.severity,
                  title=excluded.title,confidence=excluded.confidence,summary=excluded.summary,
                  recommendation=excluded.recommendation,evidence_json=excluded.evidence_json,
                  context_json=excluded.context_json,acknowledged=excluded.acknowledged,
                  notified_ha=MAX(incidents.notified_ha, excluded.notified_ha),
                  updated_ts=excluded.updated_ts""",
                (
                    incident["id"], incident["start_ts"], incident.get("end_ts"), incident["status"],
                    incident["severity"], incident["category"], incident["title"], incident["confidence"],
                    incident["summary"], incident["recommendation"],
                    json.dumps(incident.get("evidence", []), ensure_ascii=False, separators=(",", ":")),
                    json.dumps(incident.get("context", {}), ensure_ascii=False, separators=(",", ":")),
                    1 if incident.get("acknowledged") else 0,
                    1 if incident.get("notified_ha") else 0,
                    incident.get("updated_ts", time.time()),
                ),
            )
            self.db.commit()

    def mark_incident_notified(self, incident_id: str) -> bool:
        with self._lock:
            cur = self.db.execute(
                "UPDATE incidents SET notified_ha=1, updated_ts=? WHERE id=?",
                (time.time(), incident_id),
            )
            self.db.commit()
            return cur.rowcount > 0

    def list_unnotified_incidents(self, since_ts: float, limit: int = 20) -> list[dict]:
        with self._lock:
            rows = self.db.execute(
                """SELECT * FROM incidents
                WHERE start_ts>=? AND notified_ha=0 AND status!='ignored'
                  AND (severity='critical' OR category IN ('host_reboot', 'native_fault_crash', 'core_unresponsive'))
                ORDER BY start_ts ASC LIMIT ?""",
                (since_ts, limit),
            ).fetchall()
        return [self._decode_incident(dict(r), include_context=False) for r in rows]

    def close_open_incidents(self, end_ts: float | None = None) -> int:
        """Close incidents left open by a previous Black Box process.

        Analyzer state is intentionally process-local. After an app restart a
        still-present fault will be detected again from fresh metrics/logs.
        """
        now = float(end_ts if end_ts is not None else time.time())
        with self._lock:
            cur = self.db.execute(
                "UPDATE incidents SET status='closed', end_ts=COALESCE(end_ts, ?), updated_ts=? WHERE status='open'",
                (now, now),
            )
            self.db.commit()
            return cur.rowcount

    def acknowledge_incident(self, incident_id: str) -> bool:
        with self._lock:
            cur = self.db.execute(
                "UPDATE incidents SET acknowledged=1, updated_ts=? WHERE id=?",
                (time.time(), incident_id),
            )
            self.db.commit()
            return cur.rowcount > 0

    def get_samples(self, since_ts: float, limit: int = 20000) -> list[dict]:
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM samples WHERE ts>=? ORDER BY ts ASC LIMIT ?", (since_ts, limit)
            ).fetchall()
        return [self._decode_sample(dict(r)) for r in rows]

    @staticmethod
    def _decode_sample(row: dict) -> dict:
        row["api_ok"] = bool(row.get("api_ok"))
        for source, target in (("addons_json", "addons"), ("extra_json", "extra")):
            raw = row.pop(source, None)
            try:
                row[target] = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                row[target] = {}
        return row

    def list_incidents(self, limit: int = 100, include_ignored: bool = False) -> list[dict]:
        with self._lock:
            if include_ignored:
                rows = self.db.execute(
                    "SELECT * FROM incidents ORDER BY start_ts DESC LIMIT ?", (limit,)
                ).fetchall()
            else:
                rows = self.db.execute(
                    "SELECT * FROM incidents WHERE status!='ignored' ORDER BY start_ts DESC LIMIT ?", (limit,)
                ).fetchall()
        return [self._decode_incident(dict(r), include_context=False) for r in rows]

    def get_incident(self, incident_id: str) -> dict | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return self._decode_incident(dict(row), include_context=True) if row else None

    @staticmethod
    def _decode_incident(row: dict, include_context: bool) -> dict:
        row["acknowledged"] = bool(row.get("acknowledged"))
        row["notified_ha"] = bool(row.get("notified_ha"))
        for source, target in (("evidence_json", "evidence"), ("context_json", "context")):
            raw = row.pop(source, None)
            if target == "context" and not include_context:
                continue
            try:
                row[target] = json.loads(raw) if raw else ([] if target == "evidence" else {})
            except json.JSONDecodeError:
                row[target] = [] if target == "evidence" else {}
        return row

    def top_entities(self, since_ts: float, limit: int = 20) -> list[dict]:
        bucket = int(since_ts // 60) * 60
        with self._lock:
            rows = self.db.execute(
                """SELECT entity_id, SUM(changes) AS changes, SUM(unavailable) AS unavailable
                FROM entity_churn WHERE bucket>=? GROUP BY entity_id
                ORDER BY changes DESC LIMIT ?""",
                (bucket, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def top_flappers(self, since_ts: float, limit: int = 20) -> list[dict]:
        """Entities with the most transitions into unavailable/unknown.

        EventMonitor records both unavailable and unknown transitions in the
        ``unavailable`` counter. Sorting this separately from total state churn
        makes connectivity/integration flapping visible even when high-rate
        numeric sensors dominate the general noisy-entity list.
        """
        bucket = int(since_ts // 60) * 60
        with self._lock:
            rows = self.db.execute(
                """SELECT entity_id, SUM(changes) AS changes, SUM(unavailable) AS unavailable
                FROM entity_churn WHERE bucket>=? GROUP BY entity_id
                HAVING SUM(unavailable) > 0
                ORDER BY unavailable DESC, changes DESC LIMIT ?""",
                (bucket, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def flap_bursts(self, since_ts: float, limit: int = 12, min_entities: int = 3) -> list[dict]:
        """Minute buckets where multiple entities entered unavailable/unknown.

        We intentionally reuse the existing minute aggregation instead of storing
        every flap as its own row; that keeps Black Box from becoming a new high-I/O
        workload while still exposing strongly correlated waves.
        """
        bucket = int(since_ts // 60) * 60
        with self._lock:
            burst_rows = self.db.execute(
                """SELECT bucket, COUNT(*) AS entity_count, SUM(unavailable) AS transitions
                FROM entity_churn WHERE bucket>=? AND unavailable>0
                GROUP BY bucket HAVING COUNT(*)>=?
                ORDER BY bucket DESC LIMIT ?""",
                (bucket, min_entities, limit),
            ).fetchall()
            result = []
            for burst in burst_rows:
                members = self.db.execute(
                    """SELECT entity_id, changes, unavailable FROM entity_churn
                    WHERE bucket=? AND unavailable>0
                    ORDER BY unavailable DESC, changes DESC LIMIT 200""",
                    (burst["bucket"],),
                ).fetchall()
                result.append({
                    "bucket": burst["bucket"],
                    "entity_count": burst["entity_count"],
                    "transitions": burst["transitions"],
                    "entities": [dict(r) for r in members],
                })
        return result

    def suppress_legacy_addon_watchdog_incidents(self) -> int:
        """Hide watchdog incidents created from add-on-internal watchdog lines.

        0.1.0-0.1.2 could promote Frigate's ffmpeg watchdog messages to a
        system incident. Keep the record in SQLite but mark it ignored so it no
        longer appears as the latest Home Assistant incident.
        """
        changed = 0
        with self._lock:
            rows = self.db.execute(
                "SELECT id,evidence_json FROM incidents WHERE category='watchdog_restart' AND status!='ignored'"
            ).fetchall()
            for row in rows:
                try:
                    evidence = json.loads(row["evidence_json"] or "[]")
                except json.JSONDecodeError:
                    evidence = []
                if evidence and all(str(item).lower().startswith("addon:") for item in evidence):
                    self.db.execute(
                        "UPDATE incidents SET status='ignored', acknowledged=1, updated_ts=? WHERE id=?",
                        (time.time(), row["id"]),
                    )
                    changed += 1
            if changed:
                self.db.commit()
        return changed

    def suppress_legacy_supervisor_app_watchdog_incidents(self) -> int:
        """Hide old critical incidents that were only a single add-on watchdog restart.

        Before 0.1.13, Supervisor lines such as ``Watchdog found app X exited ...
        restarting`` were promoted to a system-critical watchdog incident. Preserve
        the raw record but mark those legacy classifications ignored; new versions
        record the same event as a warning-level add-on incident instead.
        """
        changed = 0
        with self._lock:
            rows = self.db.execute(
                "SELECT id,evidence_json FROM incidents WHERE category='watchdog_restart' AND status!='ignored'"
            ).fetchall()
            for row in rows:
                try:
                    evidence = json.loads(row["evidence_json"] or "[]")
                except json.JSONDecodeError:
                    evidence = []
                texts = [str(item).lower() for item in evidence]
                if texts and all("supervisor:" in item and "watchdog found app " in item and "restarting" in item for item in texts):
                    self.db.execute(
                        "UPDATE incidents SET status='ignored', acknowledged=1, updated_ts=? WHERE id=?",
                        (time.time(), row["id"]),
                    )
                    changed += 1
            if changed:
                self.db.commit()
        return changed

    def suppress_legacy_false_recorder_incidents(self) -> int:
        """Hide Recorder incidents caused by the pre-0.1.2 sqlite-web false positive.

        Older Black Box versions could match the word ``full`` inside
        ``successfully`` on benign sqlite-web service lines. Preserve the raw
        database record but mark those known false incidents ignored.
        """
        changed = 0
        real_failure_terms = (
            "database is locked",
            "database or disk is full",
            "database disk image is malformed",
            "disk i/o error",
            "corrupt",
            "malformed",
            "recorder error",
            "recorder failed",
            "recorder failure",
        )
        with self._lock:
            rows = self.db.execute(
                "SELECT id,evidence_json FROM incidents WHERE category='recorder_database' AND status!='ignored'"
            ).fetchall()
            for row in rows:
                try:
                    evidence = json.loads(row["evidence_json"] or "[]")
                except json.JSONDecodeError:
                    evidence = []
                texts = [str(item).lower() for item in evidence]
                sqlite_web_only = bool(texts) and all(
                    item.startswith("addon:a0d7b954_sqlite-web:") for item in texts
                )
                has_real_failure = any(
                    term in item for item in texts for term in real_failure_terms
                )
                if sqlite_web_only and not has_real_failure:
                    self.db.execute(
                        "UPDATE incidents SET status='ignored', acknowledged=1, updated_ts=? WHERE id=?",
                        (time.time(), row["id"]),
                    )
                    changed += 1
            if changed:
                self.db.commit()
        return changed

    def top_automations(self, since_ts: float, limit: int = 20) -> list[dict]:
        bucket = int(since_ts // 60) * 60
        with self._lock:
            rows = self.db.execute(
                """SELECT entity_id, SUM(triggers) AS triggers
                FROM automation_churn WHERE bucket>=? GROUP BY entity_id
                ORDER BY triggers DESC LIMIT ?""",
                (bucket, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def aggregate_minutes(self, since_ts: float) -> dict:
        bucket = int(since_ts // 60) * 60
        with self._lock:
            row = self.db.execute(
                """SELECT COALESCE(SUM(state_changes),0) AS state_changes,
                COALESCE(SUM(automation_triggers),0) AS automation_triggers,
                COALESCE(SUM(service_calls),0) AS service_calls,
                COALESCE(SUM(unavailable_transitions),0) AS unavailable_transitions
                FROM minute_stats WHERE bucket>=?""",
                (bucket,),
            ).fetchone()
        return dict(row)

    def get_logs(self, since_ts: float, limit: int = 1000, source: str | None = None) -> list[dict]:
        sql = "SELECT ts,source,level,message FROM important_logs WHERE ts>=?"
        params: list = [since_ts]
        if source:
            sql += " AND source=?"
            params.append(source)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self.db.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def set_kv(self, key: str, value) -> None:
        raw = json.dumps(value, ensure_ascii=False)
        with self._lock:
            self.db.execute(
                "INSERT INTO kv(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, raw),
            )
            self.db.commit()

    def get_kv(self, key: str, default=None):
        with self._lock:
            row = self.db.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except json.JSONDecodeError:
            return default

    def prune(self, metric_days: int, incident_days: int, log_days: int) -> None:
        now = time.time()
        metric_cutoff = now - metric_days * 86400
        incident_cutoff = now - incident_days * 86400
        log_cutoff = now - log_days * 86400
        bucket_cutoff = int(metric_cutoff // 60) * 60
        with self._lock:
            self.db.execute("DELETE FROM samples WHERE ts<?", (metric_cutoff,))
            self.db.execute("DELETE FROM minute_stats WHERE bucket<?", (bucket_cutoff,))
            self.db.execute("DELETE FROM entity_churn WHERE bucket<?", (bucket_cutoff,))
            self.db.execute("DELETE FROM automation_churn WHERE bucket<?", (bucket_cutoff,))
            self.db.execute("DELETE FROM important_logs WHERE ts<?", (log_cutoff,))
            self.db.execute("DELETE FROM incidents WHERE start_ts<? AND status!='open'", (incident_cutoff,))
            self.db.commit()
            self.db.execute("PRAGMA wal_checkpoint(PASSIVE)")

    def database_info(self) -> dict:
        try:
            size = Path(self.path).stat().st_size
        except OSError:
            size = 0
        try:
            wal_size = Path(self.path + "-wal").stat().st_size
        except OSError:
            wal_size = 0
        with self._lock:
            sample_count = self.db.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
            incident_count = self.db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            log_count = self.db.execute("SELECT COUNT(*) FROM important_logs").fetchone()[0]
        return {
            "path": self.path,
            "bytes": size,
            "wal_bytes": wal_size,
            "samples": sample_count,
            "incidents": incident_count,
            "important_logs": log_count,
        }

    def samples_csv(self, since_ts: float) -> str:
        rows = self.get_samples(since_ts, limit=100000)
        output = io.StringIO()
        fields = [
            "ts", "core_cpu", "core_memory_percent", "core_memory_usage",
            "core_blk_read_rate", "core_blk_write_rate", "supervisor_cpu",
            "supervisor_memory_percent", "disk_used_percent", "disk_free_gb",
            "disk_life_time", "api_ok", "api_latency_ms", "state_changes_per_minute",
            "automation_triggers_per_minute", "unavailable_per_minute", "psi_cpu",
            "psi_memory", "psi_io", "recorder_bytes", "recorder_growth_mb_hour",
        ]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue()

    def close(self) -> None:
        with self._lock:
            self.db.commit()
            self.db.close()
