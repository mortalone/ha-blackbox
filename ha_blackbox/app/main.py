from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
from pathlib import Path

try:
    from aiohttp import web
    from webapp import WebApp
except ModuleNotFoundError:  # pragma: no cover - unit tests without aiohttp installed
    web = None  # type: ignore[assignment]
    WebApp = None  # type: ignore[assignment]

from analyzer import Analyzer
from config import Settings
from event_monitor import HAEventMonitor
from log_monitor import LogMonitor, inspect_fault_log
from metrics import MetricsCollector
from storage import Storage
from supervisor import APIError, SupervisorClient
from version import VERSION

LOGGER = logging.getLogger("blackbox")


def configure_logging() -> None:
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


class CoreAutoHealWatchdog:
    """Monitors Core API responsiveness, home-assistant.log.fault, and executes guarded auto-heal restarts."""

    def __init__(
        self,
        settings: Settings,
        client: SupervisorClient,
        storage: Storage,
        analyzer: Analyzer,
        fault_log_path: str = "/homeassistant/home-assistant.log.fault",
        share_status_path: str = "/share/ha_blackbox/latest_status.json",
    ) -> None:
        self.settings = settings
        self.client = client
        self.storage = storage
        self.analyzer = analyzer
        self.fault_log_path = fault_log_path
        self.share_status_path = share_status_path
        self.unresponsive_since_ts: float | None = None
        self.last_fault_check_ts: float = 0.0
        self.last_status_publish_ts: float = 0.0
        self.camera_prefs_synced: bool = False
        self.restart_history: list[float] = list(storage.get_kv("auto_heal_restart_history", []) or [])
        self.last_action: dict = dict(storage.get_kv("last_auto_heal", {}) or {})

    async def check_fault_log(self, now: float | None = None) -> dict:
        ts = float(now if now is not None else time.time())
        fault_info = inspect_fault_log(self.fault_log_path)
        self.last_fault_check_ts = ts
        incident = await self.analyzer.ingest_fault_log(fault_info, ts)
        if incident:
            self.storage.save_important_log({
                "ts": ts,
                "source": "core:fault_log",
                "level": "error",
                "message": f"home-assistant.log.fault: {fault_info.get('summary_da')}",
            })
        return fault_info

    async def _has_blocking_supervisor_job(self) -> tuple[bool, str]:
        try:
            info = await self.client.jobs_info()
        except Exception as exc:
            return False, f"jobs_info_unavailable:{exc}"
        jobs = info.get("jobs") if isinstance(info, dict) else []
        for job in jobs or []:
            if not isinstance(job, dict) or job.get("done") is True:
                continue
            name = str(job.get("name") or "").lower()
            ref = str(job.get("reference") or "").lower()
            if any(term in f"{name} {ref}" for term in ("backup", "restore", "update", "core", "rebuild", "snapshot")):
                return True, f"{name or 'job'}:{ref}"
        return False, ""

    async def on_sample(self, sample: dict) -> None:
        now = float(sample.get("ts") or time.time())
        api_ok = bool(sample.get("api_ok"))
        extra = sample.get("extra") or {}
        supervisor_ok = bool(extra.get("supervisor_ok"))

        # Poll home-assistant.log.fault every 15s, or immediately when Core API fails.
        if (not api_ok and self.unresponsive_since_ts is None) or (now - self.last_fault_check_ts >= 15):
            try:
                await self.check_fault_log(now)
            except Exception as exc:
                LOGGER.warning("Fault log check failed: %s", exc)

        await self.analyzer.evaluate(sample)

        if api_ok:
            self.unresponsive_since_ts = None
            if not self.camera_prefs_synced:
                self.camera_prefs_synced = True
                asyncio.create_task(self._sync_camera_prefs())
        elif supervisor_ok and self.analyzer.ever_api_ok:
            if self.unresponsive_since_ts is None:
                self.unresponsive_since_ts = now
            down_seconds = now - self.unresponsive_since_ts
            if self.settings.auto_restart_unresponsive_core and down_seconds >= self.settings.core_unresponsive_restart_seconds:
                await self._maybe_trigger_core_restart(now, down_seconds)

        if now - self.last_status_publish_ts >= 30:
            self.last_status_publish_ts = now
            asyncio.create_task(self._publish_live_telemetry(now, sample))

    async def _sync_camera_prefs(self) -> None:
        try:
            result = await self.client.sync_camera_preload_prefs()
            if result.get("synced"):
                LOGGER.info("Synchronized camera preload_stream preferences: %s", result.get("updated"))
        except Exception as exc:
            LOGGER.debug("Could not sync camera preload preferences: %s", exc)

    async def _maybe_trigger_core_restart(self, now: float, down_seconds: float) -> None:
        cooldown_sec = self.settings.core_restart_cooldown_minutes * 60
        self.restart_history = [ts for ts in self.restart_history if now - ts < 3600]
        last_restart_ts = self.restart_history[-1] if self.restart_history else 0.0
        if now - last_restart_ts < cooldown_sec:
            return
        if len(self.restart_history) >= 2:
            self.last_action = {
                "ts": now,
                "status": "circuit_breaker_open",
                "down_seconds": round(down_seconds, 1),
                "detail": "Max 2 automatiske Core-genstarter pr. time er nået.",
            }
            self.storage.set_kv("last_auto_heal", self.last_action)
            return

        busy, job_desc = await self._has_blocking_supervisor_job()
        if busy:
            LOGGER.info("Skipping Core auto-restart because Supervisor job is active: %s", job_desc)
            return

        # Re-check fault_log right before restarting so any native crash is recorded first.
        fault_info = await self.check_fault_log(now)
        fault_note = f" ({fault_info.get('summary_da')})" if fault_info.get("found") else ""
        msg = (
            f"Auto-heal: Home Assistant Core API har ikke svaret i {int(down_seconds)}s mens Supervisor er sund"
            f"{fault_note}. Udfører kontrolleret genstart af Core via Supervisor API."
        )
        LOGGER.warning(msg)
        self.storage.save_important_log({
            "ts": now,
            "source": "blackbox:auto_heal",
            "level": "warning",
            "message": msg,
        })

        self.restart_history.append(now)
        self.storage.set_kv("auto_heal_restart_history", self.restart_history[-10:])
        self.last_action = {
            "ts": now,
            "status": "restarting",
            "down_seconds": round(down_seconds, 1),
            "fault_summary": fault_info.get("summary_da") if fault_info.get("found") else None,
            "detail": msg,
        }
        self.storage.set_kv("last_auto_heal", self.last_action)

        active_inc = self.analyzer.active.get("core_unresponsive")
        if active_inc:
            ev = f"auto_heal: Genstart af Home Assistant Core udløst efter {int(down_seconds)}s nedetid{fault_note}"
            if ev not in active_inc["evidence"]:
                active_inc["evidence"].append(ev)
            active_inc["updated_ts"] = now
            self.storage.save_incident(active_inc)

        try:
            await self.client.restart_core()
            self.last_action["status"] = "completed"
            self.last_action["completed_ts"] = time.time()
            self.storage.set_kv("last_auto_heal", self.last_action)
            self.unresponsive_since_ts = time.time()
            self.camera_prefs_synced = False
            LOGGER.warning("Auto-heal: Supervisor Core restart completed successfully")
        except Exception as exc:
            self.last_action["status"] = "failed"
            self.last_action["error"] = str(exc)[:300]
            self.storage.set_kv("last_auto_heal", self.last_action)
            LOGGER.error("Auto-heal: Supervisor Core restart failed: %s", exc)

    def status(self) -> dict:
        now = time.time()
        recent_1h = [ts for ts in self.restart_history if now - ts < 3600]
        return {
            "enabled": self.settings.auto_restart_unresponsive_core,
            "trigger_after_seconds": self.settings.core_unresponsive_restart_seconds,
            "cooldown_minutes": self.settings.core_restart_cooldown_minutes,
            "current_unresponsive_seconds": round(now - self.unresponsive_since_ts, 1) if self.unresponsive_since_ts else 0.0,
            "restarts_last_hour": len(recent_1h),
            "last_action": self.last_action or None,
        }

    async def _publish_live_telemetry(self, now: float, sample: dict) -> None:
        health = self.analyzer.status()
        incidents = self.storage.list_incidents(5)
        last_inc = incidents[0] if incidents else {}
        fault = self.analyzer.last_fault_info or {"found": False}
        auto_heal = self.status()

        snapshot = {
            "version": VERSION,
            "updated_ts": now,
            "health": health,
            "auto_heal": auto_heal,
            "fault_log": {
                "found": bool(fault.get("found")),
                "mtime_ts": fault.get("mtime_ts"),
                "crash_count": fault.get("crash_count"),
                "signal": fault.get("signal"),
                "crashing_thread": fault.get("crashing_thread"),
                "suspected_component": fault.get("suspected_component"),
                "top_frame": fault.get("top_frame"),
                "summary_da": fault.get("summary_da"),
            },
            "recent_incidents": incidents,
        }
        try:
            target = Path(self.share_status_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError:
            pass

        if sample.get("api_ok"):
            attrs = {
                "friendly_name": "HA Black Box Status",
                "icon": "mdi:shield-search",
                "version": VERSION,
                "data_quality": health.get("data_quality"),
                "active_incidents_count": len(health.get("active_incidents") or []),
                "warnings_count": len(health.get("warnings") or []),
                "last_incident_id": last_inc.get("id"),
                "last_incident_title": last_inc.get("title"),
                "last_incident_category": last_inc.get("category"),
                "last_incident_severity": last_inc.get("severity"),
                "last_incident_confidence": last_inc.get("confidence"),
                "last_incident_start_ts": last_inc.get("start_ts"),
                "fault_log_found": bool(fault.get("found")),
                "fault_log_summary": fault.get("summary_da"),
                "fault_log_thread": fault.get("crashing_thread"),
                "fault_log_component": fault.get("suspected_component"),
                "fault_log_mtime_ts": fault.get("mtime_ts"),
                "auto_heal_enabled": auto_heal["enabled"],
                "auto_heal_trigger_seconds": auto_heal["trigger_after_seconds"],
                "auto_heal_restarts_last_hour": auto_heal["restarts_last_hour"],
                "auto_heal_last_action": auto_heal["last_action"],
                "updated_ts": now,
            }
            try:
                await self.client.set_ha_state("sensor.ha_blackbox_status", str(health.get("health") or "healthy"), attrs)
            except Exception as exc:
                LOGGER.debug("Could not update sensor.ha_blackbox_status: %s", exc)


async def boot_postmortem(
    client: SupervisorClient,
    storage: Storage,
    analyzer: Analyzer,
    watchdog: CoreAutoHealWatchdog,
) -> None:
    # Always inspect home-assistant.log.fault on startup so any native C/Python crash is captured
    # and correlated with recent core_unresponsive / host_reboot incidents immediately.
    fault_info = await watchdog.check_fault_log()

    # Startup stage is `system`, so Core may not exist yet. Supervisor/host can still become ready shortly after us.
    for attempt in range(20):
        try:
            host = await client.get("/host/info")
            if not isinstance(host, dict) or not host.get("boot_timestamp"):
                raise APIError("host boot_timestamp unavailable")
            current_boot = host["boot_timestamp"]
            previous_boot = storage.get_kv("host_boot_timestamp")
            if previous_boot is not None and previous_boot != current_boot:
                LOGGER.warning("Detected a new host boot; collecting previous-boot postmortem")
                logs: dict[str, str] = {}
                for source in ("host", "supervisor", "core"):
                    try:
                        logs[source] = await client.previous_boot_logs(source, lines=1200)
                    except Exception as exc:
                        LOGGER.warning("Could not fetch previous %s log: %s", source, exc)
                await analyzer.create_reboot_postmortem(logs, host, fault_info=fault_info)
            storage.set_kv("host_boot_timestamp", current_boot)
            storage.set_kv("host_info_at_last_start", host)
            return
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if attempt in {0, 4, 9, 19}:
                LOGGER.warning("Waiting for Supervisor host info: %s", exc)
            await asyncio.sleep(min(30, 2 + attempt * 2))


async def main() -> None:
    configure_logging()
    started_ts = time.time()
    settings = Settings.load()
    storage = Storage()
    closed_previous = storage.close_open_incidents(started_ts)
    if closed_previous:
        LOGGER.info("Closed %d incident(s) left open by the previous Black Box process", closed_previous)
    suppressed_watchdogs = storage.suppress_legacy_addon_watchdog_incidents()
    if suppressed_watchdogs:
        LOGGER.info("Ignored %d legacy add-on watchdog incident(s) from older Black Box versions", suppressed_watchdogs)
    suppressed_supervisor_apps = storage.suppress_legacy_supervisor_app_watchdog_incidents()
    if suppressed_supervisor_apps:
        LOGGER.info("Ignored %d legacy system-critical add-on watchdog incident(s) from older Black Box versions", suppressed_supervisor_apps)
    suppressed_recorder = storage.suppress_legacy_false_recorder_incidents()
    if suppressed_recorder:
        LOGGER.info("Ignored %d legacy false Recorder incident(s) from older Black Box versions", suppressed_recorder)
    client = SupervisorClient()
    events = HAEventMonitor(storage)
    analyzer = Analyzer(settings, storage, client)
    restored = analyzer.restore_pending_notifications(started_ts - 86400)
    if restored:
        LOGGER.info("Restored %d un-notified incident(s) from the last 24h for delivery once HA Core is ready", restored)

    watchdog = CoreAutoHealWatchdog(
        settings=settings,
        client=client,
        storage=storage,
        analyzer=analyzer,
    )
    logs = LogMonitor(
        client=client,
        storage=storage,
        ring_lines=settings.log_ring_lines,
        initial_lines=settings.log_initial_lines,
        on_entry=analyzer.on_log,
    )
    metrics = MetricsCollector(
        settings=settings,
        client=client,
        storage=storage,
        events=events,
        on_sample=watchdog.on_sample,
        log_monitor=logs,
    )
    analyzer.set_context_providers(metrics.recent, logs.recent, storage.top_entities)

    web_app = WebApp(settings, storage, analyzer, metrics, events, logs, started_ts, watchdog=watchdog)
    runner = web.AppRunner(web_app.app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", 8099)
    await site.start()

    LOGGER.info("HA Black Box %s started on port 8099", VERSION)
    if not client.token:
        LOGGER.error("SUPERVISOR_TOKEN is missing; monitoring APIs will not work")

    await logs.start_base_sources()
    tasks = [
        asyncio.create_task(events.run(), name="ha-events"),
        asyncio.create_task(metrics.run(), name="metrics"),
        asyncio.create_task(boot_postmortem(client, storage, analyzer, watchdog), name="boot-postmortem"),
    ]

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    try:
        await stop_event.wait()
    finally:
        LOGGER.info("Stopping HA Black Box")
        metrics.stop()
        events.stop()
        await logs.stop()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await runner.cleanup()
        await analyzer.close()
        await client.close()
        storage.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
