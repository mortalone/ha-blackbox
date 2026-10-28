from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import time

from aiohttp import web

from analyzer import Analyzer
from config import Settings
from event_monitor import HAEventMonitor
from log_monitor import LogMonitor
from metrics import MetricsCollector
from storage import Storage
from supervisor import APIError, SupervisorClient
from webapp import WebApp
from version import VERSION
LOGGER = logging.getLogger("blackbox")


def configure_logging() -> None:
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


async def boot_postmortem(client: SupervisorClient, storage: Storage, analyzer: Analyzer) -> None:
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
                await analyzer.create_reboot_postmortem(logs, host)
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
        on_sample=analyzer.evaluate,
        log_monitor=logs,
    )
    analyzer.set_context_providers(metrics.recent, logs.recent, storage.top_entities)

    web_app = WebApp(settings, storage, analyzer, metrics, events, logs, started_ts)
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
        asyncio.create_task(boot_postmortem(client, storage, analyzer), name="boot-postmortem"),
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
