from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import Counter, deque
from pathlib import Path
from typing import Awaitable, Callable

from config import Settings
from event_monitor import HAEventMonitor
from storage import Storage
from supervisor import APIError, SupervisorClient

LOGGER = logging.getLogger("blackbox.metrics")


def _number(value, default=None):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default




def read_local_system() -> dict:
    result: dict = {}
    try:
        parts = Path("/proc/loadavg").read_text(encoding="utf-8").split()
        if parts:
            result["load1"] = float(parts[0])
            result["load5"] = float(parts[1])
            result["load15"] = float(parts[2])
    except (OSError, ValueError, IndexError):
        pass

    try:
        meminfo = {}
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if ":" not in line:
                continue
            key, raw = line.split(":", 1)
            value = raw.strip().split()[0]
            meminfo[key] = int(value) * 1024
        for key, out in (("MemTotal", "memory_total_bytes"), ("MemAvailable", "memory_available_bytes"), ("SwapTotal", "swap_total_bytes"), ("SwapFree", "swap_free_bytes")):
            if key in meminfo:
                result[out] = meminfo[key]
    except (OSError, ValueError):
        pass

    temps: list[tuple[str, float]] = []
    try:
        for zone in Path("/sys/class/thermal").glob("thermal_zone*"):
            try:
                temp = float((zone / "temp").read_text().strip())
                if temp > 1000:
                    temp /= 1000.0
                label = (zone / "type").read_text().strip() if (zone / "type").exists() else zone.name
                if 0 < temp < 130:
                    temps.append((label, temp))
            except (OSError, ValueError):
                continue
    except OSError:
        pass
    try:
        for hwmon in Path("/sys/class/hwmon").glob("hwmon*"):
            try:
                chip = (hwmon / "name").read_text().strip()
            except OSError:
                chip = hwmon.name
            for input_file in hwmon.glob("temp*_input"):
                try:
                    temp = float(input_file.read_text().strip())
                    if temp > 1000:
                        temp /= 1000.0
                    label_file = input_file.with_name(input_file.name.replace("_input", "_label"))
                    label = label_file.read_text().strip() if label_file.exists() else input_file.stem
                    if 0 < temp < 130:
                        temps.append((f"{chip}:{label}", temp))
                except (OSError, ValueError):
                    continue
    except OSError:
        pass
    if temps:
        label, temp = max(temps, key=lambda item: item[1])
        result["temperature_c"] = round(temp, 1)
        result["temperature_sensor"] = label
        result["temperatures"] = [{"sensor": label, "c": round(temp, 1)} for label, temp in sorted(temps, key=lambda item: item[1], reverse=True)[:10]]
    return result

def read_psi(kind: str) -> float | None:
    path = Path(f"/proc/pressure/{kind}")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        if not line.startswith("some "):
            continue
        for part in line.split():
            if part.startswith("avg10="):
                return _number(part.split("=", 1)[1])
    return None


class MetricsCollector:
    def __init__(
        self,
        settings: Settings,
        client: SupervisorClient,
        storage: Storage,
        events: HAEventMonitor,
        on_sample: Callable[[dict], Awaitable[None]],
        log_monitor=None,
    ) -> None:
        self.settings = settings
        self.client = client
        self.storage = storage
        self.events = events
        self.on_sample = on_sample
        self.log_monitor = log_monitor
        ring_size = max(300, int(settings.pre_incident_minutes * 60 / settings.sample_interval_seconds) + 120)
        self.ring: deque[dict] = deque(maxlen=ring_size)
        self.last_sample: dict = {}
        self.last_addons: dict[str, dict] = {}
        self.last_addon_list: list[dict] = []
        self.last_disk_breakdown: dict = {}
        self.last_resolution: dict = {}
        self.last_inventory: dict = {"unavailable": [], "unknown": [], "by_domain": {}, "total": 0}
        self.last_host_info: dict = {}
        self._db_size_points: deque[tuple[float, int]] = deque(maxlen=2000)
        self._last_core_io: tuple[float, float, float] | None = None
        self._last_persist = 0.0
        self._stop = asyncio.Event()
        self._background_tasks: list[asyncio.Task] = []

    async def run(self) -> None:
        self._background_tasks = [
            asyncio.create_task(self._addon_loop(), name="addon-stats"),
            asyncio.create_task(self._disk_breakdown_loop(), name="disk-breakdown"),
            asyncio.create_task(self._resolution_loop(), name="resolution"),
            asyncio.create_task(self._inventory_loop(), name="ha-inventory"),
            asyncio.create_task(self._prune_loop(), name="storage-prune"),
        ]
        try:
            while not self._stop.is_set():
                started = time.monotonic()
                try:
                    sample = await self.collect_sample()
                    self.last_sample = sample
                    self.ring.append(sample)
                    if sample["ts"] - self._last_persist >= self.settings.persist_interval_seconds:
                        self.storage.save_sample(sample)
                        self._last_persist = sample["ts"]
                    await self.on_sample(sample)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    LOGGER.exception("Metric collection failed: %s", exc)
                elapsed = time.monotonic() - started
                wait = max(0.2, self.settings.sample_interval_seconds - elapsed)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=wait)
                except asyncio.TimeoutError:
                    pass
        finally:
            for task in self._background_tasks:
                task.cancel()
            await asyncio.gather(*self._background_tasks, return_exceptions=True)

    async def collect_sample(self) -> dict:
        now = time.time()
        core_task = asyncio.create_task(self._safe_get("/core/stats"))
        supervisor_task = asyncio.create_task(self._safe_get("/supervisor/stats"))
        api_task = asyncio.create_task(self._api_probe())
        supervisor_probe_task = asyncio.create_task(self._supervisor_probe())

        # Host info is cached for 15 seconds; it contains disk capacity and boot data.
        if not self.last_host_info or now - self.last_host_info.get("_fetched", 0) >= 15:
            host = await self._safe_get("/host/info")
            if host:
                host["_fetched"] = now
                self.last_host_info = host

        core, supervisor, api, supervisor_probe = await asyncio.gather(core_task, supervisor_task, api_task, supervisor_probe_task)
        rates = self.events.rates()
        local_system = read_local_system()
        recorder = self._recorder_stats(now)
        io_rates = self._io_rates(now, core)
        host = self.last_host_info

        disk_total = _number(host.get("disk_total"), 0.0) or 0.0
        disk_used = _number(host.get("disk_used"), 0.0) or 0.0
        disk_free = _number(host.get("disk_free"), None)
        disk_percent = (disk_used / disk_total * 100.0) if disk_total > 0 else None

        sample = {
            "ts": now,
            "core_cpu": _number(core.get("cpu_percent")),
            "core_memory_percent": _number(core.get("memory_percent")),
            "core_memory_usage": int(core.get("memory_usage") or 0) if core else None,
            "core_blk_read_rate": io_rates[0],
            "core_blk_write_rate": io_rates[1],
            "supervisor_cpu": _number(supervisor.get("cpu_percent")),
            "supervisor_memory_percent": _number(supervisor.get("memory_percent")),
            "disk_used_percent": disk_percent,
            "disk_free_gb": disk_free,
            "disk_life_time": _number(host.get("disk_life_time")),
            "api_ok": api[0],
            "api_latency_ms": api[1],
            "state_changes_per_minute": rates["state_changes_per_minute"],
            "automation_triggers_per_minute": rates["automation_triggers_per_minute"],
            "unavailable_per_minute": rates["unavailable_per_minute"],
            "unavailable_battery_per_minute": rates.get("unavailable_battery_per_minute"),
            "unavailable_nonbattery_per_minute": rates.get("unavailable_nonbattery_per_minute"),
            "psi_cpu": read_psi("cpu"),
            "psi_memory": read_psi("memory"),
            "psi_io": read_psi("io"),
            "recorder_bytes": recorder["bytes"],
            "recorder_growth_mb_hour": recorder["growth_mb_hour"],
            "addons": self.last_addons,
            "extra": {
                "host": {
                    k: host.get(k) for k in (
                        "operating_system", "kernel", "hostname", "boot_timestamp",
                        "timezone", "dt_synchronized", "startup_time"
                    ) if host.get(k) is not None
                },
                "event_websocket_connected": rates["websocket_connected"],
                "event_monitor_status": rates.get("event_monitor_status") or {},
                "supervisor_ok": supervisor_probe[0],
                "supervisor_latency_ms": supervisor_probe[1],
                "local_system": local_system,
                "recorder": recorder,
            },
        }
        return sample

    async def _safe_get(self, path: str) -> dict:
        try:
            data = await self.client.get(path)
            return data if isinstance(data, dict) else {}
        except APIError as exc:
            LOGGER.debug("Supervisor endpoint %s unavailable: %s", path, exc)
            return {}

    async def _api_probe(self) -> tuple[bool, float | None]:
        try:
            _, latency = await self.client.ha_get("/", timeout=min(7, max(3, self.settings.sample_interval_seconds)))
            return True, latency
        except APIError:
            return False, None

    async def _supervisor_probe(self) -> tuple[bool, float | None]:
        started = time.perf_counter()
        try:
            await self.client.get("/supervisor/ping", timeout=min(5, max(2, self.settings.sample_interval_seconds)))
            return True, (time.perf_counter() - started) * 1000
        except APIError:
            return False, None

    def _recorder_stats(self, now: float) -> dict:
        configured = self.settings.recorder_db_path.lstrip("/")
        base = Path("/homeassistant") / configured
        files = [base, Path(str(base) + "-wal"), Path(str(base) + "-shm")]
        parts: dict[str, int] = {}
        total = 0
        for path in files:
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            parts[path.name] = size
            total += size

        if total > 0:
            self._db_size_points.append((now, total))
        cutoff = now - 1800
        while self._db_size_points and self._db_size_points[0][0] < cutoff:
            self._db_size_points.popleft()

        growth = None
        if len(self._db_size_points) >= 2:
            first_ts, first_size = self._db_size_points[0]
            last_ts, last_size = self._db_size_points[-1]
            seconds = last_ts - first_ts
            if seconds >= 120:
                growth = ((last_size - first_size) / 1024 / 1024) * (3600 / seconds)

        return {
            "configured_path": configured,
            "exists": base.exists(),
            "bytes": total if total > 0 else None,
            "growth_mb_hour": growth,
            "parts": parts,
        }

    def _io_rates(self, now: float, core: dict) -> tuple[float | None, float | None]:
        read_now = _number(core.get("blk_read"))
        write_now = _number(core.get("blk_write"))
        if read_now is None or write_now is None:
            return None, None
        previous = self._last_core_io
        self._last_core_io = (now, read_now, write_now)
        if previous is None:
            return None, None
        prev_ts, prev_read, prev_write = previous
        dt = now - prev_ts
        if dt <= 0 or read_now < prev_read or write_now < prev_write:
            return None, None
        return (
            (read_now - prev_read) / dt / 1024 / 1024,
            (write_now - prev_write) / dt / 1024 / 1024,
        )

    async def _addon_loop(self) -> None:
        while not self._stop.is_set():
            try:
                payload = await self.client.get("/addons")
                addons = payload.get("addons", []) if isinstance(payload, dict) else []
                self.last_addon_list = addons
                excluded = set(self.settings.excluded_apps)
                started = [
                    a for a in addons
                    if a.get("slug")
                    and a.get("state") == "started"
                    and a.get("slug") not in excluded
                    and not str(a.get("slug")).endswith("ha_blackbox")
                ]
                if self.settings.monitor_all_apps:
                    semaphore = asyncio.Semaphore(6)

                    async def fetch(addon: dict):
                        slug = addon["slug"]
                        async with semaphore:
                            try:
                                stats = await self.client.get(f"/addons/{slug}/stats")
                            except APIError:
                                return slug, None
                            if isinstance(stats, dict):
                                return slug, {"name": addon.get("name", slug), **stats}
                            return slug, None

                    results = await asyncio.gather(*(fetch(a) for a in started))
                    self.last_addons = {slug: stats for slug, stats in results if stats}

                if self.log_monitor:
                    await self.log_monitor.sync_addons(
                        addons,
                        excluded=excluded,
                        monitor_all=self.settings.monitor_all_apps,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOGGER.warning("App stats discovery failed: %s", exc)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=30)
            except asyncio.TimeoutError:
                pass

    async def _disk_breakdown_loop(self) -> None:
        while not self._stop.is_set():
            try:
                data = await self.client.get("/host/disks/default/usage?max_depth=1", timeout=65)
                if isinstance(data, dict):
                    self.last_disk_breakdown = data
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOGGER.debug("Detailed disk usage unavailable: %s", exc)
            try:
                await asyncio.wait_for(
                    self._stop.wait(), timeout=self.settings.detailed_disk_scan_minutes * 60
                )
            except asyncio.TimeoutError:
                pass

    async def _resolution_loop(self) -> None:
        while not self._stop.is_set():
            try:
                data = await self.client.get("/resolution/info")
                if isinstance(data, dict):
                    self.last_resolution = data
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOGGER.debug("Supervisor resolution info unavailable: %s", exc)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=60)
            except asyncio.TimeoutError:
                pass

    async def _inventory_loop(self) -> None:
        while not self._stop.is_set():
            delay = 300
            try:
                data, _latency = await self.client.ha_get("/states", timeout=20)
                if isinstance(data, list):
                    unavailable = []
                    unknown = []
                    domains = Counter()
                    automation_meta: dict[str, dict] = {}
                    for item in data:
                        entity_id = str(item.get("entity_id") or "unknown")
                        attrs = item.get("attributes") or {}
                        if entity_id.startswith("automation."):
                            automation_meta[entity_id] = {
                                "automation_id": attrs.get("id"),
                                "friendly_name": attrs.get("friendly_name"),
                            }
                        state = item.get("state")
                        if state not in {"unavailable", "unknown"}:
                            continue
                        domains[entity_id.split(".", 1)[0]] += 1
                        target = unavailable if state == "unavailable" else unknown
                        if len(target) < 200:
                            target.append(entity_id)
                    self.last_inventory = {
                        "unavailable": unavailable,
                        "unknown": unknown,
                        "by_domain": dict(domains.most_common()),
                        "total": sum(domains.values()),
                        "automation_meta": automation_meta,
                        "fetched_ts": time.time(),
                    }
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOGGER.debug("HA state inventory unavailable: %s", exc)
                delay = 60
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass

    async def _prune_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.storage.prune(
                    self.settings.metric_retention_days,
                    self.settings.incident_retention_days,
                    self.settings.important_log_retention_days,
                )
            except Exception as exc:
                LOGGER.warning("Black Box retention cleanup failed: %s", exc)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=6 * 3600)
            except asyncio.TimeoutError:
                pass

    def recent(self, minutes: int | None = None) -> list[dict]:
        items = list(self.ring)
        if minutes is not None:
            cutoff = time.time() - minutes * 60
            items = [sample for sample in items if sample["ts"] >= cutoff]
        return items

    def stop(self) -> None:
        self._stop.set()
