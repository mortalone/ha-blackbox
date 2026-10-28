from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from collections import defaultdict
from typing import Callable

from config import Settings
from storage import Storage
from supervisor import APIError, SupervisorClient
from notifier import DirectNotifier

LOGGER = logging.getLogger("blackbox.analyzer")

LOG_PATTERNS = [
    (
        "memory_exhaustion",
        "RAM/OOM",
        re.compile(r"out of memory|oom-killer|memory cgroup out of memory|killed process .*python", re.I),
        95,
        "Kernel eller container rapporterede direkte hukommelsesmangel/OOM.",
        "Find processen/integrationen der voksede i RAM. Genstart alene er kun midlertidig afhjælpning.",
    ),
    (
        "disk_full",
        "Disk fuld",
        re.compile(r"no space left on device|\benospc\b|filesystem.*(?:full|100%)", re.I),
        98,
        "Der er en direkte logsignatur for manglende diskplads.",
        "Find den voksende mappe/database/backups før du sletter noget. Recorder og backup-lager er typiske kandidater.",
    ),
    (
        "storage_io",
        "Storage I/O-fejl",
        re.compile(r"i/o error|input/output error|blk_update_request|nvme.*(?:timeout|reset|abort)|ext4.*error|btrfs.*error", re.I),
        94,
        "Hostloggen indeholder en direkte storage/NVMe/filesystem-fejl.",
        "Kontrollér SSD/NVMe, kernel-log og diskens health/lifetime. Tag backup før større ændringer.",
    ),
    (
        "recorder_database",
        "Recorder/database-fejl",
        re.compile(
            # Keep these signatures deliberately specific. A previous pattern used
            # plain ``full`` after ``sqlite``; that made benign lines from the
            # sqlite-web app match the ``full`` inside ``successfully``.
            r"\bdatabase is locked\b|"
            r"\bdatabase or disk is full\b|"
            r"\bdatabase disk image is malformed\b|"
            r"\bdisk i/o error\b|"
            r"\bdatabase\b.*\b(?:locked|malformed|corrupt(?:ed|ion)?)\b|"
            r"\bsqlite(?:3)?\b.*\b(?:locked|malformed|corrupt(?:ed|ion)?)\b|"
            r"\brecorder\b.*\b(?:failed|failure|error)\b|"
            r"\brecorder\b.*\bpurge\b.*\b(?:failed|failure|error)\b",
            re.I,
        ),
        90,
        "Loggen peger direkte på Recorder/SQLite/databaseproblemer.",
        "Se databasevækst, WAL-størrelse og de mest støjende entities før du ændrer Recorder-konfigurationen.",
    ),
    (
        "watchdog_restart",
        "Watchdog/restart",
        re.compile(r"watchdog.*(?:restart|unhealthy|failed)|home assistant.*(?:unhealthy|not healthy)", re.I),
        80,
        "Supervisor/watchdog rapporterede en usund eller genstartet komponent.",
        "Brug tidslinjen før watchdog-hændelsen til at finde den oprindelige CPU/RAM/I/O/log-fejl.",
    ),
    (
        "native_fault_crash",
        "Fatal Python crash (SIGABRT/SIGSEGV)",
        re.compile(r"fatal python error:\s*\S+|segmentation fault|\bsigabrt\b|\bsigsegv\b", re.I),
        96,
        "Home Assistant Core døde af en fatal C/Python-fejl (fx SIGABRT/SIGSEGV i home-assistant.log.fault).",
        "Se den crashede tråd og komponent i home-assistant.log.fault (fx stream_worker/PyAV). Deaktivér preload_stream og brug go2rtc/WebRTC ved kamera-crashes.",
    ),
]

SUPERVISOR_APP_WATCHDOG_RE = re.compile(
    r"watchdog found app (?P<name>.+?) exited with code (?P<code>-?\d+), restarting", re.I
)

def log_pattern_applies(category: str, source: str | None) -> bool:
    """Return whether a crash signature is meaningful for this log source.

    Add-ons often have their own internal watchdogs (Frigate/FFmpeg is a common
    example). Those restarts are not evidence that Home Assistant Core,
    Supervisor or the host watchdog restarted anything. Keep such lines as log
    context, but do not promote them to a system watchdog incident.
    """
    source = (source or "").lower()
    if category == "watchdog_restart" and source.startswith("addon:"):
        return False
    return True


class Analyzer:
    def __init__(self, settings: Settings, storage: Storage, client: SupervisorClient) -> None:
        self.settings = settings
        self.storage = storage
        self.client = client
        self.direct_notifier = DirectNotifier(settings)
        self.current_warnings: list[dict] = []
        self.current_advisories: list[dict] = []
        self.current_monitoring_issues: list[dict] = []
        self.active: dict[str, dict] = {}
        self.signal_active: dict[str, bool] = {}
        self.signal_since: dict[str, float] = {}
        self.signal_clear_since: dict[str, float] = {}
        self.condition_since: dict[str, float] = {}
        self.last_sample: dict = {}
        self.pending_notifications: set[str] = set()
        self.warning_notification_active: set[str] = set()
        self.warning_notification_last_sent: dict[str, float] = {}
        self.warning_notification_last_attempt: dict[str, float] = {}
        self.ever_api_ok = False
        self.ever_supervisor_ok = False
        self.last_fault_info: dict = {"found": False}
        self.metrics_provider: Callable[[int | None], list[dict]] = lambda _m=None: []
        self.logs_provider: Callable[[float | None, int], list[dict]] = lambda _s=None, _l=3000: []
        self.top_entities_provider: Callable[[float, int], list[dict]] = lambda _s, _l=10: []

    def restore_pending_notifications(self, since_ts: float) -> int:
        unnotified = self.storage.list_unnotified_incidents(since_ts)
        for item in unnotified:
            if item.get("id"):
                self.pending_notifications.add(item["id"])
        return len(unnotified)

    def set_context_providers(self, metrics_provider, logs_provider, top_entities_provider) -> None:
        self.metrics_provider = metrics_provider
        self.logs_provider = logs_provider
        self.top_entities_provider = top_entities_provider

    async def evaluate(self, sample: dict) -> None:
        self.last_sample = sample
        now = sample["ts"]
        warnings: list[dict] = []
        advisories: list[dict] = []
        monitoring_issues: list[dict] = []
        bad_categories: set[str] = set()

        def warning(category: str, title: str, detail: str) -> None:
            warnings.append({"category": category, "title": title, "detail": detail, "level": "warning"})

        def advisory(category: str, title: str, detail: str, level: str = "observe") -> None:
            advisories.append({"category": category, "title": title, "detail": detail, "level": level})

        async def sustained(
            category: str,
            condition: bool,
            seconds: int,
            title: str,
            confidence: int,
            summary: str,
            recommendation: str,
            evidence: list[str],
        ) -> None:
            if condition:
                bad_categories.add(category)
                first = self.condition_since.setdefault(category, now)
                if now - first >= seconds:
                    await self._touch_incident(
                        category, title, "critical", confidence, summary, recommendation, evidence, sample
                    )
            else:
                self.condition_since.pop(category, None)

        disk_pct = sample.get("disk_used_percent")
        disk_free = sample.get("disk_free_gb")
        disk_warning = (
            (disk_pct is not None and disk_pct >= self.settings.disk_warning_percent)
            or (disk_free is not None and disk_free <= self.settings.disk_warning_free_gb)
        )
        disk_critical = (
            (disk_pct is not None and disk_pct >= self.settings.disk_critical_percent)
            or (disk_free is not None and disk_free <= self.settings.disk_critical_free_gb)
        )
        if disk_warning:
            warning("disk_full", "Diskplads er lav", self._disk_text(sample))
        await sustained(
            "disk_full", disk_critical, 15, "Kritisk lav diskplads", 90,
            "Hostens datadisk er tæt på at være fuld.",
            "Brug diskfordelingen til at finde hvad der vokser. Undgå blind sletning; identificér Recorder, backups eller app-data først.",
            [self._disk_text(sample)],
        )

        memory = sample.get("core_memory_percent")
        if memory is not None and memory >= self.settings.memory_warning_percent:
            warning("memory_pressure", "Core bruger meget RAM", f"Core RAM: {memory:.1f}%")
        await sustained(
            "memory_pressure",
            memory is not None and memory >= self.settings.memory_critical_percent,
            120,
            "Vedvarende kritisk RAM-forbrug",
            72,
            "Home Assistant Core har ligget ved kritisk højt RAM-forbrug i mindst 2 minutter.",
            "Se efter memory leak, en integration med voksende cache eller event/log storm. OOM-signatur i hostloggen løfter diagnosen til høj sikkerhed.",
            [f"Core RAM: {memory:.1f}%" if memory is not None else "Core RAM utilgængelig"],
        )

        cpu = sample.get("core_cpu")
        if cpu is not None and cpu >= self.settings.cpu_warning_percent:
            warning("cpu_saturation", "Core CPU er høj", f"Core CPU: {cpu:.1f}%")
        await sustained(
            "cpu_saturation",
            cpu is not None and cpu >= self.settings.cpu_critical_percent,
            120,
            "Vedvarende Core CPU-mætning",
            68,
            "Home Assistant Core har ligget ved kritisk CPU-forbrug i mindst 2 minutter.",
            "Sammenhold med event-rate, automations og Core-log. En støjende integration eller løkke er en typisk årsag.",
            [f"Core CPU: {cpu:.1f}%" if cpu is not None else "Core CPU utilgængelig"],
        )

        extra = sample.get("extra") or {}
        supervisor_ok = bool(extra.get("supervisor_ok"))
        supervisor_latency = extra.get("supervisor_latency_ms")
        if supervisor_ok:
            self.ever_supervisor_ok = True
        if self.ever_supervisor_ok and not supervisor_ok:
            warning("supervisor_unresponsive", "Supervisor svarer ikke", "Black Box-processen kører stadig, men Supervisor API er utilgængelig")
        elif supervisor_ok and supervisor_latency is not None and supervisor_latency >= self.settings.api_latency_warning_ms:
            warning("supervisor_latency", "Supervisor svarer langsomt", f"Supervisor API: {supervisor_latency:.0f} ms")
        await sustained(
            "supervisor_unresponsive",
            self.ever_supervisor_ok and not supervisor_ok,
            15,
            "Supervisor svarer ikke",
            82,
            "HA Black Box kører, men Supervisor API har været utilgængeligt i mindst 15 sekunder.",
            "Undersøg host- og Supervisor-log samt disk/I/O-pres. Hvis både Core og Supervisor forsvinder, ligger fejlen sandsynligvis under Core-niveau.",
            ["Supervisor API utilgængelig"],
        )

        api_ok = bool(sample.get("api_ok"))
        api_latency = sample.get("api_latency_ms")
        if api_ok:
            self.ever_api_ok = True
        if self.ever_api_ok and supervisor_ok and not api_ok:
            warning("core_unresponsive", "Home Assistant API svarer ikke", "Supervisor svarer stadig")
        elif api_ok and api_latency is not None and api_latency >= self.settings.api_latency_warning_ms:
            warning("api_latency", "Home Assistant svarer langsomt", f"API: {api_latency:.0f} ms")
        # The app starts before Core. Also avoid blaming Core when the Supervisor proxy itself is down.
        api_critical = self.ever_api_ok and supervisor_ok and ((not api_ok) or (
            api_latency is not None and api_latency >= self.settings.api_latency_critical_ms
        ))
        await sustained(
            "core_unresponsive", api_critical, 15, "Home Assistant Core svarer ikke normalt", 80,
            "Black Box kan nå Supervisor, men Home Assistant API er utilgængeligt eller ekstremt langsomt.",
            "Se tidslinjen umiddelbart før udfaldet: CPU, RAM, Recorder-vækst, disk-I/O og logsignaturer er de vigtigste spor.",
            ["HA API utilgængeligt mens Supervisor svarer" if not api_ok else f"HA API svartid: {api_latency:.0f} ms"],
        )

        event_stream_connected = bool(extra.get("event_websocket_connected"))
        event_monitor_status = extra.get("event_monitor_status") or {}
        outage_seconds = float(event_monitor_status.get("outage_seconds") or 0.0)
        transport = str(event_monitor_status.get("transport") or "none")
        fallback_active = bool(event_monitor_status.get("fallback_active"))
        last_reason = str(event_monitor_status.get("last_disconnect_reason") or "")
        failure_stage = str(event_monitor_status.get("last_failure_stage") or "")

        # Data-collection health is deliberately separate from Home Assistant
        # health. If Core/Supervisor are healthy but Black Box cannot consume the
        # live event feed, that is a Black Box coverage problem — not evidence
        # that the user's Home Assistant system is unhealthy.
        if self.ever_api_ok and api_ok and event_stream_connected and fallback_active:
            monitoring_issues.append({
                "category": "event_monitor_fallback",
                "level": "info",
                "title": "Black Box bruger fallback til live-events",
                "detail": "Home Assistant svarer normalt. WebSocket-forbindelsen kunne ikke bruges, så Black Box indsamler live-events via Supervisor event-stream (SSE). Analysen fungerer fortsat; ingen handling er nødvendig.",
                "transport": transport,
                "action_required": False,
                "last_error": last_reason,
            })
        elif self.ever_api_ok and api_ok and not event_stream_connected:
            minutes = max(1, int(outage_seconds // 60)) if outage_seconds >= 60 else 0
            monitoring_issues.append({
                "category": "event_monitor_unavailable",
                "level": "warning" if outage_seconds >= 300 else "observe",
                "title": "Black Box live-overvågning er ufuldstændig",
                "detail": (
                    f"Home Assistant Core svarer normalt, men Black Box kan ikke modtage live-events{f' i ca. {minutes} min' if minutes else ''}. "
                    "Det er ikke i sig selv et Home Assistant-problem; det betyder, at Black Box ikke kan måle state-, automation- og flap-rate pålideligt. "
                    "Black Box prøver automatisk WebSocket og skifter efter gentagne fejl til Supervisor event-stream (SSE)."
                ),
                "transport": transport,
                "action_required": outage_seconds >= 300,
                "last_error": last_reason,
                "failure_stage": failure_stage,
                "recommendation": "Ingen ændring i Home Assistant er nødvendig ud fra dette signal alene. Brug 'Test/genopret overvågning'. Hvis både WebSocket og SSE fejler, vises den konkrete forbindelsesfejl som næste trin.",
            })

        state_rate = sample.get("state_changes_per_minute") or 0
        event_warn = float(self.settings.state_changes_warning_per_minute)
        event_clear = event_warn * self.settings.state_changes_clear_ratio
        event_active = self._latched_signal(
            "event_activity",
            state_rate >= event_warn,
            state_rate < event_clear,
            now,
            self.settings.state_changes_warning_sustain_seconds,
        )
        # High event volume by itself is not proof that HA is unhealthy. Distinguish
        # 'busy but coping' from measured impact, otherwise a system hovering around
        # a single threshold flips green/yellow every few seconds.
        impact = []
        recorder_growth_now = sample.get("recorder_growth_mb_hour")
        psi_io_now = sample.get("psi_io")
        api_latency_now = sample.get("api_latency_ms")
        cpu_now = sample.get("core_cpu")
        if recorder_growth_now is not None and recorder_growth_now >= min(self.settings.recorder_growth_warning_mb_per_hour, 100.0):
            impact.append(f"Recorder +{recorder_growth_now:.0f} MB/time")
        if psi_io_now is not None and psi_io_now >= 10:
            impact.append(f"I/O PSI {psi_io_now:.1f}%")
        if api_latency_now is not None and api_latency_now >= min(self.settings.api_latency_warning_ms, 500):
            impact.append(f"API {api_latency_now:.0f} ms")
        if cpu_now is not None and cpu_now >= 75:
            impact.append(f"Core CPU {cpu_now:.0f}%")

        if event_active:
            if state_rate >= min(self.settings.state_changes_critical_per_minute, event_warn * 1.5) or impact:
                warning(
                    "event_storm", "Høj event-aktivitet med mulig påvirkning",
                    f"{state_rate:.0f} state changes/min" + (" · " + " · ".join(impact) if impact else ""),
                )
            else:
                advisory(
                    "event_activity", "Høj state-aktivitet, men systemet følger med",
                    f"{state_rate:.0f} state changes/min. Ingen tydelig CPU/API/I/O/Recorder-påvirkning måles lige nu.",
                )
        await sustained(
            "event_storm",
            state_rate >= self.settings.state_changes_critical_per_minute,
            60,
            "Kritisk event/state storm",
            78,
            "Home Assistant producerer usædvanligt mange state changes, hvilket kan belaste Core og Recorder.",
            "Se listen over støjende entities og automations. Begræns opdateringsfrekvens eller ekskludér irrelevante højfrekvente entities fra Recorder.",
            [f"State changes: {state_rate:.0f}/min"],
        )

        unavailable_rate = sample.get("unavailable_per_minute") or 0
        unavailable_battery = sample.get("unavailable_battery_per_minute")
        unavailable_nonbattery = sample.get("unavailable_nonbattery_per_minute")
        # Entity Registry lets us avoid treating a few sleepy/battery devices as
        # equivalent to mains-powered/integration flapping. If registry metadata
        # is not available, fall back to the total rate.
        effective_unavailable = unavailable_nonbattery if unavailable_nonbattery is not None else unavailable_rate
        flap_active = self._latched_signal(
            "entity_flapping",
            effective_unavailable >= self.settings.unavailable_warning_per_minute,
            effective_unavailable < self.settings.unavailable_warning_per_minute * 0.5,
            now,
            60,
        )
        if flap_active:
            detail = f"{effective_unavailable:.0f} ikke-batteri overgange/min"
            if unavailable_battery:
                detail += f" + {unavailable_battery:.0f} battery/sleepy"
            warning(
                "entity_flapping",
                "Mange entities skifter til unavailable/unknown",
                detail + ". Gentagne eller samtidige ikke-batteri flaps er normalt ikke forventet.",
            )
        elif unavailable_battery is not None and unavailable_battery >= self.settings.unavailable_warning_per_minute:
            advisory(
                "battery_availability",
                "Mange availability-skift kommer fra battery/sleepy devices",
                f"{unavailable_battery:.0f}/min er klassificeret som battery/sleepy. Det kan være forventeligt omkring restart/timeout, men gentagne bølger bør sammenholdes med Zigbee2MQTT passive timeout.",
                level="observe",
            )
        await sustained(
            "entity_flapping",
            effective_unavailable >= self.settings.unavailable_critical_per_minute,
            60,
            "Kritisk unavailable/unknown-flapping",
            76,
            "Et meget stort antal ikke-batteri entities skifter vedvarende til unavailable/unknown.",
            "Find den fælles integration/kilde og kontrollér availability-/timeout-indstillinger før individuelle devices fejlsøges.",
            [
                f"Ikke-batteri unavailable/unknown: {effective_unavailable:.0f}/min",
                f"Battery/sleepy: {unavailable_battery:.0f}/min" if unavailable_battery is not None else "",
            ],
        )

        db_growth = sample.get("recorder_growth_mb_hour")
        if db_growth is not None and db_growth >= self.settings.recorder_growth_warning_mb_per_hour:
            warning("recorder_growth", "Recorder-databasen vokser hurtigt", f"{db_growth:.0f} MB/time")
        await sustained(
            "recorder_growth",
            db_growth is not None and db_growth >= self.settings.recorder_growth_critical_mb_per_hour,
            180,
            "Kritisk hurtig Recorder-vækst",
            84,
            "Recorder SQLite/WAL vokser vedvarende meget hurtigt.",
            "Se de mest støjende entities og automationer. Kontrollér også purge og databasefejl i Core-loggen.",
            [f"Recorder-vækst: {db_growth:.0f} MB/time" if db_growth is not None else ""],
        )

        psi_io = sample.get("psi_io")
        if psi_io is not None and psi_io >= 10:
            warning("io_pressure", "Kernel rapporterer I/O-pres", f"I/O PSI avg10: {psi_io:.1f}%")
        await sustained(
            "io_pressure", psi_io is not None and psi_io >= 25, 120,
            "Vedvarende kritisk I/O-pres", 75,
            "Linux PSI viser at processer bruger betydelig tid på at vente på I/O.",
            "Sammenhold med Recorder-vækst, Core block-write-rate og storagefejl i hostloggen.",
            [f"I/O PSI avg10: {psi_io:.1f}%" if psi_io is not None else ""],
        )

        local_system = (sample.get("extra") or {}).get("local_system") or {}
        temperature = local_system.get("temperature_c")
        if temperature is not None and temperature >= 85:
            warning("temperature", "Høj hardwaretemperatur", f"{temperature:.1f} °C ({local_system.get('temperature_sensor', 'sensor')})")
        await sustained(
            "temperature",
            temperature is not None and temperature >= 100,
            60,
            "Kritisk hardwaretemperatur",
            75,
            "En eksponeret thermal/hwmon-sensor har ligget over 100 °C i mindst et minut.",
            "Kontrollér køling, luftflow og hvilken hwmon-sensor der er varm. Temperaturdata er kun med, hvis hostens sysfs er synlig i app-containeren.",
            [f"{temperature:.1f} °C · {local_system.get('temperature_sensor', 'ukendt sensor')}" if temperature is not None else ""],
        )

        disk_life = sample.get("disk_life_time")
        if disk_life is not None and disk_life >= 90:
            warning("disk_wear", "SSD/NVMe levetidsindikator er høj", f"Forbrugt levetid: {disk_life:.0f}%")

        resolution = (sample.get("extra") or {}).get("resolution") or {}
        issues = resolution.get("issues") or []
        if issues:
            warning("supervisor_issues", "Supervisor har aktive systemproblemer", f"{len(issues)} issue(s) i Resolution")

        self.current_warnings = warnings
        self.current_advisories = advisories
        self.current_monitoring_issues = monitoring_issues
        await self._notify_warning_transitions(warnings, now)
        await self._recover_old_incidents(now, bad_categories)

        if self.pending_notifications:
            await self._retry_notifications()

    async def on_log(self, entry: dict) -> None:
        line = entry.get("message", "")
        source = entry.get("source")
        # A Supervisor watchdog restart of one add-on is not the same severity as
        # Core/Supervisor/host becoming unhealthy. Keep it visible as a warning
        # incident, but do not turn the whole Black Box status critical or send a
        # priority-5 alarm for a single add-on restart.
        if str(source or "").lower() == "supervisor":
            match = SUPERVISOR_APP_WATCHDOG_RE.search(line)
            if match:
                name = match.group("name").strip()
                code = match.group("code")
                await self._touch_incident(
                    "addon_watchdog_restart",
                    f"Add-on genstartet: {name}",
                    "warning",
                    92,
                    f"Supervisor-watchdog genstartede add-on'en {name}; Home Assistant Core eller hosten er ikke dermed meldt nede.",
                    "Kontrollér den pågældende add-ons log, især hvis genstarten gentager sig. En enkelt add-on-genstart er normalt ikke en kritisk Home Assistant-hændelse.",
                    [f"supervisor: {line[-1200:]}"],
                    self.last_sample or {"ts": entry.get("ts", time.time())},
                )
                return
        for category, title, pattern, confidence, summary, recommendation in LOG_PATTERNS:
            if log_pattern_applies(category, source) and pattern.search(line):
                await self._touch_incident(
                    category,
                    title,
                    "critical",
                    confidence,
                    summary,
                    recommendation,
                    [f"{entry.get('source')}: {line[-1200:]}"],
                    self.last_sample or {"ts": entry.get("ts", time.time())},
                )
                return

    @staticmethod
    def _fault_log_recommendation(fault_info: dict) -> tuple[str, str, str]:
        signal_name = str(fault_info.get("signal") or "Fatal Python error")
        thread_name = str(fault_info.get("crashing_thread") or "unknown")
        comp = fault_info.get("suspected_component")
        summary_da = str(fault_info.get("summary_da") or f"Fatal Python error: {signal_name}")
        if thread_name == "stream_worker" or comp == "stream":
            title = f"Home Assistant Core crashede i stream_worker ({signal_name})"
            summary = (
                f"Home Assistant Core døde af et C-level crash ({summary_da}) i PyAV/FFmpeg under lukning "
                f"eller håndtering af en RTSP-kamerastream."
            )
            recommendation = (
                "Deaktivér 'preload_stream' på kameraer i Home Assistant, aktivér indbygget WebRTC (enable_webrtc) "
                "i Frigate-integrationen, og sørg for at live.streams peger på aktive go2rtc-substreams, så "
                "Python PyAV stream_worker ikke kører unødigt i baggrunden."
            )
        else:
            title = f"Home Assistant Core crashede ({signal_name})"
            summary = f"Home Assistant Core døde af en fatal C/Python-fejl registreret i home-assistant.log.fault: {summary_da}."
            recommendation = (
                "Undersøg den crashede tråd og komponent i home-assistant.log.fault (ofte en C-extension som "
                "PyAV/FFmpeg, Bluetooth eller lignende)."
            )
        return title, summary, recommendation

    async def ingest_fault_log(self, fault_info: dict, now: float | None = None) -> dict | None:
        self.last_fault_info = fault_info or {"found": False}
        if not fault_info or not fault_info.get("found"):
            return None

        ts_now = float(now if now is not None else time.time())
        mtime_ts = float(fault_info.get("mtime_ts") or ts_now)
        sig_key = str(fault_info.get("signature_key") or "")
        last_sig = self.storage.get_kv("fault_log_signature")
        title, summary, recommendation = self._fault_log_recommendation(fault_info)
        fault_evidence = [
            f"home-assistant.log.fault (mtime={int(mtime_ts)}, crashes={fault_info.get('crash_count', 1)}): {fault_info.get('summary_da')}",
            *[f"fault_log: {ln}" for ln in (fault_info.get("excerpt_lines") or [])[:12]],
        ]

        # Retroactively enrich any recent core_unresponsive or host_reboot incidents
        # that occurred around or right after this native crash so nothing remains unexplained.
        recent_incidents = self.storage.list_incidents(25)
        for inc_summary in recent_incidents:
            inc_cat = inc_summary.get("category")
            inc_start = float(inc_summary.get("start_ts") or 0)
            inc_end = float(inc_summary.get("end_ts") or inc_start)
            correlates = False
            if inc_cat == "core_unresponsive" and abs(inc_start - mtime_ts) <= 600:
                correlates = True
            elif inc_cat == "host_reboot" and 0 <= (inc_start - mtime_ts) <= 21600:
                correlates = True
            if correlates and "Fatal Python error" not in str(inc_summary.get("summary") or ""):
                full_inc = self.storage.get_incident(inc_summary["id"])
                if full_inc:
                    if inc_cat == "core_unresponsive":
                        duration_min = max(1, int((inc_end - inc_start) // 60)) if inc_end > inc_start else 0
                        dur_str = f" i {duration_min} min" if duration_min else ""
                        full_inc["title"] = f"Home Assistant Core nede efter {fault_info.get('crashing_thread') or 'native'} crash"
                        full_inc["confidence"] = max(int(full_inc.get("confidence") or 80), 96)
                        full_inc["summary"] = (
                            f"Home Assistant Core svarede ikke{dur_str} (502 Bad Gateway), mens Supervisor og add-ons "
                            f"kørte videre. Udfaldet blev udløst af: {fault_info.get('summary_da')}."
                        )
                        full_inc["recommendation"] = recommendation
                    elif inc_cat == "host_reboot":
                        full_inc["title"] = f"Host genstartet efter Core crash ({fault_info.get('crashing_thread') or 'Fatal Python error'})"
                        full_inc["severity"] = "critical"
                        full_inc["confidence"] = max(int(full_inc.get("confidence") or 59), 95)
                        full_inc["summary"] = (
                            f"Hosten blev genstartet efter at Home Assistant Core crashede med {fault_info.get('summary_da')} "
                            f"og efterfølgende ikke svarede på API-kald."
                        )
                        full_inc["recommendation"] = recommendation
                    existing_ev = list(full_inc.get("evidence") or [])
                    for ev in fault_evidence:
                        if ev not in existing_ev:
                            existing_ev.append(ev)
                    full_inc["evidence"] = existing_ev
                    full_inc.setdefault("context", {})["fault_log"] = fault_info
                    full_inc["updated_ts"] = ts_now
                    self.storage.save_incident(full_inc)

        if sig_key and sig_key == last_sig:
            return None

        # Only create a standalone native_fault_crash incident if it is within the last 48h
        created_incident = None
        if ts_now - mtime_ts <= 172800:
            incident = self._make_incident(
                category="native_fault_crash",
                title=title,
                severity="critical",
                confidence=96,
                summary=summary,
                recommendation=recommendation,
                evidence=fault_evidence,
                sample=self.last_sample or {"ts": mtime_ts},
                status="closed",
            )
            incident["start_ts"] = mtime_ts
            incident["end_ts"] = mtime_ts
            incident["context"]["fault_log"] = fault_info
            self.storage.save_incident(incident)
            self.pending_notifications.add(incident["id"])
            created_incident = incident

        if sig_key:
            self.storage.set_kv("fault_log_signature", sig_key)
        if self.pending_notifications:
            await self._retry_notifications()
        return created_incident

    async def create_reboot_postmortem(
        self,
        boot_logs: dict[str, str],
        boot_info: dict,
        fault_info: dict | None = None,
    ) -> None:
        combined_entries = []
        best = None
        for source, text in boot_logs.items():
            for line in text.splitlines():
                if line.strip():
                    combined_entries.append({"ts": time.time(), "source": source, "level": "info", "message": line[-12000:]})
                    for pattern_tuple in LOG_PATTERNS:
                        if log_pattern_applies(pattern_tuple[0], source) and pattern_tuple[2].search(line):
                            if best is None or pattern_tuple[3] > best[3]:
                                best = pattern_tuple

        evidence = [
            f"Ny host boot_timestamp: {boot_info.get('boot_timestamp')}",
            "Postmortem analyseret fra forrige boot-log.",
        ]

        # Check if there was a preceding core_unresponsive incident right before the reboot
        recent_outage = None
        now_ts = time.time()
        for item in self.storage.list_incidents(10):
            if item.get("category") == "core_unresponsive":
                end_ts = float(item.get("end_ts") or item.get("updated_ts") or 0)
                if now_ts - end_ts <= 600:
                    recent_outage = item
                    break

        if fault_info and fault_info.get("found") and (now_ts - float(fault_info.get("mtime_ts") or 0) <= 21600):
            _f_title, _f_summary, f_rec = self._fault_log_recommendation(fault_info)
            category = "host_reboot"
            title = f"Host genstartet efter Core crash ({fault_info.get('crashing_thread') or 'Fatal Python error'})"
            confidence = 96
            outage_note = ""
            if recent_outage:
                dur_min = max(1, int((float(recent_outage.get("end_ts") or now_ts) - float(recent_outage.get("start_ts") or now_ts)) // 60))
                outage_note = f" og var utilgængelig i ca. {dur_min} minutter"
            summary = (
                f"Hosten blev genstartet efter at Home Assistant Core crashede med {fault_info.get('summary_da')}"
                f"{outage_note}."
            )
            recommendation = f_rec
            severity = "critical"
            evidence.append(f"home-assistant.log.fault: {fault_info.get('summary_da')}")
            for ln in (fault_info.get("excerpt_lines") or [])[:8]:
                evidence.append(f"fault_log: {ln}")
        elif best:
            category, title, confidence, summary, recommendation = (
                best[0], f"Host genstartede – {best[1]}", best[3], best[4], best[5]
            )
            severity = "critical"
        elif recent_outage:
            dur_min = max(1, int((float(recent_outage.get("end_ts") or now_ts) - float(recent_outage.get("start_ts") or now_ts)) // 60))
            category = "host_reboot"
            title = "Host genstartet efter længere Core-udfald"
            confidence = 88
            summary = (
                f"Hosten blev genstartet efter at Home Assistant Core havde været utilgængelig i ca. {dur_min} minutter, "
                f"mens Supervisor og add-ons stadig kørte."
            )
            recommendation = "Undersøg det tilhørende 'Home Assistant Core svarer ikke normalt'-incident og home-assistant.log.fault for rodårsagen."
            severity = "critical"
            evidence.append(f"Forudgående Core-udfald: incident {recent_outage.get('id')} ({dur_min} min)")
        else:
            category = "host_reboot"
            title = "Host genstartede"
            confidence = 45
            summary = "Black Box registrerede en ny host-boot, men fandt ingen entydig fejlsignatur i de hentede loglinjer."
            recommendation = "Gennemgå tidslinjen og forrige boot-log. Strømsvigt eller hard lock kan efterlade få spor."
            severity = "warning"

        incident = self._make_incident(
            category=category,
            title=title,
            severity=severity,
            confidence=confidence,
            summary=summary,
            recommendation=recommendation,
            evidence=evidence,
            sample=self.last_sample or {"ts": time.time()},
            status="closed",
        )
        incident["end_ts"] = time.time()
        incident["context"]["previous_boot_logs"] = {
            source: text.splitlines()[-1200:] for source, text in boot_logs.items()
        }
        if fault_info and fault_info.get("found"):
            incident["context"]["fault_log"] = fault_info
        self.storage.save_incident(incident)
        self.pending_notifications.add(incident["id"])

    async def _touch_incident(
        self,
        category: str,
        title: str,
        severity: str,
        confidence: int,
        summary: str,
        recommendation: str,
        evidence: list[str],
        sample: dict,
    ) -> None:
        now = sample.get("ts", time.time())
        if category in self.active:
            incident = self.active[category]
            incident["updated_ts"] = now
            incident["last_bad_ts"] = now
            incident["confidence"] = max(incident["confidence"], confidence)
            for item in evidence:
                if item and item not in incident["evidence"]:
                    incident["evidence"].append(item)
            self.storage.save_incident(incident)
            return

        incident = self._make_incident(
            category, title, severity, confidence, summary, recommendation, evidence, sample, "open"
        )
        incident["last_bad_ts"] = now
        self.active[category] = incident
        self.storage.save_incident(incident)
        self.pending_notifications.add(incident["id"])
        await self._retry_notifications()

    def _make_incident(
        self,
        category: str,
        title: str,
        severity: str,
        confidence: int,
        summary: str,
        recommendation: str,
        evidence: list[str],
        sample: dict,
        status: str,
    ) -> dict:
        now = sample.get("ts", time.time())
        recent_samples = self.metrics_provider(self.settings.pre_incident_minutes)
        cutoff = now - self.settings.pre_incident_minutes * 60
        recent_logs = self.logs_provider(cutoff, 2500)
        top_entities = self.top_entities_provider(now - 3600, 10)
        candidates = self._rank_causes(sample, recent_samples, recent_logs, top_entities)
        if candidates and candidates[0]["confidence"] > confidence:
            confidence = candidates[0]["confidence"]
        context = {
            "samples": recent_samples,
            "logs": recent_logs[-2500:],
            "top_entities_last_hour": top_entities,
            "cause_candidates": candidates,
        }
        return {
            "id": uuid.uuid4().hex,
            "start_ts": now,
            "end_ts": None,
            "status": status,
            "severity": severity,
            "category": category,
            "title": title,
            "confidence": int(min(99, max(1, confidence))),
            "summary": summary,
            "recommendation": recommendation,
            "evidence": [x for x in evidence if x],
            "context": context,
            "acknowledged": False,
            "updated_ts": now,
        }

    def _rank_causes(self, sample: dict, samples: list[dict], logs: list[dict], top_entities: list[dict]) -> list[dict]:
        scores: dict[str, float] = defaultdict(float)
        evidence: dict[str, list[str]] = defaultdict(list)
        titles = {
            "disk_full": "Diskplads",
            "recorder_database": "Recorder/database",
            "storage_io": "Storage I/O/SSD",
            "memory_exhaustion": "RAM/OOM",
            "cpu_saturation": "CPU/integration",
            "event_storm": "Event/entity storm",
            "core_unresponsive": "Core/integration",
            "supervisor_unresponsive": "Supervisor/host",
            "temperature": "Hardwaretemperatur",
        }

        for entry in logs[-2500:]:
            line = entry.get("message", "")
            source = entry.get("source")
            for category, _title, pattern, confidence, _summary, _recommendation in LOG_PATTERNS:
                if log_pattern_applies(category, source) and pattern.search(line):
                    scores[category] += 80 if confidence >= 90 else 55
                    if len(evidence[category]) < 3:
                        evidence[category].append(f"Log: {line[-300:]}")

        disk_pct = sample.get("disk_used_percent")
        if disk_pct is not None and disk_pct >= self.settings.disk_warning_percent:
            scores["disk_full"] += 45
            evidence["disk_full"].append(f"Disk {disk_pct:.1f}% brugt")
        db_growth = sample.get("recorder_growth_mb_hour")
        if db_growth is not None and db_growth >= self.settings.recorder_growth_warning_mb_per_hour:
            scores["recorder_database"] += 45
            evidence["recorder_database"].append(f"Recorder +{db_growth:.0f} MB/time")
        state_rate = sample.get("state_changes_per_minute") or 0
        if state_rate >= self.settings.state_changes_warning_per_minute:
            scores["event_storm"] += 45
            scores["recorder_database"] += 20
            evidence["event_storm"].append(f"{state_rate:.0f} state changes/min")
        if top_entities and top_entities[0].get("changes", 0) >= self.settings.noisy_entity_warning_per_hour:
            scores["event_storm"] += 30
            evidence["event_storm"].append(
                f"Top entity {top_entities[0]['entity_id']}: {top_entities[0]['changes']} ændringer/time"
            )
        memory = sample.get("core_memory_percent")
        if memory is not None and memory >= self.settings.memory_warning_percent:
            scores["memory_exhaustion"] += 35
            evidence["memory_exhaustion"].append(f"Core RAM {memory:.1f}%")
        cpu = sample.get("core_cpu")
        if cpu is not None and cpu >= self.settings.cpu_warning_percent:
            scores["cpu_saturation"] += 35
            evidence["cpu_saturation"].append(f"Core CPU {cpu:.1f}%")
        psi_io = sample.get("psi_io")
        if psi_io is not None and psi_io >= 10:
            scores["storage_io"] += 30
            scores["recorder_database"] += 15
            evidence["storage_io"].append(f"I/O PSI {psi_io:.1f}%")
        extra = sample.get("extra") or {}
        supervisor_ok = extra.get("supervisor_ok", True)
        if supervisor_ok is False:
            scores["supervisor_unresponsive"] += 45
            evidence["supervisor_unresponsive"].append("Supervisor API svarer ikke")
        if not sample.get("api_ok", True) and supervisor_ok is not False:
            scores["core_unresponsive"] += 35
            evidence["core_unresponsive"].append("HA API svarer ikke mens Supervisor svarer")
        local_system = extra.get("local_system") or {}
        temperature = local_system.get("temperature_c")
        if temperature is not None and temperature >= 85:
            scores["temperature"] += 35
            evidence["temperature"].append(f"Højeste temperatur {temperature:.1f} °C")

        ranked = []
        for category, score in sorted(scores.items(), key=lambda item: item[1], reverse=True)[:5]:
            # Direct signatures tend to land around 90+, metric-only correlations around 55-80.
            confidence = min(97, int(40 + score * 0.55))
            ranked.append({
                "category": category,
                "title": titles.get(category, category),
                "confidence": confidence,
                "evidence": evidence[category][:5],
            })
        return ranked

    def _latched_signal(self, category: str, turn_on: bool, clear_condition: bool, now: float, sustain_seconds: int, clear_sustain_seconds: int | None = None) -> bool:
        """Hysteresis for noisy metrics so the UI does not oscillate around one threshold."""
        active = bool(self.signal_active.get(category))
        if active:
            if clear_condition:
                first_clear = self.signal_clear_since.setdefault(category, now)
                clear_after = self.settings.recovery_minutes * 60 if clear_sustain_seconds is None else clear_sustain_seconds
                if now - first_clear >= clear_after:
                    self.signal_active[category] = False
                    self.signal_clear_since.pop(category, None)
                    self.signal_since.pop(category, None)
                    return False
            else:
                self.signal_clear_since.pop(category, None)
            return True

        self.signal_clear_since.pop(category, None)
        if turn_on:
            first = self.signal_since.setdefault(category, now)
            if now - first >= sustain_seconds:
                self.signal_active[category] = True
                return True
        else:
            self.signal_since.pop(category, None)
        return False

    async def _recover_old_incidents(self, now: float, bad_categories: set[str]) -> None:
        recovery_seconds = self.settings.recovery_minutes * 60
        for category, incident in list(self.active.items()):
            if category in bad_categories:
                incident["last_bad_ts"] = now
                continue
            if now - incident.get("last_bad_ts", incident["start_ts"]) < recovery_seconds:
                continue
            incident["status"] = "closed"
            incident["end_ts"] = now
            incident["updated_ts"] = now
            # Capture a small amount of post-recovery context as well.
            incident["context"]["post_recovery_samples"] = self.metrics_provider(min(10, self.settings.recovery_minutes + 2))
            self.storage.save_incident(incident)
            self.active.pop(category, None)

    async def _notify_warning_transitions(self, warnings: list[dict], now: float) -> None:
        """Optionally send one priority-4 direct push when a warning becomes active.

        Critical incidents use the durable incident notification path. Warnings
        are intentionally best-effort and rate-limited so a noisy threshold
        cannot turn ntfy into a notification storm. The feature is disabled by
        default.
        """
        current_categories = {str(item.get("category") or "unknown") for item in warnings}
        self.warning_notification_active.intersection_update(current_categories)

        if not (self.settings.direct_critical_notifications and self.settings.direct_warning_notifications):
            return
        if not self.direct_notifier.configured():
            return

        for item in warnings:
            category = str(item.get("category") or "unknown")
            if category in self.warning_notification_active:
                continue
            # Do not resend the same category more than once per hour, even if
            # it briefly clears and returns. Failed deliveries may retry after
            # five minutes while the warning remains active.
            last_sent = self.warning_notification_last_sent.get(category, 0.0)
            if now - last_sent < 3600:
                self.warning_notification_active.add(category)
                continue
            last_attempt = self.warning_notification_last_attempt.get(category, 0.0)
            if now - last_attempt < 300:
                continue
            self.warning_notification_last_attempt[category] = now
            payload = dict(item)
            payload["ts"] = now
            result = await self.direct_notifier.send_warning(payload)
            if result.ok:
                self.warning_notification_last_sent[category] = now
                self.warning_notification_active.add(category)
            else:
                LOGGER.warning("Direct warning notification failed for %s: %s", category, result.detail)

    async def _retry_notifications(self) -> None:
        """Deliver alerts through independent and HA-dependent channels.

        Direct delivery is attempted first and does not require Home Assistant
        Core. Delivery state is stored inside the incident context so a failed HA
        notification retry does not duplicate an already-sent external alert.
        """
        if not self.pending_notifications:
            return
        for incident_id in list(self.pending_notifications):
            incident = self.storage.get_incident(incident_id)
            if not incident:
                self.pending_notifications.discard(incident_id)
                continue

            context = incident.setdefault("context", {})
            delivery = context.setdefault("notification_delivery", {})
            critical = incident.get("severity") == "critical"

            # 1) External direct channel. This is deliberately independent of
            # Home Assistant Core and therefore still works during a Core/API
            # outage as long as the app container and network are alive.
            if critical and self.settings.direct_critical_notifications:
                if self.direct_notifier.configured():
                    if delivery.get("direct", {}).get("status") != "sent":
                        result = await self.direct_notifier.send_incident(incident)
                        delivery["direct"] = {
                            "status": "sent" if result.ok else "pending",
                            "provider": self.direct_notifier.provider,
                            "detail": result.detail,
                            "ts": time.time(),
                        }
                else:
                    delivery["direct"] = {
                        "status": "not_configured",
                        "provider": self.direct_notifier.provider,
                        "detail": "Direct critical notifications are enabled but the selected provider is incomplete.",
                        "ts": time.time(),
                    }

            message = (
                f"{incident['summary']}\n\n"
                f"Sandsynlighed: {incident['confidence']}%\n"
                f"Åbn HA Black Box for tidslinje og evidens."
            )

            # 2) Fire the HA event when Core is available. This keeps existing
            # user automations/integrations possible, but is not the resilient
            # path for a Core outage.
            if delivery.get("ha_event", {}).get("status") != "sent":
                try:
                    await self.client.fire_event(
                        "ha_blackbox_incident",
                        {
                            "incident_id": incident["id"],
                            "category": incident["category"],
                            "severity": incident["severity"],
                            "confidence": incident["confidence"],
                            "title": incident["title"],
                        },
                    )
                    delivery["ha_event"] = {"status": "sent", "ts": time.time()}
                except (APIError, asyncio.TimeoutError, OSError) as exc:
                    delivery["ha_event"] = {"status": "pending", "detail": str(exc)[:300], "ts": time.time()}

            # 3) Optional Home Assistant notification service. This can be a
            # persistent_notification or notify.mobile_app_*, but depends on Core.
            should_notify_ha = critical or incident.get("category") in {"host_reboot", "native_fault_crash", "core_unresponsive"}
            if should_notify_ha and self.settings.persistent_notifications:
                if delivery.get("ha_notification", {}).get("status") != "sent":
                    try:
                        await self.client.notify(
                            self.settings.notification_service,
                            f"HA Black Box: {incident['title']}",
                            message,
                        )
                        delivery["ha_notification"] = {
                            "status": "sent",
                            "service": self.settings.notification_service,
                            "ts": time.time(),
                        }
                    except (APIError, asyncio.TimeoutError, OSError) as exc:
                        delivery["ha_notification"] = {
                            "status": "pending",
                            "service": self.settings.notification_service,
                            "detail": str(exc)[:300],
                            "ts": time.time(),
                        }

            incident["updated_ts"] = max(float(incident.get("updated_ts") or 0), time.time())
            self.storage.save_incident(incident)
            # Keep the in-memory active incident in sync so a later metric touch
            # does not overwrite notification delivery metadata.
            for active in self.active.values():
                if active.get("id") == incident_id:
                    active.setdefault("context", {})["notification_delivery"] = dict(delivery)
                    break

            expected = ["ha_event"]
            if should_notify_ha and self.settings.persistent_notifications:
                expected.append("ha_notification")
            if critical and self.settings.direct_critical_notifications and self.direct_notifier.configured():
                expected.append("direct")
            if all(delivery.get(channel, {}).get("status") == "sent" for channel in expected):
                self.storage.mark_incident_notified(incident_id)
                self.pending_notifications.discard(incident_id)

    def notification_status(self) -> dict:
        result = self.direct_notifier.status()
        result["ha_notification_service"] = self.settings.notification_service
        result["pending_incidents"] = len(self.pending_notifications)
        return result

    async def test_direct_notification(self) -> dict:
        fake = {
            "id": "test",
            "category": "notification_test",
            "severity": "critical",
            "confidence": 100,
            "title": "Test af direkte kritisk notifikation",
            "summary": "HA Black Box kan sende direkte uden en Home Assistant automation.",
            "evidence": ["Test initieret manuelt fra HA Black Box"],
        }
        result = await self.direct_notifier.send_incident(fake, test=True)
        return {"ok": result.ok, "detail": result.detail, "provider": self.direct_notifier.provider}

    async def close(self) -> None:
        await self.direct_notifier.close()

    def status(self) -> dict:
        active_incidents = [
            {
                "id": incident["id"],
                "category": incident["category"],
                "title": incident["title"],
                "severity": incident["severity"],
                "confidence": incident["confidence"],
                "start_ts": incident["start_ts"],
            }
            for incident in self.active.values()
        ]
        if any(item.get("severity") == "critical" for item in active_incidents):
            health = "critical"
        elif active_incidents or self.current_warnings:
            health = "degraded"
        elif self.current_advisories:
            health = "observed"
        elif not self.ever_supervisor_ok or not self.ever_api_ok:
            health = "initializing"
        else:
            health = "healthy"
        return {
            "health": health,
            "warnings": self.current_warnings,
            "advisories": self.current_advisories,
            "monitoring_issues": self.current_monitoring_issues,
            "data_quality": "limited" if any(i.get("category") == "event_monitor_unavailable" for i in self.current_monitoring_issues) else "full",
            "active_incidents": active_incidents,
        }

    @staticmethod
    def _disk_text(sample: dict) -> str:
        pct = sample.get("disk_used_percent")
        free = sample.get("disk_free_gb")
        values = []
        if pct is not None:
            values.append(f"{pct:.1f}% brugt")
        if free is not None:
            values.append(f"{free:.1f} GB ledig")
        return ", ".join(values) or "Diskstatus utilgængelig"
