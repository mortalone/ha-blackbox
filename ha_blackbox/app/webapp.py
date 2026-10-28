from __future__ import annotations

import asyncio
import io
import json
import time
import zipfile
from pathlib import Path

from aiohttp import web

from analyzer import Analyzer
from churn_analysis import summarize_groups, suspected_flap_source
from diagnostic_context import collect_context, automations_context, redact, redact_text
from ai_export import build_ai_summary, build_ai_readme, build_file_index, build_privacy_manifest
from config import Settings
from event_monitor import HAEventMonitor
from log_monitor import LogMonitor
from metrics import MetricsCollector
from storage import Storage
from version import VERSION


@web.middleware
async def no_cache_middleware(request: web.Request, handler):
    """Never cache the Ingress UI or diagnostics.

    Home Assistant Ingress keeps a stable URL between local app upgrades. If
    index.html is cached, a newer backend can otherwise be paired with an older
    frontend and newly-added diagnostic actions appear to be missing.
    """
    response = await handler(request)
    if request.path == "/" or request.path.startswith("/static/") or request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response



class WebApp:
    def __init__(
        self,
        settings: Settings,
        storage: Storage,
        analyzer: Analyzer,
        metrics: MetricsCollector,
        events: HAEventMonitor,
        logs: LogMonitor,
        started_ts: float,
        watchdog=None,
    ) -> None:
        self.settings = settings
        self.storage = storage
        self.analyzer = analyzer
        self.metrics = metrics
        self.events = events
        self.logs = logs
        self.started_ts = started_ts
        self.watchdog = watchdog
        self.static_dir = Path(__file__).parent / "static"
        self._churn_analysis_ts = 0.0
        self._churn_analysis_cache: dict = {}
        self._diag_context_ts = 0.0
        self._diag_context_cache: dict = {}
        self.app = web.Application(client_max_size=2 * 1024 * 1024, middlewares=[no_cache_middleware])
        self._routes()

    def _routes(self) -> None:
        self.app.router.add_get("/", self.index)
        self.app.router.add_get("/healthz", self.healthz)
        self.app.router.add_get("/api/status", self.status)
        self.app.router.add_get("/api/metrics", self.metric_history)
        self.app.router.add_get("/api/incidents", self.incidents)
        self.app.router.add_get("/api/incidents/{incident_id}", self.incident)
        self.app.router.add_post("/api/incidents/{incident_id}/ack", self.ack_incident)
        self.app.router.add_get("/api/noisy", self.noisy)
        self.app.router.add_get("/api/logs", self.important_logs)
        self.app.router.add_get("/api/export", self.export)
        self.app.router.add_post("/api/notifications/test", self.test_notification)
        self.app.router.add_post("/api/events/reconnect", self.reconnect_events)
        self.app.router.add_static("/static/", self.static_dir, show_index=False)

    async def index(self, _request: web.Request) -> web.FileResponse:
        return web.FileResponse(self.static_dir / "index.html")

    async def healthz(self, _request: web.Request) -> web.Response:
        # Watchdog monitors Black Box itself, not Home Assistant. External failures must not restart the recorder.
        return web.json_response({"ok": True, "version": VERSION, "uptime": time.time() - self.started_ts})

    async def status(self, _request: web.Request) -> web.Response:
        now = time.time()
        current = dict(self.metrics.last_sample) if self.metrics.last_sample else {}
        if current:
            extra = dict(current.get("extra") or {})
            extra["disk_breakdown"] = self.metrics.last_disk_breakdown
            extra["resolution"] = self.metrics.last_resolution
            extra["inventory"] = self.metrics.last_inventory
            current["extra"] = extra
        all_hour = self.events.enrich_rows(self.storage.top_entities(now - 3600, 250))
        top_hour = all_hour[:25]
        hour_flappers = self.events.enrich_rows(self.storage.top_flappers(now - 3600, 100))
        automations_hour = self.events.enrich_rows(self.storage.top_automations(now - 3600, 50))
        all_day = self.events.enrich_rows(self.storage.top_entities(now - 86400, 500))
        top_day = all_day[:50]
        all_flappers = self.events.enrich_rows(self.storage.top_flappers(now - 86400, 250))
        top_flappers = all_flappers[:50]
        helper_domains = {
            "input_boolean", "input_number", "input_select", "input_text",
            "input_datetime", "counter", "timer", "schedule"
        }
        top_helpers = [
            item for item in all_day if item.get("entity_id", "").split(".", 1)[0] in helper_domains
        ][:10]
        automations = self.events.enrich_rows(self.storage.top_automations(now - 86400, 50))
        automation_meta = (self.metrics.last_inventory or {}).get("automation_meta") or {}
        for rows in (automations_hour, automations):
            for row in rows:
                meta = automation_meta.get(str(row.get("entity_id") or ""), {})
                if meta.get("automation_id"):
                    row["automation_id"] = meta["automation_id"]
                if meta.get("friendly_name"):
                    row["friendly_name"] = meta["friendly_name"]
        aggregate_day = self.storage.aggregate_minutes(now - 86400)
        if now - self._churn_analysis_ts >= 60 or not self._churn_analysis_cache:
            bursts = self.storage.flap_bursts(now - 86400, 12, 3)
            for burst in bursts:
                burst["groups"] = summarize_groups(burst.pop("entities"), "unavailable", "changes")[:5]
            self._churn_analysis_cache = {
                "activity_groups": summarize_groups(all_day, "changes", "unavailable")[:10],
                "flap_groups": summarize_groups(all_flappers, "unavailable", "changes")[:10],
                "suspected_flap_source": suspected_flap_source(all_flappers),
                "flap_bursts": bursts,
            }
            self._churn_analysis_ts = now
        churn_analysis = dict(self._churn_analysis_cache)
        churn_analysis["activity_groups_hour"] = summarize_groups(all_hour, "changes", "unavailable")[:10]
        churn_analysis["flap_groups_hour"] = summarize_groups(hour_flappers, "unavailable", "changes")[:10]
        churn_analysis["suspected_flap_source_hour"] = suspected_flap_source(hour_flappers)
        live_flappers = self.events.enrich_rows(self.events.current_top_flappers(100))
        churn_analysis["live_flap_source"] = suspected_flap_source(live_flappers)
        churn_analysis["live_top_flappers"] = live_flappers[:10]
        diagnostic_context = await self._get_diagnostic_context(now=now)
        incidents = self.storage.list_incidents(1)
        payload = {
            "version": VERSION,
            "now": now,
            "uptime_seconds": now - self.started_ts,
            "health": self.analyzer.status(),
            "current": current,
            "event_websocket_connected": self.events.connected,
            "event_monitor": self.events.status(),
            "fault_log": self.analyzer.last_fault_info,
            "auto_heal": self.watchdog.status() if self.watchdog else None,
            "top_entities_hour": top_hour,
            "top_automations_hour": automations_hour,
            "top_flappers_hour": hour_flappers[:10],
            "top_entities_day": top_day,
            "top_flappers_day": top_flappers,
            "top_helpers_day": top_helpers,
            "top_automations_day": automations,
            "aggregate_day": aggregate_day,
            "churn_analysis": churn_analysis,
            "diagnostic_context": diagnostic_context,
            "last_incident": incidents[0] if incidents else None,
            "blackbox_storage": self.storage.database_info(),
            "settings": self.settings.public_dict(),
            "notifications": self.analyzer.notification_status(),
        }
        return web.json_response(payload)


    async def test_notification(self, _request: web.Request) -> web.Response:
        result = await self.analyzer.test_direct_notification()
        status = 200 if result.get("ok") else 400
        return web.json_response(result, status=status)

    async def reconnect_events(self, _request: web.Request) -> web.Response:
        before = self.events.status()
        await self.events.force_reconnect()
        return web.json_response({"ok": True, "message": "Genforbindelse startet", "before": before, "event_monitor": self.events.status()})

    async def metric_history(self, request: web.Request) -> web.Response:
        minutes = self._clamp_int(request.query.get("minutes"), 60, 5, 7 * 24 * 60)
        since = time.time() - minutes * 60
        return web.json_response({"minutes": minutes, "samples": self.storage.get_samples(since)})

    async def incidents(self, request: web.Request) -> web.Response:
        limit = self._clamp_int(request.query.get("limit"), 100, 1, 500)
        return web.json_response({"incidents": self.storage.list_incidents(limit)})

    async def incident(self, request: web.Request) -> web.Response:
        item = self.storage.get_incident(request.match_info["incident_id"])
        if not item:
            raise web.HTTPNotFound(text="Incident not found")
        return web.json_response(item)

    async def ack_incident(self, request: web.Request) -> web.Response:
        ok = self.storage.acknowledge_incident(request.match_info["incident_id"])
        if not ok:
            raise web.HTTPNotFound(text="Incident not found")
        return web.json_response({"ok": True})

    async def noisy(self, request: web.Request) -> web.Response:
        hours = self._clamp_int(request.query.get("hours"), 24, 1, 24 * 30)
        limit = self._clamp_int(request.query.get("limit"), 50, 1, 500)
        since = time.time() - hours * 3600
        entities = self.events.enrich_rows(self.storage.top_entities(since, max(limit, 500)))
        flappers = self.events.enrich_rows(self.storage.top_flappers(since, max(limit, 250)))
        bursts = self.storage.flap_bursts(since, 20, 3)
        for burst in bursts:
            burst["groups"] = summarize_groups(burst.pop("entities"), "unavailable", "changes")[:5]
        return web.json_response(
            {
                "hours": hours,
                "entities": entities[:limit],
                "flappers": flappers[:limit],
                "automations": self.events.enrich_rows(self.storage.top_automations(since, limit)),
                "totals": self.storage.aggregate_minutes(since),
                "analysis": {
                    "activity_groups": summarize_groups(entities, "changes", "unavailable")[:10],
                    "flap_groups": summarize_groups(flappers, "unavailable", "changes")[:10],
                    "suspected_flap_source": suspected_flap_source(flappers),
                    "flap_bursts": bursts,
                },
            }
        )

    async def important_logs(self, request: web.Request) -> web.Response:
        minutes = self._clamp_int(request.query.get("minutes"), 60, 1, 7 * 24 * 60)
        limit = self._clamp_int(request.query.get("limit"), 500, 1, 5000)
        source = request.query.get("source") or None
        all_recent = request.query.get("all") in {"1", "true", "yes"}
        since = time.time() - minutes * 60
        if all_recent:
            items = self.logs.recent(since, limit)
            if source:
                items = [item for item in items if item.get("source") == source]
            items = items[-limit:][::-1]
        else:
            items = self.storage.get_logs(since, limit, source)
        return web.json_response({"logs": items})

    async def _relevant_addon_details(self) -> dict[str, dict]:
        """Fetch details only for diagnostic-relevant apps.

        `/addons/<slug>/info` can contain sensitive app options for manager-role
        callers. The raw responses stay in memory only; `collect_context()`
        applies strict app-specific allowlists before anything reaches the UI
        or export.
        """
        relevant_terms = ("zigbee2mqtt", "frigate", "mosquitto", "mqtt", "mariadb", "mysql", "unifi", "sqlite")
        candidates = []
        for item in self.metrics.last_addon_list or []:
            if not isinstance(item, dict) or not item.get("slug"):
                continue
            text = f"{item.get('slug', '')} {item.get('name', '')}".lower()
            if any(term in text for term in relevant_terms):
                candidates.append(str(item["slug"]))

        semaphore = asyncio.Semaphore(4)

        async def fetch(slug: str):
            async with semaphore:
                try:
                    data = await self.metrics.client.get(f"/addons/{slug}/info")
                    return slug, data if isinstance(data, dict) else {}
                except Exception:
                    return slug, {}

        results = await asyncio.gather(*(fetch(slug) for slug in candidates)) if candidates else []
        return {slug: info for slug, info in results if info}

    async def _get_diagnostic_context(self, now: float | None = None, force: bool = False) -> dict:
        """Small safe context used by the live UI.

        Full automation definitions are intentionally export-only so the status
        endpoint remains small and cheap to poll.
        """
        now = now or time.time()
        if force or now - self._diag_context_ts >= 300 or not self._diag_context_cache:
            addon_details = await self._relevant_addon_details()
            self._diag_context_cache = collect_context(
                self.metrics.last_addon_list,
                addon_details=addon_details,
                top_automations=None,
            )
            self._diag_context_ts = now
        return self._diag_context_cache

    async def export(self, _request: web.Request) -> web.Response:
        now = time.time()
        since = now - 24 * 3600
        status_response = {
            "version": VERSION,
            "generated_ts": now,
            "health": self.analyzer.status(),
            "current": self.metrics.last_sample,
            "settings": self.settings.public_dict(),
            "notifications": self.analyzer.notification_status(),
            "event_monitor": self.events.status(),
            "blackbox_storage": self.storage.database_info(),
        }
        export_entities = self.events.enrich_rows(self.storage.top_entities(since, 500))
        export_flappers = self.events.enrich_rows(self.storage.top_flappers(since, 500))
        export_automations = self.events.enrich_rows(self.storage.top_automations(since, 200))
        export_bursts = self.storage.flap_bursts(since, 100, 3)
        for burst in export_bursts:
            burst["groups"] = summarize_groups(burst.pop("entities"), "unavailable", "changes")[:10]
        churn = {
            "entities": export_entities,
            "flappers": export_flappers,
            "automations": export_automations,
            "totals": self.storage.aggregate_minutes(since),
            "analysis": {
                "activity_groups": summarize_groups(export_entities, "changes", "unavailable"),
                "flap_groups": summarize_groups(export_flappers, "unavailable", "changes"),
                "suspected_flap_source": suspected_flap_source(export_flappers),
                "flap_bursts": export_bursts,
            },
        }
        incidents = self.storage.list_incidents(200)
        incident_details = []
        for item in incidents[:20]:
            detail = self.storage.get_incident(str(item.get("id")))
            if detail:
                incident_details.append(detail)
        important_logs = self.storage.get_logs(since, 5000)
        diagnostic_context = dict(await self._get_diagnostic_context(now=now, force=True))
        diagnostic_context["automations"] = automations_context(export_automations)
        metric_samples = self.storage.get_samples(since, 20000)

        # Sanitize *all* free-form export structures. Context collection is
        # already allowlisted, but incidents and logs can embed a URL/secret in
        # an arbitrary message string.
        safe_status = redact(status_response)
        safe_churn = redact(churn)
        safe_incidents = redact(incidents)
        safe_incident_details = redact(incident_details)
        safe_context = redact(diagnostic_context)
        safe_logs = [{**item, "message": redact_text(str(item.get("message", "")))} for item in important_logs]

        ai_summary = build_ai_summary(
            safe_status, safe_churn, safe_context, safe_incidents, metric_samples, safe_logs,
            incident_detail_count=len(safe_incident_details),
            registry_entity_count=len(self.events.entity_registry),
        )
        ai_readme = build_ai_readme(ai_summary)
        privacy_manifest = build_privacy_manifest(safe_context)
        file_index = build_file_index()

        memory = io.BytesIO()
        with zipfile.ZipFile(memory, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("AI-START-HERE.md", ai_readme)
            archive.writestr("ai-summary.json", json.dumps(ai_summary, indent=2, ensure_ascii=False))
            archive.writestr("file-index.json", json.dumps(file_index, indent=2, ensure_ascii=False))
            archive.writestr("privacy-manifest.json", json.dumps(privacy_manifest, indent=2, ensure_ascii=False))
            archive.writestr("status.json", json.dumps(safe_status, indent=2, ensure_ascii=False))
            archive.writestr("incidents.json", json.dumps(safe_incidents, indent=2, ensure_ascii=False))
            archive.writestr("incident-details.json", json.dumps(safe_incident_details, indent=2, ensure_ascii=False))
            archive.writestr("churn.json", json.dumps(safe_churn, indent=2, ensure_ascii=False))
            archive.writestr("metrics-24h.csv", self.storage.samples_csv(since))
            archive.writestr("diagnostic-context.json", json.dumps(safe_context, indent=2, ensure_ascii=False))
            lines = [
                f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(item['ts']))} "
                f"[{item['source']}] {item['level'].upper()} {item['message']}"
                for item in reversed(safe_logs)
            ]
            archive.writestr("important-logs-24h.txt", "\n".join(lines))
        memory.seek(0)
        filename = time.strftime("ha-blackbox-%Y%m%d-%H%M%S.zip")
        return web.Response(
            body=memory.read(),
            content_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @staticmethod
    def _clamp_int(value, default: int, low: int, high: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = default
        return max(low, min(high, parsed))
