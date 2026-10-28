from __future__ import annotations

import json
import time
from typing import Any


def _top(items: list[dict] | None, n: int = 10) -> list[dict]:
    return list(items or [])[:n]


def _config_findings(context: dict) -> list[dict]:
    findings: list[dict] = []
    z2m = context.get("zigbee2mqtt") or {}
    for item in z2m.get("findings") or []:
        findings.append({"source": "zigbee2mqtt", **item})

    recorder = context.get("recorder") or {}
    if recorder.get("found"):
        settings = recorder.get("settings") or {}
        findings.append({
            "source": "recorder",
            "level": "info",
            "title": "Recorder configuration captured",
            "detail": json.dumps(settings, ensure_ascii=False, separators=(",", ":"))[:4000],
        })
    elif recorder.get("configuration_file_found"):
        findings.append({
            "source": "recorder",
            "level": "info",
            "title": "Recorder uses no explicit recorder block",
            "detail": recorder.get("note") or "No explicit recorder settings were found.",
        })
    return findings


def build_ai_summary(
    status: dict,
    churn: dict,
    context: dict,
    incidents: list[dict],
    metrics_samples: list[dict],
    important_logs: list[dict],
    incident_detail_count: int,
    registry_entity_count: int,
) -> dict:
    health = status.get("health") or {}
    current = status.get("current") or {}
    analysis = churn.get("analysis") or {}
    top_entities = churn.get("entities") or []
    top_flappers = churn.get("flappers") or []
    top_automations = churn.get("automations") or []

    metrics_start = metrics_samples[0].get("ts") if metrics_samples else None
    metrics_end = metrics_samples[-1].get("ts") if metrics_samples else None

    primary_findings: list[dict] = []
    for item in health.get("warnings") or []:
        primary_findings.append({"level": "warning", "type": item.get("category"), "title": item.get("title"), "detail": item.get("detail")})
    for item in health.get("advisories") or []:
        primary_findings.append({"level": item.get("level", "observe"), "type": item.get("category"), "title": item.get("title"), "detail": item.get("detail")})
    flap_source = analysis.get("suspected_flap_source") or {}
    if flap_source:
        primary_findings.append({
            "level": "warning" if float(flap_source.get("share_percent") or 0) >= 50 else "observe",
            "type": "suspected_flap_source",
            "title": flap_source.get("title"),
            "detail": flap_source.get("detail"),
            "confidence": flap_source.get("confidence"),
        })
    if top_automations:
        auto = top_automations[0]
        primary_findings.append({
            "level": "observe",
            "type": "top_automation",
            "title": str(auto.get("entity_id")),
            "detail": f"{auto.get('triggers', 0)} triggers in the exported churn window.",
        })

    impact = {
        "core_cpu_percent": current.get("core_cpu"),
        "core_memory_percent": current.get("core_memory_percent"),
        "api_ok": current.get("api_ok"),
        "api_latency_ms": current.get("api_latency_ms"),
        "io_pressure_psi_percent": current.get("psi_io"),
        "recorder_bytes": current.get("recorder_bytes"),
        "recorder_growth_mb_hour": current.get("recorder_growth_mb_hour"),
        "disk_used_percent": current.get("disk_used_percent"),
        "disk_free_gb": current.get("disk_free_gb"),
        "state_changes_per_minute": current.get("state_changes_per_minute"),
        "automation_triggers_per_minute": current.get("automation_triggers_per_minute"),
        "unavailable_per_minute": current.get("unavailable_per_minute"),
        "unavailable_battery_per_minute": current.get("unavailable_battery_per_minute"),
        "unavailable_nonbattery_per_minute": current.get("unavailable_nonbattery_per_minute"),
    }

    config_sources = {
        "zigbee2mqtt_configuration_found": bool((context.get("zigbee2mqtt") or {}).get("found")),
        "frigate_configuration_found": bool((context.get("frigate") or {}).get("found")),
        "recorder_configuration_found": bool((context.get("recorder") or {}).get("configuration_file_found") or (context.get("recorder") or {}).get("found")),
        "automation_file_found": bool((context.get("automations") or {}).get("found")),
        "addon_details_count": len(context.get("addons") or {}),
    }

    return {
        "schema": "ha-blackbox-ai-summary-v1",
        "purpose": "Self-contained sanitized Home Assistant diagnostic bundle intended for AI-assisted root-cause analysis.",
        "generated_ts": status.get("generated_ts") or time.time(),
        "blackbox_version": status.get("version"),
        "health": health,
        "primary_findings": primary_findings,
        "current_impact_indicators": impact,
        "event_churn_24h": {
            "totals": churn.get("totals") or {},
            "top_activity_groups": _top(analysis.get("activity_groups"), 10),
            "top_flap_groups": _top(analysis.get("flap_groups"), 10),
            "suspected_flap_source": flap_source or None,
            "top_entities": _top(top_entities, 25),
            "top_flappers": _top(top_flappers, 25),
            "top_automations": _top(top_automations, 25),
            "flap_bursts": _top(analysis.get("flap_bursts"), 20),
        },
        "configuration_findings": _config_findings(context),
        "configuration_sources": config_sources,
        "incidents": {
            "count": len(incidents),
            "full_context_in_incident_details_json": incident_detail_count,
            "latest": _top(incidents, 10),
        },
        "data_coverage": {
            "metrics_sample_count": len(metrics_samples),
            "metrics_start_ts": metrics_start,
            "metrics_end_ts": metrics_end,
            "important_log_count": len(important_logs),
            "entity_registry_metadata_count": registry_entity_count,
            "churn_window_hours": 24,
        },
        "privacy": context.get("privacy") or {},
        "recommended_ai_workflow": [
            "Start with primary_findings and current_impact_indicators; do not assume high event count alone caused a crash.",
            "Correlate metrics-24h.csv with important-logs-24h.txt and incident-details.json around the same timestamps.",
            "Use churn.json to distinguish high-frequency normal state updates from repeated unavailable/unknown flapping.",
            "Use diagnostic-context.json for Zigbee2MQTT availability settings, Frigate structure, Recorder settings, add-on context and sanitized definitions of the busiest automations.",
            "Only ask the user for additional data after checking data_gaps in AI-START-HERE.md and the configuration_sources flags above.",
        ],
    }


def build_ai_readme(summary: dict) -> str:
    coverage = summary.get("data_coverage") or {}
    config = summary.get("configuration_sources") or {}
    return f"""# HA Black Box – AI START HERE

This ZIP is a **sanitized, AI-oriented Home Assistant diagnostic bundle** generated by HA Black Box {summary.get('blackbox_version') or 'unknown'}.

## Goal

Analyse the likely root cause(s) of Home Assistant instability, crashes, Recorder/database growth, event storms, unavailable/unknown flapping, noisy entities or automations. **Do not ask the user to manually collect data that is already present in this ZIP.**

## Start in this order

1. `ai-summary.json` – compact machine-readable overview and ranked findings.
2. `status.json` – current health, resource state and thresholds.
3. `churn.json` – top entities, flappers, automations, grouped sources and correlated flap bursts.
4. `diagnostic-context.json` – sanitized relevant configuration/context (Zigbee2MQTT, Frigate, Recorder, add-ons, busy automations).
5. `metrics-24h.csv` – time series; correlate event/Recorder/API/I/O changes around incidents.
6. `important-logs-24h.txt` – sanitized important log lines.
7. `incident-details.json` – recent incidents with pre/post context when available.

## Important interpretation rule

A large number of state changes is **not by itself proof of a fault**. Distinguish:

- expected high-frequency telemetry that the system handles without impact;
- repeated `unavailable/unknown` transitions or synchronized flap waves;
- automation loops / unusually high trigger rates;
- measured impact such as Recorder growth, I/O PSI, API latency, CPU/RAM pressure, OOM/storage errors or Core/Supervisor loss.

Battery/sleepy Zigbee devices can legitimately report less often. Zigbee2MQTT availability settings are included when readable so those transitions can be interpreted in context rather than blindly treated as faults.

## Data coverage

- Metrics samples: {coverage.get('metrics_sample_count', 0)}
- Entity Registry metadata: {coverage.get('entity_registry_metadata_count', 0)} entities
- Important logs: {coverage.get('important_log_count', 0)}
- Zigbee2MQTT config found: {config.get('zigbee2mqtt_configuration_found')}
- Frigate config found: {config.get('frigate_configuration_found')}
- Recorder config/context found: {config.get('recorder_configuration_found')}
- Automations file found: {config.get('automation_file_found')}

## Privacy / redaction

The export is deliberately sanitized. Passwords, API keys, tokens, Authorization headers, network keys, username/credential fields and URL path/query strings are redacted. Notification destinations/credentials such as ntfy topic, ntfy access token and ntfy click URL are not exported. Raw Frigate FFmpeg/RTSP/go2rtc camera inputs are never copied from Frigate configuration. Exported logs and incident evidence are re-sanitized because URLs/secrets can appear inside free-form log lines.

Entity IDs and automation IDs are retained because they are important for diagnosis.

## Suggested AI task

> Analyse this HA Black Box diagnostic package. Identify the most likely root causes and distinguish harmless expected activity from abnormal behavior. Correlate churn, flapping, automations, Recorder growth, I/O, API latency and logs over time. Use the included configuration context before asking me for more data. Give me a ranked list of findings, evidence for each, and safe next steps. Do not recommend deleting databases or disabling integrations unless the evidence supports it.
"""


def build_file_index() -> dict[str, Any]:
    return {
        "schema": "ha-blackbox-export-v1",
        "files": {
            "AI-START-HERE.md": "Human/AI instructions, privacy notes and analysis order.",
            "ai-summary.json": "Compact AI-first summary with primary findings, impact indicators and data coverage.",
            "status.json": "Current status, thresholds, resources and add-on statistics.",
            "incidents.json": "Incident summaries/history.",
            "incident-details.json": "Recent incidents with captured context/timeline.",
            "churn.json": "24h entity/automation churn, flappers, grouped sources and flap bursts.",
            "metrics-24h.csv": "Persisted time-series metrics for temporal correlation.",
            "diagnostic-context.json": "Sanitized relevant configuration and add-on/automation context.",
            "important-logs-24h.txt": "Sanitized important log lines from Core/Supervisor/host/add-ons.",
            "privacy-manifest.json": "What is intentionally redacted/retained.",
            "file-index.json": "This file index.",
        },
    }


def build_privacy_manifest(context: dict) -> dict:
    return {
        "mode": "allowlist + recursive redaction + log string sanitization",
        "redacted": [
            "password/passwd/pwd fields",
            "tokens and API keys",
            "Authorization/Bearer credentials",
            "secret/private/network keys",
            "username/credential fields",
            "URL userinfo, paths and query strings",
            "Recorder db_url",
            "raw Frigate FFmpeg/RTSP/go2rtc input URLs",
            "notification destinations and credentials (ntfy topic/token/click URL, webhook, Telegram, Pushover)",
        ],
        "retained_for_diagnosis": [
            "entity IDs",
            "automation IDs/aliases and sanitized definitions of busiest automations",
            "integration/platform names from Entity Registry",
            "add-on names/versions/states and safe operational option summaries",
            "resource and event metrics",
        ],
        "context_note": (context.get("privacy") or {}).get("note"),
    }
