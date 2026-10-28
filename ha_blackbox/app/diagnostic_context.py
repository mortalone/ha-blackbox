from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

SENSITIVE_KEY_RE = re.compile(
    r"(?:^|_)(?:pass(?:word|wd)?|token|secret|api[_-]?key|network[_-]?key|private[_-]?key|credential|auth|username|user)(?:$|_)",
    re.I,
)
URL_SCHEMES_RE = re.compile(r"^(?:rtsp|rtsps|http|https|mqtt|mqtts|ws|wss)://", re.I)
EMBEDDED_URL_RE = re.compile(r"(?:rtsp|rtsps|http|https|mqtt|mqtts|ws|wss)://[^\s\"'<>]+", re.I)
AUTH_HEADER_RE = re.compile(r"\bAuthorization\s*:\s*(?:Bearer\s+)?[^\s,;]+", re.I)
BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+\-/=]+", re.I)
INLINE_SECRET_RE = re.compile(
    r"\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization)\b"
    r"(\s*[:=]\s*)([^\s,;]+)",
    re.I,
)


class _UnknownTagLoader(yaml.SafeLoader if yaml else object):
    pass


if yaml:
    def _unknown_tag(loader, tag_suffix, node):
        # !secret and other HA-specific YAML tags are deliberately not resolved.
        # For a scalar we retain only the literal reference/name, never the
        # contents of secrets.yaml.
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_mapping(node)

    _UnknownTagLoader.add_multi_constructor("!", _unknown_tag)


def _read_yaml_any(path: Path) -> Any:
    if not yaml or not path.exists():
        return None
    try:
        return yaml.load(path.read_text(encoding="utf-8"), Loader=_UnknownTagLoader)
    except Exception:
        return None


def _read_yaml(path: Path) -> dict:
    value = _read_yaml_any(path)
    return value if isinstance(value, dict) else {}


def _existing(*paths: str) -> Path | None:
    for raw in paths:
        p = Path(raw)
        if p.exists() and p.is_file():
            return p
    return None


def _safe_url(value: str) -> str:
    """Keep protocol/host only; never export credentials, paths or query tokens."""
    if not URL_SCHEMES_RE.match(value.strip()):
        return value
    try:
        parts = urlsplit(value)
        host = parts.hostname or "<host>"
        if parts.port:
            host = f"{host}:{parts.port}"
        return urlunsplit((parts.scheme, host, "", "", ""))
    except Exception:
        return "<redacted-url>"


def redact_text(value: str) -> str:
    """Redact secrets and embedded URLs in free-form log/evidence strings.

    Exported logs are especially important to sanitize because add-ons may put
    an RTSP URL, webhook URL or Authorization header directly in an error line.
    """
    text = str(value)
    # Strip full URL paths/query/userinfo first. Otherwise a token=... inside a
    # query string could be redacted separately and leave a dangling fragment.
    text = EMBEDDED_URL_RE.sub(lambda m: _safe_url(m.group(0)), text)
    text = AUTH_HEADER_RE.sub("Authorization: <redacted>", text)
    text = BEARER_RE.sub("Bearer <redacted>", text)
    text = INLINE_SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", text)
    return text


def redact(value: Any, key: str = "") -> Any:
    if SENSITIVE_KEY_RE.search(str(key)):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, key) for v in value]
    if isinstance(value, tuple):
        return [redact(v, key) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _pick(mapping: Any, keys: tuple[str, ...]) -> dict:
    if not isinstance(mapping, dict):
        return {}
    return {k: mapping.get(k) for k in keys if k in mapping}


def zigbee2mqtt_context() -> dict:
    path = _existing(
        "/homeassistant/zigbee2mqtt/configuration.yaml",
        "/homeassistant/zigbee2mqtt/configuration.yml",
        "/homeassistant/config/zigbee2mqtt/configuration.yaml",
    )
    if not path:
        return {"found": False}
    cfg = _read_yaml(path)
    availability = cfg.get("availability")
    if isinstance(availability, bool):
        availability = {"enabled": availability}
    availability = availability if isinstance(availability, dict) else {}

    devices = cfg.get("devices") if isinstance(cfg.get("devices"), dict) else {}
    overrides = []
    for _device_id, raw in devices.items():
        if not isinstance(raw, dict):
            continue
        if "availability" not in raw and "disabled" not in raw:
            continue
        item = {
            "friendly_name": str(raw.get("friendly_name") or "<unnamed>"),
            "availability": redact(raw.get("availability"), "availability"),
            "disabled": bool(raw.get("disabled", False)),
        }
        overrides.append(item)
        if len(overrides) >= 200:
            break

    advanced = _pick(cfg.get("advanced"), (
        "channel", "cache_state", "cache_state_persistent", "cache_state_send_on_startup",
        "last_seen", "elapsed", "log_level", "log_output",
    ))
    homeassistant = _pick(cfg.get("homeassistant"), (
        "enabled", "experimental_event_entities", "legacy_action_sensor",
    ))
    device_options = _pick(cfg.get("device_options"), (
        "availability", "retain", "debounce", "debounce_ignore",
    ))
    mqtt = _pick(cfg.get("mqtt"), ("base_topic", "version"))
    serial = _pick(cfg.get("serial"), ("adapter", "baudrate"))

    safe = {
        "found": True,
        "path": str(path.relative_to("/homeassistant")) if str(path).startswith("/homeassistant/") else path.name,
        "version": cfg.get("version"),
        "availability": redact(availability),
        "advanced": redact(advanced),
        "homeassistant": redact(homeassistant),
        "device_options": redact(device_options),
        "mqtt": redact(mqtt),
        "serial": redact(serial),
        "device_count": len(devices),
        "availability_overrides": overrides,
        "group_count": len(cfg.get("groups") or {}) if isinstance(cfg.get("groups"), dict) else 0,
    }
    safe["findings"] = analyze_zigbee2mqtt(safe)
    return safe


def analyze_zigbee2mqtt(ctx: dict) -> list[dict]:
    if not ctx.get("found"):
        return []
    availability = ctx.get("availability") or {}
    enabled = bool(availability.get("enabled", False))
    findings: list[dict] = []
    if not enabled:
        findings.append({
            "level": "info",
            "title": "Zigbee2MQTT availability er ikke globalt aktiveret",
            "detail": "Globale availability-timeouts kan derfor ikke forklare mange unavailable-overgange alene; enkelte devices kan stadig have overrides.",
        })
    else:
        active = availability.get("active") if isinstance(availability.get("active"), dict) else {}
        passive = availability.get("passive") if isinstance(availability.get("passive"), dict) else {}
        active_timeout = float(active.get("timeout", 10) or 10)
        passive_timeout = float(passive.get("timeout", 1500) or 1500)
        level = "normal"
        notes = []
        if active_timeout < 5:
            level = "warning"
            notes.append(f"active timeout er kun {active_timeout:g} min")
        if passive_timeout < 300:
            level = "warning"
            notes.append(f"passive/batteri timeout er kun {passive_timeout:g} min")
        detail = (
            f"Aktive devices: {active_timeout:g} min; passive/batteridrevne devices: {passive_timeout:g} min. "
            "Zigbee2MQTT-standarderne er 10 min og 1500 min (25 timer)."
        )
        if notes:
            detail += " Kort timeout kan skabe forventelige offline/online-skift: " + ", ".join(notes) + "."
        findings.append({
            "level": level,
            "title": "Zigbee2MQTT availability-timeouts",
            "detail": detail,
        })

    low_overrides = []
    for item in ctx.get("availability_overrides") or []:
        av = item.get("availability")
        if isinstance(av, dict):
            try:
                timeout = float(av.get("timeout"))
            except (TypeError, ValueError):
                continue
            if timeout < 300:
                low_overrides.append({"friendly_name": item.get("friendly_name"), "timeout": timeout})
    if low_overrides:
        findings.append({
            "level": "warning",
            "title": "Korte device-specifikke availability-timeouts",
            "detail": f"{len(low_overrides)} device(s) har timeout under 300 min. Vurder om de er aktive eller passive før timeout ændres.",
            "examples": low_overrides[:20],
        })
    return findings


def frigate_context() -> dict:
    path = _existing(
        "/homeassistant/frigate.yml",
        "/homeassistant/frigate.yaml",
        "/homeassistant/config/frigate.yml",
        "/homeassistant/config/frigate.yaml",
    )
    if not path:
        return {"found": False}
    cfg = _read_yaml(path)
    cameras = cfg.get("cameras") if isinstance(cfg.get("cameras"), dict) else {}
    camera_summary = {}
    for name, raw in cameras.items():
        if not isinstance(raw, dict):
            continue
        ffmpeg = raw.get("ffmpeg") if isinstance(raw.get("ffmpeg"), dict) else {}
        inputs = ffmpeg.get("inputs") if isinstance(ffmpeg.get("inputs"), list) else []
        roles = []
        for inp in inputs:
            if isinstance(inp, dict):
                roles.extend(str(x) for x in (inp.get("roles") or []) if x)
        camera_summary[str(name)] = {
            "enabled": raw.get("enabled", True),
            "detect": redact(_pick(raw.get("detect"), ("enabled", "width", "height", "fps"))),
            "record": redact(_pick(raw.get("record"), ("enabled",))),
            "snapshots": redact(_pick(raw.get("snapshots"), ("enabled",))),
            "audio": redact(_pick(raw.get("audio"), ("enabled",))),
            "ffmpeg_input_count": len(inputs),
            "ffmpeg_roles": sorted(set(roles)),
        }
    detectors = cfg.get("detectors") if isinstance(cfg.get("detectors"), dict) else {}
    safe_detectors = {
        str(name): redact(_pick(raw, ("type", "device", "num_threads", "model")))
        for name, raw in detectors.items() if isinstance(raw, dict)
    }
    streams = ((cfg.get("go2rtc") or {}).get("streams") or {}) if isinstance(cfg.get("go2rtc"), dict) else {}
    return {
        "found": True,
        "path": str(path.relative_to("/homeassistant")) if str(path).startswith("/homeassistant/") else path.name,
        "camera_count": len(cameras),
        "cameras": camera_summary,
        "detectors": safe_detectors,
        "go2rtc_stream_count": len(streams) if isinstance(streams, dict) else 0,
        "privacy": "FFmpeg/RTSP input paths, MQTT host/user/password and go2rtc stream URLs are intentionally omitted.",
    }


def recorder_context() -> dict:
    path = _existing("/homeassistant/configuration.yaml", "/homeassistant/configuration.yml")
    if not path:
        return {"found": False, "configuration_file_found": False}
    cfg = _read_yaml(path)
    recorder = cfg.get("recorder")
    if not isinstance(recorder, dict):
        return {
            "found": False,
            "configuration_file_found": True,
            "configured": False,
            "note": "Ingen eksplicit recorder:-blok fundet; Home Assistant-standarder kan derfor være i brug.",
        }
    safe = _pick(recorder, ("purge_keep_days", "auto_purge", "auto_repack", "commit_interval"))
    for side in ("include", "exclude"):
        block = recorder.get(side)
        if isinstance(block, dict):
            safe[side] = {
                "domains": list(block.get("domains") or [])[:200],
                "entity_count": len(block.get("entities") or []) if isinstance(block.get("entities"), list) else 0,
                "entity_glob_count": len(block.get("entity_globs") or []) if isinstance(block.get("entity_globs"), list) else 0,
                "event_type_count": len(block.get("event_types") or []) if isinstance(block.get("event_types"), list) else 0,
            }
    db_url = recorder.get("db_url")
    if isinstance(db_url, str) and db_url:
        try:
            safe["database_backend"] = (urlsplit(db_url).scheme or db_url.split(":", 1)[0] or "unknown").lower()
        except Exception:
            safe["database_backend"] = "configured"
        safe["db_url"] = "<redacted>"
    else:
        safe["database_backend"] = "default/Home Assistant"
    return {"found": True, "configured": True, "settings": redact(safe)}


def _addon_kind(slug: str, name: str) -> str | None:
    text = f"{slug} {name}".lower()
    if "zigbee2mqtt" in text:
        return "zigbee2mqtt"
    if "frigate" in text:
        return "frigate"
    if "mosquitto" in text or "mqtt broker" in text:
        return "mosquitto"
    if "mariadb" in text or "mysql" in text:
        return "database"
    if "unifi" in text:
        return "unifi"
    if "sqlite" in text:
        return "sqlite"
    return None


def addon_context(addons: list[dict] | None = None, addon_details: dict[str, dict] | None = None) -> dict:
    """Safe app inventory plus selected operational options.

    Supervisor app info may expose complete app options to manager-role callers,
    so values are never exported generically. We keep option *names* and only a
    tiny allowlist of non-secret operational values for known apps.
    """
    details = addon_details or {}
    result: dict[str, dict] = {}
    for item in addons or []:
        if not isinstance(item, dict):
            continue
        slug = str(item.get("slug") or "")
        name = str(item.get("name") or slug)
        kind = _addon_kind(slug, name)
        info = details.get(slug) if isinstance(details.get(slug), dict) else {}
        options = info.get("options") if isinstance(info.get("options"), dict) else {}
        safe = {
            "slug": slug,
            "name": name,
            "kind": kind,
            "state": item.get("state") or info.get("state"),
            "version": item.get("version") or info.get("version"),
            "version_latest": item.get("version_latest") or info.get("version_latest"),
            "update_available": item.get("update_available") if item.get("update_available") is not None else info.get("update_available"),
        }
        if info:
            safe.update({
                "boot": info.get("boot"),
                "watchdog": info.get("watchdog"),
                "protected": info.get("protected"),
                "auto_update": info.get("auto_update"),
                "option_keys": sorted(str(k) for k in options.keys() if not SENSITIVE_KEY_RE.search(str(k)))[:100],
            })
            if kind == "zigbee2mqtt":
                safe_opts = _pick(options, ("data_path",))
                socat = options.get("socat")
                if isinstance(socat, dict):
                    safe_opts["socat_enabled"] = bool(socat.get("enabled", False))
                safe["safe_options"] = redact(safe_opts)
            elif kind == "mosquitto":
                safe["safe_options"] = {
                    "anonymous": options.get("anonymous") if isinstance(options.get("anonymous"), bool) else None,
                    "logins_count": len(options.get("logins") or []) if isinstance(options.get("logins"), list) else 0,
                    "customize_present": bool(options.get("customize")),
                }
            elif kind == "database":
                safe["safe_options"] = {
                    "databases_count": len(options.get("databases") or []) if isinstance(options.get("databases"), list) else 0,
                    "logins_count": len(options.get("logins") or []) if isinstance(options.get("logins"), list) else 0,
                }
        result[slug or name] = redact(safe)
    return result


def automations_context(top_automations: list[dict] | None = None) -> dict:
    """Export sanitized definitions of the busiest automations when available."""
    path = _existing("/homeassistant/automations.yaml", "/homeassistant/automations.yml")
    if not path:
        return {"found": False, "items": []}
    raw = _read_yaml_any(path)
    entries = raw if isinstance(raw, list) else []
    by_id = {
        str(item.get("id")): item
        for item in entries
        if isinstance(item, dict) and item.get("id") is not None
    }
    items = []
    for row in (top_automations or [])[:25]:
        if not isinstance(row, dict):
            continue
        automation_id = row.get("unique_id")
        entry = by_id.get(str(automation_id)) if automation_id is not None else None
        item = {
            "entity_id": row.get("entity_id"),
            "triggers": row.get("triggers"),
            "source_platform": row.get("source_platform"),
            "automation_id": automation_id,
            "definition_found": bool(entry),
        }
        if entry:
            selected = {}
            for key in (
                "id", "alias", "description", "mode", "max", "max_exceeded",
                "trigger", "triggers", "condition", "conditions", "action", "actions",
            ):
                if key in entry:
                    selected[key] = entry.get(key)
            item["definition"] = redact(selected)
        items.append(redact(item))
    return {
        "found": True,
        "path": str(path.relative_to("/homeassistant")) if str(path).startswith("/homeassistant/") else path.name,
        "automation_count": len(entries),
        "items": items,
        "note": "Kun de mest aktive automationer medtages. Secrets/URLs sanitiseres; !secret-værdier opløses aldrig.",
    }


def collect_context(
    addons: list[dict] | None = None,
    addon_details: dict[str, dict] | None = None,
    top_automations: list[dict] | None = None,
) -> dict:
    return {
        "privacy": {
            "mode": "allowlist + recursive redaction",
            "note": "Passwords, tokens, usernames/credentials, network keys, Authorization headers and URL paths/query strings are not exported.",
            "frigate": "Raw FFmpeg/RTSP/go2rtc camera inputs are never copied from Frigate configuration.",
            "logs": "Exported important logs are sanitized again at export time because log messages can contain credentials or URLs.",
        },
        "zigbee2mqtt": zigbee2mqtt_context(),
        "frigate": frigate_context(),
        "recorder": recorder_context(),
        "addons": addon_context(addons, addon_details),
        "automations": automations_context(top_automations),
    }
