from __future__ import annotations

import re
from collections import Counter

_TXRX_RE = re.compile(r"(?:[._])(?:tx|rx)(?:_\d+)?$", re.I)
_UNIFI_RE = re.compile(r"(?:^|[._])(?:unifi|uap|usw)(?:[._]|$)|uplink_mac", re.I)
_WATTS_RE = re.compile(r"^sensor\.watts(?:_|live)|^sensor\.watts_live_", re.I)
_PRESENCE_RE = re.compile(r"occupancy_probability|presence_confidence|activity_confidence|decay_status|_evidence$", re.I)
_CAMERA_RE = re.compile(r"^image\.|camera|doorbell|frigate", re.I)
_MEDIA_RE = re.compile(r"^media_player\.|(?:^|[._])(?:pc|computer)(?:[._]|$)|lastactive|last_active", re.I)
_HELPER_RE = re.compile(r"^(?:input_boolean|input_number|input_select|input_text|input_datetime|counter|timer|schedule)\.", re.I)
_BATTERY_RE = re.compile(r"(?:^|[._])(?:battery|batteri|battery_level|battery_low)(?:[._]|$)", re.I)


def classify_entity(row_or_entity) -> tuple[str, str]:
    """Group churn using registry metadata first, then conservative name heuristics."""
    if isinstance(row_or_entity, dict):
        row = row_or_entity
        entity_id = str(row.get("entity_id") or "")
        platform = str(row.get("source_platform") or "").lower()
        battery_device = bool(row.get("battery_device"))
        entity_category = str(row.get("entity_category") or "").lower()
        device_class = str(row.get("device_class") or "").lower()
    else:
        row = {}
        entity_id = str(row_or_entity or "")
        platform = ""
        battery_device = False
        entity_category = ""
        device_class = ""

    e = entity_id.lower()
    # Exact registry ownership beats name guessing.
    if platform == "unifi":
        return "network", "Netværk / UniFi"
    if battery_device or device_class == "battery" or _BATTERY_RE.search(e):
        return "battery", "Batteri / sleepy devices"
    if _TXRX_RE.search(e) or _UNIFI_RE.search(e):
        return "network", "Netværk / UniFi-lignende"
    if _WATTS_RE.search(e):
        return "watts", "Watts Live / energimåling"
    if _PRESENCE_RE.search(e):
        return "presence", "Presence / beregnede sensorer"
    if _CAMERA_RE.search(e):
        return "camera", "Kamera / billed-entiteter"
    if _MEDIA_RE.search(e):
        return "media", "Media / PC"
    if _HELPER_RE.search(e):
        return "helpers", "Helpers"
    if entity_category == "diagnostic":
        return "diagnostic", "Diagnostiske entities"
    domain = e.split(".", 1)[0] if "." in e else "other"
    return f"domain:{domain}", f"Andre · {domain}"


def summarize_groups(rows: list[dict], count_field: str = "changes", secondary_field: str = "unavailable") -> list[dict]:
    groups: dict[str, dict] = {}
    for row in rows:
        entity = row.get("entity_id", "")
        key, label = classify_entity(row)
        item = groups.setdefault(key, {
            "key": key,
            "label": label,
            "entities": 0,
            "changes": 0,
            "unavailable": 0,
            "examples": [],
            "explicit_unifi": False,
            "platforms": Counter(),
            "config_entries": Counter(),
            "battery_entities": 0,
            "diagnostic_entities": 0,
        })
        item["entities"] += 1
        item["changes"] += int(row.get("changes") or 0)
        item["unavailable"] += int(row.get("unavailable") or 0)
        if len(item["examples"]) < 6:
            item["examples"].append(entity)
        platform = str(row.get("source_platform") or "")
        if platform:
            item["platforms"][platform] += 1
        config_entry_id = str(row.get("config_entry_id") or "")
        if config_entry_id:
            item["config_entries"][config_entry_id] += 1
        if row.get("battery_device") or row.get("device_class") == "battery":
            item["battery_entities"] += 1
        if row.get("entity_category") == "diagnostic":
            item["diagnostic_entities"] += 1
        if str(row.get("source_platform") or "").lower() == "unifi" or _UNIFI_RE.search(entity):
            item["explicit_unifi"] = True

    output = []
    for item in groups.values():
        item["platforms"] = dict(item["platforms"].most_common(6))
        item["config_entries"] = dict(item["config_entries"].most_common(6))
        output.append(item)
    return sorted(output, key=lambda x: (x.get(count_field, 0), x.get(secondary_field, 0)), reverse=True)


def suspected_flap_source(rows: list[dict]) -> dict | None:
    rows = [r for r in rows if int(r.get("unavailable") or 0) > 0]
    if not rows:
        return None
    groups = summarize_groups(rows, "unavailable", "changes")
    top = groups[0]
    total_flaps = sum(int(r.get("unavailable") or 0) for r in rows)
    share = (top["unavailable"] / total_flaps * 100.0) if total_flaps else 0.0
    platforms = top.get("platforms") or {}
    exact_unifi = platforms.get("unifi", 0) > 0

    if top["key"] == "network":
        if exact_unifi:
            title = "Sandsynlig fælles kilde: Home Assistant UniFi-integrationen"
            confidence = 99 if top["entities"] >= 10 and share >= 60 else 94
            detail = (
                f"Entity Registry angiver platform=unifi for {platforms.get('unifi', 0)} af de grupperede entities. "
                f"Gruppen står for {top['unavailable']} af {total_flaps} unavailable/unknown-overgange ({share:.0f}%)."
            )
        else:
            title = "Sandsynlig fælles kilde: UniFi/netværksdata"
            confidence = 92 if top.get("explicit_unifi") and top["entities"] >= 10 and share >= 60 else 82 if top["entities"] >= 5 else 68
            detail = (
                f"{top['entities']} netværksrelaterede entities står for {top['unavailable']} af {total_flaps} "
                f"unavailable/unknown-overgange ({share:.0f}%). "
                + ("Navne som UAP/USW/uplink peger mod UniFi-gruppen. " if top.get("explicit_unifi") else "")
                + "Hvis registry-metadata mangler, er denne del mønsterbaseret."
            )
    elif top["key"] == "battery":
        title = "Fælles kilde: batteri/sleepy devices"
        # A few sleepy devices going offline occasionally can be expected. Large simultaneous waves are not.
        per_entity = top["unavailable"] / max(1, top["entities"])
        confidence = 90 if top["battery_entities"] >= 3 else 72
        detail = (
            f"{top['entities']} battery/sleepy-relaterede entities står for {top['unavailable']} af {total_flaps} overgange ({share:.0f}%). "
            f"Gennemsnit {per_entity:.1f} flaps/entity i perioden. Enkeltstående, sjældne offline-markeringer kan være forventelige; gentagne eller samtidige bølger er ikke."
        )
    else:
        title = f"Sandsynlig fælles kilde: {top['label']}"
        confidence = 80 if share >= 70 and top["entities"] >= 4 else 65
        detail = (
            f"{top['entities']} entities i gruppen står for {top['unavailable']} af {total_flaps} "
            f"unavailable/unknown-overgange ({share:.0f}%). Vurderingen er baseret på samtidighed og tilgængelig registry-metadata."
        )
    return {
        "title": title,
        "confidence": confidence,
        "detail": detail,
        "share_percent": round(share, 1),
        "total_flaps": total_flaps,
        "group": top,
    }
