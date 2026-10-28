from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import Counter, deque
from pathlib import Path

try:
    import aiohttp
except ModuleNotFoundError:  # pragma: no cover - unit tests without aiohttp installed
    aiohttp = None  # type: ignore[assignment]

from storage import Storage

LOGGER = logging.getLogger("blackbox.events")


class HAEventMonitor:
    def __init__(self, storage: Storage, registry_path: str = "/homeassistant/.storage/core.entity_registry") -> None:
        self.storage = storage
        self.token = os.environ.get("SUPERVISOR_TOKEN", "")
        self.ws_url = "ws://supervisor/core/websocket"
        self.sse_url = "http://supervisor/core/api/stream"
        self.connected = False
        self.transport = "none"  # websocket | sse | none
        self.fallback_active = False
        self.last_failure_stage: str | None = None
        self.last_ws_error: str | None = None
        self.last_sse_error: str | None = None
        self.last_event_ts: float | None = None
        self.last_message_ts: float | None = None
        self.last_connected_ts: float | None = None
        self.last_disconnect_ts: float | None = None
        self.last_disconnect_reason: str | None = None
        self.outage_since_ts: float | None = None
        self.reconnect_attempts = 0
        self.consecutive_failures = 0
        self._stop = asyncio.Event()
        self._force_reconnect = asyncio.Event()
        self._current_ws = None
        self._current_stream = None

        self.current_bucket = int(time.time() // 60) * 60
        self.state_changes = 0
        self.automation_triggers = 0
        self.service_calls = 0
        self.unavailable_transitions = 0
        self.entity_counts: Counter[str] = Counter()
        self.entity_unavailable: Counter[str] = Counter()
        self.automation_counts: Counter[str] = Counter()

        self.recent_state_changes: deque[float] = deque()
        self.recent_automation_triggers: deque[float] = deque()
        self.recent_unavailable: deque[float] = deque()
        self.recent_unavailable_battery: deque[float] = deque()
        self.recent_unavailable_nonbattery: deque[float] = deque()

        # Home Assistant entity-registry metadata. This lets Black Box distinguish
        # a real UniFi entity from an entity that merely happens to end in _rx/_tx,
        # and identify diagnostic/battery entities without guessing from names.
        self.entity_registry: dict[str, dict] = {}
        self.battery_device_ids: set[str] = set()
        self.registry_path = Path(registry_path)
        self.registry_source = "none"
        self._registry_mtime: float | None = None
        self._load_entity_registry_from_storage(force=True)

    def _apply_registry_rows(self, rows: list[dict], source: str) -> None:
        mapping: dict[str, dict] = {}
        battery_devices: set[str] = set()
        for item in rows:
            if not isinstance(item, dict) or not item.get("entity_id"):
                continue
            config_entry_id = item.get("config_entry_id")
            if not config_entry_id:
                ids = item.get("config_entry_ids")
                if isinstance(ids, list) and ids:
                    config_entry_id = ids[0]
            meta = {
                "source_platform": item.get("platform"),
                "device_id": item.get("device_id"),
                "config_entry_id": config_entry_id,
                "entity_category": item.get("entity_category"),
                "device_class": item.get("device_class") or item.get("original_device_class"),
                "unique_id": item.get("unique_id"),
                "original_name": item.get("original_name"),
            }
            mapping[item["entity_id"]] = meta
            entity_id = str(item.get("entity_id") or "").lower()
            if meta.get("device_id") and (meta.get("device_class") == "battery" or entity_id.endswith("_battery") or ".battery" in entity_id):
                battery_devices.add(str(meta["device_id"]))
        if mapping:
            self.entity_registry = mapping
            self.battery_device_ids = battery_devices
            self.registry_source = source
            LOGGER.info("Loaded Home Assistant entity registry metadata for %s entities via %s", len(mapping), source)

    def _load_entity_registry_from_storage(self, force: bool = False) -> None:
        """Load registry metadata from HA's read-only .storage as a WS-independent fallback."""
        try:
            stat = self.registry_path.stat()
            if not force and self._registry_mtime == stat.st_mtime:
                return
            payload = json.loads(self.registry_path.read_text(encoding="utf-8"))
            rows = ((payload.get("data") or {}).get("entities") or []) if isinstance(payload, dict) else []
            self._apply_registry_rows(rows, "storage")
            self._registry_mtime = stat.st_mtime
        except Exception as exc:
            LOGGER.debug("Entity registry storage fallback unavailable: %s", exc)

    async def _refresh_entity_registry(self, ws) -> None:
        """Best-effort registry lookup; monitoring continues if HA changes the WS command."""
        try:
            await ws.send_json({"id": 9001, "type": "config/entity_registry/list"})
            response = await ws.receive_json(timeout=10)
            if response.get("id") != 9001 or response.get("type") != "result" or not response.get("success"):
                return
            rows = response.get("result") or []
            self._apply_registry_rows(rows, "websocket")
        except Exception as exc:
            LOGGER.debug("Entity registry metadata unavailable: %s", exc)

    def enrich_rows(self, rows: list[dict]) -> list[dict]:
        self._load_entity_registry_from_storage()
        enriched = []
        for raw in rows:
            row = dict(raw)
            meta = self.entity_registry.get(str(row.get("entity_id") or ""), {})
            row.update({k: v for k, v in meta.items() if v is not None})
            device_id = meta.get("device_id")
            row["battery_device"] = bool(device_id and str(device_id) in self.battery_device_ids)
            enriched.append(row)
        return enriched

    def stop(self) -> None:
        self._stop.set()

    async def force_reconnect(self) -> dict:
        """Restart live monitoring and retry the preferred WebSocket transport first."""
        self._force_reconnect.set()
        self.consecutive_failures = 0
        ws = self._current_ws
        if ws is not None and not getattr(ws, "closed", True):
            try:
                await ws.close(code=1001, message=b"HA Black Box manual reconnect")
            except Exception as exc:
                LOGGER.debug("Could not close event websocket for reconnect: %s", exc)
        stream = self._current_stream
        if stream is not None:
            try:
                stream.close()
            except Exception as exc:
                LOGGER.debug("Could not close fallback event stream for reconnect: %s", exc)
        return self.status()

    def status(self) -> dict:
        now = time.time()
        return {
            "connected": self.connected,
            "transport": self.transport,
            "fallback_active": self.fallback_active,
            "last_failure_stage": self.last_failure_stage,
            "last_ws_error": self.last_ws_error,
            "last_sse_error": self.last_sse_error,
            "last_event_ts": self.last_event_ts,
            "last_event_age_seconds": (now - self.last_event_ts) if self.last_event_ts else None,
            "last_message_ts": self.last_message_ts,
            "last_connected_ts": self.last_connected_ts,
            "last_disconnect_ts": self.last_disconnect_ts,
            "last_disconnect_reason": self.last_disconnect_reason,
            "outage_since_ts": self.outage_since_ts,
            "outage_seconds": (now - self.outage_since_ts) if self.outage_since_ts else 0.0,
            "reconnect_attempts": self.reconnect_attempts,
            "consecutive_failures": self.consecutive_failures,
            "entity_registry_count": len(self.entity_registry),
            "entity_registry_source": self.registry_source,
        }

    async def run(self) -> None:
        """Keep a live event feed available.

        WebSocket is preferred because it can subscribe only to the events Black
        Box needs. If the Supervisor/Core WebSocket path repeatedly fails, use
        Supervisor's supported /core/api/stream proxy as a transparent fallback.
        A working fallback is considered valid monitoring, not a Home Assistant
        health problem.
        """
        backoff = 2
        while not self._stop.is_set():
            use_sse = self.consecutive_failures >= 3
            try:
                if use_sse:
                    await self._run_sse_once()
                else:
                    await self._run_websocket_once()
                if not self._stop.is_set():
                    raise RuntimeError(f"{self.transport or 'event'} stream closed by peer")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.connected = False
                failed_transport = self.transport if self.transport in {"websocket", "sse"} else ("sse" if use_sse else "websocket")
                self.transport = "none"
                self.fallback_active = False
                now = time.time()
                self.last_disconnect_ts = now
                if self.outage_since_ts is None:
                    self.outage_since_ts = now
                reason = str(exc)[:500]
                self.last_disconnect_reason = reason
                if failed_transport == "websocket":
                    self.last_ws_error = reason
                else:
                    self.last_sse_error = reason
                self.reconnect_attempts += 1
                self.consecutive_failures += 1
                LOGGER.warning("Home Assistant %s event transport disconnected: %s", failed_transport, exc)

                manual = self._force_reconnect.is_set()
                if manual:
                    self._force_reconnect.clear()
                    await asyncio.sleep(0.2)
                    backoff = 2
                else:
                    try:
                        await asyncio.wait_for(self._force_reconnect.wait(), timeout=backoff)
                        self._force_reconnect.clear()
                        self.consecutive_failures = 0
                        backoff = 2
                    except asyncio.TimeoutError:
                        backoff = min(backoff * 2, 30)
        self._flush_current_bucket()

    async def _run_websocket_once(self) -> None:
        timeout = aiohttp.ClientTimeout(total=None, connect=10, sock_read=None)
        headers = {"Authorization": f"Bearer {self.token}"}
        self.last_failure_stage = "websocket_connect"
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.ws_connect(self.ws_url, autoping=True, max_msg_size=0) as ws:
                self._current_ws = ws
                self.last_failure_stage = "websocket_handshake"
                first = await ws.receive_json(timeout=10)
                if first.get("type") != "auth_required":
                    raise RuntimeError(f"Unexpected websocket handshake: {first}")
                self.last_failure_stage = "websocket_auth"
                await ws.send_json({"type": "auth", "access_token": self.token})
                auth = await ws.receive_json(timeout=10)
                if auth.get("type") != "auth_ok":
                    raise RuntimeError(f"Home Assistant websocket auth failed: {auth}")

                self.last_failure_stage = "entity_registry"
                self._load_entity_registry_from_storage()
                if not self.entity_registry:
                    await self._refresh_entity_registry(ws)

                subscriptions = (
                    (1, "state_changed"),
                    (2, "automation_triggered"),
                    (3, "call_service"),
                )
                pending = {msg_id for msg_id, _event_type in subscriptions}
                self.last_failure_stage = "event_subscription"
                for msg_id, event_type in subscriptions:
                    await ws.send_json({"id": msg_id, "type": "subscribe_events", "event_type": event_type})

                deadline = time.monotonic() + 15
                while pending:
                    remaining = max(0.1, deadline - time.monotonic())
                    if remaining <= 0.1 and time.monotonic() >= deadline:
                        raise RuntimeError(f"subscription acknowledgement timeout: {sorted(pending)}")
                    payload = await ws.receive_json(timeout=remaining)
                    self.last_message_ts = time.time()
                    if payload.get("type") == "event":
                        self._handle_event(payload.get("event") or {})
                        continue
                    msg_id = payload.get("id")
                    if msg_id in pending and payload.get("type") == "result":
                        if not payload.get("success"):
                            raise RuntimeError(f"event subscription {msg_id} failed: {payload.get('error')}")
                        pending.remove(msg_id)

                self._mark_connected("websocket")
                LOGGER.info("Home Assistant event WebSocket connected; subscriptions confirmed")
                self.last_failure_stage = "websocket_stream"

                async for msg in ws:
                    if self._stop.is_set():
                        break
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        self.last_message_ts = time.time()
                        try:
                            payload = json.loads(msg.data)
                        except json.JSONDecodeError:
                            continue
                        if payload.get("type") == "event":
                            self._handle_event(payload.get("event") or {})
                    elif msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSE):
                        break
        self.connected = False
        self._current_ws = None

    async def _run_sse_once(self) -> None:
        """Consume Supervisor's Home Assistant event-stream proxy as fallback."""
        timeout = aiohttp.ClientTimeout(total=None, connect=10, sock_read=None)
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
        }
        self.last_failure_stage = "sse_connect"
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(self.sse_url) as response:
                self._current_stream = response
                if response.status != 200:
                    body = (await response.text())[:300]
                    raise RuntimeError(f"SSE HTTP {response.status}: {body}")
                self._mark_connected("sse")
                LOGGER.warning("Event WebSocket unavailable; using supported Supervisor event-stream fallback (SSE)")
                self.last_failure_stage = "sse_stream"
                data_lines: list[str] = []
                async for raw_line in response.content:
                    if self._stop.is_set() or self._force_reconnect.is_set():
                        break
                    line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                    self.last_message_ts = time.time()
                    if not line:
                        if data_lines:
                            self._handle_sse_data("\n".join(data_lines))
                            data_lines.clear()
                        continue
                    if line.startswith("data:"):
                        data_lines.append(line[5:].lstrip())
                if data_lines:
                    self._handle_sse_data("\n".join(data_lines))
        self.connected = False
        self._current_stream = None

    def _handle_sse_data(self, raw: str) -> None:
        if not raw or raw in {"ping", "keep-alive"}:
            return
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return
        # /api/stream historically emits the event object directly. Accept a
        # websocket-like wrapper too so this remains forward-compatible.
        event = payload.get("event") if isinstance(payload, dict) and isinstance(payload.get("event"), dict) else payload
        if isinstance(event, dict) and event.get("event_type"):
            self._handle_event(event)

    def _mark_connected(self, transport: str) -> None:
        self.connected = True
        self.transport = transport
        self.fallback_active = transport == "sse"
        self.last_connected_ts = time.time()
        self.outage_since_ts = None
        self.consecutive_failures = 0
        self.last_failure_stage = None

    def _roll_bucket_if_needed(self, now: float) -> None:
        bucket = int(now // 60) * 60
        if bucket == self.current_bucket:
            return
        self._flush_current_bucket()
        self.current_bucket = bucket
        self.state_changes = 0
        self.automation_triggers = 0
        self.service_calls = 0
        self.unavailable_transitions = 0
        self.entity_counts.clear()
        self.entity_unavailable.clear()
        self.automation_counts.clear()

    def _flush_current_bucket(self) -> None:
        if not any((self.state_changes, self.automation_triggers, self.service_calls, self.unavailable_transitions)):
            return
        entity_counts = {
            entity: (count, self.entity_unavailable.get(entity, 0))
            for entity, count in self.entity_counts.items()
        }
        self.storage.save_minute_stats(
            self.current_bucket,
            self.state_changes,
            self.automation_triggers,
            self.service_calls,
            self.unavailable_transitions,
            entity_counts,
            dict(self.automation_counts),
        )

    def _handle_event(self, event: dict) -> None:
        now = time.time()
        self._roll_bucket_if_needed(now)
        self.last_event_ts = now
        event_type = event.get("event_type")
        data = event.get("data") or {}

        if event_type == "state_changed":
            entity_id = data.get("entity_id") or "unknown"
            self.state_changes += 1
            self.entity_counts[entity_id] += 1
            self.recent_state_changes.append(now)

            old_state_obj = data.get("old_state") or {}
            new_state_obj = data.get("new_state") or {}
            old_state = old_state_obj.get("state")
            new_state = new_state_obj.get("state")
            if new_state in {"unavailable", "unknown"} and old_state not in {"unavailable", "unknown"}:
                self.unavailable_transitions += 1
                self.entity_unavailable[entity_id] += 1
                self.recent_unavailable.append(now)
                meta = self.entity_registry.get(str(entity_id), {})
                device_id = meta.get("device_id")
                is_battery = bool(
                    (device_id and str(device_id) in self.battery_device_ids)
                    or str(meta.get("device_class") or "").lower() == "battery"
                    or str(entity_id).lower().endswith(("_battery", "_batteri"))
                )
                (self.recent_unavailable_battery if is_battery else self.recent_unavailable_nonbattery).append(now)

        elif event_type == "automation_triggered":
            entity_id = data.get("entity_id") or data.get("name") or "unknown"
            self.automation_triggers += 1
            self.automation_counts[entity_id] += 1
            self.recent_automation_triggers.append(now)

        elif event_type == "call_service":
            self.service_calls += 1

        self._prune_recent(now)

    def _prune_recent(self, now: float | None = None) -> None:
        now = now or time.time()
        cutoff = now - 60
        for queue in (
            self.recent_state_changes, self.recent_automation_triggers, self.recent_unavailable,
            self.recent_unavailable_battery, self.recent_unavailable_nonbattery,
        ):
            while queue and queue[0] < cutoff:
                queue.popleft()

    def rates(self) -> dict:
        self._prune_recent()
        return {
            "state_changes_per_minute": float(len(self.recent_state_changes)),
            "automation_triggers_per_minute": float(len(self.recent_automation_triggers)),
            "unavailable_per_minute": float(len(self.recent_unavailable)),
            "unavailable_battery_per_minute": float(len(self.recent_unavailable_battery)),
            "unavailable_nonbattery_per_minute": float(len(self.recent_unavailable_nonbattery)),
            "websocket_connected": self.connected,
            "event_monitor_status": self.status(),
        }

    def current_top_entities(self, limit: int = 10) -> list[dict]:
        return [
            {"entity_id": entity, "changes": count, "unavailable": self.entity_unavailable.get(entity, 0)}
            for entity, count in self.entity_counts.most_common(limit)
        ]

    def current_top_flappers(self, limit: int = 50) -> list[dict]:
        return [
            {"entity_id": entity, "changes": self.entity_counts.get(entity, 0), "unavailable": count}
            for entity, count in self.entity_unavailable.most_common(limit)
        ]
