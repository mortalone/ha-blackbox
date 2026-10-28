from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import AsyncIterator

try:
    import aiohttp
except ModuleNotFoundError:  # pragma: no cover - unit tests without aiohttp installed
    aiohttp = None  # type: ignore[assignment]


class APIError(RuntimeError):
    pass


class SupervisorClient:
    def __init__(self) -> None:
        self.base = "http://supervisor"
        self.token = os.environ.get("SUPERVISOR_TOKEN", "")
        self.headers = {"Authorization": f"Bearer {self.token}"}
        self.session = aiohttp.ClientSession(
            headers=self.headers,
            timeout=aiohttp.ClientTimeout(total=8, connect=4),
        )

    async def close(self) -> None:
        await self.session.close()

    async def get(self, path: str, timeout: float = 8) -> dict | list:
        try:
            async with self.session.get(
                self.base + path, timeout=aiohttp.ClientTimeout(total=timeout)
            ) as response:
                text = await response.text()
                if response.status >= 400:
                    raise APIError(f"GET {path}: HTTP {response.status}: {text[:300]}")
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise APIError(f"GET {path}: invalid JSON") from exc
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            raise APIError(f"GET {path}: {exc}") from exc

        if isinstance(payload, dict) and payload.get("result") in {"ok", "error"}:
            if payload.get("result") != "ok":
                raise APIError(f"GET {path}: {payload.get('message', 'Supervisor error')}")
            return payload.get("data", {})
        return payload

    async def get_text(self, path: str, timeout: float = 15) -> str:
        headers = {**self.headers, "Accept": "text/x-log"}
        try:
            async with self.session.get(
                self.base + path,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as response:
                text = await response.text(errors="replace")
                if response.status >= 400:
                    raise APIError(f"GET {path}: HTTP {response.status}: {text[:300]}")
                return text
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            raise APIError(f"GET {path}: {exc}") from exc

    async def ha_get(self, api_path: str = "/", timeout: float = 8) -> tuple[dict | list | str, float]:
        path = "/core/api" + (api_path if api_path.startswith("/") else "/" + api_path)
        started = time.perf_counter()
        try:
            async with self.session.get(
                self.base + path,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as response:
                text = await response.text()
                elapsed_ms = (time.perf_counter() - started) * 1000
                if response.status >= 400:
                    raise APIError(f"HA GET {api_path}: HTTP {response.status}: {text[:300]}")
                try:
                    return json.loads(text), elapsed_ms
                except json.JSONDecodeError:
                    return text, elapsed_ms
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            raise APIError(f"HA GET {api_path}: {exc}") from exc

    async def ha_post(self, api_path: str, payload: dict, timeout: float = 8) -> dict | list | str:
        path = "/core/api" + (api_path if api_path.startswith("/") else "/" + api_path)
        try:
            async with self.session.post(
                self.base + path,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as response:
                text = await response.text()
                if response.status >= 400:
                    raise APIError(f"HA POST {api_path}: HTTP {response.status}: {text[:300]}")
                try:
                    return json.loads(text) if text else {}
                except json.JSONDecodeError:
                    return text
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            raise APIError(f"HA POST {api_path}: {exc}") from exc

    async def notify(self, service: str, title: str, message: str) -> None:
        if "." not in service:
            service = "persistent_notification.create"
        domain, service_name = service.split(".", 1)
        data = {"message": message}
        if domain == "persistent_notification":
            data["title"] = title
            data["notification_id"] = "ha_blackbox"
        else:
            data["title"] = title
        await self.ha_post(f"/services/{domain}/{service_name}", data)

    async def fire_event(self, event_type: str, data: dict) -> None:
        await self.ha_post(f"/events/{event_type}", data)

    async def set_ha_state(self, entity_id: str, state: str, attributes: dict) -> None:
        await self.ha_post(f"/states/{entity_id}", {"state": str(state), "attributes": attributes})

    async def post(self, path: str, payload: dict | None = None, timeout: float = 30) -> dict | list:
        try:
            async with self.session.post(
                self.base + path,
                json=payload if payload is not None else {},
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as response:
                text = await response.text()
                if response.status >= 400:
                    raise APIError(f"POST {path}: HTTP {response.status}: {text[:300]}")
                if not text.strip():
                    return {}
                try:
                    data = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise APIError(f"POST {path}: invalid JSON") from exc
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            raise APIError(f"POST {path}: {exc}") from exc

        if isinstance(data, dict) and data.get("result") in {"ok", "error"}:
            if data.get("result") != "ok":
                raise APIError(f"POST {path}: {data.get('message', 'Supervisor error')}")
            return data.get("data", {})
        return data

    async def jobs_info(self) -> dict:
        data = await self.get("/jobs/info", timeout=8)
        return data if isinstance(data, dict) else {}

    async def restart_core(self) -> dict:
        data = await self.post("/core/restart", timeout=120)
        return data if isinstance(data, dict) else {}

    async def sync_camera_preload_prefs(self, camera_storage_path: str = "/homeassistant/.storage/camera") -> dict:
        from pathlib import Path
        p = Path(camera_storage_path)
        if not p.exists():
            return {"synced": 0, "status": "no_storage_file"}
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            cam_map = (raw.get("data") or {}) if isinstance(raw, dict) else {}
        except (OSError, json.JSONDecodeError) as exc:
            return {"synced": 0, "status": f"read_error:{exc}"}
        if not cam_map or not self.token:
            return {"synced": 0, "status": "empty_or_no_token"}

        updated: list[str] = []
        try:
            async with self.session.ws_connect(
                "ws://supervisor/core/api/websocket",
                headers=self.headers,
                timeout=8,
            ) as ws:
                first = await ws.receive_json(timeout=5)
                if first.get("type") == "auth_required":
                    await ws.send_json({"type": "auth", "access_token": self.token})
                    auth_reply = await ws.receive_json(timeout=5)
                    if auth_reply.get("type") != "auth_ok":
                        return {"synced": 0, "status": "auth_failed"}
                msg_id = 1
                for entity_id, prefs in cam_map.items():
                    if not isinstance(prefs, dict) or "preload_stream" not in prefs:
                        continue
                    await ws.send_json({
                        "id": msg_id,
                        "type": "camera/update_prefs",
                        "entity_id": entity_id,
                        "preload_stream": bool(prefs.get("preload_stream")),
                    })
                    reply = await ws.receive_json(timeout=5)
                    if reply.get("success"):
                        updated.append(f"{entity_id}={bool(prefs.get('preload_stream'))}")
                    msg_id += 1
        except Exception as exc:
            return {"synced": len(updated), "updated": updated, "status": f"ws_error:{exc}"}
        return {"synced": len(updated), "updated": updated, "status": "ok"}

    async def stream_lines(self, path: str, initial_lines: int = 100) -> AsyncIterator[str]:
        separator = "&" if "?" in path else "?"
        full_path = f"{path}{separator}verbose&lines={initial_lines}&no_colors"
        headers = {**self.headers, "Accept": "text/x-log"}
        timeout = aiohttp.ClientTimeout(total=None, connect=10, sock_read=None)
        async with self.session.get(self.base + full_path, headers=headers, timeout=timeout) as response:
            if response.status >= 400:
                text = await response.text()
                raise APIError(f"STREAM {path}: HTTP {response.status}: {text[:300]}")
            buffer = ""
            async for chunk in response.content.iter_any():
                buffer += chunk.decode("utf-8", errors="replace")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if line.strip():
                        yield line.rstrip("\r")
            if buffer.strip():
                yield buffer.strip()

    async def previous_boot_logs(self, source: str, lines: int = 1200) -> str:
        source = source.strip()
        if source == "host":
            path = f"/host/logs/boots/-1?verbose&lines={lines}&no_colors"
        elif source == "core":
            path = f"/core/logs/boots/-1?verbose&lines={lines}&no_colors"
        elif source == "supervisor":
            path = f"/supervisor/logs/boots/-1?verbose&lines={lines}&no_colors"
        elif source.startswith("addon:"):
            slug = source.split(":", 1)[1]
            path = f"/addons/{slug}/logs/boots/-1?verbose&lines={lines}&no_colors"
        else:
            raise ValueError(source)
        return await self.get_text(path, timeout=30)
