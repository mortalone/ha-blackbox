from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import deque
from collections.abc import Awaitable, Callable

from storage import Storage
from supervisor import APIError, SupervisorClient

LOGGER = logging.getLogger("blackbox.logs")

LEVEL_RE = re.compile(r"\b(CRITICAL|ERROR|ERR|WARNING|WARN|NOTICE|INFO|DEBUG)\b", re.I)
IMPORTANT_RE = re.compile(
    r"out of memory|oom-killer|no space left on device|enospc|i/o error|input/output error|"
    r"nvme.*(?:timeout|reset|abort)|database.*(?:locked|malformed|corrupt|full)|"
    r"disk i/o error|watchdog|unhealthy|blocking call|recorder.*(?:error|failed|purge)",
    re.I,
)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def classify_log(line: str) -> str:
    match = LEVEL_RE.search(line)
    if match:
        value = match.group(1).lower()
        if value in {"critical", "error", "err"}:
            return "error"
        if value in {"warning", "warn"}:
            return "warning"
        if value == "notice":
            return "notice"
        if value == "debug":
            return "debug"
    if IMPORTANT_RE.search(line):
        return "warning"
    return "info"


class LogMonitor:
    def __init__(
        self,
        client: SupervisorClient,
        storage: Storage,
        ring_lines: int,
        initial_lines: int,
        on_entry: Callable[[dict], Awaitable[None]],
    ) -> None:
        self.client = client
        self.storage = storage
        self.ring = deque(maxlen=ring_lines)
        self.initial_lines = initial_lines
        self.on_entry = on_entry
        self.tasks: dict[str, asyncio.Task] = {}
        self._stop = asyncio.Event()
        self._last_persist: dict[str, float] = {}
        self._history_loaded: set[str] = set()

    async def start_base_sources(self) -> None:
        await self.ensure_source("core", "/core/logs/follow")
        await self.ensure_source("supervisor", "/supervisor/logs/follow")
        await self.ensure_source("host", "/host/logs/follow")

    async def ensure_source(self, source: str, path: str) -> None:
        task = self.tasks.get(source)
        if task and not task.done():
            return
        self.tasks[source] = asyncio.create_task(self._stream_source(source, path), name=f"logs:{source}")

    async def sync_addons(self, addons: list[dict], excluded: set[str], monitor_all: bool) -> None:
        if not monitor_all:
            return
        wanted: set[str] = set()
        for addon in addons:
            slug = str(addon.get("slug") or "")
            state = str(addon.get("state") or "")
            installed = addon.get("installed")
            if not slug or slug == "ha_blackbox" or slug.endswith("ha_blackbox") or slug in excluded:
                continue
            if state == "started":
                wanted.add(f"addon:{slug}")
                await self.ensure_source(f"addon:{slug}", f"/addons/{slug}/logs/follow")

        for source, task in list(self.tasks.items()):
            if source.startswith("addon:") and source not in wanted:
                task.cancel()
                self.tasks.pop(source, None)

    async def _stream_source(self, source: str, path: str) -> None:
        backoff = 2
        while not self._stop.is_set():
            try:
                # Load a small historical tail for context, but never let those
                # already-existing lines create a *new* incident. The /follow
                # endpoint otherwise replays its requested tail on every connect.
                if source not in self._history_loaded:
                    history_path = path[:-7] if path.endswith("/follow") else path
                    separator = "&" if "?" in history_path else "?"
                    history = await self.client.get_text(
                        f"{history_path}{separator}verbose&lines={self.initial_lines}&no_colors"
                    )
                    for historical_line in history.splitlines():
                        if historical_line.strip():
                            await self._ingest(source, historical_line, analyze=False)
                    self._history_loaded.add(source)

                # Ask /follow for only its latest line. That first returned line
                # is backlog, not a newly observed event, so it is context-only.
                first_line = True
                async for line in self.client.stream_lines(path, 1):
                    if self._stop.is_set():
                        return
                    await self._ingest(source, line, analyze=not first_line)
                    first_line = False
                backoff = 2
            except asyncio.CancelledError:
                raise
            except APIError as exc:
                LOGGER.warning("Log stream %s unavailable: %s", source, exc)
            except Exception as exc:
                LOGGER.exception("Unexpected log stream failure for %s: %s", source, exc)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=backoff)
            except asyncio.TimeoutError:
                pass
            backoff = min(backoff * 2, 60)

    async def _ingest(self, source: str, line: str, analyze: bool = True) -> None:
        clean = ANSI_RE.sub("", line).strip()
        if not clean:
            return
        level = classify_log(clean)
        entry = {"ts": time.time(), "source": source, "level": level, "message": clean[:12000]}
        self.ring.append(entry)

        # Persist warnings/errors, but throttle identical lines so a log storm cannot fill Black Box itself.
        if level in {"warning", "error"} or IMPORTANT_RE.search(clean):
            signature = f"{source}|{level}|{clean[-1000:]}"
            last = self._last_persist.get(signature, 0)
            if entry["ts"] - last >= 30:
                self.storage.save_important_log(entry)
                self._last_persist[signature] = entry["ts"]

        if analyze:
            await self.on_entry(entry)

    def recent(self, since_ts: float | None = None, limit: int = 3000) -> list[dict]:
        items = list(self.ring)
        if since_ts is not None:
            items = [entry for entry in items if entry["ts"] >= since_ts]
        return items[-limit:]

    async def stop(self) -> None:
        self._stop.set()
        for task in self.tasks.values():
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks.values(), return_exceptions=True)
        self.tasks.clear()
