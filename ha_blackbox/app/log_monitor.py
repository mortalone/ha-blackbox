from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import deque
from collections.abc import Awaitable, Callable
from pathlib import Path

from storage import Storage
from supervisor import APIError, SupervisorClient

LOGGER = logging.getLogger("blackbox.logs")

LEVEL_RE = re.compile(r"\b(CRITICAL|ERROR|ERR|WARNING|WARN|NOTICE|INFO|DEBUG)\b", re.I)
IMPORTANT_RE = re.compile(
    r"out of memory|oom-killer|no space left on device|enospc|i/o error|input/output error|"
    r"nvme.*(?:timeout|reset|abort)|database.*(?:locked|malformed|corrupt|full)|"
    r"disk i/o error|watchdog|unhealthy|blocking call|recorder.*(?:error|failed|purge)|"
    r"fatal python error|segmentation fault|sigabrt|sigsegv",
    re.I,
)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
FATAL_BLOCK_RE = re.compile(r"(?=^Fatal Python error:\s*.+$)", re.M)
FATAL_HEADER_RE = re.compile(r"^Fatal Python error:\s*(?P<signal>.+?)\s*$", re.M)
CURRENT_THREAD_RE = re.compile(
    r"^Current thread\s+(?P<tid>0x[0-9a-fA-F]+)(?:\s+\[(?P<name>[^\]]+)\])?\s+\(most recent call first\):",
    re.M,
)
STACK_FRAME_RE = re.compile(r'^\s*File "(?P<file>[^"]+)", line (?P<line>\d+) in (?P<func>\S+)')
HA_COMPONENT_RE = re.compile(r"/homeassistant/components/(?P<comp>[a-zA-Z0-9_]+)/")
CUSTOM_COMPONENT_RE = re.compile(r"custom_components/(?P<comp>[a-zA-Z0-9_]+)/")


def inspect_fault_log(path: str = "/homeassistant/home-assistant.log.fault") -> dict:
    p = Path(path)
    try:
        if not p.exists():
            return {"found": False, "path": path}
        stat = p.stat()
        if stat.st_size <= 0:
            return {"found": False, "path": path, "size_bytes": 0, "mtime_ts": float(stat.st_mtime)}
        with p.open("rb") as fh:
            if stat.st_size > 262144:
                fh.seek(stat.st_size - 262144)
            text = fh.read().decode("utf-8", errors="replace")
    except OSError as exc:
        return {"found": False, "path": path, "error": str(exc)}

    raw_blocks = [b.strip() for b in FATAL_BLOCK_RE.split(text) if b.strip() and "Fatal Python error:" in b]
    if not raw_blocks:
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if not lines:
            return {"found": False, "path": path, "size_bytes": stat.st_size, "mtime_ts": float(stat.st_mtime)}
        return {
            "found": True,
            "path": path,
            "size_bytes": stat.st_size,
            "mtime_ts": float(stat.st_mtime),
            "signature_key": f"{stat.st_mtime_ns}:{stat.st_size}:raw",
            "crash_count": 1,
            "signal": "Unknown fatal signal",
            "crashing_thread": "unknown",
            "suspected_component": None,
            "top_frame": lines[0][:240],
            "frames": [],
            "excerpt_lines": lines[:12],
            "summary_da": f"Fatal crash-log fundet i home-assistant.log.fault ({lines[0][:120]})",
        }

    latest = raw_blocks[-1]
    sig_match = FATAL_HEADER_RE.search(latest)
    signal_reason = sig_match.group("signal").strip() if sig_match else "Aborted"

    crashing_thread = "unknown"
    frames: list[str] = []
    excerpt_lines: list[str] = [f"Fatal Python error: {signal_reason}"]
    suspected_component: str | None = None

    ct_match = CURRENT_THREAD_RE.search(latest)
    if ct_match:
        crashing_thread = (ct_match.group("name") or ct_match.group("tid") or "unknown").strip()
        header_line = ct_match.group(0).strip()
        excerpt_lines.append(header_line)
        tail_lines = latest[ct_match.end():].splitlines()
        for raw_ln in tail_lines:
            stripped = raw_ln.strip()
            if not stripped:
                if frames:
                    break
                continue
            if stripped.startswith(("Thread 0x", "Extension modules:", "Fatal Python error:")):
                break
            fm = STACK_FRAME_RE.match(raw_ln)
            if fm:
                file_path = fm.group("file")
                line_no = fm.group("line")
                func_name = fm.group("func")
                short_file = file_path.replace("/usr/src/homeassistant/", "")
                frame_summary = f"{short_file}:{line_no} in {func_name}"
                frames.append(frame_summary)
                excerpt_lines.append(f"  File \"{short_file}\", line {line_no} in {func_name}")
                if not suspected_component:
                    cm = CUSTOM_COMPONENT_RE.search(file_path)
                    if cm:
                        suspected_component = f"custom:{cm.group('comp')}"
                    else:
                        hm = HA_COMPONENT_RE.search(file_path)
                        if hm:
                            suspected_component = hm.group("comp")
            elif len(excerpt_lines) < 12:
                excerpt_lines.append(f"  {stripped}")

    top_frame = frames[0] if frames else None
    comp_text = f", komponent: {suspected_component}" if suspected_component else ""
    frame_text = f" ved {top_frame}" if top_frame else ""
    summary_da = (
        f"Fatal Python error: {signal_reason} i tråd [{crashing_thread}]"
        f"{comp_text}{frame_text}"
    )

    return {
        "found": True,
        "path": path,
        "size_bytes": stat.st_size,
        "mtime_ts": float(stat.st_mtime),
        "signature_key": f"{stat.st_mtime_ns}:{stat.st_size}:{len(raw_blocks)}",
        "crash_count": len(raw_blocks),
        "signal": signal_reason,
        "crashing_thread": crashing_thread,
        "suspected_component": suspected_component,
        "top_frame": top_frame,
        "frames": frames[:8],
        "excerpt_lines": excerpt_lines[:15],
        "summary_da": summary_da,
    }


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
