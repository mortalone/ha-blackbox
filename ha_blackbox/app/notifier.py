from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from urllib.parse import urlparse

import aiohttp

from config import Settings
from diagnostic_context import redact_text

LOGGER = logging.getLogger("blackbox.notifier")


@dataclass(slots=True)
class DeliveryResult:
    ok: bool
    detail: str


class DirectNotifier:
    """Send alerts without depending on Home Assistant Core.

    The direct channel intentionally uses its own HTTP session. Reusing the
    Supervisor client would risk forwarding the Supervisor bearer token to an
    external service.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._session: aiohttp.ClientSession | None = None

    @property
    def provider(self) -> str:
        value = str(self.settings.direct_notification_provider or "disabled").strip().lower()
        return value if value in {"disabled", "ntfy", "pushover", "telegram", "webhook"} else "disabled"

    def configured(self) -> bool:
        provider = self.provider
        if provider == "disabled":
            return False
        if provider == "ntfy":
            return bool(self.settings.ntfy_topic.strip() and self._valid_http_url(self.settings.ntfy_server))
        if provider == "pushover":
            return bool(self.settings.pushover_user_key.strip() and self.settings.pushover_app_token.strip())
        if provider == "telegram":
            return bool(self.settings.telegram_bot_token.strip() and self.settings.telegram_chat_id.strip())
        if provider == "webhook":
            return bool(self._valid_http_url(self.settings.direct_webhook_url))
        return False

    def status(self) -> dict:
        provider = self.provider
        return {
            "enabled": bool(self.settings.direct_critical_notifications),
            "provider": provider,
            "configured": self.configured(),
            "ha_notification_enabled": bool(self.settings.persistent_notifications),
            "critical_only": not bool(self.settings.direct_warning_notifications),
            "warning_notifications": bool(self.settings.direct_warning_notifications),
            "independent_of_core": provider != "disabled" and self.configured(),
            "critical_priority": 5 if provider == "ntfy" else None,
            "warning_priority": 4 if provider == "ntfy" else None,
            "click_configured": bool(self.settings.ntfy_click_url.strip()) if provider == "ntfy" else False,
            "android_recommended": provider in {"disabled", "ntfy"},
        }

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def send_incident(self, incident: dict, test: bool = False) -> DeliveryResult:
        if not self.settings.direct_critical_notifications:
            return DeliveryResult(False, "Direct critical notifications are disabled")
        if not self.configured():
            return DeliveryResult(False, f"Provider {self.provider!r} is not configured")

        title = "HA Black Box – TESTALARM" if test else "HA Black Box – KRITISK"
        title = redact_text(title)
        message = self._incident_message(incident, test=test)
        try:
            if self.provider == "ntfy":
                await self._send_ntfy(title, message, priority=5, tags="rotating_light,warning")
            elif self.provider == "pushover":
                await self._send_pushover(title, message)
            elif self.provider == "telegram":
                await self._send_telegram(title, message)
            elif self.provider == "webhook":
                await self._send_webhook(title, message, incident, test=test)
            else:
                return DeliveryResult(False, "No direct provider selected")
            return DeliveryResult(True, f"Sent via {self.provider}")
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
            LOGGER.warning("Direct notification via %s failed: %s", self.provider, exc)
            return DeliveryResult(False, str(exc)[:500])

    async def send_warning(self, warning: dict) -> DeliveryResult:
        """Optionally send a high-priority warning without creating an incident.

        This is off by default to avoid notification fatigue. ntfy receives
        priority 4; critical incidents always use priority 5.
        """
        if not self.settings.direct_critical_notifications or not self.settings.direct_warning_notifications:
            return DeliveryResult(False, "Direct warning notifications are disabled")
        if not self.configured():
            return DeliveryResult(False, f"Provider {self.provider!r} is not configured")

        title = "HA Black Box – ADVARSEL"
        message = self._warning_message(warning)
        try:
            if self.provider == "ntfy":
                await self._send_ntfy(title, message, priority=4, tags="warning")
            elif self.provider == "pushover":
                await self._send_pushover(title, message)
            elif self.provider == "telegram":
                await self._send_telegram(title, message)
            elif self.provider == "webhook":
                await self._send_webhook(title, message, warning, test=False, event="warning")
            else:
                return DeliveryResult(False, "No direct provider selected")
            return DeliveryResult(True, f"Sent warning via {self.provider}")
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
            LOGGER.warning("Direct warning via %s failed: %s", self.provider, exc)
            return DeliveryResult(False, str(exc)[:500])

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10, connect=5))
        return self._session

    @staticmethod
    def _valid_http_url(value: str) -> bool:
        try:
            parsed = urlparse(str(value).strip())
            return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
        except Exception:
            return False

    @staticmethod
    def _safe_time(ts) -> str:
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts)))
        except Exception:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    def _incident_message(self, incident: dict, test: bool = False) -> str:
        if test:
            return (
                "Dette er en PRIORITET 5-test fra HA Black Box.\n"
                "Den direkte ntfy-kanal virker uden en Home Assistant automation eller et Core-servicekald.\n"
                "Hvis du har givet ntfy's MAX/URGENT-kanal lyd, vibration og evt. adgang gennem Forstyr ikke, "
                "skal denne test bruge den kanal."
            )

        evidence = [redact_text(str(x).strip()) for x in (incident.get("evidence") or []) if str(x).strip()][:2]
        lines = [
            f"Årsag: {redact_text(str(incident.get('title') or 'Kritisk incident'))}",
            f"Tidspunkt: {self._safe_time(incident.get('start_ts') or incident.get('updated_ts') or time.time())}",
            f"Incident: {redact_text(str(incident.get('id') or 'ukendt'))[:80]}",
            redact_text(str(incident.get("summary") or "HA Black Box registrerede et kritisk incident.")),
            f"Sandsynlighed: {int(incident.get('confidence') or 0)}%",
        ]
        if evidence:
            lines.append("Kort evidens: " + " | ".join(x[:260] for x in evidence))
        lines.append("Detaljer og AI-diagnose findes lokalt i HA Black Box.")
        return "\n".join(lines)

    # Backwards-compatible helper used by existing tests and any local tooling.
    def _message(self, incident: dict, test: bool = False) -> str:
        return self._incident_message(incident, test=test)

    def _warning_message(self, warning: dict) -> str:
        lines = [
            f"Årsag: {redact_text(str(warning.get('title') or 'Advarsel'))}",
            f"Tidspunkt: {self._safe_time(warning.get('ts') or time.time())}",
            redact_text(str(warning.get("detail") or "Black Box har registreret en vedvarende advarsel.")),
            "Dette er ikke en kritisk alarm. Åbn Black Box for årsager og systempåvirkning.",
        ]
        return "\n".join(lines)

    def _ntfy_headers(self, title: str, priority: int, tags: str) -> dict[str, str]:
        headers = {
            "Title": redact_text(title),
            "Priority": str(max(1, min(5, int(priority)))),
            "Tags": tags,
            "Content-Type": "text/plain; charset=utf-8",
        }
        click_url = self.settings.ntfy_click_url.strip()
        if click_url and self._valid_http_url(click_url):
            headers["Click"] = click_url
        if self.settings.ntfy_access_token.strip():
            headers["Authorization"] = f"Bearer {self.settings.ntfy_access_token.strip()}"
        return headers

    async def _send_ntfy(self, title: str, message: str, priority: int = 5, tags: str = "warning") -> None:
        server = self.settings.ntfy_server.strip().rstrip("/")
        topic = self.settings.ntfy_topic.strip().strip("/")
        url = f"{server}/{topic}"
        headers = self._ntfy_headers(title, priority, tags)
        session = await self._get_session()
        async with session.post(url, data=redact_text(message).encode("utf-8"), headers=headers) as response:
            text = await response.text()
            if response.status >= 300:
                raise ValueError(f"ntfy HTTP {response.status}: {redact_text(text[:200])}")

    async def _send_pushover(self, title: str, message: str) -> None:
        session = await self._get_session()
        data = {
            "token": self.settings.pushover_app_token.strip(),
            "user": self.settings.pushover_user_key.strip(),
            "title": title,
            "message": message,
            "priority": "1",
        }
        async with session.post("https://api.pushover.net/1/messages.json", data=data) as response:
            text = await response.text()
            if response.status >= 300:
                raise ValueError(f"Pushover HTTP {response.status}: {redact_text(text[:200])}")

    async def _send_telegram(self, title: str, message: str) -> None:
        token = self.settings.telegram_bot_token.strip()
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        session = await self._get_session()
        payload = {
            "chat_id": self.settings.telegram_chat_id.strip(),
            "text": f"{title}\n\n{message}",
            "disable_web_page_preview": True,
        }
        async with session.post(url, json=payload) as response:
            text = await response.text()
            if response.status >= 300:
                raise ValueError(f"Telegram HTTP {response.status}: {redact_text(text[:200])}")

    async def _send_webhook(self, title: str, message: str, incident: dict, test: bool = False, event: str | None = None) -> None:
        url = self.settings.direct_webhook_url.strip()
        headers = {"Content-Type": "application/json"}
        if self.settings.direct_webhook_bearer_token.strip():
            headers["Authorization"] = f"Bearer {self.settings.direct_webhook_bearer_token.strip()}"
        payload = {
            "source": "ha_blackbox",
            "event": event or ("test" if test else "critical_incident"),
            "title": title,
            "message": redact_text(message),
            "incident": {
                "id": incident.get("id"),
                "category": incident.get("category"),
                "severity": incident.get("severity"),
                "confidence": incident.get("confidence"),
                "title": redact_text(str(incident.get("title") or "")),
                "summary": redact_text(str(incident.get("summary") or incident.get("detail") or "")),
                "evidence": [redact_text(str(x)) for x in (incident.get("evidence") or [])[:3]],
            },
        }
        session = await self._get_session()
        async with session.post(url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"), headers=headers) as response:
            text = await response.text()
            if response.status >= 300:
                raise ValueError(f"Webhook HTTP {response.status}: {redact_text(text[:200])}")
