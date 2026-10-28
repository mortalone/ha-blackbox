from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class Settings:
    sample_interval_seconds: int = 5
    persist_interval_seconds: int = 15
    metric_retention_days: int = 7
    incident_retention_days: int = 90
    important_log_retention_days: int = 7
    pre_incident_minutes: int = 30
    recovery_minutes: int = 5
    auto_restart_unresponsive_core: bool = True
    core_unresponsive_restart_seconds: int = 180
    core_restart_cooldown_minutes: int = 30
    monitor_all_apps: bool = True
    excluded_apps: list[str] = field(default_factory=list)
    persistent_notifications: bool = True
    notification_service: str = "persistent_notification.create"
    direct_critical_notifications: bool = False
    direct_notification_provider: str = "ntfy"
    direct_warning_notifications: bool = False
    ntfy_server: str = "https://ntfy.sh"
    ntfy_topic: str = ""
    ntfy_access_token: str = ""
    ntfy_click_url: str = ""
    pushover_user_key: str = ""
    pushover_app_token: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    direct_webhook_url: str = ""
    direct_webhook_bearer_token: str = ""
    disk_warning_percent: float = 90.0
    disk_critical_percent: float = 97.0
    disk_warning_free_gb: float = 10.0
    disk_critical_free_gb: float = 2.0
    memory_warning_percent: float = 85.0
    memory_critical_percent: float = 95.0
    cpu_warning_percent: float = 90.0
    cpu_critical_percent: float = 98.0
    api_latency_warning_ms: int = 1000
    api_latency_critical_ms: int = 5000
    state_changes_warning_per_minute: int = 1000
    state_changes_critical_per_minute: int = 3000
    state_changes_warning_sustain_seconds: int = 60
    state_changes_clear_ratio: float = 0.80
    unavailable_warning_per_minute: int = 100
    unavailable_critical_per_minute: int = 500
    noisy_entity_warning_per_hour: int = 500
    recorder_growth_warning_mb_per_hour: float = 250.0
    recorder_growth_critical_mb_per_hour: float = 1000.0
    recorder_db_path: str = "home-assistant_v2.db"
    detailed_disk_scan_minutes: int = 15
    log_initial_lines: int = 100
    log_ring_lines: int = 12000

    @classmethod
    def load(cls, path: str = "/data/options.json") -> "Settings":
        values: dict = {}
        p = Path(path)
        if p.exists():
            try:
                values = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                values = {}
        allowed = cls.__dataclass_fields__.keys()
        clean = {k: v for k, v in values.items() if k in allowed}
        settings = cls(**clean)
        settings._normalize()
        return settings

    def _normalize(self) -> None:
        self.sample_interval_seconds = max(2, min(60, int(self.sample_interval_seconds)))
        self.persist_interval_seconds = max(5, min(300, int(self.persist_interval_seconds)))
        self.pre_incident_minutes = max(5, min(120, int(self.pre_incident_minutes)))
        self.recovery_minutes = max(1, min(60, int(self.recovery_minutes)))
        self.auto_restart_unresponsive_core = bool(self.auto_restart_unresponsive_core)
        self.core_unresponsive_restart_seconds = max(60, min(3600, int(self.core_unresponsive_restart_seconds)))
        self.core_restart_cooldown_minutes = max(5, min(360, int(self.core_restart_cooldown_minutes)))
        self.excluded_apps = [str(x).strip() for x in self.excluded_apps if str(x).strip()]
        self.state_changes_warning_sustain_seconds = max(15, min(1800, int(self.state_changes_warning_sustain_seconds)))
        self.state_changes_clear_ratio = max(0.25, min(0.95, float(self.state_changes_clear_ratio)))
        self.notification_service = str(self.notification_service or "persistent_notification.create").strip()
        provider = str(self.direct_notification_provider or "disabled").strip().lower()
        self.direct_notification_provider = provider if provider in {"disabled", "ntfy", "pushover", "telegram", "webhook"} else "disabled"
        self.ntfy_server = str(self.ntfy_server or "https://ntfy.sh").strip()
        self.ntfy_topic = str(self.ntfy_topic or "").strip()
        self.ntfy_access_token = str(self.ntfy_access_token or "").strip()
        self.ntfy_click_url = str(self.ntfy_click_url or "").strip()
        self.pushover_user_key = str(self.pushover_user_key or "").strip()
        self.pushover_app_token = str(self.pushover_app_token or "").strip()
        self.telegram_bot_token = str(self.telegram_bot_token or "").strip()
        self.telegram_chat_id = str(self.telegram_chat_id or "").strip()
        self.direct_webhook_url = str(self.direct_webhook_url or "").strip()
        self.direct_webhook_bearer_token = str(self.direct_webhook_bearer_token or "").strip()
        self.recorder_db_path = str(self.recorder_db_path or "home-assistant_v2.db").strip()

    def public_dict(self) -> dict:
        # Never expose notification credentials via the live API or AI export.
        secret_fields = {
            "ntfy_access_token", "pushover_user_key", "pushover_app_token",
            "telegram_bot_token", "telegram_chat_id", "direct_webhook_url",
            "direct_webhook_bearer_token", "ntfy_topic", "ntfy_click_url",
        }
        result = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if name in secret_fields:
                result[name] = "<configured>" if str(value or "").strip() else ""
            else:
                result[name] = value
        return result
