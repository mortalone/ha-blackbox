# HA Black Box — Flight Recorder, Crash Diagnostics & Auto-Heal for Home Assistant

**HA Black Box** (`ha_blackbox`) er en Home Assistant Supervisor add-on (flight recorder), der kører uafhængigt af Home Assistant Core og overvåger systemhelbred, hændelser, log-signaturer, native C/Python-crashes (`home-assistant.log.fault`), state-churn og uventede genstarter.

## Hovedfunktioner (v0.1.14)

- **Uafhængig overvågning**: Kører i egen container på `system`-trinnet via Supervisor API, så den fortsætter med at logge og analysere, selv når Home Assistant Core hænger eller crasher (`502 Bad Gateway`).
- **Native Crash-detektion (`home-assistant.log.fault`)**: Parser Python `faulthandler`-dumps (`Fatal Python error: Aborted`, `Segmentation fault` m.fl.), identificerer crashende tråd (f.eks. `[stream_worker]` i `PyAV`/`FFmpeg`) og korrelerer automatisk med `core_unresponsive`- og `host_reboot`-hændelser.
- **Core Auto-Heal Watchdog**: Genstarter automatisk og kontrolleret Home Assistant Core via Supervisor (`POST /core/restart`), hvis Core API er utilgængelig i længere tid (standard 180 sek.), mens Supervisor er sund og ingen backup/opdatering kører.
- **Persistent Notifikationskø & Direkte Push (ntfy / Pushover / Telegram / Webhook)**: Garanterer at kritiske hændelser under nedbrud leveres til Home Assistant efter genstart, og understøtter direkte push-alarmer uden om Home Assistant Core.
- **State-churn & Flapping-analyse**: Finder støjende sensorer, utilgængelige enheder (`unavailable`-hop) og travle automationer med direkte genveje til enhed, integration og automationseditor.
- **AI-klar Eksport (`diagnostic.zip`)**: Saniteret diagnostisk bundle med `AI-START-HERE.md` og `ai-summary.json` (renset for tokens, passwords og RTSP-stier).

## Installation som Home Assistant Add-on Repository

1. Åbn Home Assistant → **Indstillinger** → **Apps (Add-ons)** → **Add-on Store**.
2. Klik på menuen øverst til højre (`⋮`) → **Repositories**.
3. Tilføj URL'en til dette repository:
   ```text
   https://github.com/mortalone/ha-blackbox
   ```
4. Installer **HA Black Box** og slå **Watchdog** og **Vis i sidebjælke** til.

## Test

```bash
python -m unittest discover -s ha_blackbox/tests -v
```