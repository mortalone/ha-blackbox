# Changelog

## 0.1.14

- **Detektion af native Python/C-crashes (`home-assistant.log.fault`)**: Læser og parser nu automatisk Python `faulthandler`-crashdumps (f.eks. `Fatal Python error: Aborted` / `Segmentation fault` i C-extensions som `PyAV` / `stream_worker`), udtrækker signal, crashende tråd, komponent og stack-frame, og opretter en høj-konfidens hændelse (`96%`).
- **Retroaktiv korrelation af hændelser**: Når et fault-log-crash opdages, beriges korrelerede `core_unresponsive`- og `host_reboot`-hændelser automatisk med den præcise rodårsag og målrettet anbefaling (f.eks. at slå `preload_stream` fra og aktivere `enable_webrtc` på Frigate-kameraer), så et frosset Core efterfulgt af manuel sluk/tænd ikke længere fremstår som "ukendt strømtab".
- **Aktiv Core Auto-Heal Watchdog**: Hvis Home Assistant Core API hænger i `502 Bad Gateway` / timeout i mere end `core_unresponsive_restart_seconds` (standard 180 sek.), mens Supervisor er sund og ingen backup/restore/update kører, udfører Black Box nu automatisk en kontrolleret `POST /core/restart` (med cooldown og max 2 genstarter pr. time).
- **Persistent HA-notifikationskø i SQLite (`notified_ha`)**: Kritiske hændelser, der opstod mens Core var nede eller før en genstart/strømafbrydelse, gemmer leveringsstatus i SQLite og leveres som persistent notifikation i Home Assistant, så snart Core er oppe igen.
- **Live telemetri til Home Assistant og delt filsystem**: Udgiver løbende status til `sensor.ha_blackbox_status` i Home Assistant samt `/share/ha_blackbox/latest_status.json`.
- **WebSocket-synkronisering af kamera `preload_stream`**: Synkroniserer `.storage/camera`-præferencer ind i Home Assistant Cores hukommelse ved opstart.
- **Retter WebSocket `Cannot write to closing transport` på store installationer (>10.000 entities)**: Sætter `max_msg_size=0` på event-WebSocket og springer `config/entity_registry/list` over på WS, når Entity Registry allerede er indlæst fra `.storage/core.entity_registry` (hvor svaret ellers oversteg `aiohttp`s 4 MB grænse og tvang forbindelsen over på SSE fallback).
- **System-fane udvidet**: Viser status for **Core Auto-Heal** og **Fault Log (`SIGABRT`/`SIGSEGV`)** direkte i brugerfladen.
- 30 tests.

## 0.1.13

- Tilføjer direkte Home Assistant-genveje fra fund og tabeller: **Åbn enhed**, **Åbn integration** og **Åbn automation** når de nødvendige registry/state-metadata findes.
- "Vis i analyse" åbner nu et særskilt **Valgt fund**-kort med præcis den entity/automation/gruppe der blev klikket på; brugeren lander ikke længere blot ved toppen af en lang tabel.
- "Find i tabellen" fremhæver den konkrete række, og relevante lister er udvidet, så aktuelle time-fund normalt også findes i 24t-tabellen.
- Entity Registry-metadata læses nu også fra Home Assistants read-only `.storage/core.entity_registry`, så enheds-/integrationslinks og platform-ejerskab fortsat virker, selv når live-events kører via SSE fallback.
- Automation-id/friendly name hentes fra det periodiske HA state-snapshot, så travle automationer kan åbnes direkte i automationseditoren.
- En fungerende SSE fallback vises ikke længere som en fremtrædende boks på Overblik. Den er nu kun en teknisk transportstatus under HA API/System, fordi den ikke kræver brugerhandling.
- Supervisor-watchdog-genstart af **én add-on** klassificeres nu som en warning-hændelse i stedet for systemkritisk. Core/Supervisor/host-watchdog-signaler kan fortsat være kritiske.
- Ældre `watchdog_restart`-incidenter, der udelukkende skyldtes `Watchdog found app ... restarting`, markeres som ignorerede ved opgradering.
- Warning-incidents gør systemstatus gul/degraded, ikke rød/critical, og udløser derfor ikke priority-5 ntfy-alarm.
- 26 tests.

## 0.1.12

- Skiller Home Assistant-systemets helbred fra Black Box' egen datadækning. Et event-stream-problem gør ikke længere HA-status gul/rød alene.
- Tilføjer automatisk fallback fra Home Assistant WebSocket til Supervisor event-stream (SSE) efter gentagne forbindelsesfejl.
- Viser tydeligt om live-events kommer via WebSocket, SSE fallback eller slet ikke er tilgængelige.
- Ny datadækningsboks forklarer: hvad betyder fejlen, er den normal, hvad skal brugeren gøre, fejlstadie og konkret seneste fejl.
- Hvis SSE fallback virker, fortsætter state-, automation- og flap-analyse uden brugerhandling.
- Manuel "Test/genopret overvågning" nulstiller fallback og prøver WebSocket igen.
- Event-monitor diagnosticerer nu forbindelsesstadie samt WebSocket- og SSE-fejl separat.
- 22 tests.

## 0.1.11
- Rettet UI-layoutfejl hvor event-stream-diagnosen blev presset ned i en smal ordkolonne.
- Event-streamen verificerer nu alle tre Home Assistant-subscriptions før forbindelsen markeres som sund.
- Automatisk reconnect er mere robust og gemmer sidste event, afbrydelsestid, fejlårsag og antal reconnect-forsøg.
- Tilføjet manuel **Genforbind event-stream** fra både årsagskort og System-fanen.
- Kort event-stream-udfald vises som datadækning/observation; vedvarende udfald over 5 minutter eskalerer til advarsel.
- Event-stream-observation rydder hurtigt igen efter en stabil genforbindelse i stedet for at hænge i recovery-perioden.
- Event-monitor-status medsendes i AI-eksporten.

## 0.1.10

- Makes ntfy the recommended/default direct provider for Android while keeping external delivery disabled until explicitly enabled.
- Sends critical ntfy incidents as **priority 5 / MAX / URGENT** with a fixed, unambiguous `HA Black Box – KRITISK` title.
- Critical push content now includes sanitized cause, local timestamp, incident ID, confidence and at most two short evidence lines.
- Adds optional direct warning pushes as **priority 4 / HIGH**. They are disabled by default and rate-limited to at most one push per warning category per hour.
- Adds optional `ntfy_click_url` so tapping the notification can open a user-supplied Home Assistant/Black Box URL. The value is treated as sensitive and is never included in the live public settings or AI export.
- Adds an Android/ntfy setup guide directly in **System → Kritiske notifikationer**, including a browser-local strong private topic generator and copy helper.
- Renames the test action to **Send PRIORITET 5-test** so Android MAX/URGENT channel configuration can be verified before a real incident.
- Exposes notification priority/readiness state without exposing topic, token or click URL.
- Adds tests for priority-5 ntfy headers, optional click action and secret masking.

## 0.1.9

- Adds direct critical notifications from the Black Box container, independent of Home Assistant automations and Core service calls.
- Supports ntfy, Pushover, Telegram and a generic webhook as direct providers.
- Keeps the existing Home Assistant event/notification channel as a secondary path when Core is available.
- Tracks per-incident delivery so retries do not repeatedly resend an external alert after it has succeeded.
- Adds a System-page notification status card and direct **Send test** action.
- Masks notification credentials and destination identifiers from live status and AI exports.
- Adds an Observér signal when the Black Box HA event WebSocket has been disconnected for more than two minutes, preventing zero event-rate data from being mistaken for genuinely quiet activity.
- Documents the hard limit that a local app cannot alert during total host power loss/kernel freeze; that requires an external heartbeat/dead-man monitor.

## 0.1.8

- Adds hysteresis and sustain/recovery timing so health does not oscillate between healthy and warning around a single event-rate threshold.
- Adds a separate **Observed / Observér** state: high telemetry volume without measurable CPU/API/I/O/Recorder impact is no longer automatically treated as a fault.
- Adds graded signal cards and badges for expected/stable, observe, warning and critical findings.
- Uses Home Assistant Entity Registry metadata to identify the owning integration/platform where available instead of relying only on entity-name heuristics.
- Distinguishes battery/sleepy-device availability transitions from non-battery flapping in live health assessment. Occasional battery availability changes are not treated like mains-powered/integration flapping.
- Adds Zigbee2MQTT diagnostic context, including global active/passive availability timeouts and device-specific overrides, when its configuration file is readable.
- Adds sanitized Frigate structural context while deliberately omitting FFmpeg/RTSP/go2rtc input URLs.
- Adds sanitized Recorder context, including backend type and include/exclude counts without exposing `db_url` credentials.
- Adds safe, allowlisted operational context for relevant apps via Supervisor app-info (Zigbee2MQTT, Frigate, Mosquitto/MQTT, UniFi, database-related apps).
- Adds sanitized definitions for the busiest automations to the diagnostic export when `automations.yaml` can be matched through Entity Registry metadata.
- Reworks the diagnostic ZIP as an **AI-first bundle** with `AI-START-HERE.md`, `ai-summary.json`, `file-index.json`, `privacy-manifest.json`, full recent incident context, 24h metrics/churn and sanitized logs.
- Re-sanitizes all exported free-form logs and incident evidence to remove credentials, Authorization headers, URL userinfo/path/query strings and common secret assignments.

## 0.1.7

- Uses physical versioned JS/CSS filenames to avoid stale Home Assistant Ingress assets.
- Adds explicit UI/JS version display.
- Restores direct problem navigation and ranked cause cards on Overview.
