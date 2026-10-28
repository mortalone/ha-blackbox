# HA Black Box – installation, signaler og diagnoseeksport

## Installation

Kopiér mappen `ha_blackbox` til `/addons/ha_blackbox`, genindlæs App Store, og opdatér/installér den lokale app. HA Black Box kræver Home Assistant OS eller en Supervised-installation med Supervisor.

## Signalniveauer

HA Black Box skelner mellem fire niveauer:

- **Normal / forventet**: aktivitet som ikke i sig selv er mistænkelig.
- **Observér**: høj aktivitet, men Core/API/I/O/Recorder følger stadig med uden tydelig påvirkning.
- **Advarsel**: vedvarende unormal aktivitet, flapping eller målbar belastning.
- **Kritisk**: stærke crash-signaler, vedvarende kritiske tærskler, Core/Supervisor-tab, OOM, storagefejl eller tilsvarende.

Event-rate bruger hysterese. Et signal skal være forhøjet i en periode før det aktiveres, og det skal ligge tydeligt under tærsklen i recovery-perioden før det ryddes. Dermed skifter forsiden ikke grøn/gul hvert få sekunder omkring én grænse.

Battery/sleepy-enheder vurderes særskilt. Enkeltstående availability-skift fra batteridrevne Zigbee-enheder er ikke det samme som gentagne eller samtidige flaps fra mains-powered enheder eller en hel integration.

## Relevant konfigurationskontekst

Når filerne er synlige gennem Home Assistants read-only config-mount, indsamles kun diagnostisk relevante felter:

- Zigbee2MQTT: availability active/passive timeout, relevante overrides og enkelte ufarlige driftsindstillinger.
- Frigate: kameraantal, detect/record/snapshot/audio-status, input-antal/roller og detector-type; rå FFmpeg/RTSP/go2rtc-inputs kopieres ikke.
- Recorder: purge/commit/include/exclude-kontekst og database-backend; `db_url` eksporteres aldrig.
- Travle automations: top-automationers triggers/conditions/actions kan medtages sanitiseret, så en AI kan vurdere loops eller for aggressive triggers uden at brugeren manuelt skal finde YAML'en.
- Relevante apps: navn/version/state samt kun allowlistede ikke-hemmelige options. Komplette app-options eksporteres aldrig generisk.

## AI-first diagnosepakke

**Eksportér diagnosepakke** laver en ZIP beregnet til at kunne uploades direkte til en AI. Den indeholder:

- `AI-START-HERE.md` – analyseorden og fortolkningsregler.
- `ai-summary.json` – kompakt status, primære fund, data coverage og vigtigste kandidater.
- `status.json` – aktuelle ressourcer, thresholds og health-state.
- `churn.json` – top entities, flappers, automations, grupper og flap-bølger.
- `metrics-24h.csv` – tidsserie til korrelation før/under/efter fejl.
- `important-logs-24h.txt` – sanitiserede vigtige loglinjer.
- `incidents.json` og `incident-details.json` – historik samt nyere incidents med kontekst/tidslinje.
- `diagnostic-context.json` – sanitiseret Z2M/Frigate/Recorder/app/automation-kontekst.
- `privacy-manifest.json` og `file-index.json`.

Formålet er, at en AI først skal udnytte det, der allerede er i pakken, i stedet for at bede brugeren om at finde en række ekstra settings og logs manuelt.

## Privacy

Eksporten bruger allowlisting og rekursiv redaction. Den fjerner bl.a. passwords, tokens, API keys, Authorization/Bearer credentials, network/private keys, username/credential-felter, Recorder `db_url` og URL path/query/userinfo.

Frigate-konfiguration kopierer aldrig rå RTSP/FFmpeg/go2rtc-inputs. Logs og incident-evidens sanitiseres igen ved eksport, fordi credentials og stream-URL'er kan forekomme inde i fritekst-loglinjer.

Entity IDs og automation IDs beholdes, fordi de normalt er nødvendige for at finde den konkrete støjkilde.

## Kritiske notifikationer

HA Black Box kan varsle gennem to uafhængige spor:

1. **Home Assistant-kanal** (`persistent_notifications` + `notification_service`). Den kan være `persistent_notification.create` eller fx en `notify.mobile_app_*` service. Denne vej kræver, at Home Assistant Core stadig kan modtage servicekald.
2. **Direkte kanal** (`direct_critical_notifications`). Denne sendes direkte fra Black Box-containeren og kræver ikke en HA-automation eller et fungerende Core API. ntfy anbefales på Android; Pushover, Telegram og generisk webhook er fortsat understøttet.

### Android + ntfy

Kritiske incidents sendes som **ntfy priority 5 (MAX/URGENT)**. På Android har ntfy en separat notifikationskanal for hver prioritet, så MAX/URGENT-kanalen kan få sin egen tydelige lyd, vibration og — hvis brugeren ønsker det — tilladelse gennem Forstyr ikke.

Valgfri direkte advarsler kan slås til med `direct_warning_notifications`; de sendes som **priority 4 (HIGH)** og er rate-limited til højst én push pr. advarselskategori pr. time. Standard er `false`, så den kritiske alarmkanal ikke udvandes af almindelige advarsler.

Eksempel i appens Configuration/options:

```yaml
direct_critical_notifications: true
direct_notification_provider: ntfy
direct_warning_notifications: false
ntfy_server: https://ntfy.sh
ntfy_topic: <privat-svært-gætteligt-topic>
ntfy_access_token: ""
ntfy_click_url: ""
```

`ntfy_click_url` er valgfri. Hvis den udfyldes med en HTTP/HTTPS-adresse, bliver den ntfy's click action. Brug kun en adresse der faktisk kan nås fra telefonen; ellers lad feltet være tomt. Topic, token og click URL behandles som følsomme værdier og medsendes ikke i AI-diagnosepakken.

Under **System → Kritiske notifikationer** findes en Android-guide, en lokal generator til et stærkt privat topic og knappen **Send PRIORITET 5-test**. Topic-forslaget genereres kun i browseren; det sendes ikke til ntfy, før brugeren selv gemmer det i app-konfigurationen og sender en test/alarm.

### Begrænsning ved komplet host-nedbrud

En lokal app kan ikke sende noget, hvis hele Home Assistant-hostens kernel/container-runtime fryser, maskinen mister strøm, eller netværket fra hosten forsvinder helt. Hvis dette også skal opdages, kræves en ekstern dead-man/heartbeat-monitor på en anden maskine eller cloud-tjeneste. Black Box' direkte kanal dækker derimod det vigtige mellemtrin, hvor Core eller Supervisor er i problemer, mens Black Box-containeren og netværket stadig lever.


## Event-stream recovery (0.1.11)
Black Box genforbinder automatisk Home Assistant event-WebSocket. Under **System → Black Box** vises sidste event, sidste forbindelse, seneste fejl og reconnect-tæller. Brug **Genforbind event-stream** til at tvinge en frisk subscription, hvis live-data ikke vender tilbage. Et event-stream-udfald betyder begrænset datadækning, ikke nødvendigvis at Home Assistant Core er nede.


## Live event-data og datadækning

Black Box skelner mellem Home Assistant-health og sin egen datadækning. Hvis Core og Supervisor svarer, men Black Box ikke kan modtage live-events, er det **ikke** i sig selv et tegn på at Home Assistant er usundt. Det betyder, at state-/automation-/flapmålinger er ufuldstændige.

Black Box foretrækker Supervisor-proxyens Home Assistant WebSocket (`/core/websocket`). Efter gentagne fejl skifter den automatisk til Supervisor event-stream (`/core/api/stream`, SSE). En fungerende SSE fallback regnes som fuld live-datadækning; der kræves ingen brugerhandling.

Hvis begge transports fejler, viser Overblik den konkrete seneste fejl, hvilket forbindelsesstadie den opstod i, og en anbefalet næste handling. System-fanen viser yderligere tekniske detaljer.


## Genveje fra diagnosefund

På Overblik og under **Støj & automations** viser Black Box, hvor muligt, direkte genveje til:

- **Åbn enhed** → `/config/devices/device/<device_id>`
- **Åbn integration** → integrationssiden for den registry-ejer, der leverer entity'en
- **Åbn automation** → Home Assistants automation-editor/show-side

Knappen **Vis i analyse** åbner først et `Valgt fund`-kort med præcis det fund, der blev klikket på. **Find i tabellen** forsøger derefter at fremhæve den konkrete række.

En fungerende SSE event-fallback er ikke en brugerfejl og fylder derfor ikke på Overblik; transporttypen kan ses på HA API-kortet og under System.

En Supervisor-watchdog-genstart af en enkelt add-on behandles som warning-hændelse. Det er først Core/Supervisor/host-fejl eller andre systemiske signaler, der klassificeres som kritiske og kan udløse priority-5-alarm.
