# HA Black Box

Independent Home Assistant flight recorder and incident diagnostics with an AI-oriented, privacy-sanitized diagnostic export and optional direct critical notifications that do not depend on Home Assistant automations. See `DOCS.md`.


## Android critical alerts

For resilient phone alerts, ntfy is the recommended direct provider. Critical incidents use ntfy priority 5 (MAX/URGENT) directly from the Black Box container, so they do not depend on a Home Assistant automation or Core service call. Optional warning pushes use priority 4 and are disabled by default. Configure and test this under **System → Kritiske notifikationer**. Topic/token/click URL are excluded from AI exports.

- Live event-overvågning med automatisk WebSocket → SSE fallback og separat datadækningsstatus.

## Direkte navigation

Når Entity Registry-metadata er tilgængelig, viser Black Box direkte genveje til Home Assistants enhedsside og integrationsside. Travle automations kan åbnes direkte i automationseditoren. Registry-metadata kan læses fra den read-only `.storage/core.entity_registry`, så genvejene også kan fungere under SSE event fallback. En fungerende SSE fallback er kun teknisk information og vises ikke som en fremtrædende fejl på Overblik.
