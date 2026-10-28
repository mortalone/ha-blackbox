"use strict";

let statusData = null;
let historySamples = [];
let activeTab = "overview";
const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));

function fmtBytes(bytes) {
  if (bytes === null || bytes === undefined) return "—";
  const units = ["B","KB","MB","GB","TB"];
  let n = Number(bytes), i = 0;
  while (Math.abs(n) >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i < 2 ? 0 : 1)} ${units[i]}`;
}
function fmtPct(v) { return v === null || v === undefined ? "—" : `${Number(v).toFixed(1)}%`; }
function fmtNum(v, digits=0) { return v === null || v === undefined ? "—" : Number(v).toFixed(digits); }
function fmtDate(ts) { return ts ? new Date(ts * 1000).toLocaleString("da-DK", {dateStyle:"short", timeStyle:"medium"}) : "—"; }
function fmtDuration(seconds) {
  if (!Number.isFinite(seconds)) return "—";
  const d = Math.floor(seconds / 86400), h = Math.floor((seconds % 86400) / 3600), m = Math.floor((seconds % 3600) / 60);
  return d ? `${d}d ${h}t` : h ? `${h}t ${m}m` : `${m}m`;
}
async function api(path, options) {
  const r = await fetch(path, {...(options || {}), cache: "no-store"});
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return await r.json();
}

function showTab(tab, anchorId=null, focus=null) {
  activeTab = tab;
  document.querySelectorAll(".tab").forEach(x => x.classList.toggle("active", x.dataset.tab === tab));
  document.querySelectorAll(".tab-page").forEach(x => x.classList.toggle("active", x.id === `tab-${tab}`));
  if (tab === "incidents") loadIncidents();
  if (tab === "logs") loadLogs();
  if (tab === "overview") requestAnimationFrame(renderChart);
  requestAnimationFrame(() => {
    if (focus && tab === "churn") {
      renderFocusDetail(focus);
      $("focus-detail")?.scrollIntoView({behavior:"smooth", block:"start"});
      return;
    }
    if (anchorId) $(anchorId)?.scrollIntoView({behavior:"smooth", block:"start"});
  });
}

function firstKey(obj) { return Object.keys(obj || {})[0] || null; }
function integrationHref(item) {
  const platform = item?.source_platform || firstKey(item?.platforms);
  if (!platform) return null;
  const entry = item?.config_entry_id || firstKey(item?.config_entries);
  const base = `/config/integrations/integration/${encodeURIComponent(platform)}`;
  return entry ? `${base}#config_entry=${encodeURIComponent(entry)}` : base;
}
function deviceHref(item) { return item?.device_id ? `/config/devices/device/${encodeURIComponent(item.device_id)}` : null; }
function automationHref(item) {
  const id = item?.automation_id;
  if (id) return `/config/automation/edit/${encodeURIComponent(id)}`;
  return item?.entity_id ? `/config/automation/show/${encodeURIComponent(item.entity_id)}` : null;
}
function navLinks(item, kind="entity") {
  const links=[];
  if (kind === "automation") {
    const href=automationHref(item);
    if (href) links.push(`<a class="button ha-link" target="_top" href="${esc(href)}">Åbn automation</a>`);
  } else {
    const device=deviceHref(item);
    const integration=integrationHref(item);
    if (device) links.push(`<a class="button ha-link" target="_top" href="${esc(device)}">Åbn enhed</a>`);
    if (integration) links.push(`<a class="button ha-link" target="_top" href="${esc(integration)}">Åbn integration</a>`);
  }
  return links.join("");
}
function rowKey(row) { return String(row?.entity_id || row?.label || row?.key || ""); }
function findAndHighlightRow(anchorId, key) {
  if (!anchorId || !key) return false;
  const root=$(anchorId); if (!root) return false;
  const row=[...root.querySelectorAll("tr[data-row-key]")].find(x=>x.dataset.rowKey===String(key));
  if (!row) return false;
  document.querySelectorAll(".focus-highlight").forEach(x=>x.classList.remove("focus-highlight"));
  row.classList.add("focus-highlight");
  row.scrollIntoView({behavior:"smooth", block:"center"});
  setTimeout(()=>row.classList.remove("focus-highlight"),5000);
  return true;
}
function renderFocusDetail(focus) {
  const el=$("focus-detail"); if(!el) return;
  el.classList.remove("hidden");
  const item=focus.item||{};
  const links=navLinks(item, focus.navKind || "entity");
  el.innerHTML=`<div class="panel-head"><div><div class="eyebrow">Valgt fund</div><h2>${esc(focus.value||focus.kind||"Detaljer")}</h2><p>${esc(focus.detail||"")}</p></div><div class="focus-actions">${links}<button class="button find-row">Find i tabellen</button></div></div><div class="focus-meta">${focus.kind?`<span>${esc(focus.kind)}</span>`:""}${item.source_platform?`<span>Integration: ${esc(item.source_platform)}</span>`:""}${item.device_id?`<span>Enhed knyttet</span>`:""}</div>`;
  el.querySelector(".find-row")?.addEventListener("click",()=>{
    if (!findAndHighlightRow(focus.anchor, focus.rowKey)) $(focus.anchor)?.scrollIntoView({behavior:"smooth",block:"start"});
  });
}

function warningTarget(category) {
  const map = {
    event_storm:["churn","problem-overview"], event_activity:["churn","problem-overview"], entity_flapping:["churn","flap-groups"],
    recorder_growth:["recorder","recorder-risk"],
    io_pressure:["recorder","recorder-risk"],
    disk_space:["system","host-info"], disk_full:["system","host-info"],
    memory_pressure:["system","host-info"], memory_exhaustion:["system","host-info"],
    cpu_saturation:["system","host-info"], temperature:["system","host-info"], disk_wear:["system","host-info"],
    supervisor_issues:["system","resolution-info"], supervisor_unresponsive:["system","host-info"],
    api_latency:["system","host-info"], core_unresponsive:["incidents","incident-list"],
    event_monitor_unavailable:["system","blackbox-info"]
  };
  return map[category] || ["incidents","incident-list"];
}

function bindTabs() {
  document.querySelectorAll(".tab").forEach(btn => btn.addEventListener("click", () => showTab(btn.dataset.tab)));
  $("chart-metric").addEventListener("change", renderChart);
  $("refresh-incidents").addEventListener("click", loadIncidents);
  $("refresh-logs").addEventListener("click", loadLogs);
  $("test-direct-notification")?.addEventListener("click", testDirectNotification);
  $("reconnect-event-stream")?.addEventListener("click", reconnectEventStream);
  $("generate-ntfy-topic")?.addEventListener("click", generateNtfyTopic);
  $("copy-ntfy-topic")?.addEventListener("click", copyNtfyTopic);
  $("log-window").addEventListener("change", loadLogs);
}


async function refreshStatus() {
  try {
    statusData = await api("api/status");
    $("live-dot").classList.add("online");
    $("last-update").textContent = `Opdateret ${new Date().toLocaleTimeString("da-DK")}`;
    renderStatus();
  } catch (err) {
    $("live-dot").classList.remove("online");
    $("last-update").textContent = "Black Box UI kan ikke hente status";
    console.error(err);
  }
}

async function refreshHistory() {
  try {
    const data = await api("api/metrics?minutes=60");
    historySamples = data.samples || [];
    renderChart();
  } catch (err) { console.error(err); }
}

function renderStatus() {
  if (!statusData) return;
  const h = statusData.health || {};
  const c = statusData.current || {};
  const banner = $("health-banner");
  banner.className = `health-banner ${h.health || "loading"}`;
  const names = {healthy:"Systemet ser normalt ud", observed:"Høj aktivitet – ingen tydelig systempåvirkning", degraded:"Noget kræver opmærksomhed", critical:"Kritisk hændelse registreret"};
  $("health-title").textContent = names[h.health] || "Indsamler data";
  $("health-score").textContent = h.health === "healthy" ? "NORMAL" : h.health === "observed" ? "OBSERVÉR" : h.health === "degraded" ? "ADVARSEL" : h.health === "critical" ? "KRITISK" : "—";
  $("health-detail").textContent = h.active_incidents?.length ? `${h.active_incidents.length} aktiv(e) incident(er)` : h.warnings?.length ? `${h.warnings.length} aktiv(e) advarsel/advarsler` : h.advisories?.length ? `${h.advisories.length} observation(er) uden målbar kritisk påvirkning` : "Ingen aktuelle faresignaler.";

  const attention = $("attention");
  const healthAction = $("health-action");
  const notices = h.warnings?.length ? h.warnings : (h.advisories || []);
  attention.classList.toggle("info", h.health === "observed");
  if (notices.length) {
    attention.classList.remove("hidden");
    attention.innerHTML = notices.map((w, idx) => {
      const [tab, anchor] = warningTarget(w.category);
      return `<div class="attention-item"><div><strong>${idx===0?"Hold øje med: ":""}${esc(w.title)}</strong><span> — ${esc(w.detail)}</span></div><button class="button warning-action" data-tab="${esc(tab)}" data-anchor="${esc(anchor)}">Se årsager</button></div>`;
    }).join("");
    attention.querySelectorAll(".warning-action").forEach(btn => btn.addEventListener("click", (e) => { e.stopPropagation(); showTab(btn.dataset.tab, btn.dataset.anchor); }));
    attention.querySelectorAll(".attention-item").forEach(row => row.addEventListener("click", () => {
      const btn = row.querySelector(".warning-action");
      if (btn) showTab(btn.dataset.tab, btn.dataset.anchor);
    }));
    const [tab, anchor] = warningTarget(notices[0].category);
    healthAction.classList.remove("hidden");
    healthAction.onclick = () => showTab(tab, anchor);
  } else if (h.active_incidents?.length) {
    attention.classList.add("hidden");
    healthAction.classList.remove("hidden");
    healthAction.onclick = () => showTab("incidents", "incident-list");
  } else {
    attention.classList.add("hidden");
    healthAction.classList.add("hidden");
    healthAction.onclick = null;
  }

  renderMonitoring(statusData);

  $("m-cpu").textContent = fmtPct(c.core_cpu);
  $("m-cpu-sub").textContent = c.psi_cpu == null ? "PSI ikke tilgængelig" : `CPU PSI ${fmtPct(c.psi_cpu)}`;
  $("m-ram").textContent = fmtPct(c.core_memory_percent);
  $("m-ram-sub").textContent = fmtBytes(c.core_memory_usage);
  $("m-disk").textContent = c.disk_free_gb == null ? "—" : `${Number(c.disk_free_gb).toFixed(1)} GB`;
  $("m-disk-sub").textContent = c.disk_used_percent == null ? "—" : `${Number(c.disk_used_percent).toFixed(1)}% brugt`;
  $("m-api").textContent = c.api_ok === false ? "OFFLINE" : c.api_latency_ms == null ? "—" : `${Number(c.api_latency_ms).toFixed(0)} ms`;
  const em = statusData.event_monitor || {};
  const transportLabel = em.transport === "websocket" ? "WebSocket" : em.transport === "sse" ? "SSE" : "ingen live-stream";
  $("m-api-sub").textContent = statusData.event_websocket_connected ? `live-data OK · ${transportLabel}` : "HA API OK · Black Box live-data mangler";
  $("m-events").textContent = c.state_changes_per_minute == null ? "—" : Number(c.state_changes_per_minute).toFixed(0);
  $("m-recorder").textContent = fmtBytes(c.recorder_bytes);
  $("m-recorder-sub").textContent = c.recorder_growth_mb_hour == null ? "vækst beregnes" : `${Number(c.recorder_growth_mb_hour).toFixed(0)} MB/time`;

  renderActiveProblem(statusData);
  renderLastIncident(statusData.last_incident);
  renderCompactList($("top-now"), statusData.top_entities_hour || [], "entity_id", "changes", " ændr./t");
  renderRecorder(c);
  renderChurn(statusData);
  renderSystem(statusData);
}

function monitoringAdvice(em) {
  const reason = String(em.last_disconnect_reason || "");
  const stage = String(em.last_failure_stage || "");
  const low = `${stage} ${reason}`.toLowerCase();
  if (/401|unauthor|auth_invalid|auth failed/.test(low)) return "Black Box bliver afvist ved godkendelse. Opdatér/rebuild add-on'en først; hvis det fortsætter, kontrollér at homeassistant_api er tilladt for add-on'en.";
  if (/403|forbidden|permission/.test(low)) return "Black Box mangler adgang til event-API'et. Kontrollér add-on-rettighederne; du behøver ikke ændre dine automations eller enheder.";
  if (/404|not found/.test(low)) return "Den forventede interne event-rute blev ikke fundet. Det peger på en Black Box/HA-kompatibilitetsfejl, ikke på dine entities.";
  if (/subscription|subscribe/.test(low)) return "WebSocket-forbindelsen når Home Assistant, men en event-subscription bliver afvist. Black Box prøver automatisk SSE-fallback.";
  if (/timeout|timed out/.test(low)) return "Forbindelsen svarer ikke hurtigt nok. Black Box prøver automatisk fallback; hvis både WebSocket og SSE fejler, bør Supervisor/Core-log undersøges.";
  return "Black Box prøver automatisk igen og skifter til SSE-fallback efter gentagne WebSocket-fejl. Hvis fallback også fejler, er den konkrete fejl vist nedenfor.";
}

function renderMonitoring(data) {
  const el = $("monitoring-notice");
  if (!el) return;
  const issues = data.health?.monitoring_issues || [];
  const em = data.event_monitor || {};
  const issue = issues[0];
  if (!issue) { el.classList.add("hidden"); el.innerHTML=""; return; }
  const isFallback = issue.category === "event_monitor_fallback";
  // A working SSE fallback is a transport detail, not a user-facing problem.
  // Keep it visible under System/HA API, but do not spend overview attention on
  // something that explicitly requires no action.
  if (isFallback && issue.action_required === false) {
    el.classList.add("hidden");
    el.innerHTML = "";
    return;
  }
  el.classList.remove("hidden");
  el.className = `monitoring-notice ${issue.level === "warning" ? "warning" : "observe"}`;
  const outage = Number(em.outage_seconds || 0);
  const duration = outage ? fmtDuration(outage) : "kort tid";
  const error = em.last_disconnect_reason || issue.last_error || "Ingen konkret fejltekst modtaget endnu";
  const stage = em.last_failure_stage || issue.failure_stage || "ukendt fase";
  el.innerHTML = `<div class="monitoring-icon">!</div><div class="monitoring-copy"><strong>Black Box mangler live-data – Home Assistant er ikke meldt usund</strong><span><b>Hvad betyder det?</b> Core API svarer, så dette er et problem med Black Box' dataindsamling, ikke i sig selv et Home Assistant-nedbrud. Live state-/automation-/flapmålinger er ufuldstændige.</span><span><b>Er det normalt?</b> Nej, ikke hvis det varer ved. Black Box skal normalt have enten WebSocket eller SSE-fallback forbundet.</span><span><b>Hvad gør du?</b> ${esc(monitoringAdvice(em))}</span><span class="tech-line"><b>Aktuelt:</b> afbrudt ${esc(duration)} · fase: ${esc(stage)} · fejl: ${esc(error)}</span></div><div class="monitoring-actions"><button class="button reconnect-now">Test/genopret overvågning</button><button class="button monitor-details">Vis teknik</button></div>`;
  el.querySelector(".reconnect-now")?.addEventListener("click", reconnectEventStream);
  el.querySelector(".monitor-details")?.addEventListener("click",()=>showTab("system","blackbox-info"));
}

function renderActiveProblem(data) {
  const el = $("active-problem"), body = $("active-problem-body"), title = $("active-problem-title"), explain = $("active-problem-explain"), main = $("active-problem-main-action");
  const warning = data.health?.warnings?.[0] || data.health?.advisories?.[0];
  if (!warning) { el.classList.add("hidden"); return; }
  el.classList.remove("hidden");
  title.textContent = warning.title || "Aktuelt problem";
  const [targetTab, targetAnchor] = warningTarget(warning.category);
  main.onclick = () => showTab(targetTab, targetAnchor);

  if (!["event_storm","event_activity","entity_flapping"].includes(warning.category)) {
    explain.textContent = warning.detail || "Black Box har registreret en aktiv advarsel.";
    const isEventStream = warning.category === "event_monitor_unavailable";
    const em = data.event_monitor || {};
    const lastEvent = em.last_event_ts ? fmtDate(em.last_event_ts) : "Ingen event modtaget siden denne opstart";
    const outage = Number(em.outage_seconds || 0);
    const outageText = outage >= 60 ? `${Math.max(1, Math.floor(outage/60))} min` : `${Math.max(0, Math.floor(outage))} sek.`;
    body.innerHTML = `<div class="cause-card primary ${isEventStream ? "event-stream-card" : ""}"><div class="cause-rank">${isEventStream ? "↻" : "!"}</div><div class="cause-copy"><small>${isEventStream ? "Datadækning" : "Registreret signal"}</small><strong>${esc(warning.detail || warning.title)}</strong><span>${isEventStream ? `Sidste event: ${esc(lastEvent)} · afbrudt i ${esc(outageText)} · ${Number(em.reconnect_attempts||0)} genforbindelsesforsøg siden opstart.` : "Brug knappen for at åbne den relevante diagnosevisning."}</span></div><div class="cause-actions">${isEventStream ? `<button class="button reconnect-now">Forbind igen nu</button>` : ""}<button class="button cause-action" data-tab="${esc(targetTab)}" data-anchor="${esc(targetAnchor)}">Se årsag og evidens</button></div></div>`;
    body.querySelector(".cause-action")?.addEventListener("click", e => showTab(e.currentTarget.dataset.tab, e.currentTarget.dataset.anchor));
    body.querySelector(".reconnect-now")?.addEventListener("click", reconnectEventStream);
    return;
  }

  const current = data.current || {}, analysis = data.churn_analysis || {};
  const rate = Number(current.state_changes_per_minute || 0);
  const topEntity = (data.top_entities_hour || [])[0];
  const topAutomation = (data.top_automations_hour || [])[0];
  const topGroup = (analysis.activity_groups_hour || analysis.activity_groups || [])[0];
  const flapSource = analysis.live_flap_source || analysis.suspected_flap_source_hour || analysis.suspected_flap_source;
  const flapper = (data.top_flappers_hour || data.top_flappers_day || [])[0];

  const unavailableRate = Number(current.unavailable_per_minute || 0);
  const impact = assessImpact(data);
  explain.textContent = `${rate.toLocaleString("da-DK")} state changes/min · ${unavailableRate.toLocaleString("da-DK")} unavailable/unknown/min. Black Box skelner mellem forventet aktivitet, afvigelser og målbar systempåvirkning.`;
  const cards = [];

  cards.push({
    kind:"Systempåvirkning lige nu", value:impact.title, detail:impact.detail,
    tab:impact.tab, anchor:impact.anchor, level:impact.level, badge:impact.badge
  });
  if (flapSource) {
    const battery = flapSource.group?.key === "battery";
    const flaps = Number(flapSource.total_flaps || flapSource.group?.unavailable || 0);
    cards.push({
      kind:`Fælles flap-kilde · ${Number(flapSource.confidence||0)}%`, value:(flapSource.title||"").replace(/^Sandsynlig fælles kilde:\s*/,"").replace(/^Fælles kilde:\s*/,""),
      detail:flapSource.detail || "Flere entities går unavailable/unknown samtidigt.",
      tab:"churn", anchor:"flap-groups", rowKey:flapSource.group?.label, item:flapSource.group, navKind:"entity", level:battery && flaps < 20 ? "observe" : "warning", badge:battery && flaps < 20 ? "KAN VÆRE FORVENTET" : "AFVIGENDE"
    });
  }
  if (topGroup) cards.push({
    kind:"Gruppe med mest aktivitet", value:topGroup.label,
    detail:`${Number(topGroup.changes||0).toLocaleString("da-DK")} ændringer fra ${Number(topGroup.entities||0).toLocaleString("da-DK")} entities${topGroup.unavailable?` · ${Number(topGroup.unavailable).toLocaleString("da-DK")} flaps`:""}. ${formatPlatforms(topGroup.platforms)}`,
    tab:"churn", anchor:"activity-groups", rowKey:topGroup.label, item:topGroup, navKind:"entity", level:Number(topGroup.unavailable||0)>100 ? "warning" : "observe", badge:Number(topGroup.unavailable||0)>100 ? "AFVIGENDE" : "HØJ AKTIVITET"
  });
  if (topEntity) {
    const entityLevel = topEntity.battery_device && Number(topEntity.unavailable||0) <= 2 ? "normal" : Number(topEntity.unavailable||0) >= 10 ? "warning" : "observe";
    cards.push({
      kind:"Mest aktive enkelt-entity", value:topEntity.entity_id,
      detail:`${Number(topEntity.changes||0).toLocaleString("da-DK")} state changes den seneste time${topEntity.unavailable?` · ${Number(topEntity.unavailable).toLocaleString("da-DK")} unavailable/unknown`:""}${topEntity.source_platform?` · integration: ${topEntity.source_platform}`:""}.`,
      tab:"churn", anchor:"noisy-entities", rowKey:topEntity.entity_id, item:topEntity, navKind:"entity", level:entityLevel, badge:entityLevel==="normal"?"FORVENTELIG":entityLevel==="warning"?"AFVIGENDE":"OBSERVÉR"
    });
  }
  if (topAutomation) {
    const tr = Number(topAutomation.triggers||0);
    const level = tr >= 300 ? "warning" : tr >= 60 ? "observe" : "normal";
    cards.push({
      kind:"Mest aktive automation", value:topAutomation.entity_id,
      detail:`${tr.toLocaleString("da-DK")} triggers den seneste time. ${tr >= 300 ? "Meget høj trigger-rate; kontrollér trigger/loop." : tr >= 60 ? "Mindst én trigger/minut. Det kan være tilsigtet, men bør vurderes." : "Ikke mistænkelig alene."}`,
      tab:"churn", anchor:"noisy-automations", rowKey:topAutomation.entity_id, item:topAutomation, navKind:"automation", level, badge:level==="warning"?"AFVIGENDE":level==="observe"?"OBSERVÉR":"OK"
    });
  }

  const z2m = data.diagnostic_context?.zigbee2mqtt;
  const zFinding = (z2m?.findings || []).find(x => x.level === "warning");
  if (zFinding) cards.push({
    kind:"Relevant Zigbee2MQTT-indstilling", value:zFinding.title, detail:zFinding.detail,
    tab:"churn", anchor:"config-context", level:"warning", badge:"KONFIGURATION"
  });

  const visibleCards=cards.slice(0,6);
  body.innerHTML = `<div class="cause-list">${visibleCards.map((c,i)=>`<div class="cause-card ${esc(c.level||"observe")}"><div class="cause-rank">${i+1}</div><div class="cause-copy"><div class="cause-meta"><small>${esc(c.kind)}</small><span class="signal-badge ${esc(c.level||"observe")}">${esc(c.badge||"OBSERVÉR")}</span></div><strong>${esc(c.value)}</strong><span>${esc(c.detail)}</span></div><div class="cause-actions">${navLinks(c.item||{},c.navKind||"entity")}<button class="button cause-action" data-index="${i}">Vis i analyse</button></div></div>`).join("")}</div>`;
  body.querySelectorAll(".cause-action").forEach(btn => btn.addEventListener("click", () => {
    const c=visibleCards[Number(btn.dataset.index)];
    if (!c) return;
    showTab(c.tab, c.anchor, c.tab==="churn" ? c : null);
  }));

}

function formatPlatforms(platforms) {
  const entries=Object.entries(platforms||{});
  if (!entries.length) return "";
  return `Registry: ${entries.slice(0,3).map(([k,v])=>`${k} (${v})`).join(" · ")}.`;
}

function assessImpact(data) {
  const c=data.current||{}, s=data.settings||{};
  const activeIncidents=data.health?.active_incidents||[];
  if (activeIncidents.some(x=>x.severity==="critical")) return {level:"critical",badge:"KRITISK",title:"Kritisk påvirkning registreret",detail:"Der er en aktiv kritisk incident. Åbn Incidenter for tidslinje og evidens.",tab:"incidents",anchor:"incident-list"};
  if (activeIncidents.length) return {level:"warning",badge:"HÆNDELSE",title:"En komponenthændelse er registreret",detail:"Der er en aktiv warning-incident, men Black Box har ikke klassificeret hele Home Assistant-systemet som kritisk.",tab:"incidents",anchor:"incident-list"};
  const critical=[];
  if (c.api_ok===false) critical.push("HA API svarer ikke");
  if ((c.psi_io||0)>=25) critical.push(`I/O PSI ${Number(c.psi_io).toFixed(1)}%`);
  if (c.recorder_growth_mb_hour!=null && c.recorder_growth_mb_hour >= (s.recorder_growth_critical_mb_per_hour||1000)) critical.push(`Recorder +${Number(c.recorder_growth_mb_hour).toFixed(0)} MB/time`);
  if (critical.length) return {level:"critical",badge:"KRITISK",title:"Systemet er målbar påvirket",detail:critical.join(" · "),tab:"recorder",anchor:"recorder-risk"};
  const warning=[];
  if ((c.psi_io||0)>=10) warning.push(`I/O PSI ${Number(c.psi_io).toFixed(1)}%`);
  if (c.api_latency_ms!=null && c.api_latency_ms >= (s.api_latency_warning_ms||1000)) warning.push(`API ${Number(c.api_latency_ms).toFixed(0)} ms`);
  if (c.recorder_growth_mb_hour!=null && c.recorder_growth_mb_hour >= (s.recorder_growth_warning_mb_per_hour||250)) warning.push(`Recorder +${Number(c.recorder_growth_mb_hour).toFixed(0)} MB/time`);
  if ((c.core_cpu||0)>=(s.cpu_warning_percent||90)) warning.push(`Core CPU ${Number(c.core_cpu).toFixed(0)}%`);
  if (warning.length) return {level:"warning",badge:"PÅVIRKNING",title:"Der er målbar belastning",detail:warning.join(" · "),tab:"recorder",anchor:"recorder-risk"};
  return {level:"normal",badge:"STABILT",title:"Ingen tydelig performancepåvirkning",detail:`Core CPU ${fmtPct(c.core_cpu)} · HA API ${c.api_latency_ms==null?"—":Number(c.api_latency_ms).toFixed(0)+" ms"} · I/O PSI ${fmtPct(c.psi_io)} · Recorder ${c.recorder_growth_mb_hour==null?"vækst beregnes":Number(c.recorder_growth_mb_hour).toFixed(0)+" MB/time"}.`,tab:"system",anchor:"host-info"};
}

function statusLabel(status) {
  return status === "open" ? "Aktiv" : status === "closed" ? "Afsluttet" : status === "ignored" ? "Ignoreret" : status;
}

function renderLastIncident(item) {
  const el = $("last-incident");
  if (!item) { el.className = "empty"; el.textContent = "Ingen incidenter endnu."; return; }
  el.className = "";
  el.innerHTML = `<div class="row"><div><strong>${esc(item.title)}</strong><div class="muted">${fmtDate(item.start_ts)} · ${esc(statusLabel(item.status))}</div></div><div class="value">${item.confidence}%</div></div><p>${esc(item.summary)}</p>`;
}

function renderCompactList(el, items, nameKey, valueKey, suffix="") {
  if (!items?.length) { el.innerHTML = `<div class="empty">Ingen data endnu.</div>`; return; }
  const max = Math.max(...items.map(x => Number(x[valueKey]) || 0), 1);
  el.innerHTML = items.map(x => `<div class="row compact-nav-row"><div class="name">${esc(x[nameKey])}<div class="bar"><i style="width:${Math.max(2,(Number(x[valueKey])||0)/max*100)}%"></i></div><div class="compact-links">${navLinks(x,"entity")}</div></div><div class="value">${esc(x[valueKey])}${esc(suffix)}</div></div>`).join("");
}

function renderChart() {
  if (activeTab !== "overview") return;
  const canvas = $("history-chart"), empty = $("chart-empty");
  const field = $("chart-metric").value;
  const points = historySamples.filter(s => s[field] !== null && s[field] !== undefined).map(s => ({x:s.ts, y:Number(s[field])}));
  if (points.length < 2) { canvas.classList.add("hidden"); empty.classList.remove("hidden"); return; }
  canvas.classList.remove("hidden"); empty.classList.add("hidden");
  const dpr = window.devicePixelRatio || 1, width = canvas.clientWidth || 900, height = 190;
  canvas.width = width * dpr; canvas.height = height * dpr;
  const ctx = canvas.getContext("2d"); ctx.scale(dpr,dpr); ctx.clearRect(0,0,width,height);
  const css = getComputedStyle(document.documentElement), border = css.getPropertyValue("--border"), line = css.getPropertyValue("--blue"), muted = css.getPropertyValue("--muted");
  const pad = {l:46,r:14,t:10,b:26};
  let min = Math.min(...points.map(p=>p.y)), max = Math.max(...points.map(p=>p.y));
  if (min === max) { min -= 1; max += 1; }
  const x0 = points[0].x, x1 = points[points.length-1].x || x0+1;
  ctx.strokeStyle = border; ctx.lineWidth = 1; ctx.fillStyle = muted; ctx.font = "11px system-ui";
  for (let i=0;i<=4;i++) { const y=pad.t+(height-pad.t-pad.b)*i/4; ctx.beginPath(); ctx.moveTo(pad.l,y); ctx.lineTo(width-pad.r,y); ctx.stroke(); const v=max-(max-min)*i/4; ctx.fillText(formatAxis(field,v),4,y+4); }
  ctx.strokeStyle = line; ctx.lineWidth = 2; ctx.beginPath();
  points.forEach((p,i)=>{ const x=pad.l+(p.x-x0)/(x1-x0)*(width-pad.l-pad.r); const y=pad.t+(max-p.y)/(max-min)*(height-pad.t-pad.b); i?ctx.lineTo(x,y):ctx.moveTo(x,y); }); ctx.stroke();
  ctx.fillStyle = muted; ctx.fillText(new Date(x0*1000).toLocaleTimeString("da-DK",{hour:"2-digit",minute:"2-digit"}),pad.l,height-6); const end=new Date(x1*1000).toLocaleTimeString("da-DK",{hour:"2-digit",minute:"2-digit"}); ctx.fillText(end,width-pad.r-36,height-6);
}
function formatAxis(field,v) { if (["core_cpu","core_memory_percent","psi_io"].includes(field)) return `${v.toFixed(0)}%`; if (field==="api_latency_ms") return `${v.toFixed(0)}ms`; if (field==="recorder_growth_mb_hour") return `${v.toFixed(0)}MB/h`; return v.toFixed(0); }

async function loadIncidents() {
  try {
    const data = await api("api/incidents?limit=100"), el=$("incident-list");
    if (!data.incidents?.length) { el.innerHTML=`<div class="empty">Ingen incidenter endnu.</div>`; return; }
    el.innerHTML = data.incidents.map(i => `<div class="incident-item" data-id="${esc(i.id)}"><div>${fmtDate(i.start_ts)}</div><div><strong>${esc(i.title)}</strong><div class="muted">${esc(i.category)} · ${esc(statusLabel(i.status))}</div></div><div class="confidence">${i.confidence}%</div><div>›</div></div>`).join("");
    el.querySelectorAll(".incident-item").forEach(row => row.addEventListener("click",()=>showIncident(row.dataset.id)));
  } catch(err) { $("incident-list").innerHTML=`<div class="empty">Kunne ikke hente incidenter.</div>`; }
}
async function showIncident(id) {
  const item = await api(`api/incidents/${encodeURIComponent(id)}`), el=$("incident-detail");
  const ctx=item.context||{}, candidates=ctx.cause_candidates||[];
  el.classList.remove("hidden");
  el.innerHTML = `<div class="panel-head"><div><h2>${esc(item.title)}</h2><p>${fmtDate(item.start_ts)} → ${item.end_ts?fmtDate(item.end_ts):"aktiv"}</p></div><span class="severity ${item.status==='open'?'critical':'closed'}">${esc(statusLabel(item.status))}</span></div>
    <div class="detail-grid"><div class="detail-box"><small>Kategori</small><strong>${esc(item.category)}</strong></div><div class="detail-box"><small>Sikkerhed</small><strong>${item.confidence}%</strong></div><div class="detail-box"><small>Status</small><strong>${esc(statusLabel(item.status))}</strong></div><div class="detail-box"><small>Præ-crash samples</small><strong>${ctx.samples?.length||0}</strong></div></div>
    <h3>Vurdering</h3><p>${esc(item.summary)}</p><h3>Anbefalet næste skridt</h3><p>${esc(item.recommendation)}</p>
    <h3>Evidens</h3>${item.evidence?.length?`<ul class="evidence">${item.evidence.map(e=>`<li>${esc(e)}</li>`).join("")}</ul>`:`<div class="empty">Ingen specifik evidens gemt.</div>`}
    <h3>Sandsynlige årsager</h3><div>${candidates.length?candidates.map(c=>`<div class="candidate"><div><strong>${esc(c.title)}</strong><div class="muted">${esc((c.evidence||[]).join(" · "))}</div></div><div>${c.confidence}%</div></div>`).join(""):`<div class="empty">Ingen rangering.</div>`}</div>
    ${!item.acknowledged?`<p><button id="ack-btn" class="button ghost">Markér som set</button></p>`:""}`;
  $("ack-btn")?.addEventListener("click", async()=>{ await api(`api/incidents/${encodeURIComponent(id)}/ack`,{method:"POST"}); await showIncident(id); await loadIncidents(); });
  el.scrollIntoView({behavior:"smooth",block:"start"});
}

function renderRecorder(c) {
  const r = c.extra?.recorder || {};
  $("r-size").textContent=fmtBytes(r.bytes); $("r-path").textContent=r.configured_path||"—";
  $("r-growth").textContent=r.growth_mb_hour==null?"—":`${Number(r.growth_mb_hour).toFixed(0)} MB/t`;
  $("r-write").textContent=c.core_blk_write_rate==null?"—":`${Number(c.core_blk_write_rate).toFixed(2)} MB/s`;
  $("r-psi").textContent=c.psi_io==null?"—":fmtPct(c.psi_io);
  const parts=r.parts||{}; $("recorder-parts").innerHTML=Object.keys(parts).length?Object.entries(parts).map(([k,v])=>`<div class="row"><div>${esc(k)}</div><div class="value">${fmtBytes(v)}</div></div>`).join(""):`<div class="empty">SQLite Recorder-fil ikke fundet.</div>`;
  const disk=c.extra?.disk_breakdown||{}, children=disk.children||[]; $("disk-breakdown").innerHTML=children.length?children.sort((a,b)=>(b.used_bytes||0)-(a.used_bytes||0)).map(x=>`<div class="row"><div>${esc(x.label||x.id)}</div><div class="value">${fmtBytes(x.used_bytes)}</div></div>`).join(""):`<div class="empty">Diskfordeling indlæses periodisk.</div>`;
  const risks=[]; const s=statusData.settings||{};
  if (r.growth_mb_hour!=null && r.growth_mb_hour>=s.recorder_growth_warning_mb_per_hour) risks.push([r.growth_mb_hour>=s.recorder_growth_critical_mb_per_hour?"crit":"warn",`Recorder vokser ${Number(r.growth_mb_hour).toFixed(0)} MB/time.`]);
  if ((c.state_changes_per_minute||0)>=s.state_changes_warning_per_minute) risks.push(["warn",`${Number(c.state_changes_per_minute).toFixed(0)} state changes/min kan øge Recorder-belastningen.`]);
  if ((c.psi_io||0)>=10) risks.push(["warn",`I/O PSI er ${Number(c.psi_io).toFixed(1)}%; processer venter på storage.`]);
  if (!risks.length) risks.push(["", "Ingen aktuelle Recorder-faresignaler ud fra vækst, event-rate og I/O."]);
  $("recorder-risk").innerHTML=risks.map(([cls,text])=>`<div class="risk ${cls}">${esc(text)}</div>`).join("");
}

function renderChurn(data) {
  const analysis=data.churn_analysis||{}, current=data.current||{}, settings=data.settings||{};
  const source=analysis.live_flap_source||analysis.suspected_flap_source;
  const rate=Number(current.state_changes_per_minute||0);
  const warn=Number(settings.state_changes_warning_per_minute||0), crit=Number(settings.state_changes_critical_per_minute||0);
  const totalFlaps=Number(data.aggregate_day?.unavailable_transitions||0);
  const cards=[
    `<div class="problem-card"><small>Aktuel event-rate</small><strong>${rate.toLocaleString("da-DK")} / min</strong><span>${warn?`Advarsel ved ${warn.toLocaleString("da-DK")}/min · kritisk ved ${crit.toLocaleString("da-DK")}/min`:""}</span></div>`,
    `<div class="problem-card"><small>Unavailable/unknown</small><strong>${totalFlaps.toLocaleString("da-DK")}</strong><span>målt i perioden (op til 24 timer)</span></div>`
  ];
  if (source) cards.push(`<div class="problem-card suspect"><small>Mest sandsynlige fælles flap-kilde · ${source.confidence}%</small><strong>${esc(source.title.replace(/^Sandsynlig fælles kilde:\s*/,""))}</strong><span>${esc(source.detail)}</span></div>`);
  else cards.push(`<div class="problem-card"><small>Fælles flap-kilde</small><strong>Ingen tydelig endnu</strong><span>Black Box har ikke nok unavailable/unknown-data til at gruppere.</span></div>`);
  $("problem-summary").innerHTML=`<div class="problem-grid">${cards.join("")}</div><div class="analysis-note">Black Box bruger Home Assistant Entity Registry, når metadata er tilgængelig; ellers falder den tilbage til samtidighed og entity-navnemønstre.</div>`;

  renderTable($("activity-groups"), analysis.activity_groups||[], [["Gruppe","label"],["Entities","entities","num"],["Ændringer","changes","num"],["Flaps","unavailable","num"]], "entity");
  renderTable($("flap-groups"), analysis.flap_groups||[], [["Gruppe","label"],["Entities","entities","num"],["Flaps","unavailable","num"],["Ændringer","changes","num"]], "entity");

  const bursts=analysis.flap_bursts||[];
  if (!bursts.length) $("flap-bursts").innerHTML=`<div class="empty">Ingen samtidige flap-bølger registreret endnu.</div>`;
  else $("flap-bursts").innerHTML=bursts.slice(0,10).map(b=>{
    const dominant=(b.groups||[])[0];
    const examples=(dominant?.examples||[]).slice(0,4).join(" · ");
    return `<div class="burst-row"><div><strong>${fmtDate(b.bucket)}</strong><div class="muted">${esc(dominant?.label||"Blandet")}${examples?` · ${esc(examples)}`:""}</div></div><div class="burst-metric"><strong>${Number(b.entity_count||0)}</strong><span>entities</span></div><div class="burst-metric"><strong>${Number(b.transitions||0)}</strong><span>flaps</span></div></div>`;
  }).join("");

  renderTable($("noisy-entities"), data.top_entities_day||[], [["Entity","entity_id"],["Ændringer","changes","num"],["Unavailable","unavailable","num"]], "entity");
  renderTable($("top-flappers"), data.top_flappers_day||[], [["Entity","entity_id"],["Flaps","unavailable","num"],["Alle ændringer","changes","num"]], "entity");
  renderTable($("noisy-automations"), data.top_automations_day||[], [["Automation","entity_id"],["Triggers","triggers","num"]], "automation");
  renderTable($("helper-churn"), data.top_helpers_day||[], [["Helper","entity_id"],["Ændringer","changes","num"]], "entity");
  const inv=data.current?.extra?.inventory||{}, unavailable=[...(inv.unavailable||[]).map(entity_id=>({entity_id,state:"unavailable"})),...(inv.unknown||[]).map(entity_id=>({entity_id,state:"unknown"}))];
  if (unavailable.length) {
    $("unavailable-now").innerHTML=`<div class="muted" style="margin-bottom:8px">I alt ${Number(inv.total||unavailable.length)} · domæner: ${esc(Object.entries(inv.by_domain||{}).map(([k,v])=>`${k} ${v}`).join(" · "))}</div>`;
    const temp=document.createElement("div"); renderTable(temp,unavailable.slice(0,60),[["Entity","entity_id"],["Status","state"]]); $("unavailable-now").appendChild(temp);
  } else $("unavailable-now").innerHTML=`<div class="empty">Ingen unavailable/unknown i seneste snapshot.</div>`;
  renderConfigContext(data.diagnostic_context || {});
  const t=data.aggregate_day||{}; $("churn-totals").innerHTML=[["State changes",t.state_changes],["Automation triggers",t.automation_triggers],["Service calls",t.service_calls],["Unavailable transitions",t.unavailable_transitions]].map(([n,v])=>`<div class="stat"><strong>${Number(v||0).toLocaleString("da-DK")}</strong><span>${esc(n)}</span></div>`).join("");
}

function renderConfigContext(ctx) {
  const el=$("config-context"); if(!el) return;
  const z=ctx.zigbee2mqtt||{}, f=ctx.frigate||{};
  const rows=[];
  if (z.found) {
    const av=z.availability||{}, active=(av.active||{}).timeout ?? 10, passive=(av.passive||{}).timeout ?? 1500;
    rows.push(`<div class="config-source"><div class="panel-head"><div><h3>Zigbee2MQTT</h3><p>Kun diagnostisk relevante, allowlistede settings. Secrets eksporteres ikke.</p></div><span class="signal-badge ${av.enabled?"observe":"normal"}">${av.enabled?"AVAILABILITY TIL":"AVAILABILITY FRA"}</span></div><div class="kv-list"><div class="row"><div>Active timeout</div><div class="value">${esc(active)} min</div></div><div class="row"><div>Passive/batteri timeout</div><div class="value">${esc(passive)} min</div></div><div class="row"><div>Device overrides</div><div class="value">${Number((z.availability_overrides||[]).length).toLocaleString("da-DK")}</div></div></div>${(z.findings||[]).map(x=>`<div class="context-finding ${esc(x.level||"info")}"><strong>${esc(x.title)}</strong><span>${esc(x.detail)}</span></div>`).join("")}</div>`);
  } else rows.push(`<div class="config-source"><h3>Zigbee2MQTT</h3><div class="empty">Konfigurationsfilen blev ikke fundet i den read-only Home Assistant config-mount. Runtime/logdata overvåges stadig.</div></div>`);
  if (f.found) rows.push(`<div class="config-source"><div class="panel-head"><div><h3>Frigate</h3><p>${esc(f.privacy||"")}</p></div><span class="signal-badge normal">SIKKER EKSPORT</span></div><div class="muted">${Number(f.camera_count||0)} kamera(er) · ${Number(f.go2rtc_stream_count||0)} go2rtc stream-definitioner. Rå stream-URL'er medsendes ikke.</div></div>`);
  el.innerHTML=rows.join("");
}

function renderTable(el, rows, cols, navKind=null) {
  if (!rows.length) { el.innerHTML=`<div class="empty">Ingen data endnu.</div>`; return; }
  const navHead=navKind?`<th>Genvej</th>`:"";
  el.innerHTML=`<div class="table-wrap"><table><thead><tr>${cols.map(c=>`<th class="${c[2]||''}">${esc(c[0])}</th>`).join("")}${navHead}</tr></thead><tbody>${rows.map(r=>`<tr data-row-key="${esc(rowKey(r))}">${cols.map(c=>`<td class="${c[2]||''}">${esc(r[c[1]])}</td>`).join("")}${navKind?`<td><div class="table-actions">${navLinks(r,navKind)||`<span class="muted">—</span>`}</div></td>`:""}</tr>`).join("")}</tbody></table></div>`;
}

async function loadLogs() {
  const minutes=$("log-window").value;
  try { const data=await api(`api/logs?minutes=${encodeURIComponent(minutes)}&limit=1000`), el=$("log-list"); if(!data.logs?.length){el.innerHTML=`<div class="empty">Ingen vigtige loglinjer i perioden.</div>`;return;} el.innerHTML=data.logs.map(l=>`<div class="log-entry ${esc(l.level)}"><div class="log-meta"><span>${fmtDate(l.ts)}</span><span>${esc(l.source)}</span><span>${esc(l.level).toUpperCase()}</span></div>${esc(l.message)}</div>`).join(""); } catch(e){$("log-list").innerHTML=`<div class="empty">Kunne ikke hente logs.</div>`;}
}

function renderSystem(data) {
  const c=data.current||{}, host=c.extra?.host||{}, local=c.extra?.local_system||{}, bb=data.blackbox_storage||{};
  const memAvail=local.memory_available_bytes==null?"—":fmtBytes(local.memory_available_bytes), swapUsed=(local.swap_total_bytes!=null&&local.swap_free_bytes!=null)?fmtBytes(local.swap_total_bytes-local.swap_free_bytes):"—";
  $("host-info").innerHTML=kv({"OS":host.operating_system,"Kernel":host.kernel,"Hostname":host.hostname,"Boot":host.boot_timestamp?fmtDate(Number(host.boot_timestamp)/1e6):"—","Load 1/5/15":local.load1==null?"—":`${local.load1.toFixed(2)} / ${local.load5.toFixed(2)} / ${local.load15.toFixed(2)}`,"RAM available":memAvail,"Swap used":swapUsed,"Højeste temperatur":local.temperature_c==null?"—":`${local.temperature_c.toFixed(1)} °C · ${local.temperature_sensor||"sensor"}`,"Disk":c.disk_free_gb==null?"—":`${c.disk_free_gb.toFixed(1)} GB ledig`,"Disk lifetime":c.disk_life_time==null?"—":`${c.disk_life_time.toFixed(0)}% brugt`});
  const em=data.event_monitor||{}, ah=data.auto_heal||{}, fl=data.fault_log||{};
  const transportName=em.transport==="websocket"?"WebSocket":em.transport==="sse"?"SSE fallback":"ingen";
  const eventState=em.connected?`Forbundet via ${transportName}${em.last_event_age_seconds!=null?` · sidste event ${fmtDuration(em.last_event_age_seconds)} siden`:""}`:`Ikke forbundet${em.outage_seconds?` · ${Math.max(1,Math.floor(Number(em.outage_seconds)/60))} min`:""}`;
  const autoHealState=ah.enabled?`Aktiv · genstarter Core efter ${ah.trigger_after_seconds||180}s nedetid (cooldown ${ah.cooldown_minutes||30}m)`:`Slået fra`;
  const lastHeal=ah.last_action?.ts?`${fmtDate(ah.last_action.ts)} · ${ah.last_action.status}`:"Ingen endnu";
  const faultState=fl.found?`${fl.summary_da||fl.signal} (${fmtDate(fl.mtime_ts)})`:"Ingen crash-fil";
  $("blackbox-info").innerHTML=kv({"Version":data.version||"—","Uptime":fmtDuration(data.uptime_seconds),"Supervisor":c.extra?.supervisor_ok?`Forbundet · ${fmtNum(c.extra?.supervisor_latency_ms,0)} ms`:"Ikke forbundet","HA API":c.api_ok?`Forbundet · ${fmtNum(c.api_latency_ms,0)} ms`:"Ikke forbundet","Core Auto-Heal":autoHealState,"Seneste Auto-Heal":lastHeal,"Fault Log (SIGABRT/SEGV)":faultState,"Live event-data":eventState,"Transport":transportName,"Entity Registry":`${Number(em.entity_registry_count||0).toLocaleString("da-DK")} entities · kilde: ${em.entity_registry_source||"ukendt"}`,"Sidste event":em.last_event_ts?fmtDate(em.last_event_ts):"—","Sidst forbundet":em.last_connected_ts?fmtDate(em.last_connected_ts):"—","Genforbindelser":Number(em.reconnect_attempts||0),"Sidste event-fejl":em.last_disconnect_reason||"—","Database":fmtBytes(bb.bytes),"WAL":fmtBytes(bb.wal_bytes),"Samples":bb.samples,"Incidenter":bb.incidents,"Vigtige logs":bb.important_logs});
  renderNotifications(data.notifications||{});
  const addons=Object.entries(c.addons||{}).map(([slug,s])=>({name:s.name||slug,cpu:s.cpu_percent,memory:s.memory_percent,write:s.blk_write})).sort((a,b)=>(b.cpu||0)-(a.cpu||0));
  renderTable($("addon-stats"),addons,[["App","name"],["CPU %","cpu","num"],["RAM %","memory","num"],["Block write","write","num"]]);
  const res=c.extra?.resolution||{}, issues=res.issues||[], checks=res.checks||[];
  $("resolution-info").innerHTML=issues.length?`<div class="attention"><strong>${issues.length} aktive issue(s)</strong><pre>${esc(JSON.stringify(issues,null,2))}</pre></div>`:`<div class="empty">Ingen aktive Supervisor Resolution-issues. Checks: ${checks.length}</div>`;
}
function renderNotifications(n) {
  const el=$("notification-info"); if(!el) return;
  const direct=n.enabled ? (n.configured ? `${n.provider} · KLAR · uafhængig af Core` : `${n.provider} · mangler topic/konfiguration`) : "Slået fra";
  const ha=n.ha_notification_enabled ? `${n.ha_notification_service||"persistent_notification.create"} · kræver Core` : "Slået fra";
  const warnings=n.warning_notifications ? "TIL · priority 4 · maks. én pr. kategori/time" : "FRA · anbefalet indtil du ønsker flere push";
  const click=n.click_configured ? "Konfigureret · åbner ved tryk" : "Ikke sat · notifikationen åbner ikke HA automatisk";
  el.innerHTML=kv({
    "Direkte kritisk kanal":direct,
    "Kritiske alarmsignal":n.provider==="ntfy" ? "Priority 5 · MAX/URGENT" : "Kritisk",
    "Direkte advarsler":warnings,
    "Klik-link":click,
    "Home Assistant-kanal":ha,
    "Pending incidents":n.pending_incidents??0
  });
  const btn=$("test-direct-notification");
  if(btn) btn.disabled=!(n.enabled&&n.configured);
  ensureNtfyTopicSuggestion();
}

function randomHex(bytes=16) {
  const arr=new Uint8Array(bytes);
  if(window.crypto?.getRandomValues) window.crypto.getRandomValues(arr);
  else for(let i=0;i<arr.length;i++) arr[i]=Math.floor(Math.random()*256);
  return Array.from(arr,b=>b.toString(16).padStart(2,"0")).join("");
}

function ensureNtfyTopicSuggestion(force=false) {
  const el=$("ntfy-topic-suggestion"), pre=$("ntfy-config-example");
  if(!el||!pre) return;
  let topic=!force ? sessionStorage.getItem("ha_blackbox_ntfy_topic_suggestion") : null;
  if(!topic) {
    topic=`ha-blackbox-${randomHex(18)}`;
    try { sessionStorage.setItem("ha_blackbox_ntfy_topic_suggestion",topic); } catch(_e) {}
  }
  el.textContent=topic;
  pre.textContent=[
    "direct_critical_notifications: true",
    "direct_notification_provider: ntfy",
    "direct_warning_notifications: false",
    "ntfy_server: https://ntfy.sh",
    `ntfy_topic: ${topic}`,
    "ntfy_access_token: ''",
    "ntfy_click_url: ''"
  ].join("\n");
}

function generateNtfyTopic() {
  ensureNtfyTopicSuggestion(true);
  const out=$("notification-test-result"); if(out) out.textContent="Nyt privat topic-forslag genereret lokalt. Brug det samme topic i ntfy-appen og Black Box-konfigurationen.";
}

async function copyNtfyTopic() {
  ensureNtfyTopicSuggestion();
  const topic=$("ntfy-topic-suggestion")?.textContent||"";
  const out=$("notification-test-result");
  try {
    await navigator.clipboard.writeText(topic);
    if(out) out.textContent="Topic kopieret. Indsæt det i ntfy-appen og i Black Box-konfigurationen.";
  } catch(_e) {
    if(out) out.textContent=`Kunne ikke kopiere automatisk. Markér topic manuelt: ${topic}`;
  }
}

async function reconnectEventStream() {
  const buttons=[...document.querySelectorAll("#reconnect-event-stream, .reconnect-now")];
  const out=$("event-reconnect-result");
  buttons.forEach(btn=>{btn.disabled=true; btn.dataset.oldText=btn.textContent; btn.textContent="Forbinder…";});
  if(out) out.textContent="Starter en ny event-stream-forbindelse…";
  try {
    const result=await api("api/events/reconnect", {method:"POST"});
    if(out) out.textContent=result.message || "Genforbindelse startet.";
    setTimeout(refreshStatus, 1200);
    setTimeout(refreshStatus, 3500);
  } catch(err) {
    if(out) out.textContent=`Kunne ikke starte genforbindelse: ${err.message}`;
  } finally {
    setTimeout(()=>buttons.forEach(btn=>{btn.disabled=false; btn.textContent=btn.dataset.oldText||"Genforbind event-stream";}), 1500);
  }
}

async function testDirectNotification() {
  const btn=$("test-direct-notification"), out=$("notification-test-result");
  if(btn) btn.disabled=true; if(out) out.textContent="Sender test…";
  try {
    const result=await api("api/notifications/test",{method:"POST"});
    if(out) out.textContent=`Test sendt via ${result.provider}: ${result.detail}`;
  } catch(e) {
    if(out) out.textContent=`Test fejlede: ${e.message||e}`;
  } finally {
    setTimeout(()=>refreshStatus(),500);
  }
}

function kv(obj) { return `<div class="kv-list">${Object.entries(obj).map(([k,v])=>`<div class="row"><div class="muted">${esc(k)}</div><div class="value">${esc(v??"—")}</div></div>`).join("")}</div>`; }

const jsVersionEl = $("js-version");
if (jsVersionEl) jsVersionEl.textContent = "JS 0.1.14";

window.addEventListener("resize",()=>requestAnimationFrame(renderChart));
bindTabs();
ensureNtfyTopicSuggestion();
refreshStatus(); refreshHistory();
setInterval(refreshStatus,10000); setInterval(refreshHistory,60000);
