// whohack tray UI. All service data is inserted with textContent, never as HTML.
"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, text) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  if (text !== undefined) e.textContent = text;
  return e;
}

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.add("hidden"), 4000);
}

function fmtTime(ms) {
  return new Date(ms).toLocaleString();
}

function fmtDuration(s) {
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return h ? `${h} h ${m} min` : `${m} min`;
}

async function call(cmd, args) {
  try {
    return await invoke(cmd, args);
  } catch (e) {
    toast(String(e));
    throw e;
  }
}

// ---- tabs ----
let activeTab = "alerts";
document.querySelectorAll("nav button").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll("nav button").forEach((x) => x.classList.toggle("active", x === b));
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    activeTab = b.dataset.tab;
    $(`tab-${activeTab}`).classList.add("active");
    refresh();
  });
});

// ---- alerts ----
const ACTIONS = [
  ["ask_user", "Acknowledge", ""],
  ["allow", "Mark as expected", ""],
];
let serviceStatus = null;
const RESPONSE_ACTIONS = [
  ["block_network", "Block connections", "danger"],
  ["suspend_and_ask", "Suspend process", "danger"],
  ["kill_and_quarantine", "Stop and quarantine", "danger"],
];

function renderAlerts(alerts) {
  const box = $("alerts");
  box.replaceChildren();
  const open = alerts.filter((a) => !a.resolved).length;
  $("alert-count").textContent = open ? String(open) : "";
  $("alerts-empty").classList.toggle("hidden", alerts.length > 0);
  for (const a of alerts) {
    const card = el("div", { class: `alert ${a.label}${a.resolved ? " resolved" : ""}` });
    const head = el("div", { class: "alert-head" });
    head.append(el("span", { class: "alert-app" }, a.app_name || a.app_id));
    head.append(el("span", {}, `${a.label} · PID ${a.pid}`));
    head.append(el("span", { class: "alert-meta" }, fmtTime(a.ts)));
    card.append(head, el("p", { class: "alert-text" }, a.explanation || "No details."));
    const details = el("details");
    details.append(el("summary", {}, "Decision evidence"));
    details.addEventListener("toggle", async () => {
      if (!details.open || details.dataset.loaded) return;
      const response = await call("decision_details", { alertId: a.id });
      if (!response) return;
      details.dataset.loaded = "true";
      const records = response.records || [];
      if (!records.length) details.append(el("p", {}, "This alert was produced by rules or scoring. No model decision has been recorded."));
      for (const r of records) {
        details.append(el("p", {}, `${r.model_name} · ${r.answers.advisory ? "advisory" : "validated"} · ${fmtTime(r.ts)}`));
        if (r.answers.error) details.append(el("p", {}, r.answers.error));
        if (r.answers.superseded_by_user) details.append(el("p", {}, "Your decision took precedence over this model result."));
        for (const answer of r.answers.answers || []) {
          details.append(el("p", {}, `${answer.id}: ${answer.probs.map(([label, p]) => `${label} ${(100 * p).toFixed(1)}%`).join(" · ")}`));
        }
        const state = el("pre", { class: "mono" }, r.state_text);
        state.style.whiteSpace = "pre-wrap";
        details.append(state);
      }
    });
    card.append(details);
    if (!a.resolved) {
      const actions = el("div", { class: "actions" });
      const available = RESPONSE_ACTIONS.filter(([action]) => serviceStatus?.response_actions?.includes(action));
      for (const [action, label, cls] of [...ACTIONS, ...available]) {
        const b = el("button", cls ? { class: cls } : {}, label);
        b.addEventListener("click", async () => {
          if (action === "kill_and_quarantine" && !window.confirm(`Stop ${a.app_name || a.app_id} (PID ${a.pid}) and quarantine its captured file? Unsaved work may be lost. The file can be restored.`)) return;
          if (action === "block_network" && !window.confirm(`${serviceStatus.network_scope}. Apply this block to ${a.app_name || a.app_id}?`)) return;
          b.disabled = true;
          try { await call("resolve", { alertId: a.id, action, note: null }); await refresh(); }
          finally { b.disabled = false; }
        });
        actions.append(b);
      }
      const trust = el("button", {}, "Always trust this app");
      trust.addEventListener("click", async () => {
        await call("allow", { entry: { kind: "app", app_id: a.app_id } });
        await call("resolve", { alertId: a.id, action: "allow", note: "trusted app" });
        refresh();
      });
      actions.append(trust);
      card.append(actions);
    }
    box.append(card);
  }
}

// ---- timeline ----
function renderTimeline(events) {
  const body = $("timeline");
  body.replaceChildren();
  for (const e of events) {
    const tr = el("tr");
    tr.append(el("td", {}, fmtTime(e.ts)), el("td", {}, String(e.pid)), el("td", {}, e.kind), el("td", { class: "mono" }, e.detail));
    body.append(tr);
  }
}

// ---- allowlist ----
function renderAllowlist(entries) {
  const body = $("allowlist");
  body.replaceChildren();
  for (const entry of entries) {
    const tr = el("tr");
    const app = entry.app_id || "";
    const value = entry.value || entry.tag || "";
    const remove = el("button", {}, "Remove");
    remove.addEventListener("click", async () => {
      await call("disallow", { entry });
      refresh();
    });
    const actionCell = el("td");
    actionCell.append(remove);
    tr.append(el("td", {}, entry.kind), el("td", { class: "mono" }, app), el("td", { class: "mono" }, value), actionCell);
    body.append(tr);
  }
}

$("allow-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const value = $("allow-dest").value.trim();
  if (!value) return;
  await call("allow", { entry: { kind: "destination", value } });
  $("allow-dest").value = "";
  refresh();
});

// ---- status & mode ----
function renderProfiles(result) {
  const body = $("profiles");
  body.replaceChildren();
  for (const p of result.profiles) {
    const row = el("tr");
    const select = el("select", { "aria-label": `Category for ${p.path || p.app_id}` });
    for (const category of result.categories) select.append(el("option", { value: category }, category.replaceAll("_", " ")));
    select.value = p.category;
    select.addEventListener("change", async () => {
      select.disabled = true;
      try {
        await call("set_category", { appId: p.app_id, category: select.value });
        toast("Behavior profile updated");
      } catch (_) {
        select.value = p.category;
      } finally {
        select.disabled = false;
      }
    });
    const cell = el("td");
    cell.append(select);
    row.append(el("td", { class: "mono", title: p.app_id }, p.path || p.app_id), cell, el("td", { class: "mono" }, p.observed.join(", ") || "No capabilities recorded"));
    body.append(row);
  }
}

function renderStatus(s) {
  serviceStatus = s;
  $("mode").value = s.mode;
  for (const option of $("mode").options) {
    option.disabled = option.value === "auto"
      ? !s.enforcement_available || !s.automatic_response_enabled
      : option.value === "prompt" && !s.enforcement_available && !s.response_actions?.includes("suspend_and_ask");
  }
  $("response-mode-note").textContent = s.mode === "monitor"
    ? "Monitor mode: activity is recorded and alerts are shown. Automatic response is off."
    : s.download_pause_enabled
      ? "whohack automatically pauses strong download-related danger signals and alerts you. Review the evidence, resume, or quarantine the identified file."
    : s.mode === "prompt" ? (s.automatic_response_enabled
      ? "Prompt mode: suspicious connections can be blocked; stronger actions need your decision."
      : "Prompt mode: response controls are enabled. Every action requires your confirmation.")
    : "Automatic mode: whohack can block, stop, and quarantine according to its detection policy.";
  const rows = [
    ["Service version", s.service_version],
    ["Response mode", s.mode],
    ["Automatic download pause", s.download_pause_enabled ? "on; pauses a process when strong download-related danger is detected" : "off"],
    ["Other automatic actions", s.automatic_response_enabled ? "enabled" : "off; require confirmation"],
    ["Downloaded video / document tracking", s.file_visibility ? "launch arguments and observed file reads" : "launch arguments only; opens in existing apps need the native file sensor"],
    ["Network block scope", s.network_scope || "Response disabled"],
    ["Response requirements", s.response_limitation || "None reported"],
    ["Network / process enforcement", s.enforcement_available ? "available" : s.response_actions?.length ? "manual process actions available" : "unavailable — alerts only"],
    ["Sensitive-file collection", s.file_visibility ? "on" : "off for the current collector"],
    ["Registry persistence", s.registry_visibility ? "on" : "off"],
    ["Remote-thread evidence", s.injection_visibility ? "existing Sysmon channel" : "off"],
    ["Collector failures", String(s.collection_failures || 0)],
    ["Integrity checks", s.integrity_issues?.length ? s.integrity_issues.join(". ") : "passed"],
    ["Events lost / queue drops", `${s.collection_kernel_lost || 0} / ${s.collection_dropped || 0}`],
    ["Unattributed sensor records", String(s.collection_unattributed || 0)],
    ["Collection details", (s.collection_notes || []).join(". ") || "None reported"],
    ["Network byte counters", s.byte_visibility ? "on" : "not available from this collector"],
    ["Behavior scoring", s.scorer || "hand-weighted heuristic"],
    ["Collectors", s.collectors.join(", ") || "none"],
    ["DNS visibility", s.dns_visible ? "on" : "off"],
    ["Decision model", s.model ? `${s.model} (${s.model_loaded ? "loaded" : "idle"})` : "rules only; no trained model"],
    ["Events processed", s.events_seen.toLocaleString()],
    ["Open alerts", String(s.open_alerts)],
    ["Uptime", fmtDuration(s.uptime_s)],
  ];
  const dl = $("status");
  dl.replaceChildren();
  for (const [k, v] of rows) dl.append(el("dt", {}, k), el("dd", {}, v));
}

$("mode").addEventListener("change", async (ev) => {
  try {
    await call("set_mode", { mode: ev.target.value });
    toast(`Protection mode: ${ev.target.selectedOptions[0].textContent}`);
  } catch {
    // call() already explains the failure. Restore the service's actual mode.
  } finally {
    await refresh();
  }
});

function setConnection(ok, message) {
  const c = $("conn");
  c.textContent = ok ? (serviceStatus?.download_pause_enabled ? "Download danger pause · on" : serviceStatus?.mode === "monitor" ? "Monitoring · alerts only" : `Response · ${serviceStatus?.mode || "connected"}`) : "Service offline";
  c.title = message || "";
  c.className = `pill ${ok ? "pill-ok" : "pill-bad"}`;
  if (ok && (serviceStatus?.collection_failures || serviceStatus?.collection_kernel_lost || serviceStatus?.collection_dropped || serviceStatus?.integrity_issues?.length)) {
    c.textContent = "Monitoring degraded";
    c.className = "pill pill-bad";
    c.title = "Sensor loss, failure or integrity issues were reported. See Status for details.";
  }
}

async function refresh() {
  try {
    renderStatus(await invoke("status"));
    setConnection(true);
    if (activeTab === "alerts") renderAlerts(await invoke("alerts", { limit: 200 }));
    if (activeTab === "timeline") renderTimeline(await invoke("events", { limit: 300 }));
    if (activeTab === "allowlist") renderAllowlist(await invoke("allowlist"));
    if (activeTab === "profiles") renderProfiles(await invoke("profiles"));
    if (activeTab === "responses") renderResponses(await invoke("responses"));
  } catch (e) {
    setConnection(false, String(e));
  }
}

function renderResponses(result) {
  const box = $("responses"); box.replaceChildren();
  if (!result.actions.length) box.append(el("p", { class: "empty" }, "No response operations recorded."));
  for (const action of result.actions) {
    const card = el("div", { class: "alert" });
    card.append(el("strong", {}, `${action.action.replaceAll("_", " ")} · ${action.status}`),
      el("p", { class: "mono" }, `${action.app} · PID ${action.pid}`), el("p", {}, action.detail), el("small", {}, fmtTime(action.ts)));
    if (["active", "degraded"].includes(action.status) || (action.status === "recovery_required" && ["block_network", "suspend_and_ask"].includes(action.action))) {
      const release = el("button", {}, action.action === "suspend_and_ask" ? "Resume process" : "Unblock connections");
      release.addEventListener("click", async () => { release.disabled = true; try { await call("release_response", { id: action.id }); await refresh(); } finally { release.disabled = false; } });
      card.append(release);
    }
    box.append(card);
  }
  const q = $("quarantine"); q.replaceChildren();
  if (!result.quarantine.length) q.append(el("p", { class: "empty" }, "No quarantined files."));
  for (const item of result.quarantine) {
    const card = el("div", { class: "alert" });
    card.append(el("strong", { class: "mono" }, item.original_path), el("p", {}, `${item.size.toLocaleString()} bytes · ${item.restored_at ? "Restored" : "Quarantined"} · ${fmtTime(item.quarantined_at)}`), el("p", { class: "mono" }, `SHA-256: ${item.sha256}`));
    if (!item.restored_at) {
      const restore = el("button", {}, "Restore file");
      restore.addEventListener("click", async () => {
        if (!window.confirm(`Restore ${item.original_path}? Existing files will never be overwritten. The restored file will not be run.`)) return;
        restore.disabled = true; try { await call("restore_quarantine", { id: item.id }); await refresh(); } finally { restore.disabled = false; }
      }); card.append(restore);
    }
    q.append(card);
  }
}

listen("whohack://push", (ev) => {
  const p = ev.payload;
  if (p.event === "mode_changed") $("mode").value = p.mode;
  if (p.event === "health" && !p.ok) toast(p.message);
  refresh();
});
listen("whohack://connection", (ev) => {
  setConnection(ev.payload.connected, ev.payload.message);
  if (ev.payload.connected) refresh();
});

refresh();
setInterval(refresh, 5000);
