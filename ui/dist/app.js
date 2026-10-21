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
let activeTab = "downloads";
function openTab(name) {
  const b = document.querySelector(`nav button[data-tab="${name}"]`);
  if (!b) return;
  document.querySelectorAll("nav button").forEach((x) => {
    x.classList.toggle("active", x === b);
    x.setAttribute("aria-pressed", String(x === b));
  });
  document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
  activeTab = name;
  $(`tab-${name}`).classList.add("active");
  $("page-title").textContent = b.textContent.replace(/^[↓!◇⚙]\s*/, "").replace(/\d+$/, "").trim();
  refresh();
}
document.querySelectorAll("nav button").forEach((b) => {
  b.addEventListener("click", () => openTab(b.dataset.tab));
});
document.querySelectorAll("[data-open-tab]").forEach(b => b.addEventListener("click", () => openTab(b.dataset.openTab)));
document.querySelector(".brand").addEventListener("click", ev => { ev.preventDefault(); openTab("downloads"); });
$("refresh-downloads").addEventListener("click", () => refresh());

let folderPending = false, folderJob = null, serviceConnected = false;
function folderControls() {
  const enabled = serviceConnected && serviceStatus?.folder_scan_available;
  const running = folderJob?.state === "running";
  $("folder-submit").disabled = !enabled || folderPending || running;
  $("folder-path").disabled = folderPending || running;
  $("folder-remediate").disabled = folderPending || running;
  $("folder-stop").classList.toggle("hidden", !running);
  $("folder-stop").disabled = !enabled || folderPending || !running;
}
function renderFolderScan(result) {
  folderJob = result.scan;
  $("folder-limitation").textContent = result.limitation;
  const box = $("folder-results"); box.replaceChildren();
  if (!folderJob) {
    $("folder-status").textContent = result.available ? "Choose a local folder. Checks report detections unless you explicitly enable remediation." : result.limitation;
  } else {
    const job = folderJob;
    $("folder-status").textContent = `${job.state.replaceAll("_", " ")} | ${job.elapsed_s} seconds | ${job.remediate ? "Defender remediation permitted" : "Report only"}. ${job.message}`;
    box.append(el("p", { class: "mono" }, job.path));
    if (job.output) {
      const output = el("pre", { class: "mono" }, job.output);
      output.style.whiteSpace = "pre-wrap"; output.style.overflowWrap = "anywhere";
      box.append(output);
    }
    if (job.output_truncated) box.append(el("p", { class: "notice warning" }, "Scanner output was truncated. This report may be incomplete."));
  }
  folderControls();
}
$("folder-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (folderPending || folderJob?.state === "running" || !serviceConnected || !serviceStatus?.folder_scan_available) return;
  const path = $("folder-path").value.trim(), remediate = $("folder-remediate").checked;
  if (remediate && !window.confirm(`Allow Microsoft Defender to quarantine or remove detected threats in ${path}? Windows manages these actions.`)) return;
  folderPending = true; folderControls();
  try {
    renderFolderScan(await call("start_folder_scan", { path, remediate }));
    rendered.delete("folders");
  } catch (error) {
    $("folder-status").textContent = `Folder check could not start: ${error}`;
  } finally { folderPending = false; folderControls(); }
});
$("folder-stop").addEventListener("click", async () => {
  if (!folderJob || folderPending) return;
  folderPending = true; folderControls();
  try {
    renderFolderScan(await call("stop_folder_scan", { id: folderJob.id }));
    toast("Stop requested. Defender may finish work already submitted.");
    rendered.delete("folders");
  } finally { folderPending = false; folderControls(); }
});

const filename = path => path.split(/[\\/]/).pop() || path;
const evidenceNames = {
  executed: "Downloaded program started", script: "Downloaded script started",
  observed_read: "File read observed", launch_argument: "Named at launch; read not confirmed",
  inherited: "Associated through a parent app",
};
const eventNames = {
  net_connect: "Network connection", dns_query: "Address lookup", persistence: "Startup change",
  injection: "Process injection", file_burst: "Many file changes", process_exit: "App exited",
  process_start: "App started", file_access: "File access", net_stats: "Network traffic",
};

function renderDownloads(result) {
  const rows = result.downloads || [];
  const box = $("downloads");
  const expanded = new Set([...box.querySelectorAll("details[open]")].map(d => d.dataset.key));
  box.replaceChildren();
  $("downloads-message").classList.toggle("hidden", rows.length > 0);
  $("downloads-message").textContent = "No downloaded-file opens recorded yet. Open a file normally, then check here. A missing entry can also mean the file origin or open was not visible to the sensor.";
  for (const row of rows) {
    const files = row.files || [];
    const card = el("article", { class: "download" });
    const head = el("div", { class: "download-head" });
    const title = el("div", { class: "file-title" });
    const first = files[0];
    title.append(el("span", { class: "file-icon", "aria-hidden": "true" }, first ? filename(first.path).split(".").pop().slice(0, 4).toUpperCase() : "APP"));
    const info = el("div", { class: "file-info" });
    info.append(el("div", { class: "file-name" }, first ? filename(first.path) : "Download-associated app"));
    const association = first?.evidence === "observed_read" ? "Opened by" : "Associated app:";
    info.append(el("div", { class: "file-sub" }, `${association} ${filename(row.app)}${files.length > 1 ? ` · ${files.length} associated files` : ""}`));
    title.append(info);
    head.append(title, el("span", { class: "pill pill-warn" }, row.exit_time ? "Exit recorded" : "Activity recorded"));
    card.append(head);
    card.append(el("p", { class: "file-evidence" }, first ? evidenceNames[first.evidence] || "Download context recorded" : "Context inherited from a downloaded app; original file not recorded here."));
    const detail = el("details", { "data-key": `${row.pid}:${row.start_time}` });
    detail.open = expanded.has(detail.dataset.key);
    detail.append(el("summary", {}, `View files & observed behavior${row.events.length ? ` (${row.events.length})` : ""}`));
    detail.append(el("p", { class: "path" }, `${row.app} · Process ${row.pid} · Started ${fmtTime(row.start_time)}`));
    for (const file of files) {
      detail.append(el("p", { class: "path" }, `${file.path} · ${evidenceNames[file.evidence] || file.evidence} · ${fmtTime(file.observed_at)}`));
    }
    detail.append(el("p", { class: "footnote" }, "These are this app's recent observations after the earliest associated file open, not proof that any one file caused them. Up to 12 retained network, lookup, startup, injection, mass-change or exit records are shown."));
    if (!row.events.length) detail.append(el("p", { class: "empty" }, "No recent behavior records available for this app. This does not confirm the file is safe."));
    for (const event of row.events) {
      const line = el("div", { class: "activity-line" });
      const label = el("div", {}, eventNames[event.kind] || event.kind);
      label.append(el("small", {}, fmtTime(event.ts)));
      line.append(label, el("span", { class: "mono" }, event.detail || "Exit observed"));
      detail.append(line);
    }
    card.append(detail);
    box.append(card);
  }
}

// ---- alerts ----
const ACTIONS = [
  ["ask_user", "Mark as reviewed", ""],
  ["allow", "Allow & resume", ""],
];
let serviceStatus = null;
const RESPONSE_ACTIONS = [
  ["block_network", "Block connections", "danger"],
  ["suspend_and_ask", "Pause app", "danger"],
  ["kill_and_quarantine", "Stop and quarantine", "danger"],
];

function renderAlerts(alerts) {
  const box = $("alerts");
  box.replaceChildren();
  const visible = alerts.filter(a => !a.resolved || $("show-resolved").checked);
  $("alerts-empty").classList.toggle("hidden", visible.length > 0);
  $("alerts-empty").textContent = serviceStatus?.open_alerts
    ? "No open alerts in the latest 200 records. Older open alerts may remain."
    : "No alerts need review in these records. This does not certify your files as safe.";
  for (const a of visible) {
    const card = el("div", { class: `alert ${a.label}${a.resolved ? " resolved" : ""}` });
    const head = el("div", { class: "alert-head" });
    head.append(el("span", { class: "alert-app" }, a.app_name || a.app_id));
    head.append(el("span", {}, `${a.label} · PID ${a.pid}`));
    head.append(el("span", { class: "alert-meta" }, fmtTime(a.ts)));
    card.append(head, el("p", { class: "alert-text" }, a.explanation || "No details."));
    for (const file of a.downloaded_files || []) {
      card.append(el("p", { class: "file-evidence" }, `Associated file: ${filename(file.path)} · ${evidenceNames[file.evidence] || file.evidence}`));
    }
    if (a.action === "suspend_and_ask") {
      const review = el("button", {}, "Check pause / resume");
      review.addEventListener("click", () => openTab("responses"));
      card.append(el("p", { class: "file-sub" }, "Check Actions & files for the current pause status. Mark as reviewed does not resume an app."), review);
    }
    const details = el("details");
    details.append(el("summary", {}, "Decision evidence"));
    details.addEventListener("toggle", async () => {
      if (!details.open || details.dataset.loaded) return;
      let response;
      try { response = await call("decision_details", { alertId: a.id }); } catch { return; }
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
        if (!window.confirm(`Trust ${a.app_name || a.app_id}? Future matching alerts for this app will be suppressed, including when it opens other files.`)) return;
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
$("show-resolved").addEventListener("change", () => { rendered.delete("alerts"); refresh(); });

// ---- timeline ----
function renderTimeline(events) {
  const body = $("timeline");
  body.replaceChildren();
  for (const e of events) {
    const tr = el("tr");
    tr.append(el("td", {}, fmtTime(e.ts)), el("td", {}, String(e.pid)), el("td", {}, eventNames[e.kind] || e.kind), el("td", { class: "mono" }, e.detail));
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
  $("mode").disabled = false;
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
  $("settings-response-note").textContent = $("response-mode-note").textContent;
  $("mode").querySelector('[value="prompt"]').textContent = s.download_pause_enabled
    ? "Pause qualified danger; ask before removal" : "Ask before taking action";
  $("tracking-value").textContent = s.file_visibility ? "File reads visible" : "Limited tracking";
  $("tracking-detail").textContent = s.file_visibility
    ? "Supported file opens can be linked to the app reading them."
    : "Launch arguments only. Opens in an already-running player may be missed.";
  $("response-value").textContent = s.download_pause_enabled ? "Danger pause on" : s.mode === "monitor" ? "Notify only" : "Ask before acting";
  $("response-detail").textContent = s.download_pause_enabled
    ? "Strong download-related evidence can pause the app for your review."
    : "Download danger pause is off. Review alerts to take an available action.";
  $("review-value").textContent = `${s.open_alerts} ${s.open_alerts === 1 ? "alert" : "alerts"}`;
  $("alert-count").textContent = s.open_alerts ? String(s.open_alerts) : "";
  $("version").textContent = `· Service ${s.service_version}`;
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
  serviceConnected = ok;
  folderControls();
  const c = $("conn");
  c.textContent = ok ? (serviceStatus?.download_pause_enabled ? "Danger pause on" : serviceStatus?.mode === "monitor" ? "Monitoring · alerts only" : "Connected · ask before acting") : "Service offline";
  c.title = message || "";
  c.className = `pill ${ok ? "pill-ok" : "pill-bad"}`;
  const warnings = [];
  if (!ok) {
    warnings.push("Cannot reach the service. Live protection cannot be confirmed. Any records below are from the last successful refresh. Open Start whohack.cmd to start the app.");
    $("tracking-value").textContent = "Service offline";
    $("response-value").textContent = "Not confirmed";
    $("tracking-detail").textContent = "Cannot confirm that new file opens are being observed.";
    $("response-detail").textContent = "Reconnect before relying on danger pause.";
    $("last-updated").textContent = "Offline · displayed records may be stale";
  }
  if (ok && (serviceStatus?.collection_failures || serviceStatus?.collection_kernel_lost || serviceStatus?.collection_dropped || serviceStatus?.integrity_issues?.length)) {
    c.textContent = "Monitoring has gaps";
    c.className = "pill pill-warn";
    c.title = "Sensor loss, failure or integrity issues were reported. See Status for details.";
    warnings.push("The service reports sensor loss, failures or changed protection files. Some activity may be missed. Check Protection settings for details; loss counts accumulate during this service session.");
  }
  if (ok && !serviceStatus?.file_visibility) warnings.push("File-read tracking is unavailable. Opens inside an already-running video player or other app may not appear.");
  if (ok && !serviceStatus?.download_activity_available) warnings.push("An older service is running. The download activity view needs the updated whohack service. Existing alerts are still available.");
  $("connection-warning").textContent = warnings.join(" ");
  $("connection-warning").classList.toggle("hidden", !warnings.length);
  for (const control of document.querySelectorAll("#mode, .actions button, #responses button, #quarantine button, #allow-form button, #allowlist button, #profiles select")) {
    if (!ok && !control.disabled) { control.dataset.offline = "true"; control.disabled = true; }
    else if (ok && control.dataset.offline) { control.disabled = false; delete control.dataset.offline; }
  }
}

const rendered = new Map();
let refreshing = false, refreshQueued = false;
async function timedInvoke(cmd, args) {
  let timer;
  try {
    return await Promise.race([invoke(cmd, args), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("Service request timed out")), 8000);
    })]);
  } finally { clearTimeout(timer); }
}
async function refresh() {
  if (refreshing) { refreshQueued = true; return; }
  refreshing = true;
  const tab = activeTab;
  try {
    renderStatus(await timedInvoke("status"));
    setConnection(true);
    $("last-updated").textContent = `Service checked ${new Date().toLocaleTimeString()}`;
    if (tab === "downloads" && !serviceStatus.download_activity_available) {
      $("downloads").replaceChildren();
      $("downloads-message").classList.remove("hidden");
      $("downloads-message").textContent = "Update the running service to see downloaded files here. The installed service does not support this view.";
      rendered.delete("downloads");
      return;
    }
    if (tab === "folders" && !serviceStatus.folder_scan_available) {
      $("folder-status").textContent = "Folder checks require an updated Windows service with Microsoft Defender available.";
      rendered.delete("folders");
      return;
    }
    const views = {
      downloads: ["downloads", undefined, renderDownloads],
      folders: ["folder_scan_status", undefined, renderFolderScan],
      alerts: ["alerts", { limit: 200 }, renderAlerts],
      timeline: ["events", { limit: 300 }, renderTimeline],
      allowlist: ["allowlist", undefined, renderAllowlist],
      profiles: ["profiles", undefined, renderProfiles],
      responses: ["responses", undefined, renderResponses],
    };
    const view = views[tab];
    if (view) {
      try {
        const result = await timedInvoke(view[0], view[1]);
        const key = JSON.stringify([result, tab === "alerts" ? serviceStatus.response_actions : null]);
        if (rendered.get(tab) !== key) { view[2](result); rendered.set(tab, key); }
      } catch (e) {
        $("connection-warning").classList.remove("hidden");
        $("connection-warning").textContent = `The service is connected, but this view could not refresh: ${e}. Any displayed records may be stale.`;
        rendered.delete(tab);
      }
    }
  } catch (e) {
    setConnection(false, String(e));
  } finally {
    refreshing = false;
    if (refreshQueued) { refreshQueued = false; setTimeout(refresh, 250); }
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
      release.addEventListener("click", async () => {
        if (!window.confirm("Release this protection action? The app can continue its previous activity.")) return;
        release.disabled = true;
        try { await call("release_response", { id: action.id }); await refresh(); }
        catch { /* call() displays the service error. */ }
        finally { release.disabled = false; }
      });
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
  if (p.event === "folder_scan_finished") { toast(p.message); rendered.delete("folders"); }
  refresh();
});
listen("whohack://connection", (ev) => {
  setConnection(ev.payload.connected, ev.payload.message);
  if (ev.payload.connected) refresh();
});

refresh();
setInterval(refresh, 5000);
// Async click handlers surface IPC failures to the user without an uncaught
// rejection. A failed action remains failed; no success state is fabricated.
window.addEventListener("unhandledrejection", event => {
  toast(String(event.reason));
  event.preventDefault();
});
