// Vigil tray UI. All service data is inserted with textContent, never as HTML.
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
  ["allow", "Allow", ""],
  ["block_network", "Block network", ""],
  ["kill_and_quarantine", "Kill & quarantine", "danger"],
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
    if (!a.resolved) {
      const actions = el("div", { class: "actions" });
      for (const [action, label, cls] of ACTIONS) {
        const b = el("button", cls ? { class: cls } : {}, label);
        b.addEventListener("click", async () => {
          await call("resolve", { alertId: a.id, action, note: null });
          refresh();
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
function renderStatus(s) {
  $("mode").value = s.mode;
  const rows = [
    ["Service version", s.service_version],
    ["Protection mode", s.mode],
    ["Collectors", s.collectors.join(", ") || "none"],
    ["DNS visibility", s.dns_visible ? "on" : "off"],
    ["Decision model", s.model ? `${s.model} (${s.model_loaded ? "loaded" : "idle"})` : "rules and scoring only"],
    ["Events processed", s.events_seen.toLocaleString()],
    ["Open alerts", String(s.open_alerts)],
    ["Uptime", fmtDuration(s.uptime_s)],
  ];
  const dl = $("status");
  dl.replaceChildren();
  for (const [k, v] of rows) dl.append(el("dt", {}, k), el("dd", {}, v));
}

$("mode").addEventListener("change", async (ev) => {
  await call("set_mode", { mode: ev.target.value });
  toast(`Protection mode: ${ev.target.selectedOptions[0].textContent}`);
});

function setConnection(ok, message) {
  const c = $("conn");
  c.textContent = ok ? "Protected" : "Service offline";
  c.title = message || "";
  c.className = `pill ${ok ? "pill-ok" : "pill-bad"}`;
}

async function refresh() {
  try {
    renderStatus(await invoke("status"));
    setConnection(true);
    if (activeTab === "alerts") renderAlerts(await invoke("alerts", { limit: 200 }));
    if (activeTab === "timeline") renderTimeline(await invoke("events", { limit: 300 }));
    if (activeTab === "allowlist") renderAllowlist(await invoke("allowlist"));
  } catch (e) {
    setConnection(false, String(e));
  }
}

listen("vigil://push", (ev) => {
  const p = ev.payload;
  if (p.event === "mode_changed") $("mode").value = p.mode;
  if (p.event === "health" && !p.ok) toast(p.message);
  refresh();
});
listen("vigil://connection", (ev) => {
  setConnection(ev.payload.connected, ev.payload.message);
  if (ev.payload.connected) refresh();
});

refresh();
setInterval(() => {
  if (activeTab === "timeline" || activeTab === "status") refresh();
}, 5000);
