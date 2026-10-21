// Browser UI regression checks with an explicitly mocked IPC boundary.
// Native collection/response is tested separately by the Windows harnesses.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile, writeFile, mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";

const root = resolve(import.meta.dirname, "../..");
const output = join(root, ".vigil/checks/m15-ui");
await mkdir(output, { recursive: true });
const profile = await mkdtemp(join(tmpdir(), "whohack-ui-test-"));
const server = createServer(async (req, res) => {
  const name = new URL(req.url, "http://localhost").pathname.slice(1) || "index.html";
  if (!["index.html", "app.js", "style.css"].includes(name)) { res.writeHead(404).end(); return; }
  res.setHeader("Content-Type", name.endsWith(".js") ? "text/javascript" : name.endsWith(".css") ? "text/css" : "text/html");
  res.end(await readFile(join(root, "ui/dist", name)));
});
await new Promise(r => server.listen(0, "127.0.0.1", r));
const browser = spawn("C:/Program Files/Google/Chrome/Application/chrome.exe", [
  "--headless=new", "--remote-debugging-port=0", `--user-data-dir=${profile}`,
  "--no-first-run", "--no-default-browser-check", "about:blank",
], { windowsHide: true, stdio: "ignore" });
let socket;
const pending = new Map(), exceptions = [];
let sequence = 0;
function command(method, params = {}) {
  const id = ++sequence;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${method} timed out`)); }, 8000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params }));
  });
}
async function evaluate(expression) {
  if (expression.includes("await ")) expression = `(async () => { ${expression} })()`;
  const r = await command("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  assert(!r.exceptionDetails, JSON.stringify(r.exceptionDetails));
  return r.result.value;
}
async function until(expression) {
  for (let n = 0; n < 100; n++) {
    if (await evaluate(expression)) return;
    await delay(100);
  }
  throw new Error(`UI condition failed: ${expression}`);
}
async function screenshot(name) {
  const capture = await command("Page.captureScreenshot", { format: "png" });
  await writeFile(join(output, name), Buffer.from(capture.data, "base64"));
}
try {
  let port;
  for (let n = 0; n < 100 && !port; n++) {
    try { port = Number((await readFile(join(profile, "DevToolsActivePort"), "utf8")).split("\n")[0]); }
    catch { await delay(100); }
  }
  assert(port, "Owned test browser did not start");
  const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  socket = new WebSocket(pages.find(p => p.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
  socket.addEventListener("message", event => {
    const value = JSON.parse(event.data);
    if (value.method === "Runtime.exceptionThrown") exceptions.push(value.params.exceptionDetails.text);
    const p = pending.get(value.id);
    if (p) {
      clearTimeout(p.timer); pending.delete(value.id);
      if (value.error) p.reject(new Error(JSON.stringify(value.error))); else p.resolve(value.result);
    }
  });
  await command("Runtime.enable");
  await command("Page.enable");
  await command("Emulation.setDeviceMetricsOverride", { width: 1080, height: 900, deviceScaleFactor: 1, mobile: false });
  await command("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] });
  await command("Page.addScriptToEvaluateOnNewDocument", { source: `
    window.mock = {
      offline: false, calls: [], failAction: false, failScan: false, confirm: true, folderScan: null,
      status: { service_version: "0.1.1", mode: "prompt", download_activity_available: true,
        folder_scan_available: true,
        file_visibility: true, download_pause_enabled: true, collectors: ["windows-etw"],
        enforcement_available: true, automatic_response_enabled: false, open_alerts: 1,
        response_actions: ["suspend_and_ask","kill_and_quarantine"], events_seen: 24,
        uptime_s: 300, integrity_issues: [], network_scope: "Fixture only" },
      downloads: [{ pid: 42, start_time: 1720000000000, app: "C:\\\\Apps\\\\Player.exe", exit_time: null,
        files: [{ path: "C:\\\\Downloads\\\\sample.wav", evidence: "observed_read", observed_at: 1720000001000 },
                { path: "C:\\\\Downloads\\\\<img src=x onerror=alert(1)>.mp4", evidence: "launch_argument", observed_at: 1720000002000 }],
        events: [{ ts: 1720000003000, pid: 42, kind: "net_connect", detail: "127.0.0.1:8000/tcp" }] }],
      alerts: [{ id: 7, ts: 1720000004000, pid: 42, app_id: "fixture", app_name: "Player.exe",
        label: "suspicious", explanation: "Harmless UI fixture: a test signature matched the downloaded input.",
        action: "suspend_and_ask", resolved: false,
        downloaded_files: [{ path: "C:\\\\Downloads\\\\sample.wav", evidence: "observed_read" }] }],
    };
    window.confirm = () => mock.confirm;
    window.__TAURI__ = {
      event: { listen: async () => () => {} },
      core: { invoke: async (cmd, args) => {
        mock.calls.push({cmd,args});
        if(mock.offline) throw new Error("Fixture service disconnected");
        if(cmd==="status") return mock.status;
        if(cmd==="downloads") return {downloads:mock.downloads};
        if(cmd==="alerts") return mock.alerts;
        if(cmd==="events" || cmd==="allowlist") return [];
        if(cmd==="profiles") return {profiles:[],categories:[]};
        if(cmd==="responses") return {actions:[],quarantine:[]};
        if(cmd==="decision_details") return {records:[]};
        if(cmd==="folder_scan_status") return {kind:"folder_scan",available:true,limitation:"Defender cloud/sample settings apply",scan:mock.folderScan};
        if(cmd==="start_folder_scan") {
          if(mock.failScan) throw new Error("Fixture scan failed");
          mock.folderScan={id:9,path:args.path,remediate:args.remediate,state:"running",elapsed_s:1,
            output:"<img src=x onerror=alert(1)>",output_truncated:true,message:"No matches is not a safety verdict."};
          return {kind:"folder_scan",available:true,limitation:"Defender cloud/sample settings apply",scan:mock.folderScan};
        }
        if(cmd==="stop_folder_scan") { mock.folderScan.state="stopped"; return {kind:"folder_scan",available:true,limitation:"Defender cloud/sample settings apply",scan:mock.folderScan}; }
        if(cmd==="resolve" && mock.failAction) throw new Error("Fixture response refused");
        if(cmd==="set_mode") { mock.status.mode=args.mode; return; }
      }}
    };
  ` });
  await command("Page.navigate", { url: `http://127.0.0.1:${server.address().port}/` });
  await until('document.querySelectorAll("#downloads .download").length === 1');
  assert.equal(await evaluate("document.title"), "whohack");
  assert.match(await evaluate('document.getElementById("tracking-value").textContent'), /File reads visible/);
  await evaluate('document.querySelector("#downloads details").open=true');
  assert.match(await evaluate('document.getElementById("downloads").textContent'), /Named at launch; read not confirmed/);
  assert.equal(await evaluate('document.querySelectorAll("#downloads img").length'), 0);
  await evaluate('refresh()');
  assert.equal(await evaluate('document.querySelector("#downloads details").open'), true);
  await screenshot("download-activity-light.png");
  await command("Emulation.setDeviceMetricsOverride", { width: 720, height: 700, deviceScaleFactor: 1, mobile: false });
  assert(await evaluate("document.documentElement.scrollWidth <= innerWidth"), "Horizontal overflow at minimum window width");
  await command("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "dark" }] });
  await screenshot("download-activity-dark-720.png");
  await evaluate('openTab("folders")');
  await until('!document.getElementById("folder-submit").disabled');
  await evaluate('document.getElementById("folder-path").value="C:\\\\Downloads"; document.getElementById("folder-form").requestSubmit()');
  await until('document.getElementById("folder-status").textContent.includes("running")');
  assert.match(await evaluate('document.getElementById("folder-status").textContent'), /Report only/);
  assert.match(await evaluate('document.getElementById("folder-status").textContent'), /not a safety verdict/);
  assert.equal(await evaluate('document.querySelectorAll("#folder-results img").length'), 0);
  assert.equal(await evaluate('mock.calls.filter(c=>c.cmd==="start_folder_scan").at(-1).args.remediate'), false);
  assert.equal(await evaluate('mock.calls.filter(c=>c.cmd==="start_folder_scan").at(-1).args.path'), "C:\\Downloads");
  assert.equal(await evaluate('document.getElementById("folder-submit").disabled'), true);
  await screenshot("optional-folder-scan.png");
  await evaluate('document.getElementById("folder-stop").click()');
  await until('document.getElementById("folder-status").textContent.includes("stopped")');
  assert.equal(await evaluate('mock.calls.filter(c=>c.cmd==="stop_folder_scan").at(-1).args.id'), 9);
  await evaluate('document.getElementById("folder-remediate").checked=true; mock.confirm=false; document.getElementById("folder-form").requestSubmit()');
  assert.equal(await evaluate('mock.calls.filter(c=>c.cmd==="start_folder_scan").length'), 1);
  await evaluate('mock.confirm=true; mock.failScan=true; document.getElementById("folder-form").requestSubmit()');
  await until('document.getElementById("folder-status").textContent.includes("Fixture scan failed")');
  assert.equal(await evaluate('mock.calls.filter(c=>c.cmd==="start_folder_scan").at(-1).args.remediate'), true);
  await evaluate('mock.status.folder_scan_available=false; await refresh()');
  assert.equal(await evaluate('document.getElementById("folder-submit").disabled'), true);
  await evaluate('openTab("alerts")');
  await until('document.querySelectorAll("#alerts .alert").length === 1');
  await evaluate('mock.confirm=false; [...document.querySelectorAll("#alerts button")].find(b=>b.textContent==="Stop and quarantine").click()');
  assert.equal(await evaluate('mock.calls.filter(c=>c.cmd==="resolve").length'), 0);
  await evaluate('mock.confirm=true; mock.failAction=true; [...document.querySelectorAll("#alerts button")].find(b=>b.textContent==="Stop and quarantine").click()');
  await until('document.getElementById("toast").textContent.includes("Fixture response refused")');
  assert.equal(await evaluate('mock.calls.filter(c=>c.cmd==="resolve").at(-1).args.alertId'), 7);
  await evaluate('mock.status.response_actions=[]; await refresh()');
  assert.equal(await evaluate('[...document.querySelectorAll("#alerts button")].some(b=>b.textContent==="Stop and quarantine")'), false);
  await evaluate('mock.status.collection_dropped=1; await refresh()');
  assert.match(await evaluate('document.getElementById("conn").textContent'), /gaps/);
  await evaluate('mock.status.file_visibility=false; await refresh()');
  assert.match(await evaluate('document.getElementById("tracking-value").textContent'), /Limited/);
  await evaluate('mock.offline=true; await refresh()');
  assert.equal(await evaluate('document.getElementById("response-value").textContent'), "Not confirmed");
  assert.equal(await evaluate('document.getElementById("mode").disabled'), true);
  assert.equal(await evaluate('[...document.querySelectorAll(".actions button")].every(b=>b.disabled)'), true);
  await evaluate('mock.offline=false; mock.status.download_activity_available=false; openTab("downloads")');
  await until('document.getElementById("downloads-message").textContent.includes("Update the running service")');
  await evaluate('mock.status.download_activity_available=true; mock.downloads=[]; await refresh()');
  assert.match(await evaluate('document.getElementById("downloads-message").textContent'), /No downloaded-file opens recorded/);
  assert.deepEqual(exceptions, []);
  await writeFile(join(output, "results.json"), JSON.stringify({
    success: true, boundary: "mocked IPC in real Chromium; not native sensor evidence",
    checks: ["whohack branding", "read versus argument evidence", "text-only untrusted filenames",
      "expanded activity retained", "minimum-width layout and light/dark rendering",
      "quarantine confirmation and exact alert identity", "failed response feedback",
      "unavailable actions hidden", "sensor gaps", "limited file visibility",
      "offline status and disabled controls", "legacy service fallback", "empty history wording",
      "optional folder scan report-only default, job state, literal output, stop identity, remediation confirmation, errors and legacy fallback"],
  }, null, 2) + "\n");
  console.log("PASS: download UI checks (mock IPC), screenshots saved");
} finally {
  if (socket?.readyState === WebSocket.OPEN) {
    try { await command("Browser.close"); } catch {}
    socket.close();
  }
  if (browser.exitCode === null) browser.kill();
  await new Promise(r => server.close(r));
  for (const p of pending.values()) clearTimeout(p.timer);
  // Only this harness's new browser profile; never touch personal profiles.
  await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
}
