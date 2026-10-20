// Real WebView2 acceptance: no mock Tauri API, no application runtime dependency.
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';

const [port, servicePid, screenshot, pauseSetting] = process.argv.slice(2);
const downloadPause = pauseSetting === 'true';
assert(/^\d+$/.test(port) && /^\d+$/.test(servicePid));
assert.equal(typeof WebSocket, 'function', 'Node 22+ is required');
let page;
for (let n = 0; n < 80 && !page; n++) {
  try {
    const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(1000) })).json();
    page = pages.find(p => p.type === 'page' && p.title === 'whohack' && p.webSocketDebuggerUrl);
  } catch { /* WebView2 is still starting. */ }
  if (!page) await delay(250);
}
assert(page, 'No owned whohack WebView2 page became ready');
const socket = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  socket.addEventListener('open', resolve, { once: true });
  socket.addEventListener('error', reject, { once: true });
});
let sequence = 0;
const pending = new Map();
const exceptions = [];
socket.addEventListener('message', event => {
  const value = JSON.parse(event.data);
  if (value.method === 'Runtime.exceptionThrown') exceptions.push(value.params.exceptionDetails.text);
  const p = pending.get(value.id);
  if (p) {
    pending.delete(value.id);
    clearTimeout(p.timer);
    if (value.error) p.reject(new Error(JSON.stringify(value.error)));
    else p.resolve(value.result);
  }
});
function command(method, params = {}) {
  const id = ++sequence;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${method} timed out`)); }, 8000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params }));
  });
}
async function evaluate(expression) {
  const response = await command('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
  assert(!response.exceptionDetails, JSON.stringify(response.exceptionDetails));
  return response.result.value;
}
async function until(expression) {
  for (let n = 0; n < 80; n++) {
    if (await evaluate(expression)) return;
    await delay(200);
  }
  throw new Error(`UI condition did not become true: ${expression}`);
}
async function tab(name) {
  await evaluate(`document.querySelector('button[data-tab="${name}"]').click()`);
  await until(`document.getElementById('tab-${name}').classList.contains('active')`);
}
try {
  await command('Runtime.enable');
  // Verify ownership before sending any UI mutation.
  await until('typeof window.__TAURI__?.core?.invoke === "function"');
  assert.equal(await evaluate('(async () => (await window.__TAURI__.core.invoke("status")).service_pid)()'), Number(servicePid));
  await evaluate('window.__TAURI__.core.invoke("set_mode", { mode: "prompt" })');
  await evaluate('document.getElementById("mode").value="prompt"; document.getElementById("mode").dispatchEvent(new Event("change"))');
  const promptPill = downloadPause ? 'Download danger pause' : 'Response';
  await until(`document.getElementById("conn").textContent.includes(${JSON.stringify(promptPill)})`);
  assert.equal(await evaluate('document.querySelector("#mode option[value=auto]").disabled'), true);
  assert.equal(await evaluate('document.querySelector("#mode option[value=prompt]").disabled'), false);
  assert.match(await evaluate('document.getElementById("response-mode-note").textContent'), downloadPause
    ? /automatically pauses strong download-related danger signals/
    : /Every action requires your confirmation/);
  await tab('timeline');
  await until('document.querySelectorAll("#timeline tr").length > 0');
  await tab('profiles');
  await until('document.querySelectorAll("#profiles tr").length > 0');
  await tab('allowlist');
  await evaluate('document.getElementById("allow-dest").value="whohack-ui-test.invalid"; document.getElementById("allow-form").requestSubmit()');
  await until('document.getElementById("allowlist").textContent.includes("whohack-ui-test.invalid")');
  await evaluate('[...document.querySelectorAll("#allowlist tr")].find(r=>r.textContent.includes("whohack-ui-test.invalid")).querySelector("button").click()');
  await until('!document.getElementById("allowlist").textContent.includes("whohack-ui-test.invalid")');
  await tab('responses');
  await until('document.getElementById("responses").textContent.includes("No response operations")');
  await evaluate('document.getElementById("mode").value="monitor"; document.getElementById("mode").dispatchEvent(new Event("change"))');
  await until('document.getElementById("conn").textContent.includes("alerts only")');
  assert.equal(await evaluate('(async () => (await window.__TAURI__.core.invoke("status")).download_pause_enabled)()'), false);
  await evaluate('document.getElementById("mode").value="prompt"; document.getElementById("mode").dispatchEvent(new Event("change"))');
  await until(`document.getElementById("conn").textContent.includes(${JSON.stringify(promptPill)})`);
  assert.equal(await evaluate('(async () => (await window.__TAURI__.core.invoke("status")).download_pause_enabled)()'), downloadPause);
  await tab('status');
  await until('document.getElementById("status").textContent.includes("windows-poll")');
  assert.equal(await evaluate('document.querySelector("#mode option[value=auto]").disabled'), true);
  assert.deepEqual(exceptions, []);
  const capture = await command('Page.captureScreenshot', { format: 'png' });
  await writeFile(screenshot, Buffer.from(capture.data, 'base64'));
  console.log('PASS: real WebView2 UI acceptance');
} finally {
  socket.close();
}
