// Optional real-browser checks. Uses Node's built-in WebSocket and a local
// Chromium browser; no npm packages or existing application data are needed.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const browserPath = process.env.BROWSER_PATH ||
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const python = process.env.PYTHON || join(root, ".venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python");
assert(existsSync(browserPath), "Set BROWSER_PATH to a Chromium browser executable.");
assert(typeof WebSocket === "function", "Use Node.js 22 or newer.");
const temporaryRoot = realpathSync(tmpdir());
const workspace = mkdtempSync(join(temporaryRoot, "apache-dashboard-"));
let browser;
let server;
let demoServer;
let socket;
let url;
let serverOutput = "";
let browserOutput = "";
let commandId = 0;
const pending = new Map();
const exceptions = [];

async function until(check, label, timeout = 15000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (await check()) return;
    await delay(75);
  }
  throw new Error("Timed out: " + label);
}

function command(method, params = {}) {
  return new Promise((resolveCommand, reject) => {
    const id = ++commandId;
    const timeout = setTimeout(() => {
      pending.delete(id);
      reject(new Error("Protocol command timed out: " + method));
    }, 10000);
    pending.set(id, {
      resolve: (result) => { clearTimeout(timeout); resolveCommand(result); },
      reject: (error) => { clearTimeout(timeout); reject(error); },
    });
    socket.send(JSON.stringify({ id, method, params }));
  });
}

async function evaluate(expression) {
  const result = await command("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || "Evaluation failed.");
  return result.result.value;
}

const waitFor = (expression, label) => until(() => evaluate(expression), label);
const click = (selector) => evaluate("document.querySelector(" + JSON.stringify(selector) + ").click()");
const field = (selector, value) => evaluate(
  "document.querySelector(" + JSON.stringify(selector) + ").value = " + JSON.stringify(value),
);
const submit = (selector) => evaluate("document.querySelector(" + JSON.stringify(selector) + ").requestSubmit()");

async function importLog(text, logType, timezone = "UTC", filename = "browser-" + logType + ".log") {
  await click("#open-import");
  await evaluate(
    "(() => { const transfer = new DataTransfer(); transfer.items.add(new File([" +
    JSON.stringify(text) + "], " + JSON.stringify(filename) + ", {type:'text/plain'})); " +
    "document.getElementById('upload-file').files = transfer.files; })()",
  );
  await field("#upload-type", logType);
  await evaluate("document.getElementById('upload-type').dispatchEvent(new Event('change'))");
  if (logType === "error") await field("#upload-timezone", timezone);
  await submit("#import-form");
  await waitFor("!document.getElementById('import-submit').disabled", "import completed");
}

try {
  server = spawn(python, [join(root, "tests/browser_server.py"), workspace], {
    cwd: root, windowsHide: true,
    env: { ...process.env, APP_HOST: "127.0.0.1", APP_PORT: "5000", APP_DEBUG: "false",
      DATABASE_PATH: join(workspace, "browser.sqlite3") },
  });
  server.on("error", (error) => { serverOutput += error.message; });
  server.stdout.on("data", (data) => {
    serverOutput += data;
    const match = serverOutput.match(/\{"url":\s*"([^"]+)"\}/);
    if (match) url = match[1];
  });
  server.stderr.on("data", (data) => { serverOutput += data; });
  await until(() => url, "isolated Python server: " + serverOutput);

  const profile = join(workspace, "browser-profile");
  const debuggingPort = process.env.APACHE_BROWSER_DEBUG_PORT || "0";
  assert(/^[0-9]+$/.test(debuggingPort) && Number(debuggingPort) <= 65535, "Invalid browser debugging port.");
  browser = spawn(browserPath, [
    "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
    "--disable-extensions", "--remote-debugging-port=" + debuggingPort, "--user-data-dir=" + profile, "about:blank",
  ], { windowsHide: true });
  browser.on("error", (error) => { browserOutput += error.message; });
  browser.stderr.on("data", (data) => { browserOutput += data; });
  await until(() => /DevTools listening on ws:\/\/127\.0\.0\.1:([0-9]+)/.test(browserOutput),
    "browser launch: " + browserOutput);
  const port = browserOutput.match(/DevTools listening on ws:\/\/127\.0\.0\.1:([0-9]+)/)[1];
  let targets;
  await until(async () => {
    try {
      targets = await (await fetch("http://127.0.0.1:" + port + "/json/list",
        { signal: AbortSignal.timeout(1000) })).json();
      return targets.some((target) => target.type === "page");
    } catch { return false; }
  }, "browser debugging endpoint");
  socket = new WebSocket(targets.find((target) => target.type === "page").webSocketDebuggerUrl);
  socket.addEventListener("message", (event) => {
    const item = JSON.parse(event.data);
    if (item.method === "Runtime.exceptionThrown") exceptions.push(item.params.exceptionDetails);
    if (!item.id) return;
    const promise = pending.get(item.id);
    if (!promise) return;
    pending.delete(item.id);
    if (item.error) promise.reject(new Error(item.error.message));
    else promise.resolve(item.result);
  });
  await until(() => socket.readyState === WebSocket.OPEN, "browser protocol connection");
  await command("Runtime.enable");
  await command("Page.enable");
  await command("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1050, deviceScaleFactor: 1, mobile: false });
  await command("Page.navigate", { url });
  await waitFor("document.getElementById('stat-events')?.textContent === '0'", "empty overview");
  console.log("PASS empty workspace and rule initialization");

  const probe = "<script>window.__evidenceExecuted=true</script>";
  const access = Array.from({ length: 26 }, (_, index) =>
    "192.0.2." + (index + 10) + ' - - [06/Oct/2026:09:00:00 +0000] "GET /.env' +
    (index === 0 ? "?q=" + probe : "") + ' HTTP/1.1" 200 0\n',
  ).join("");
  await importLog(access, "access");
  assert.match(await evaluate("document.getElementById('import-message').textContent"), /Imported 26 events/);
  await click("#import-dialog [data-close]");
  await waitFor("document.getElementById('stat-open').textContent === '27'", "import refresh");
  console.log("PASS browser file import and automatic alert detection");

  await click('[data-view="alerts"]');
  await waitFor("document.getElementById('alert-pagination').textContent.includes('1–25 of 27')", "alert page one");
  await click("#alert-pagination button:last-child");
  await waitFor("document.getElementById('alert-pagination').textContent.includes('26–27 of 27')", "alert page two");
  await click("#alert-pagination button:first-child");
  await field('#alert-filters [name="severity"]', "high");
  await submit("#alert-filters");
  await waitFor("document.querySelectorAll('#alert-rows .row-link').length === 1", "severity filter");
  await click("#alert-rows .row-link");
  await waitFor("document.getElementById('analyst-status').disabled === false", "alert detail");
  await click("#evidence-rows button");
  await waitFor("document.getElementById('raw-log').textContent.includes('__evidenceExecuted')", "raw evidence");
  assert.equal(await evaluate("window.__evidenceExecuted"), undefined);
  assert.equal(await evaluate("document.querySelector('#raw-log script')"), null);
  assert.match(await evaluate("document.getElementById('raw-log').textContent"), /<script>/);
  await click("#event-dialog [data-close]");
  await field("#analyst-status", "resolved");
  await submit("#status-form");
  await waitFor("document.getElementById('status-message').textContent === 'Status saved.'", "status saved");
  await click("#alert-dialog [data-close]");
  await field('#alert-filters [name="status"]', "resolved");
  await submit("#alert-filters");
  await waitFor("document.querySelector('#alert-rows .badge.resolved') !== null", "status filter");
  console.log("PASS alert pagination, filters, nested raw evidence, XSS rendering, and status updates");

  await field('#common-filters [name="source_ip"]', "192.0.2.10");
  await field('#common-filters [name="start"]', "2026-10-06T09:00:00");
  await field('#common-filters [name="end"]', "2026-10-06T09:00:00");
  await submit("#common-filters");
  await click('[data-view="overview"]');
  await waitFor("document.getElementById('stat-events').textContent === '1'", "source/date filtered overview");
  assert.equal(await evaluate("document.getElementById('stat-open').textContent"), "1");
  await click("#clear-filters");
  await waitFor("document.getElementById('stat-events').textContent === '26'", "cleared filters");
  if (process.argv[2]) {
    const screenshot = await command("Page.captureScreenshot", { format: "png" });
    writeFileSync(resolve(process.argv[2]), Buffer.from(screenshot.data, "base64"));
  }
  console.log("PASS inclusive UTC filters, overview counts, and filter reset");

  await click('[data-view="events"]');
  await waitFor("document.getElementById('event-pagination').textContent.includes('1–25 of 26')", "event page one");
  await click("#event-pagination button:last-child");
  await waitFor("document.getElementById('event-pagination').textContent.includes('26–26 of 26')", "event page two");
  await field('#event-filters [name="log_type"]', "error");
  await submit("#event-filters");
  await waitFor("document.getElementById('event-pagination').textContent.includes('0 results')", "empty error filter");
  const error = "[Tue Oct 06 09:00:00.123456 2026] [core:error] AH00001: Synthetic failure\n";
  await importLog(error.repeat(10), "error", "-07:00");
  assert.match(await evaluate("document.getElementById('import-message').textContent"), /Imported 10 events/);
  await click("#import-dialog [data-close]");
  await waitFor("document.querySelectorAll('#event-rows button').length === 10", "error event list");
  await click("#event-rows button");
  await waitFor("document.getElementById('event-metadata').textContent.includes('UTC-07:00')", "error timezone");
  assert.match(await evaluate("document.getElementById('event-metadata').textContent"), /16:00:00.123456Z/);
  await click("#event-dialog [data-close]");
  await importLog(error, "access");
  assert.match(await evaluate("document.getElementById('import-message').textContent"), /No supported Apache access records/);
  assert.match(await evaluate("document.getElementById('import-summary').textContent"), /Imported events0/);
  await click("#import-dialog [data-close]");
  console.log("PASS event pagination, error timezone, empty results, and rejected import summary");

  await field('#common-filters [name="source_ip"]', "not-an-ip");
  await submit("#common-filters");
  await waitFor("document.getElementById('page-message').textContent.includes('IPv4 or IPv6')", "validation error");
  await evaluate(
    "(() => { const original = window.fetch; let fail = true; window.fetch = (...args) => {" +
    "if (args[0] === '/api/rules' && fail) { fail = false; return Promise.resolve(new Response(" +
    "JSON.stringify({error:{message:'Synthetic catalog failure'}}), " +
    "{status:503,headers:{'Content-Type':'application/json'}})); } return original(...args); }; })()",
  );
  await click('[data-view="rules"]');
  await waitFor("document.getElementById('page-message').textContent.includes('Synthetic catalog failure')",
    "catalog failure feedback");
  await click("#refresh");
  await waitFor("document.querySelectorAll('#rule-cards .rule-card').length === 11", "rule catalog");
  await waitFor("document.getElementById('refresh').disabled === false", "catalog recovery");
  assert.equal(await evaluate("document.getElementById('page-message').hidden"), true);
  assert.equal(await evaluate("document.getElementById('rule-filter').options.length"), 12);
  await click('[data-view="overview"]');
  await click("#clear-filters");
  await waitFor("document.getElementById('stat-events').textContent === '36'", "final overview");
  await command("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
  assert(await evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "Mobile layout overflows the viewport.");
  assert.deepEqual(exceptions, [], "Unexpected browser JavaScript errors.");
  console.log("PASS validation feedback, 11 rule cards, and mobile layout");

  // Run the published demo in a second, empty database so its documented
  // totals do not depend on the preceding browser scenarios.
  const demoWorkspace = join(workspace, "public-demo");
  let demoOutput = "";
  let demoUrl;
  demoServer = spawn(python, [join(root, "tests/browser_server.py"), demoWorkspace], {
    cwd: root, windowsHide: true,
    env: { ...process.env, APP_HOST: "127.0.0.1", APP_PORT: "5000", APP_DEBUG: "false",
      DATABASE_PATH: join(demoWorkspace, "browser.sqlite3") },
  });
  demoServer.on("error", (error) => { demoOutput += error.message; });
  demoServer.stdout.on("data", (data) => {
    demoOutput += data;
    const match = demoOutput.match(/\{"url":\s*"([^"]+)"\}/);
    if (match) demoUrl = match[1];
  });
  demoServer.stderr.on("data", (data) => { demoOutput += data; });
  await until(() => demoUrl, "public demo server");
  await command("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1050, deviceScaleFactor: 1, mobile: false });
  await command("Page.navigate", { url: demoUrl });
  await waitFor("document.getElementById('stat-events')?.textContent === '0'", "empty demo workspace");
  const expected = JSON.parse(readFileSync(join(root, "examples/expected.json"), "utf8"));
  for (const file of expected.files) {
    await importLog(readFileSync(join(root, "examples", file.name), "utf8"), file.log_type, "UTC", file.name);
    assert.match(await evaluate("document.getElementById('import-message').textContent"),
      new RegExp("Imported " + file.imported_events + " events"));
    await click("#import-dialog [data-close]");
  }
  await waitFor("document.getElementById('stat-events').textContent === '195'", "public demo totals");
  assert.equal(await evaluate("document.getElementById('stat-open').textContent"), String(expected.alerts));
  assert.equal(await evaluate("document.getElementById('stat-severe').textContent"), "6");
  assert.equal(await evaluate("document.getElementById('stat-sources').textContent"), String(expected.distinct_source_ips));
  await click('[data-view="alerts"]');
  await field("#rule-filter", "APACHE-REQUEST-BURST");
  await submit("#alert-filters");
  await waitFor("document.querySelectorAll('#alert-rows .row-link').length === 1", "demo burst rule filter");
  await click("#alert-rows .row-link");
  await waitFor("document.getElementById('evidence-pagination').textContent.includes('1–25 of 120')",
    "complete burst evidence");
  for (const range of ["26–50", "51–75", "76–100", "101–120"]) {
    await click("#evidence-pagination button:last-child");
    await waitFor("document.getElementById('evidence-pagination').textContent.includes('" + range + " of 120')",
      "demo evidence page " + range);
  }
  await click("#evidence-rows button");
  await waitFor("document.getElementById('event-metadata').textContent.includes('/demo_access.txt')",
    "demo upload provenance");
  assert.match(await evaluate("document.getElementById('event-metadata').textContent"), /Line number143/);
  await click("#event-dialog [data-close]");
  await field("#analyst-status", "false_positive");
  await submit("#status-form");
  await waitFor("document.getElementById('status-message').textContent === 'Status saved.'", "demo triage");
  await click("#alert-dialog [data-close]");
  await click('[data-view="overview"]');
  await waitFor("document.getElementById('stat-open').textContent === '10'", "demo triage statistics");
  assert.deepEqual(exceptions, [], "Unexpected browser JavaScript errors during the public demo.");
  console.log("PASS published demo: 195 events, 11 rules, all 120 burst evidence records, and analyst triage");
  console.log("All browser checks passed.");
} catch (error) {
  console.error(error);
  if (socket?.readyState === WebSocket.OPEN) {
    try { console.error(await evaluate("document.body.innerText")); } catch {}
  } else {
    console.error(serverOutput, browserOutput);
  }
  process.exitCode = 1;
} finally {
  if (socket?.readyState === WebSocket.OPEN) {
    try { await command("Browser.close"); } catch {}
    socket.close();
  }
  for (const child of [server, demoServer, browser]) {
    if (!child) continue;
    if (child.exitCode === null) child.kill();
    await until(() => child.exitCode !== null || child.signalCode !== null, "test process stopped", 5000).catch(() => {});
  }
  // Verify the resolved deletion target is the unique test directory we created
  // directly under the OS temporary root before removing it recursively.
  const target = realpathSync(workspace);
  assert.equal(dirname(target), temporaryRoot);
  assert(basename(target).startsWith("apache-dashboard-"));
  rmSync(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
