// Optional real-browser checks. Uses Node's built-in WebSocket and a local
// Chromium browser; no npm packages or existing application data are needed.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { gzipSync } from "node:zlib";

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

async function importLog(text, logType, timezone = "UTC", filename = "browser-" + logType + ".log", domainId = "chronoscrate") {
  const content = typeof text === "string" ? JSON.stringify(text) :
    "Uint8Array.from(" + JSON.stringify([...text]) + ")";
  await click("#open-import");
  await evaluate(
    "(() => { const transfer = new DataTransfer(); transfer.items.add(new File([" +
    content + "], " + JSON.stringify(filename) + ", {type:" +
    JSON.stringify(typeof text === "string" ? "text/plain" : "application/gzip") + "})); " +
    "document.getElementById('upload-file').files = transfer.files; })()",
  );
  await field("#upload-type", logType);
  await field("#upload-domain", domainId);
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
  await waitFor("document.querySelectorAll('#rule-cards .rule-card').length === 12", "rule catalog");
  await waitFor("document.getElementById('refresh').disabled === false", "catalog recovery");
  assert.equal(await evaluate("document.getElementById('page-message').hidden"), true);
  assert.equal(await evaluate("document.getElementById('rule-filter').options.length"), 13);
  await click('[data-view="overview"]');
  await click("#clear-filters");
  await waitFor("document.getElementById('stat-events').textContent === '36'", "final overview");
  await command("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
  assert(await evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "Mobile layout overflows the viewport.");
  assert.deepEqual(exceptions, [], "Unexpected browser JavaScript errors.");
  console.log("PASS validation feedback, 12 rule cards, and mobile layout");

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
  assert.match(await evaluate("document.getElementById('upload-file').accept"), /\.gz/);
  for (const file of expected.files) {
    await importLog(gzipSync(readFileSync(join(root, "examples", file.name))), file.log_type, "UTC", file.name + ".gz");
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
  await waitFor("document.getElementById('event-metadata').textContent.includes('/demo_access.txt.gz')",
    "demo upload provenance");
  assert.match(await evaluate("document.getElementById('event-metadata').textContent"), /Line number143/);
  await click("#event-dialog [data-close]");
  await field("#analyst-status", "false_positive");
  await submit("#status-form");
  await waitFor("document.getElementById('status-message').textContent === 'Status saved.'", "demo triage");
  await click("#alert-dialog [data-close]");
  await click('[data-view="overview"]');
  await waitFor("document.getElementById('stat-open').textContent === '10'", "demo triage statistics");
  const damaged = gzipSync(readFileSync(join(root, "tests/fixtures/access_combined_extended.txt"))).subarray(0, -1);
  await importLog(damaged, "access", "UTC", "damaged.log.gz");
  assert.match(await evaluate("document.getElementById('import-message').textContent"), /Cannot read gzip log/);
  await click("#import-dialog [data-close]");
  assert.equal(await evaluate("document.getElementById('stat-events').textContent"), "195");
  assert.equal(await evaluate("document.getElementById('stat-open').textContent"), "10");
  assert.deepEqual(exceptions, [], "Unexpected browser JavaScript errors during the public demo.");
  console.log("PASS gzip demo: 195 events, 11 demo alerts, all 120 burst evidence records, triage, and damaged gzip feedback");
  await importLog(readFileSync(join(root, "examples/bot_traffic.txt"), "utf8"), "access", "UTC", "bot_traffic.txt");
  await click("#import-dialog [data-close]");
  await click('[data-view="bots"]');
  await waitFor("document.getElementById('bot-confirmed').textContent === '9'", "bot risk priority");
  assert.equal(await evaluate("document.getElementById('bot-suspected').textContent"), "23");
  assert.equal(await evaluate("document.getElementById('bot-normal').textContent"), "2");
  assert.equal(await evaluate("document.querySelectorAll('#bot-rows tr').length"), 25);
  await click("#bot-pagination button:last-child");
  await waitFor("document.querySelectorAll('#bot-rows tr').length === 9", "bot pagination");
  await field('#common-filters [name="source_ip"]', "203.0.113.201");
  await submit("#common-filters");
  await waitFor("document.querySelectorAll('#bot-rows .row-link').length === 1", "IP assessment filter");
  await click("#bot-rows .row-link");
  assert.match(await evaluate("document.getElementById('bot-title').textContent"), /Confirmed bot/);
  assert.match(await evaluate("document.getElementById('bot-metadata').textContent"), /Home page requests \(neutral\)1/);
  assert.match(await evaluate("document.getElementById('bot-metadata').textContent"), /Checkout requests \(neutral\)1/);
  assert.equal(await evaluate("document.querySelectorAll('#bot-browsing-evidence button').length"), 0);
  await click("#bot-risk-evidence button");
  await waitFor("document.getElementById('analyst-status').disabled === false", "bot linked alert");
  await field("#analyst-status", "false_positive");
  await submit("#status-form");
  await waitFor("document.getElementById('status-message').textContent === 'Status saved.'", "bot false positive status");
  await waitFor("document.getElementById('bot-suspected').textContent === '1'", "bot reclassification without CSS");
  assert.equal(await evaluate("document.getElementById('bot-normal').textContent"), "0");
  await click("#alert-dialog [data-close]");
  assert.equal(await evaluate("document.getElementById('export-bots').disabled"), true);
  await click("#bot-rows .row-link");
  assert.match(await evaluate("document.getElementById('bot-title').textContent"), /Suspected bot/);
  await click("#bot-dialog [data-close]");
  await click("#clear-filters");
  await waitFor("document.getElementById('bot-confirmed').textContent === '8'", "bot global counts after review");
  const downloadPath = join(workspace, "downloads");
  mkdirSync(downloadPath, { recursive: true });
  await command("Browser.setDownloadBehavior", { behavior: "allow", downloadPath });
  await click("#export-bots");
  const download = join(downloadPath, "ban-candidates.txt");
  await until(() => existsSync(download), "ban candidate download");
  const candidates = readFileSync(download, "utf8");
  assert.equal(candidates, await evaluate("fetch('/api/bots/export').then(response => response.text())"));
  assert.equal(candidates.trim().split("\n").length, 8);
  assert(!candidates.includes("203.0.113.201"), "False positive was exported for blocking.");
  await field('#bot-filters [name="classification"]', "not_a_bot");
  await submit("#bot-filters");
  await waitFor("document.querySelectorAll('#bot-rows .row-link').length === 2", "CSS category filter");
  assert.deepEqual(await evaluate("Array.from(document.querySelectorAll('#bot-rows tr td:first-child'), cell => cell.textContent).sort()"),
    ["203.0.113.203", "203.0.113.205"]);
  await click("#bot-rows .row-link");
  await click("#bot-browsing-evidence button");
  await waitFor("document.getElementById('raw-log').textContent.includes('.css')", "CSS raw evidence");
  await click("#event-dialog [data-close]");
  await click("#bot-dialog [data-close]");
  await click("#clear-filters");
  await field('#common-filters [name="source_ip"]', "203.0.113.202");
  await submit("#common-filters");
  await waitFor("document.getElementById('bot-suspected').textContent === '1'", "HTML-only visit is neutral");
  assert.equal(await evaluate("document.getElementById('bot-normal').textContent"), "0");
  await command("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
  assert.equal(await evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), true);
  assert.deepEqual(exceptions, [], "Unexpected browser errors in bot assessments.");
  console.log("PASS bot categories, pagination, IP filters, raw evidence, false-positive reclassification, candidate export, and mobile layout");
  await command("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1050, deviceScaleFactor: 1, mobile: false });
  await click("#clear-filters");
  const seals = '192.0.2.10 - - [21/Oct/2026:10:00:00 +0000] "GET https://protectlajollaseals.xyz/theme.css HTTP/1.1" 200 100 "-" "Synthetic browser"\n' +
    '192.0.2.20 - - [21/Oct/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 10 "-" "Synthetic browser"\n';
  await click("#open-import");
  assert.equal(await evaluate("document.getElementById('upload-domain').value"), "");
  assert.equal(await evaluate("document.getElementById('upload-domain').required"), true);
  await click("#import-dialog [data-close]");
  await importLog(gzipSync(Buffer.from(seals)), "access", "UTC", "seals.log.gz", "la_jolla_seals");
  assert.match(await evaluate("document.getElementById('import-summary').textContent"), /La Jolla Seals \(Namecheap\)/);
  assert.equal(await evaluate("document.getElementById('active-domain').value"), "la_jolla_seals");
  assert.match(await evaluate("location.search"), /domain_id=la_jolla_seals/);
  await click("#import-dialog [data-close]");
  await waitFor("document.getElementById('bot-confirmed').textContent === '1' && document.getElementById('bot-normal').textContent === '1'", "independent La Jolla assessments");
  assert.match(await evaluate("document.getElementById('bot-site').textContent"), /protectlajollaseals.xyz/);
  await click("#export-bots");
  const sealsDownload = join(downloadPath, "ban-candidates-la_jolla_seals.txt");
  await until(() => existsSync(sealsDownload), "domain-scoped ban candidate download");
  assert.equal(readFileSync(sealsDownload, "utf8"), "192.0.2.20\n");
  await click('[data-view="events"]');
  await waitFor("document.querySelectorAll('#event-rows button').length === 2", "La Jolla events");
  await click("#event-rows tr:last-child button");
  await waitFor("document.getElementById('raw-log').textContent.includes('protectlajollaseals.xyz/theme.css')", "domain-scoped event details");
  assert.match(await evaluate("document.getElementById('event-metadata').textContent"), /Namecheap/);
  await click("#event-dialog [data-close]");
  await field("#active-domain", "chronoscrate");
  await evaluate("document.getElementById('active-domain').dispatchEvent(new Event('change'))");
  await waitFor("document.getElementById('stat-events').textContent === '203'", "legacy domain preserved");
  await click('[data-view="bots"]');
  await waitFor("document.getElementById('bot-confirmed').textContent === '8'", "no cross-domain risk or CSS");
  await click('[data-view="comparison"]');
  await waitFor("document.querySelectorAll('#comparison-rows tr').length === 2", "domain comparison");
  assert.match(await evaluate("document.getElementById('comparison-rows').textContent"), /Dynadot/);
  assert.match(await evaluate("document.getElementById('comparison-rows').textContent"), /Namecheap/);
  assert.equal(await evaluate("document.querySelector('#comparison-rows tr:first-child td:nth-child(2)').textContent"), "193");
  assert.equal(await evaluate("document.querySelector('#comparison-rows tr:last-child td:nth-child(2)').textContent"), "2");
  assert.equal(await evaluate("document.querySelector('#comparison-rows tr:last-child td:last-child').textContent"), "50");
  await command("Page.navigate", { url: demoUrl + "/?domain_id=la_jolla_seals#alerts/1" });
  await waitFor("document.getElementById('alert-metadata')?.textContent.includes('Namecheap')", "domain-scoped deep link");
  assert.equal(await evaluate("document.getElementById('active-domain').value"), "la_jolla_seals");
  await field("#analyst-status", "false_positive");
  await submit("#status-form");
  await waitFor("document.getElementById('status-message').textContent === 'Status saved.'", "domain-specific analyst status");
  assert.equal(await evaluate("fetch('/api/alerts/1').then(response => response.json()).then(body => body.item.status)"), "new");
  await click("#alert-dialog [data-close]");
  await click('[data-view="comparison"]');
  await waitFor("document.querySelector('#comparison-rows tr:last-child td:last-child')?.textContent === '0'", "comparison follows analyst decision");
  await command("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
  assert.equal(await evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), true);
  assert.deepEqual(exceptions, [], "Unexpected browser errors during domain comparison.");
  console.log("PASS required domain selection, gzip import, independent events/alerts/bots/exports, deep links, comparison, and analyst isolation");
  const sealsBefore = await evaluate("fetch('/api/stats?domain_id=la_jolla_seals').then(response => response.json())");
  await importLog(gzipSync(Buffer.from(seals)), "access", "UTC", "renamed-seals.gz", "la_jolla_seals");
  assert.match(await evaluate("document.getElementById('import-message').textContent"), /Already imported/);
  assert.match(await evaluate("document.getElementById('import-summary').textContent"), /Imported events0/);
  assert.deepEqual(await evaluate("fetch('/api/stats?domain_id=la_jolla_seals').then(response => response.json())"), sealsBefore);
  await click("#import-dialog [data-close]");
  const repeatedCss = '198.51.100.200 - - [21/Oct/2026:12:00:00 +0000] "GET /assets/repeat-check.css HTTP/1.1" 200 123 "-" "Synthetic browser"\n';
  await importLog(repeatedCss.repeat(31), "access", "UTC", "repeat-lines.log");
  assert.match(await evaluate("document.getElementById('import-message').textContent"), /30 repeated lines retained/);
  assert.equal(await evaluate("document.getElementById('review-duplicate-lines').hidden"), false);
  await click("#review-duplicate-lines");
  await waitFor("document.getElementById('duplicate-pagination').textContent.includes('1–25 of 30')", "repeated-line page one");
  assert.equal(await evaluate("document.querySelectorAll('#duplicate-rows tr').length"), 25);
  await click("#duplicate-pagination button:last-child");
  await waitFor("document.getElementById('duplicate-pagination').textContent.includes('26–30 of 30')", "repeated-line page two");
  await click("#duplicate-rows tr:first-child td:last-child button");
  await waitFor("document.getElementById('raw-log').textContent.includes('/assets/repeat-check.css')", "repeated-line raw evidence");
  assert.match(await evaluate("document.getElementById('event-metadata').textContent"), /Line number27/);
  const repeatedRaw = await evaluate("document.getElementById('raw-log').textContent");
  await click("#event-dialog [data-close]");
  await click("#duplicate-rows tr:first-child td:nth-child(3) button");
  await waitFor("document.getElementById('event-metadata').textContent.includes('Line number1')", "first-occurrence evidence");
  assert.equal(await evaluate("document.getElementById('raw-log').textContent"), repeatedRaw);
  await click("#event-dialog [data-close]");
  await click("#duplicate-dialog [data-close]");
  await click("#import-dialog [data-close]");
  const primaryBefore = await evaluate("fetch('/api/stats').then(response => response.json())");
  await importLog(gzipSync(Buffer.from(repeatedCss.repeat(31))), "access", "UTC", "copy.gz");
  assert.match(await evaluate("document.getElementById('import-message').textContent"), /Already imported/);
  assert.match(await evaluate("document.getElementById('import-summary').textContent"), /repeat-lines.log/);
  assert.deepEqual(await evaluate("fetch('/api/stats').then(response => response.json())"), primaryBefore);
  await click("#review-duplicate-lines");
  await waitFor("document.querySelectorAll('#duplicate-rows tr').length === 25", "persisted repeated-line review");
  await click("#duplicate-dialog [data-close]");
  await click("#import-dialog [data-close]");
  await importLog(repeatedCss.repeat(31), "access", "UTC", "seals-repeats.log", "la_jolla_seals");
  assert.match(await evaluate("document.getElementById('import-message').textContent"), /Imported 31 events/);
  await click("#review-duplicate-lines");
  await waitFor("document.getElementById('duplicate-source').textContent.includes('seals-repeats.log')", "domain-scoped repetition review");
  assert.match(await evaluate("document.getElementById('duplicate-source').textContent"), /Namecheap/);
  await click("#duplicate-rows tr:first-child td:last-child button");
  await waitFor("document.getElementById('event-metadata').textContent.includes('seals-repeats.log')", "domain-scoped repeated record");
  assert.match(await evaluate("document.getElementById('event-metadata').textContent"), /Namecheap/);
  await click("#event-dialog [data-close]");
  await click("#duplicate-dialog [data-close]");
  await click("#import-dialog [data-close]");
  assert.deepEqual(exceptions, [], "Unexpected browser errors in duplicate prevention.");
  console.log("PASS file duplicate prevention, gzip/rename detection, retained repeated lines, paginated evidence review, and domain isolation");
  await command("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1050, deviceScaleFactor: 1, mobile: false });
  await click("#clear-filters");
  const historyIp = "198.51.100.77";
  const historyLines = Array.from({ length: 30 }, (_, index) =>
    historyIp + ' - - [21/Oct/2026:14:00:' + String(index).padStart(2, "0") +
    ' +0000] "GET /history/page-' + index + ' HTTP/1.1" 200 123 "-" "' +
    (index === 29 ? "<script>window.__requestReviewExecuted=true</script>" : "Synthetic client") + '"\n',
  ).join("");
  await importLog(historyLines +
    '198.51.100.78 - - [21/Oct/2026:14:00:15 +0000] "GET /other-ip HTTP/1.1" 200 123 "-" "Synthetic client"\n',
    "access", "UTC", "suspected-history.log");
  await click("#import-dialog [data-close]");
  await importLog("[Wed Oct 21 14:00:15.000000 2026] [core:notice] [client 198.51.100.77:1234] AH00001: Synthetic context\n",
    "error", "UTC", "history-error.log");
  await click("#import-dialog [data-close]");
  await click('[data-view="bots"]');
  await field('#common-filters [name="source_ip"]', historyIp);
  await submit("#common-filters");
  await waitFor("document.querySelectorAll('#bot-rows .row-link').length === 1", "suspected request-history IP");
  await click("#bot-rows .row-link");
  assert.match(await evaluate("document.getElementById('bot-title').textContent"), /Suspected bot/);
  await waitFor("document.getElementById('bot-request-pagination').textContent.includes('1–25 of 30')", "suspected request page one");
  assert.equal(await evaluate("document.querySelectorAll('#bot-request-rows tr').length"), 25);
  assert.equal(await evaluate("document.querySelector('#bot-request-rows tr:first-child td:nth-child(4)').textContent"), "GET /history/page-0 HTTP/1.1");
  assert.equal(await evaluate("Array.from(document.querySelectorAll('#bot-request-rows tr')).every(row => row.cells[1].textContent === 'access' && row.cells[2].textContent === '198.51.100.77')"), true);
  await click("#bot-request-pagination button:last-child");
  await waitFor("document.getElementById('bot-request-pagination').textContent.includes('26–30 of 30')", "suspected request page two");
  await click("#bot-request-rows tr:last-child button");
  await waitFor("document.getElementById('raw-log').textContent.includes('/history/page-29')", "suspected raw log request");
  assert.match(await evaluate("document.getElementById('event-metadata').textContent"), /suspected-history.log/);
  assert.match(await evaluate("document.getElementById('event-metadata').textContent"), /Line number30/);
  assert.equal(await evaluate("window.__requestReviewExecuted"), undefined);
  await click("#event-dialog [data-close]");
  assert.equal(await evaluate("document.getElementById('bot-dialog').open"), true);
  await click("#refresh-bot-requests");
  await waitFor("document.getElementById('bot-request-pagination').textContent.includes('1–25 of 30')", "request refresh resets pagination");
  await click("#bot-dialog [data-close]");
  await field('#common-filters [name="start"]', "2026-10-21T14:00:10");
  await field('#common-filters [name="end"]', "2026-10-21T14:00:12");
  await submit("#common-filters");
  await waitFor("document.querySelectorAll('#bot-rows .row-link').length === 1", "filtered suspected IP");
  await click("#bot-rows .row-link");
  await waitFor("document.getElementById('bot-request-count').textContent === '(3)'", "inclusive request date range");
  assert.deepEqual(await evaluate("Array.from(document.querySelectorAll('#bot-request-rows tr'), row => row.cells[3].textContent)"),
    ["GET /history/page-10 HTTP/1.1", "GET /history/page-11 HTTP/1.1", "GET /history/page-12 HTTP/1.1"]);
  await evaluate("(() => { const original = window.fetch; let fail = true; window.fetch = (...args) => {" +
    "if (String(args[0]).startsWith('/api/events?') && fail) { fail = false; return Promise.resolve(new Response(" +
    "JSON.stringify({error:{message:'Synthetic request history failure'}}), {status:503,headers:{'Content-Type':'application/json'}})); } " +
    "return original(...args); }; })()");
  await click("#refresh-bot-requests");
  await waitFor("document.getElementById('bot-request-message').textContent.includes('Synthetic request history failure')", "request history error feedback");
  await click("#refresh-bot-requests");
  await waitFor("document.querySelectorAll('#bot-request-rows button').length === 3", "request history retry");
  assert.equal(await evaluate("document.getElementById('bot-request-message').hidden"), true);
  await click("#bot-dialog [data-close]");
  await click("#clear-filters");
  await importLog(historyIp + ' - - [21/Oct/2026:14:00:15 +0000] "GET /seals-only HTTP/1.1" 200 123 "-" "Synthetic client"\n',
    "access", "UTC", "seals-history.log", "la_jolla_seals");
  await click("#import-dialog [data-close]");
  await field('#common-filters [name="source_ip"]', historyIp);
  await submit("#common-filters");
  await waitFor("document.querySelectorAll('#bot-rows .row-link').length === 1", "same IP on second domain");
  await click("#bot-rows .row-link");
  await waitFor("document.getElementById('bot-request-count').textContent === '(1)'", "domain-specific request history");
  assert.equal(await evaluate("document.querySelector('#bot-request-rows tr td:nth-child(4)').textContent"), "GET /seals-only HTTP/1.1");
  await click("#bot-request-rows button");
  await waitFor("document.getElementById('event-metadata').textContent.includes('seals-history.log')", "domain-scoped raw request");
  assert.match(await evaluate("document.getElementById('event-metadata').textContent"), /Namecheap/);
  await click("#event-dialog [data-close]");
  // Hold a response, switch domains, and ensure it cannot overwrite the new IP view.
  await evaluate("(() => { const original = window.fetch; let hold = true; window.fetch = (...args) => {" +
    "if (String(args[0]).startsWith('/api/events?') && hold) { hold = false; const response = original(...args); " +
    "return new Promise(resolve => { window.__releaseBotRequest = () => response.then(resolve); }); } return original(...args); }; })()");
  await click("#refresh-bot-requests");
  await waitFor("typeof window.__releaseBotRequest === 'function'", "held request history");
  await click("#bot-dialog [data-close]");
  await field("#active-domain", "chronoscrate");
  await evaluate("document.getElementById('active-domain').dispatchEvent(new Event('change'))");
  await waitFor("document.querySelectorAll('#bot-rows .row-link').length === 1", "reopened primary IP");
  await click("#bot-rows .row-link");
  await waitFor("document.getElementById('bot-request-count').textContent === '(30)'", "new domain request history");
  await evaluate("window.__releaseBotRequest()");
  await delay(100);
  assert.equal(await evaluate("document.getElementById('bot-request-count').textContent"), "(30)");
  assert.equal(await evaluate("document.querySelector('#bot-request-rows tr td:nth-child(4)').textContent"), "GET /history/page-0 HTTP/1.1");
  await command("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
  assert.equal(await evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), true);
  await click("#bot-dialog [data-close]");
  assert.deepEqual(exceptions, [], "Unexpected errors in suspected-bot request history.");
  console.log("PASS suspected-IP request history, pagination, raw evidence, date/IP/domain filters, retry, stale-response protection, and mobile layout");
  await command("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1050, deviceScaleFactor: 1, mobile: false });
  await click("#clear-filters");
  const wordpressIp = "198.51.100.91";
  const wordpress = wordpressIp + ' - - [24/Sep/2026:09:27:18 +0000] "GET /wp-admin/install.php?step=1 HTTP/1.1" 404 493 "-" "http://example.test/wp-admin/install.php?step=1" lang:"en-us,en;q=0.8,fr;q=0.5,fr-ca;q=0.3" enc:"gzip" sfm:"-" sfs:"-" sfd:"-" sfu:"-" chua:"-" chplat:"-" uir:"-" proto:HTTP/1.1 reqtime:342\n' +
    wordpressIp + ' - - [24/Sep/2026:09:27:19 +0000] "GET /style.css HTTP/1.1" 200 100 "-" "Synthetic browser"\n';
  await importLog(wordpress, "access", "UTC", "wordpress-probes.log");
  await click("#import-dialog [data-close]");
  await field('#common-filters [name="source_ip"]', wordpressIp);
  await submit("#common-filters");
  await waitFor("document.querySelectorAll('#bot-rows .row-link').length === 1", "WordPress probe IP");
  await click("#bot-rows .row-link");
  assert.match(await evaluate("document.getElementById('bot-title').textContent"), /Confirmed bot/);
  assert.match(await evaluate("document.getElementById('bot-metadata').textContent"), /Successful CSS requests1/);
  assert.match(await evaluate("document.getElementById('bot-metadata').textContent"), /Requests with language preference \(neutral\)1/);
  await click("#bot-risk-evidence button");
  await waitFor("document.getElementById('alert-title').textContent.includes('WordPress')", "WordPress alert explanation");
  await click("#evidence-rows button");
  await waitFor("document.getElementById('raw-log').textContent.includes('/wp-admin/install.php?step=1')", "original WordPress probe evidence");
  assert.match(await evaluate("document.getElementById('raw-log').textContent"), /404 493/);
  await click("#event-dialog [data-close]");
  await click("#alert-dialog [data-close]");
  assert.deepEqual(exceptions, [], "Unexpected browser errors in WordPress detection.");
  console.log("PASS single WordPress installer probe classified as confirmed despite CSS/language, with raw 404 evidence");
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
