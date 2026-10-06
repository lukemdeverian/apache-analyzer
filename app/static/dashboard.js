"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const PAGE_SIZE = 25;
  const statusLabels = {
    new: "New", investigating: "Investigating", resolved: "Resolved", false_positive: "False positive",
  };
  const titles = {
    overview: ["Overview", "Import your logs. Follow the evidence."],
    alerts: ["Alerts", "Review suspicious activity and track your investigation."],
    events: ["Events", "Browse parsed records and their original evidence."],
    rules: ["Detection rules", "Eleven rules for Apache request patterns and server issues."],
  };
  const state = {
    view: "overview", common: {}, alerts: {}, events: {}, offsets: { alerts: 0, events: 0 },
    rules: new Map(), alert: null, evidenceOffset: 0, importing: false,
  };
  let loadSerial = 0;
  let alertSerial = 0;
  let eventSerial = 0;
  let evidenceSerial = 0;

  // Log-derived values always enter the document as text. Never interpret
  // request targets, messages, filenames, or raw evidence as HTML or URLs.
  function element(tag, text, className) {
    const result = document.createElement(tag);
    if (text !== undefined && text !== null) result.textContent = String(text);
    if (className) result.className = className;
    return result;
  }

  function message(id, text, kind = "error") {
    const target = $(id);
    target.textContent = text;
    target.className = "notice " + kind;
    target.hidden = !text;
  }

  async function api(path, options = {}) {
    let response;
    try {
      response = await fetch("/api/" + path, { cache: "no-store", ...options });
    } catch {
      throw new Error("Cannot reach the analyzer. Check that the local server is running, then refresh.");
    }
    let body;
    try {
      body = await response.json();
    } catch {
      throw new Error("The server returned an unreadable response. Refresh and try again.");
    }
    if (!response.ok) {
      const error = new Error(body.error?.message || "The request could not be completed.");
      error.summary = body.summary;
      throw error;
    }
    return body;
  }

  function query(values) {
    return new URLSearchParams(Object.entries(values).filter(([, value]) => value !== "")).toString();
  }

  function formValues(form, dates = false) {
    const result = {};
    for (const [key, raw] of new FormData(form)) {
      const value = raw.trim();
      if (!value) continue;
      result[key] = dates && (key === "start" || key === "end")
        ? value + (value.length === 16 ? ":00" : "") + "Z" : value;
    }
    return result;
  }

  function time(value) {
    return value ? value.replace("T", " ").replace(/(?:\.000000)?Z$/, "") : "—";
  }

  function badge(value, labels = null) {
    return element("span", labels ? labels[value] : value, "badge " + value);
  }

  function emptyRows(id, text, columns = 6) {
    const row = element("tr");
    const cell = element("td", text, "empty-state");
    cell.colSpan = columns;
    row.append(cell);
    $(id).replaceChildren(row);
  }

  function source(item) {
    return item.source_ip || item.source_host || (item.log_type ? "Not logged" : "Server-wide");
  }

  function alertRows(id, items) {
    if (!items.length) {
      emptyRows(id, "No alerts match. Import Apache logs or adjust the filters.");
      return;
    }
    const rows = items.map((item) => {
      const row = element("tr");
      const title = element("td");
      const button = element("button", item.title, "row-link");
      button.type = "button";
      button.addEventListener("click", () => {
        const hash = "#alerts/" + item.id;
        if (location.hash === hash) openAlert(item.id);
        else location.hash = hash;
      });
      title.append(button, element("span", item.rule_id, "row-subtitle"));
      const severity = element("td");
      severity.append(badge(item.severity));
      const status = element("td");
      status.append(badge(item.status, statusLabels));
      row.append(title, severity, element("td", source(item), "mono"), status,
        element("td", time(item.first_seen), "time-cell"), element("td", item.event_count, "mono"));
      return row;
    });
    $(id).replaceChildren(...rows);
  }

  function eventRows(id, items) {
    if (!items.length) {
      emptyRows(id, "No events match. Import Apache logs or adjust the filters.");
      return;
    }
    const rows = items.map((item) => {
      const row = element("tr");
      const summary = element("td", item.request || item.message || "Request not logged", "summary-cell mono");
      summary.title = summary.textContent;
      const details = element("td");
      const button = element("button", "View record", "text-button");
      button.type = "button";
      button.addEventListener("click", () => openEvent(item.id));
      details.append(button);
      row.append(element("td", time(item.timestamp), "time-cell"), element("td", item.log_type),
        element("td", source(item), "mono"), summary,
        element("td", item.status_code ?? item.level ?? "—", "mono"), details);
      return row;
    });
    $(id).replaceChildren(...rows);
  }

  function pagination(id, page, onChange) {
    const label = page.total && page.returned
      ? (page.offset + 1) + "–" + (page.offset + page.returned) + " of " + page.total.toLocaleString()
      : page.total ? "No records on this page · " + page.total.toLocaleString() + " total" : "0 results";
    const controls = element("div", null, "pagination-controls");
    for (const [text, disabled, offset] of [
      ["Previous", page.offset === 0, Math.max(0, page.offset - page.limit)],
      ["Next", !page.has_more, page.offset + page.limit],
    ]) {
      const button = element("button", text, "button secondary");
      button.type = "button";
      button.disabled = disabled;
      button.addEventListener("click", () => onChange(offset));
      controls.append(button);
    }
    $(id).replaceChildren(element("span", label), controls);
  }

  function metadata(id, entries) {
    $(id).replaceChildren(...entries.map(([label, value]) => {
      const group = element("div");
      group.append(element("dt", label), element("dd", value ?? "—"));
      return group;
    }));
  }

  function chartRow(label, count, total) {
    const row = element("div", null, "chart-row");
    const title = element("span", label);
    title.title = label;
    const bar = element("progress");
    bar.max = Math.max(total, 1);
    bar.value = count;
    bar.setAttribute("aria-label", label + ": " + count);
    row.append(title, bar, element("strong", count.toLocaleString()));
    return row;
  }

  function renderStats(stats) {
    $("stat-events").textContent = stats.events.total.toLocaleString();
    $("stat-open").textContent = stats.alerts.open.toLocaleString();
    $("stat-severe").textContent = (stats.alerts.by_severity.high + stats.alerts.by_severity.critical).toLocaleString();
    $("stat-sources").textContent = stats.events.distinct_source_ips.toLocaleString();
    $("alert-total").textContent = stats.alerts.total.toLocaleString() + " alerts";
    $("status-chart").replaceChildren(...Object.entries(statusLabels).map(([status, label]) =>
      chartRow(label, stats.alerts.by_status[status], stats.alerts.total)));
    const activity = Object.entries(stats.alerts.by_rule_id).sort((a, b) => b[1] - a[1]);
    $("activity-chart").replaceChildren(...(activity.length ? activity.map(([rule, count]) =>
      chartRow(state.rules.get(rule)?.title || rule, count, stats.alerts.total))
      : [element("p", "No detected activity in this selection.", "empty-state")]));
    $("history-range").textContent = stats.events.total
      ? time(stats.events.first_seen) + " → " + time(stats.events.last_seen) + " UTC"
      : "Import a log file to begin your investigation.";
  }

  async function loadRules() {
    const catalog = await api("rules");
    state.rules = new Map(catalog.items.map((item) => [item.rule_id, item]));
    const selected = $("rule-filter").value;
    const allRules = element("option", "All rules");
    allRules.value = "";
    $("rule-filter").replaceChildren(allRules);
    for (const item of catalog.items) {
      const option = element("option", item.title);
      option.value = item.rule_id;
      $("rule-filter").append(option);
    }
    $("rule-filter").value = selected;
    $("rule-cards").replaceChildren(...catalog.items.map((item) => {
      const card = element("article", null, "rule-card");
      const heading = element("header");
      heading.append(element("h2", item.title), badge(item.severity));
      const settings = item.settings
        ? item.settings.threshold + " records / " + item.settings.window_seconds + "s" +
          (item.settings.min_distinct_paths > 1 ? " / " + item.settings.min_distinct_paths + " distinct paths" : "")
        : "Each matching request · " + catalog.request_correlation_seconds + "s correlation gap";
      const details = element("div", null, "rule-settings");
      details.append(element("div", item.rule_id), element("div", item.log_type + " · " + settings));
      if (item.rule_id === "APACHE-UNUSUAL-METHOD") {
        details.append(element("div", "Expected: " + catalog.allowed_methods.join(", ")));
      }
      card.append(heading, element("p", item.description), details);
      return card;
    }));
  }

  async function refresh() {
    const serial = ++loadSerial;
    const view = state.view;
    message("page-message", "");
    $("load-status").textContent = "Loading " + view + ".";
    $("refresh").disabled = true;
    $("main").setAttribute("aria-busy", "true");
    if (view === "rules") {
      try {
        await loadRules();
        if (serial === loadSerial) $("load-status").textContent = "Detection rules loaded.";
      } catch (error) {
        if (serial === loadSerial) message("page-message", error.message);
      } finally {
        if (serial === loadSerial) {
          $("refresh").disabled = false;
          $("main").setAttribute("aria-busy", "false");
        }
      }
      return;
    }
    const table = view === "overview" ? "recent-alerts" : view === "alerts" ? "alert-rows" : "event-rows";
    emptyRows(table, "Loading records…");
    if (view === "overview") {
      for (const id of ["stat-events", "stat-open", "stat-severe", "stat-sources"]) $(id).textContent = "—";
      $("status-chart").replaceChildren();
      $("activity-chart").replaceChildren();
      $("alert-total").textContent = "";
      $("history-range").textContent = "Loading selected history…";
    } else {
      $(view === "alerts" ? "alert-pagination" : "event-pagination").replaceChildren();
    }
    const values = view === "overview" ? { ...state.common, limit: 5 }
      : { ...state.common, ...state[view], limit: PAGE_SIZE, offset: state.offsets[view] };
    try {
      const [stats, list] = await Promise.all([
        api("stats?" + query(state.common)),
        api((view === "events" ? "events?" : "alerts?") + query(values)),
        state.rules.size ? Promise.resolve() : loadRules(),
      ]);
      if (serial !== loadSerial) return;
      renderStats(stats);
      if (view === "events") eventRows(table, list.items);
      else alertRows(table, list.items);
      if (view !== "overview") {
        pagination(view === "alerts" ? "alert-pagination" : "event-pagination", list.pagination, (offset) => {
          state.offsets[view] = offset;
          refresh();
        });
      }
      $("load-status").textContent = list.pagination.total + " matching records loaded.";
    } catch (error) {
      if (serial !== loadSerial) return;
      message("page-message", error.message);
      emptyRows(table, "Records could not be loaded.");
      if (view === "overview") $("history-range").textContent = "History could not be loaded.";
      $("load-status").textContent = "Loading failed.";
    } finally {
      if (serial === loadSerial) {
        $("refresh").disabled = false;
        $("main").setAttribute("aria-busy", "false");
      }
    }
  }

  function renderAlert(item, requestedId) {
    state.alert = item;
    $("alert-identity").textContent = "ALERT #" + item.id +
      (String(item.id) !== String(requestedId) ? " · MERGED FROM #" + requestedId : "");
    $("alert-title").textContent = item.title;
    $("alert-description").textContent = item.description;
    metadata("alert-metadata", [
      ["Rule", item.rule_id], ["Severity", item.severity], ["Source", source(item)],
      ["Grouping", item.grouping_key], ["First seen (UTC)", item.first_seen],
      ["Last seen (UTC)", item.last_seen], ["Created (UTC)", item.created_at], ["Evidence records", item.event_count],
    ]);
    $("analyst-status").value = item.status;
    $("analyst-status").disabled = false;
    $("save-status").disabled = false;
    $("evidence-count").textContent = "(" + item.event_count + ")";
  }

  async function openAlert(identity) {
    const serial = ++alertSerial;
    ++evidenceSerial;
    state.alert = null;
    state.evidenceOffset = 0;
    $("alert-title").textContent = "Loading alert…";
    $("alert-identity").textContent = "ALERT";
    $("alert-description").textContent = "";
    $("alert-metadata").replaceChildren();
    $("evidence-pagination").replaceChildren();
    $("evidence-count").textContent = "";
    $("status-message").textContent = "";
    $("analyst-status").disabled = $("save-status").disabled = true;
    message("alert-message", "");
    emptyRows("evidence-rows", "Loading evidence…");
    if (!$("alert-dialog").open) $("alert-dialog").showModal();
    try {
      const [detail, evidence] = await Promise.all([
        api("alerts/" + identity), api("alerts/" + identity + "/events?limit=" + PAGE_SIZE),
      ]);
      if (serial !== alertSerial || !$("alert-dialog").open) return;
      renderAlert(detail.item, detail.requested_id);
      renderEvidence(evidence);
    } catch (error) {
      if (serial !== alertSerial || !$("alert-dialog").open) return;
      $("alert-title").textContent = "Alert unavailable";
      message("alert-message", error.message);
      emptyRows("evidence-rows", "Evidence could not be loaded.");
    }
  }

  function renderEvidence(evidence) {
    eventRows("evidence-rows", evidence.items);
    $("evidence-count").textContent = "(" + evidence.pagination.total + ")";
    pagination("evidence-pagination", evidence.pagination, loadEvidence);
  }

  async function loadEvidence(offset) {
    if (!state.alert) return;
    const serial = ++evidenceSerial;
    const identity = state.alert.id;
    state.evidenceOffset = offset;
    message("alert-message", "");
    emptyRows("evidence-rows", "Loading evidence…");
    $("evidence-pagination").replaceChildren();
    try {
      const evidence = await api("alerts/" + identity + "/events?" + query({ limit: PAGE_SIZE, offset }));
      if (serial !== evidenceSerial || !$("alert-dialog").open) return;
      renderEvidence(evidence);
    } catch (error) {
      if (serial !== evidenceSerial || !$("alert-dialog").open) return;
      message("alert-message", error.message);
      emptyRows("evidence-rows", "Evidence could not be loaded.");
    }
  }

  async function openEvent(identity) {
    const serial = ++eventSerial;
    $("event-title").textContent = "Event #" + identity;
    $("event-metadata").replaceChildren();
    $("parsed-fields").replaceChildren();
    $("raw-log").textContent = "Loading record…";
    message("event-message", "");
    if (!$("event-dialog").open) $("event-dialog").showModal();
    try {
      const { item } = await api("events/" + identity);
      if (serial !== eventSerial || !$("event-dialog").open) return;
      metadata("event-metadata", [
        ["Timestamp (UTC)", item.timestamp], ["Log format", item.log_format],
        ["Source", source(item)], ["Source file", item.source_file],
        ["Line number", item.line_number], ["Assumed timezone", item.assumed_timezone],
      ]);
      $("raw-log").textContent = item.raw_log;
      metadata("parsed-fields", Object.entries(item).filter(([key]) => key !== "raw_log"));
    } catch (error) {
      if (serial !== eventSerial || !$("event-dialog").open) return;
      message("event-message", error.message);
      $("raw-log").textContent = "Record unavailable.";
    }
  }

  $("status-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!state.alert) return;
    const serial = alertSerial;
    const identity = state.alert.id;
    const status = $("analyst-status").value;
    $("save-status").disabled = $("analyst-status").disabled = true;
    $("status-message").textContent = "Saving…";
    message("alert-message", "");
    try {
      const result = await api("alerts/" + identity + "/status", {
        method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status }),
      });
      if (serial === alertSerial && $("alert-dialog").open) {
        renderAlert(result.item, result.requested_id);
        $("status-message").textContent = "Status saved.";
      }
      await refresh();
    } catch (error) {
      if (serial !== alertSerial || !$("alert-dialog").open) return;
      message("alert-message", error.message);
      $("status-message").textContent = "";
    } finally {
      if (serial === alertSerial && state.alert) {
        $("save-status").disabled = $("analyst-status").disabled = false;
      }
    }
  });

  function importSummary(summary) {
    $("import-summary").hidden = false;
    metadata("import-summary", [
      ["Source label", summary.source_file], ["Lines read", summary.lines_read],
      ["Imported events", summary.imported_events], ["Rejected lines", summary.rejected_lines],
      ["Blank lines", summary.blank_lines], ["Malformed lines", summary.malformed_lines],
      ["Invalid UTF-8", summary.encoding_error_lines], ["Oversized lines", summary.oversized_lines],
      ["Out-of-range values", summary.invalid_value_lines],
      ...(summary.detection ? [
        ["New alerts", summary.detection.alerts_created], ["Alert updates", summary.detection.alert_updates],
        ["Merged alerts", summary.detection.alerts_merged],
      ] : []),
    ]);
  }

  function importBusy(busy) {
    state.importing = busy;
    for (const control of $("import-dialog").querySelectorAll("button, input, select")) control.disabled = busy;
    $("upload-timezone").disabled = busy || $("upload-type").value !== "error";
    $("import-submit").textContent = busy ? "Importing and analyzing…" : "Import and analyze";
  }

  $("import-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (state.importing) return;
    const file = $("upload-file").files[0];
    if (!file) return;
    $("import-summary").hidden = true;
    if (file.size > Number(document.body.dataset.maxUploadBytes)) {
      message("import-message", "Apache files must be no larger than 10 MiB.");
      return;
    }
    const body = new FormData($("import-form"));
    importBusy(true);
    message("import-message", "Importing records and checking stored history for alerts…", "pending");
    try {
      const { summary } = await api("imports", {
        method: "POST", headers: { "X-Apache-Upload": "1" }, body,
      });
      importSummary(summary);
      message("import-message", "Imported " + summary.imported_events.toLocaleString() + " events. " +
        summary.detection.alerts_created + " new alerts, " + summary.detection.alert_updates + " alert updates.", "");
      $("import-form").reset();
      state.offsets.alerts = state.offsets.events = 0;
      await refresh();
    } catch (error) {
      message("import-message", error.message);
      if (error.summary) importSummary(error.summary);
    } finally {
      importBusy(false);
    }
  });

  $("open-import").addEventListener("click", () => $("import-dialog").showModal());
  $("upload-type").addEventListener("change", () => {
    $("upload-timezone").disabled = $("upload-type").value !== "error";
  });
  $("import-dialog").addEventListener("cancel", (event) => {
    if (state.importing) event.preventDefault();
  });
  for (const button of document.querySelectorAll("[data-close]")) {
    button.addEventListener("click", () => {
      if (button.dataset.close === "import-dialog" && state.importing) return;
      $(button.dataset.close).close();
    });
  }
  $("alert-dialog").addEventListener("close", () => {
    if ($("alert-dialog").open) return;
    ++alertSerial;
    ++evidenceSerial;
    state.alert = null;
    if (location.hash.startsWith("#alerts/")) history.replaceState(null, "", "#alerts");
  });
  $("event-dialog").addEventListener("close", () => {
    if (!$("event-dialog").open) ++eventSerial;
  });

  $("common-filters").addEventListener("submit", (event) => {
    event.preventDefault();
    state.common = formValues(event.target, true);
    state.offsets.alerts = state.offsets.events = 0;
    refresh();
  });
  for (const view of ["alert", "event"]) {
    $(view + "-filters").addEventListener("submit", (event) => {
      event.preventDefault();
      state[view + "s"] = formValues(event.target);
      state.offsets[view + "s"] = 0;
      refresh();
    });
  }
  $("clear-filters").addEventListener("click", () => {
    for (const id of ["common-filters", "alert-filters", "event-filters"]) $(id).reset();
    state.common = state.alerts = state.events = {};
    state.offsets.alerts = state.offsets.events = 0;
    refresh();
  });
  $("refresh").addEventListener("click", refresh);

  function navigate() {
    const [candidate, identity] = location.hash.slice(1).split("/");
    const view = Object.hasOwn(titles, candidate) ? candidate : "overview";
    state.view = view;
    for (const section of document.querySelectorAll("[data-section]")) section.hidden = section.dataset.section !== view;
    for (const link of document.querySelectorAll("[data-view]")) {
      if (link.dataset.view === view) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
    $("page-title").textContent = titles[view][0];
    $("page-description").textContent = titles[view][1];
    document.title = titles[view][0] + " · Apache Analyzer";
    $("common-filters").hidden = view === "rules";
    if ($("event-dialog").open) $("event-dialog").close();
    const hasAlert = view === "alerts" && identity && /^[0-9]+$/.test(identity);
    if ($("alert-dialog").open && !hasAlert) $("alert-dialog").close();
    refresh();
    if (hasAlert) openAlert(identity);
  }

  window.addEventListener("hashchange", navigate);
  navigate();
})();
