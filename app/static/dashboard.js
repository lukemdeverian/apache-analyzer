"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const PAGE_SIZE = 25;
  const statusLabels = {
    new: "New", investigating: "Investigating", resolved: "Resolved", false_positive: "False positive",
  };
  const botLabels = { confirmed_bot: "Confirmed bot", suspected_bot: "Suspected bot", not_a_bot: "Not a bot" };
  const recommendations = {
    review_for_block: "Review for blocking", monitor_or_challenge: "Monitor or challenge", allow_and_monitor: "Allow and monitor",
  };
  const titles = {
    overview: ["Overview", "Import your logs. Follow the evidence."],
    alerts: ["Alerts", "Review suspicious activity and track your investigation."],
    events: ["Events", "Browse parsed records and their original evidence."],
    bots: ["Bot traffic", "Review IPs by risk alerts and successful CSS requests."],
    comparison: ["Domain comparison", "Compare observed traffic for Chronoscrate and La Jolla Seals."],
    rules: ["Detection rules", "Twelve rules for Apache request patterns and server issues."],
  };
  const state = {
    view: "overview", common: {}, alerts: {}, events: {}, bots: {}, offsets: { alerts: 0, events: 0, bots: 0 },
    rules: new Map(), alert: null, evidenceOffset: 0, importing: false, domain_id: "chronoscrate", importReview: null,
    botRequests: null,
  };
  let loadSerial = 0;
  let alertSerial = 0;
  let eventSerial = 0;
  let evidenceSerial = 0;
  let duplicateSerial = 0;
  let botRequestSerial = 0;
  const initialDomain = new URLSearchParams(location.search).get("domain_id");
  if (Array.from($("active-domain").options).some((option) => option.value === initialDomain)) {
    state.domain_id = initialDomain;
  }
  $("active-domain").value = state.domain_id;

  function domainLabel() {
    return $("active-domain").selectedOptions[0].textContent;
  }

  function applyDomain(domainId) {
    state.domain_id = domainId;
    $("active-domain").value = domainId;
    state.offsets.alerts = state.offsets.events = state.offsets.bots = 0;
    ++alertSerial;
    ++eventSerial;
    ++evidenceSerial;
    ++duplicateSerial;
    ++botRequestSerial;
    for (const id of ["alert-dialog", "event-dialog", "bot-dialog", "duplicate-dialog"]) {
      if ($(id).open) $(id).close();
    }
    const url = new URL(location.href);
    if (domainId === "chronoscrate") url.searchParams.delete("domain_id");
    else url.searchParams.set("domain_id", domainId);
    if (url.hash.startsWith("#alerts/")) url.hash = "#alerts";
    history.replaceState(null, "", url);
    $("bot-site").textContent = $("active-domain").selectedOptions[0].dataset.hostname;
    $("domain-caption").textContent = "Events, alerts, assessments, and exports are scoped to this website.";
  }

  function apiPath(path) {
    const url = new URL("/api/" + path, location.origin);
    if (state.domain_id !== "chronoscrate" && !path.startsWith("domains") && path !== "imports") {
      url.searchParams.set("domain_id", state.domain_id);
    }
    return url.pathname + url.search;
  }

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
      response = await fetch(apiPath(path), { cache: "no-store", ...options });
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

  function openBot(item) {
    state.botRequests = {
      domainId: state.domain_id,
      filters: { ...state.common, source_ip: item.source_ip, log_type: "access", order: "asc" },
    };
    $("bot-title").textContent = item.source_ip + " · " + item.label;
    metadata("bot-metadata", [
      ["Website", domainLabel()],
      ["Recommendation", recommendations[item.recommendation]], ["Requests", item.request_count],
      ["First seen (UTC)", time(item.first_seen)], ["Last seen (UTC)", time(item.last_seen)],
      ["Home page requests (neutral)", item.home_requests], ["Checkout requests (neutral)", item.checkout_requests],
      ["HTML requests (neutral)", item.html_requests], ["Successful CSS requests", item.css_requests],
      ["Requests with language preference (neutral)", item.language_requests],
      ["Requests with a logged language field", item.language_logged_requests],
      ["Observed languages", item.languages.join(", ") || "Not observed"],
      ["Risk alerts", item.risk_alert_count],
    ]);
    $("bot-reasons").replaceChildren(...item.reasons.map((reason) => element("li", reason)));
    $("bot-risk-evidence").replaceChildren(...(item.risk_alerts.length
      ? item.risk_alerts.map((alert) => {
        const button = element("button", "#" + alert.id + " " + alert.title + " · " + alert.status, "text-button");
        button.type = "button";
        button.addEventListener("click", () => {
          $("bot-dialog").close();
          openAlert(alert.id);
        });
        return button;
      }) : [element("p", "No IP-attributed risk alerts in this selection.", "muted")]));
    $("bot-browsing-evidence").replaceChildren(...(item.browsing_evidence.length
      ? item.browsing_evidence.map((proof) => {
        const button = element("button", proof.signal.replaceAll("_", " ") + " · Event #" + proof.event_id, "text-button");
        button.type = "button";
        button.addEventListener("click", () => openEvent(proof.event_id));
        return button;
      }) : [element("p", "No successful CSS requests in this selection.", "muted")]));
    if (!$("bot-dialog").open) $("bot-dialog").showModal();
    loadBotRequests();
  }

  async function loadBotRequests(offset = 0) {
    const context = state.botRequests;
    if (!context || context.domainId !== state.domain_id) return;
    const serial = ++botRequestSerial;
    message("bot-request-message", "");
    $("bot-request-count").textContent = "";
    $("bot-requests").setAttribute("aria-busy", "true");
    emptyRows("bot-request-rows", "Loading requests…");
    $("bot-request-pagination").replaceChildren();
    try {
      const result = await api("events?" + query({ ...context.filters, limit: PAGE_SIZE, offset }));
      if (serial !== botRequestSerial || !$("bot-dialog").open || state.botRequests !== context) return;
      eventRows("bot-request-rows", result.items);
      $("bot-request-count").textContent = "(" + result.pagination.total.toLocaleString() + ")";
      pagination("bot-request-pagination", result.pagination, loadBotRequests);
    } catch (error) {
      if (serial !== botRequestSerial || !$("bot-dialog").open || state.botRequests !== context) return;
      message("bot-request-message", error.message);
      emptyRows("bot-request-rows", "Requests could not be loaded. Select Refresh requests to try again.");
    } finally {
      if (serial === botRequestSerial && $("bot-dialog").open) $("bot-requests").setAttribute("aria-busy", "false");
    }
  }

  $("refresh-bot-requests").addEventListener("click", () => loadBotRequests());
  $("bot-dialog").addEventListener("close", () => {
    if ($("bot-dialog").open) return;
    ++botRequestSerial;
    state.botRequests = null;
  });

  function botRows(items, summary) {
    $("bot-confirmed").textContent = summary.by_classification.confirmed_bot.toLocaleString();
    $("bot-suspected").textContent = summary.by_classification.suspected_bot.toLocaleString();
    $("bot-normal").textContent = summary.by_classification.not_a_bot.toLocaleString();
    $("bot-scope").textContent = summary.total + " IPs assessed. " + summary.unattributed_requests +
      " access requests lack a usable IP. Counts cover the shared IP/date filters.";
    $("export-bots").disabled = summary.ban_candidates === 0;
    if (!items.length) {
      emptyRows("bot-rows", "No IPs match. Import Apache access logs or adjust the filters.");
      return;
    }
    $("bot-rows").replaceChildren(...items.map((item) => {
      const row = element("tr"), classification = element("td"), details = element("td");
      classification.append(badge(item.classification, botLabels));
      const button = element("button", "Review IP", "row-link");
      button.type = "button";
      button.addEventListener("click", () => openBot(item));
      details.append(button);
      row.append(element("td", item.source_ip, "mono"), classification,
        element("td", recommendations[item.recommendation]), element("td", item.request_count, "mono"),
        element("td", time(item.last_seen), "time-cell"), details);
      return row;
    }));
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
    if (view === "comparison") {
      emptyRows("comparison-rows", "Loading domain comparison…");
      try {
        const result = await api("domains/comparison?" + query(state.common));
        if (serial !== loadSerial) return;
        $("comparison-rows").replaceChildren(...result.items.map((item) => {
          const row = element("tr"), site = element("td");
          site.append(element("strong", item.domain.name),
            element("span", item.domain.hostname + " · " + item.domain.provider, "row-subtitle"));
          const categories = item.bots.by_classification;
          row.append(site, element("td", item.access_requests.toLocaleString()),
            element("td", item.alerts.total.toLocaleString()),
            element("td", item.alerts_per_1000_requests ?? "—"),
            element("td", [categories.confirmed_bot, categories.suspected_bot, categories.not_a_bot].join(" / ")),
            element("td", item.confirmed_bot_ip_percent ?? "—"));
          return row;
        }));
        $("load-status").textContent = "Domain comparison loaded.";
      } catch (error) {
        if (serial === loadSerial) {
          message("page-message", error.message);
          emptyRows("comparison-rows", "Comparison could not be loaded. Initialize both site databases with init-db.");
        }
      } finally {
        if (serial === loadSerial) {
          $("refresh").disabled = false;
          $("main").setAttribute("aria-busy", "false");
        }
      }
      return;
    }
    const table = view === "overview" ? "recent-alerts" : view === "alerts" ? "alert-rows" : view === "bots" ? "bot-rows" : "event-rows";
    emptyRows(table, "Loading records…");
    if (view === "overview") {
      for (const id of ["stat-events", "stat-open", "stat-severe", "stat-sources"]) $(id).textContent = "—";
      $("status-chart").replaceChildren();
      $("activity-chart").replaceChildren();
      $("alert-total").textContent = "";
      $("history-range").textContent = "Loading selected history…";
    } else {
      $(view === "alerts" ? "alert-pagination" : view === "bots" ? "bot-pagination" : "event-pagination").replaceChildren();
      if (view === "bots") {
        for (const id of ["bot-confirmed", "bot-suspected", "bot-normal"]) $(id).textContent = "—";
        $("export-bots").disabled = true;
        $("bot-scope").textContent = "Loading assessments…";
      }
    }
    const values = view === "overview" ? { ...state.common, limit: 5 }
      : { ...state.common, ...state[view], limit: PAGE_SIZE, offset: state.offsets[view] };
    try {
      const [stats, list] = await Promise.all([
        api("stats?" + query(state.common)),
        api((view === "events" ? "events?" : view === "bots" ? "bots?" : "alerts?") + query(values)),
        state.rules.size ? Promise.resolve() : loadRules(),
      ]);
      if (serial !== loadSerial) return;
      renderStats(stats);
      if (view === "bots") botRows(list.items, list.summary);
      else if (view === "events") eventRows(table, list.items);
      else alertRows(table, list.items);
      if (view !== "overview") {
        pagination(view === "alerts" ? "alert-pagination" : view === "bots" ? "bot-pagination" : "event-pagination", list.pagination, (offset) => {
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
      ["Website", domainLabel()],
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
        ["Website", domainLabel()],
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
    state.importReview = summary.import_id || summary.duplicate_of_import_id;
    $("review-duplicate-lines").hidden = !state.importReview || !summary.duplicate_lines;
    metadata("import-summary", [
      ["Website", summary.domain ? summary.domain.name + " (" + summary.domain.provider + ")" : "Not supplied"],
      ["Outcome", summary.duplicate_file ? "Already imported; no changes" : summary.import_id ? "New import" : "No import saved"],
      ["Import ID", state.importReview],
      ...(summary.duplicate_file ? [["Original source", summary.duplicate_of_source_file],
        ["Duplicate file events skipped", summary.skipped_duplicate_events]] : []),
      [summary.duplicate_file ? "Repeated lines in original import" : "Repeated lines retained for review", summary.duplicate_lines ?? 0],
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

  async function loadDuplicateLines(offset = 0) {
    if (!state.importReview) return;
    const serial = ++duplicateSerial;
    message("duplicate-message", "");
    emptyRows("duplicate-rows", "Loading repeated lines…", 4);
    $("duplicate-pagination").replaceChildren();
    try {
      const result = await api("imports/" + state.importReview + "/duplicates?" + query({ limit: PAGE_SIZE, offset }));
      if (serial !== duplicateSerial || !$("duplicate-dialog").open) return;
      $("duplicate-source").textContent = domainLabel() + " · " + result.import.source_file;
      if (!result.items.length) emptyRows("duplicate-rows", "No repeated lines.", 4);
      else $("duplicate-rows").replaceChildren(...result.items.map((item) => {
        const row = element("tr");
        row.append(element("td", item.original_line_number), element("td", item.line_number));
        for (const [label, identity] of [["Original record", item.original_event_id], ["Repeated record", item.event_id]]) {
          const cell = element("td"), button = element("button", label, "text-button");
          button.type = "button";
          button.addEventListener("click", () => openEvent(identity));
          cell.append(button);
          row.append(cell);
        }
        return row;
      }));
      pagination("duplicate-pagination", result.pagination, loadDuplicateLines);
    } catch (error) {
      if (serial === duplicateSerial && $("duplicate-dialog").open) message("duplicate-message", error.message);
    }
  }

  $("review-duplicate-lines").addEventListener("click", () => {
    $("duplicate-source").textContent = "";
    $("duplicate-dialog").showModal();
    loadDuplicateLines();
  });
  $("duplicate-dialog").addEventListener("close", () => {
    if (!$("duplicate-dialog").open) ++duplicateSerial;
  });

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
    $("review-duplicate-lines").hidden = true;
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
      applyDomain(summary.domain_id);
      importSummary(summary);
      message("import-message", summary.duplicate_file
        ? "Already imported for this website. Skipped " + summary.skipped_duplicate_events + " events; no event or alert changes."
        : "Imported " + summary.imported_events.toLocaleString() + " events. " +
          summary.detection.alerts_created + " new alerts, " + summary.detection.alert_updates + " alert updates." +
          (summary.duplicate_lines ? " " + summary.duplicate_lines + " repeated lines retained for review." : ""), "");
      $("import-form").reset();
      state.offsets.alerts = state.offsets.events = state.offsets.bots = 0;
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
    state.offsets.alerts = state.offsets.events = state.offsets.bots = 0;
    refresh();
  });
  for (const view of ["alert", "event", "bot"]) {
    $(view + "-filters").addEventListener("submit", (event) => {
      event.preventDefault();
      state[view + "s"] = formValues(event.target);
      state.offsets[view + "s"] = 0;
      refresh();
    });
  }
  $("clear-filters").addEventListener("click", () => {
    for (const id of ["common-filters", "alert-filters", "event-filters", "bot-filters"]) $(id).reset();
    state.common = state.alerts = state.events = state.bots = {};
    state.offsets.alerts = state.offsets.events = state.offsets.bots = 0;
    refresh();
  });
  $("refresh").addEventListener("click", refresh);
  $("active-domain").addEventListener("change", () => {
    applyDomain($("active-domain").value);
    refresh();
  });
  $("export-bots").addEventListener("click", async () => {
    $("export-bots").disabled = true;
    try {
      const response = await fetch(apiPath("bots/export?" + query(state.common)), { cache: "no-store" });
      if (!response.ok) {
        const body = await response.json();
        throw new Error(body.error?.message || "Export failed.");
      }
      const url = URL.createObjectURL(await response.blob());
      const link = element("a");
      link.href = url;
      link.download = state.domain_id === "chronoscrate" ? "ban-candidates.txt" : "ban-candidates-" + state.domain_id + ".txt";
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      message("page-message", error.message);
    } finally {
      $("export-bots").disabled = $("bot-confirmed").textContent === "0";
    }
  });

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
    $("domain-selector").hidden = view === "comparison";
    $("bot-site").textContent = $("active-domain").selectedOptions[0].dataset.hostname;
    $("domain-caption").textContent = "Events, alerts, assessments, and exports are scoped to this website.";
    if ($("event-dialog").open) $("event-dialog").close();
    if ($("bot-dialog").open) $("bot-dialog").close();
    const hasAlert = view === "alerts" && identity && /^[0-9]+$/.test(identity);
    if ($("alert-dialog").open && !hasAlert) $("alert-dialog").close();
    refresh();
    if (hasAlert) openAlert(identity);
  }

  window.addEventListener("hashchange", navigate);
  navigate();
})();
