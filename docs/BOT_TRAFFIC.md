# Bot traffic assessments

Select Chronoscrate (**chronoscrate.xyz**) or La Jolla Seals
(**protectlajollaseals.xyz**), then open **Bot traffic** after importing its logs.
Existing imports work after restarting the application. Assessments use stored
evidence and current analyst decisions. After the required init-db schema upgrade,
existing logs need no reimport. [Duplicate prevention](DUPLICATE_IMPORTS.md)
stops repeated files from increasing counts; historical duplicates are preserved.
Plain and gzip imports use the same logic.

Labels implement the requested policy and do not prove an IP is a bot or human.
Bots can request normal pages and legitimate visitors can trigger risk rules.
Review the linked evidence before applying a block. More comprehensive systems
combine multiple kinds of signals; see [Cloudflare's detection engines](https://developers.cloudflare.com/bots/concepts/bot-detection-engines/).

## Categories

Rules are evaluated in this order:

| Category | Evidence | Recommendation |
| --- | --- | --- |
| Confirmed bot | An unexpected WordPress entry-point request, any risk alert attributed to this IP and linked to access evidence in the selected history, a cached threat-intelligence hit (AbuseIPDB score ≥ 70 or OTX reputation 1), or a [User-Agent that declares automation](#user-agent-evidence) | Review for blocking |
| Not a bot | No qualifying probe or risk alert, plus a successful CSS request | Allow and monitor |
| Suspected bot | Neither of the above; insufficient normal browsing evidence | Monitor or challenge |

**Any IP-attributed risk alert overrides normal browsing**, regardless of severity.
New, investigating, and resolved alerts count. **False positive** alerts do not.
Changing the last qualifying alert to false positive updates the assessment and
export on refresh. Server-wide HTTP-500 and Apache-error bursts do not identify
an individual malicious visitor and are not assigned to every IP involved.

An unexpected WordPress entry point such as `/wp-admin/install.php?step=1`
produces an IP-attributed `APACHE-WORDPRESS-PROBE` alert from one request,
including a 404 response. It takes priority over CSS requests and language
headers. Bot assessment also checks the stored request path directly, so existing
requests confirm bots without a saved alert, reimport, or detection rescan. A
false-positive decision on a linked WordPress alert excludes its requests from
this direct check; it does not exempt other requests by the same IP. The details
show probe counts and up to ten raw-record links. Probe counts exclude dismissed
requests. See the [detection catalog](DETECTIONS.md) for matching and rescan commands.

Verify address attribution before acting on a ban candidate. For example,
`104.23.187.194` falls within `104.16.0.0/13` on
[Cloudflare's published IP list](https://www.cloudflare.com/ips-v4); the logged
address may be a proxy rather than the original visitor. Apache's
[trusted-proxy logging](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html)
supports original-client attribution when configured correctly. This analyzer
does not infer an unlogged original IP or change server configuration.

Suspected bot is an uncertainty category. A missing language header, absent CSS,
or a single unknown-page request alone does not justify a ban. The app exports
recommendations for review and never changes the website or firewall.

## CSS evidence and neutral context

- CSS evidence means GET with a 2xx or 304 response, where the path ends in
  `.css` (case insensitive) or the log includes `sfd:"style"`. Failed responses,
  redirects, HEAD, and POST do not count. Query strings are excluded when
  identifying the resource, so `/theme.css?v=1` counts but `/?file=theme.css` does not.
- CSS alone suggests normal browsing. Neither a previous HTML request nor a
  language preference is required, and there is no multi-request time-window
  requirement. Evidence links point directly to a successful CSS request.
- Absolute HTTP(S) targets must name the selected website. An absolute CSS request
  for another website does not supply this site's normal-browsing signal.
- HTML, home-page visits, checkout visits, and language preferences are neutral.
  Their counts remain visible for context but never change a category.
- `/`, `/checkout`, and `/checkout/` are tracked page paths. HTML context also
  includes `.html`/`.htm` paths and `sfd:"document"` requests. Successful visits
  to these paths without CSS remain Suspected bot if there are no risk alerts.
- Language context comes from `lang`, `accept-language`, or `accept_language`
  in extended combined evidence. Names are case insensitive. Valid specific
  language tags with nonzero preference weights are listed without favoring any
  language. Missing or ambiguous preferences remain unavailable and do not
  affect CSS-based classification.

[Accept-Language](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept-Language)
expresses client language preferences. It does not verify identity. Logs also
cannot show whether the browser rendered HTML/CSS or executed JavaScript.

## Threat intelligence (AbuseIPDB and AlienVault OTX)

Reputation lookups can move IPs out of **Suspected bot** or **Not a bot** into
**Confirmed bot**. An IP is confirmed when either provider reports it:

| Provider | Value used | Confirms a bot when |
| --- | --- | --- |
| AbuseIPDB | `data.abuseConfidenceScore` from `/api/v2/check` (last 90 days) | Score is 70 or higher |
| AlienVault OTX | `reputation` from `/api/v1/indicators/IPv4/{ip}/general` (or `IPv6`) | Reputation is 1 (malicious) |

Thresholds live in `THRESHOLDS` in `app/threat_intel.py`. Raw scores are cached,
so a changed threshold applies without re-querying. The OTX reputation field is
binary (0 = clean, 1 = malicious), so the threshold of 1 means any malicious report.

**Keys.** Copy `threat_intel_keys.example.toml` to `threat_intel_keys.toml`
(already present and ignored by git) and list keys under `[abuseipdb]` and
`[otx]`. Keys are tried in order. A key that returns HTTP 429 (rate or session
limit) is skipped until its `Retry-After` time (default one hour), and a key
that returns 401/403 is skipped for an hour; the next key is used and the run
continues. When every key for one provider is used up, the other provider keeps
going. Three consecutive network or server errors pause that provider for the
run; failed lookups are retried next time.

**Running lookups.** Lookups never happen while viewing assessments. Select
**Check IP reputation** on the Bot traffic page, which checks the selected
website's IPs in batches of 20 until done or out of keys, or run:

```powershell
.\.venv\Scripts\python.exe -m flask --app app threat-intel            # both websites
.\.venv\Scripts\python.exe -m flask --app app threat-intel --domain la_jolla_seals --limit 100 --json
```

Only public (globally routable) IPs that are not already confirmed by local
evidence are sent. Results are cached in `instance/threat_intel.sqlite3`, shared
by both websites, and never expire (`--refresh` or `?refresh=true`
re-checks). Reputation is third-party opinion: shared cloud, VPN, and proxy
addresses can be listed because of other users. Review before blocking.

## User-Agent evidence

A client that announces itself as automated is a bot by its own account, so one
such request confirms the IP and overrides CSS evidence. The rules come from
[Cloudflare's bot score](https://developers.cloudflare.com/bots/concepts/bot-score/)
(a missing User-Agent is scored as automated) and the log-only method in
[Shy Guys (arXiv 2603.28546)](https://arxiv.org/abs/2603.28546). Checks run in
this order, and the first match names the agent:

| Category | Matches | Example |
| --- | --- | --- |
| Missing User-Agent | `"-"` or blank in a combined log, when a request line was received | `"POST / HTTP/1.1" 200 … "-" "-"` |
| Security scanner | Known scanner and internet-survey names | `zgrab`, `CensysInspect`, `Palo Alto Networks` (Xpanse), `Infrawatch`, `sqlmap`, `Nuclei`, `Hello, World` |
| AI crawler or agent | Tokens from the [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt) list, with the operator | `GPTBot (OpenAI)`, `ClaudeBot`, `Bytespider`, `CCBot`, `PerplexityBot` |
| Automation tool or HTTP library | Leading tool tokens, headless browsers, or a bare `Mozilla/5.0` | `curl/8.4.0`, `python-requests`, `Go-http-client`, `HeadlessChrome` |
| Self-declared crawler | Any word ending in `bot`, `crawler`, `spider`, `scraper`, `scanner`, or `Slurp` | `Googlebot`, `bingbot`, `AhrefsBot`, `360Spider` |

Exclusions that prevent false positives:

- Common-format logs never record the header, so absence there means nothing.
- A `"-" 408` line is a spare browser connection that timed out before sending
  anything; it has no headers to judge.
- ai.robots.txt tokens that are ordinary words or desktop-app names (`Code`,
  `Cursor`, `Dot`, `Operator`, `Muse`, and others in `_AMBIGUOUS_AI_TOKENS`)
  are skipped because they appear in Electron app User-Agents.
- `CUBOT` (an Android phone brand) is not treated as a crawler name.

The bot details list each distinct agent (up to ten) with its request count and
a link to the first matching record; hover the link to see the full header.

**Limits.** A browser-like User-Agent proves nothing; scrapers copy real Chrome
strings, and those IPs stay in Suspected unless other evidence applies. Search
engines that declare themselves (Googlebot, bingbot) are also confirmed and
exported. Check them against the operator's published IP ranges before
blocking. Legitimate crawlers can be impersonated, and a genuine crawler may
be one you want to allow.

The ai.robots.txt list is vendored in `app/data/ai_robots.json` under its MIT
license (`app/data/ai_robots.LICENSE`). To update it, replace the file with
the upstream `robots.json`; no reimport is needed.

## Apache logging

Standard common/combined logs already support CSS path detection; no extra
headers are required. The existing bot-tracking format also supplies optional
language context and fetch destination. An example Apache configuration is:

```apache
LogFormat "%a %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" lang:\"%{Accept-Language}i\" sfd:\"%{Sec-Fetch-Dest}i\"" bot_tracking
CustomLog logs/bot-tracking-access.log bot_tracking
```

Apache's [mod_log_config reference](https://httpd.apache.org/docs/2.4/mod/mod_log_config.html)
documents the client-IP and request-header directives. Configure logging on the
website's server if needed; the analyzer does not alter server configuration.
Behind a proxy/CDN, verify that the logged IP is the original client before
blocking it. One IP can represent multiple visitors.

Import this site's logs separately. Origin-form Apache requests omit the host,
so the analyzer cannot identify mixed websites from those records. The page
paths come from the supplied requirements; classification never crawls the site.

## Developer workflow

1. Select the source IP and a relevant UTC date range for the incident.
2. Review Confirmed bot IPs first. **Review IP** shows reasons, page/asset/language
   counts, timestamps, and linked evidence. Every classification, including
   Suspected bot, also shows **Requests made by this IP**. Historical risk alone should not
   automatically produce a permanent block.
3. Open an alert to inspect all evidence or mark it false positive.
4. Select **Export ban candidates** to download `ban-candidates.txt`, with one
   canonical IP per line. Review the list before applying your own controls.

Cards cover the shared IP/date filters. The category selector narrows the table.
Export always contains **all confirmed IPs matching the shared filters**,
regardless of table category or pagination. Unattributed requests are counted
separately and never exported. Details show up to ten recent alert samples and
a CSS evidence link; each alert retains its complete paginated evidence.

The IP request-history table is available even when there are no alerts or CSS
signals. It shows all access requests for that IP and selected website/date
range, including unsuccessful requests and requests that triggered no alert.
Rows show timestamp, request, HTTP status, and a **View record** link to the raw
log, source file, physical line number, and parsed fields. Error-log messages
are not access requests and are excluded from this table.

History is ordered oldest first with 25 requests per page. **Refresh requests**
reloads the first page for the current selection and also retries failed loads.
Closing raw evidence returns to the same IP request-history page. Switching
websites closes the IP details; pending requests cannot overwrite another site's
history. No reimport or schema change is needed for this view.

## APIs

`GET /api/bots` accepts `domain_id`, `source_ip`, `start`, `end`, `classification`, `limit`,
`offset`, and `order`. Categories are `confirmed_bot`, `suspected_bot`, and
`not_a_bot`. Validation and UTC formats match other investigation endpoints.
Categories appear in risk-priority order; `order=desc` (default) or `asc` sorts
last-seen times within each category.

The response contains `items`, `pagination`, `summary`, and `policy`. Each item
includes reasons, recommendation, timestamps, counts, bounded language samples,
risk-alert samples, CSS evidence event IDs, `wordpress_probe_count`, and up to ten
`wordpress_probe_evidence` event IDs. HTML/page/language counts are
informational. Policy metadata exposes the CSS criterion and neutral signals;
the previous HTML/language sequence and its five-minute window have been removed.
Summary counts precede the category
filter. Alert attribution uses linked evidence timestamps within the selected
range even if a correlated alert started earlier.

The dashboard loads the full request history separately through `/api/events`,
using the selected `domain_id`, the IP's `source_ip`, `log_type=access`, shared
`start`/`end` bounds, `order=asc`, and standard `limit`/`offset` pagination.

`GET /api/bots/export` accepts `domain_id`, `source_ip`, `start`, and `end` and returns
the text attachment. No confirmed IPs produces an empty file. Both endpoints
are read only, use a consistent database snapshot, and require initialization.
They scan matching history; memory grows with IP count rather than request count.

`POST /api/bots/threat-intel` accepts the same filters plus `refresh=true` and
requires an empty JSON body (`{}` with `Content-Type: application/json`), so
other websites cannot trigger lookups. It checks one batch and returns
`processed`, `remaining`, `can_continue`, per-provider `checked`/`errors`, and
key status (`keys_rate_limited`, `keys_rejected`, `stopped`). It returns 409
`threat_intel_not_configured` when no keys are set. Bot items include
`threat_intel` (cached results with score, threshold, and `malicious`) and
`threat_intel_hits`; the summary adds `threat_intel_confirmed` and `threat_intel_checked`.
Items also include `declared_agent_count` and `declared_agents` (category,
label, name, reason, raw `user_agent`, first `event_id`, and `requests`); the
summary adds `declared_agent_confirmed`, and `policy` adds `user_agent_policy`.

```powershell
Invoke-RestMethod 'http://127.0.0.1:5000/api/bots?classification=confirmed_bot&limit=25'
Invoke-WebRequest 'http://127.0.0.1:5000/api/bots/export' -OutFile ban-candidates.txt
```

## Synthetic example

Import [bot_traffic.txt](../examples/bot_traffic.txt) as an access log into a
fresh workspace. Eight events produce one sensitive-file alert:

Choose **Chronoscrate** for this synthetic sample. See the
[two-domain guide](MULTI_DOMAIN.md) for isolation and comparison behavior.

| IP | Category | Reason |
| --- | --- | --- |
| 203.0.113.201 | Confirmed bot | Sensitive-file risk alert; page visits are neutral |
| 203.0.113.202 | Suspected bot | Home page without CSS; insufficient evidence |
| 203.0.113.203 | Not a bot | Successful CSS request; HTML and language are neutral |
| 203.0.113.204 | Suspected bot | Unknown page; insufficient normal evidence |
| 203.0.113.205 | Not a bot | Successful CSS request without HTML |

The export initially contains only `203.0.113.201`. Mark its alert false positive
and refresh: it becomes Suspected bot because it has no CSS evidence, and the
export becomes empty. All addresses are documentation addresses.
