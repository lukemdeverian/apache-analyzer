# Apache detection catalog

IP-level bot categories combine these risk alerts with site-browsing signals.
See [Bot traffic assessments](BOT_TRAFFIC.md) for the policy, evidence, and
developer review/export workflow. The catalog below lists the current rules.

Apache Analyzer has 12 built-in rules. Alerts identify evidence for review;
request signatures do not establish that a request succeeded. The catalog
returned by `GET /api/rules` and shown in the dashboard describes these defaults.
Custom Python engine settings apply only to the caller that uses them.

## Behavioral windows

Time windows include both ends and are evaluated in logged UTC time. These
four rules require a logged IP; a hostname alone does not create an IP group.
Paths use the logged path without its query string, retaining case and encoding.

| Rule ID | Qualifying evidence | Threshold / window | Severity | Review context |
| --- | --- | --- | --- | --- |
| `APACHE-PATH-ENUMERATION` | HTTP 403/404 from one IP across at least five distinct paths | 10 / 300s | Medium | Compare requested paths with broken links, crawlers, and expected discovery traffic. |
| `APACHE-HTTP-ERRORS` | HTTP 403/404 from one IP, including repeated paths or a missing request | 20 / 300s | Medium | Check application changes and automated clients repeatedly requesting unavailable resources. |
| `APACHE-AUTH-FAILURES` | HTTP 401 from one IP to the same path | 10 / 300s | High | Check expected authentication challenges, shared clients, and the application's authentication logs. |
| `APACHE-REQUEST-BURST` | Access records from one IP, at any response status | 120 / 60s | Medium | Compare with load tests, monitoring, busy clients, and multiple users behind a proxy. |

A qualifying window emits a finding at each matching anchor after reaching
its threshold. Correlation joins related findings into an incident; an alert's
evidence count can therefore exceed one window's threshold. Query variations
on one path do not increase the distinct-path count.

## Request signatures

Each parsed matching request produces a finding regardless of its response
status. Inspection checks the original path/query and up to two percent-decoding
passes without modifying stored evidence. These examples are recorded strings
from [demo_access.txt](../examples/demo_access.txt) and
[wordpress_probes.txt](../examples/wordpress_probes.txt), not requests to execute.

| Rule ID | Match | Demo target or method | Severity | Review context |
| --- | --- | --- | --- | --- |
| `APACHE-TRAVERSAL` | Parent-directory segments with slash or backslash separators | `/files/..%2Fprivate/report.txt` | High | Check the exact target and application path handling; text mentions of dots alone do not qualify. |
| `APACHE-SQL-INJECTION` | Selected SQL syntax, including UNION SELECT, literal comparisons, delay calls, and stacked statements | `/?id=1+UNION+SELECT+1` | High | Compare with permitted search/report inputs; a quote or the word select alone does not match. |
| `APACHE-XSS` | Script tags, HTML event-handler attributes, or JavaScript URIs | `/?q=%3Cscript%3EDEMO%3C%2Fscript%3E` | High | Check whether the input was reflected or rendered elsewhere; access logs do not contain the response body. |
| `APACHE-SENSITIVE-FILE` | Known configuration, credential, repository, database, and backup path components or suffixes | `/.env` | Medium | Check whether the resource is intentionally public. Query mentions of a filename do not qualify. |
| `APACHE-UNUSUAL-METHOD` | A parsed method outside the configured expected set | `TRACE / HTTP/1.1` | Medium | Check WebDAV, proxy, or application methods that the server intentionally accepts. |
| `APACHE-WORDPRESS-PROBE` | Unexpected WordPress installation, administration, login, or XML-RPC entry points | `/wp-admin/install.php?step=1` | High | One request is enough, even with a 404 response, language headers, or CSS activity. Check whether WordPress is expected on the selected site. |

Expected methods are GET, HEAD, POST, PUT, DELETE, PATCH, and OPTIONS;
comparisons are case-sensitive. Request signatures group by logged IP, otherwise
logged hostname, otherwise an unattributed group. Their default correlation gap
is 300 seconds. More than one signature can link the same event to different
alerts. XSS inspection also decodes bounded HTML entity references.

WordPress-probe matching uses the actual path only, with case-insensitive
components and up to two percent-decoding passes. It recognizes bare `wp-admin`
entry paths, `wp-admin/install.php`, `setup-config.php`, `upgrade.php`, `admin.php`,
and `index.php`, plus `wp-login.php` and `xmlrpc.php`, including subdirectory
installations. It does not flag ordinary `wp-content`/`wp-admin/css` assets,
`admin-ajax.php`, query-string mentions, referrer text, or user-agent text solely
for mentioning these URLs. Raw evidence remains unchanged.

These endpoints are unexpected under the study sites' policy; they are not
universally malicious. WordPress documents legitimate use of its
[installation script](https://developer.wordpress.org/advanced-administration/before-install/howto-install/).
If WordPress is intentionally hosted, review these alerts for false positives.
Any non-false-positive IP-attributed probe alert overrides CSS observations in
Bot traffic. Language preferences are neutral and never exempt a probe.

To apply a new detector to existing events, rescan rather than reimport:

```powershell
.\.venv\Scripts\python.exe -m flask --app app detect --domain chronoscrate --json
.\.venv\Scripts\python.exe -m flask --app app detect --domain la_jolla_seals --json
```

Restart the application to use updated detectors for future imports. These scans
reuse stored events and preserve analyst decisions; duplicate-file imports do
not substitute for explicit rescanning.

Sensitive paths include `.git`, `.svn`, `.hg`, `.env` variants, `.htaccess`,
`.htpasswd`, `wp-config.php`, `config.php`, `web.config`, `id_rsa`, and
`id_ed25519`, plus suffixes `.sql`, `.sqlite`, `.sqlite3`, `.db`, `.bak`,
`.old`, `.orig`, `.swp`, and `~`. Filename comparisons ignore case.

## User-Agent classification

User-Agent matching runs at assessment time, not import time, so no rescan is
needed after adding new log files. It is not a risk alert and produces no alert
ID; instead it sets or confirms the bot category directly. See
[User-Agent evidence](BOT_TRAFFIC.md#user-agent-evidence) for the full policy.

| Check | What it matches | Example |
| --- | --- | --- |
| Missing User-Agent | `"-"` or blank in a combined/extended-combined log line that has a request method | `"POST / HTTP/1.1" 200 … "-" "-"` |
| Security scanner | Exact names of known scanners and internet-survey tools | `zgrab`, `CensysInspect`, `Palo Alto Networks` (Xpanse), `Infrawatch`, `sqlmap`, `Nuclei`, `Hello, World`, `Odin`, `ModatScanner` |
| AI crawler or agent | Tokens from the vendored [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt) list, shown with the operator name | `GPTBot (OpenAI)`, `ClaudeBot (Anthropic)`, `Bytespider (ByteDance)`, `PerplexityBot` |
| Automation tool or HTTP library | Leading tool tokens, headless browsers, or a bare `Mozilla/5.0` | `curl`, `python-requests`, `Go-http-client`, `HeadlessChrome`, `python-urllib` |
| Self-declared crawler | Any word ending in `bot`, `crawler`, `spider`, `scraper`, `scanner`, or `Slurp` | `Googlebot`, `bingbot`, `AhrefsBot`, `360Spider` |

Checks run in the order above; the first match names the agent. A `"-" 408`
line is a spare browser connection that timed out before sending a request and
carries no headers; it is excluded. Common-format logs do not record the
User-Agent, so a missing header there is not flagged. CUBOT (an Android phone
brand) is excluded from the crawler check.

Before these checks apply, every IP is compared with the IP ranges that Google,
Microsoft, OpenAI, Apple, Perplexity, and DuckDuckGo publish for their
crawlers. An IP inside one is a **Verified crawler**. A User-Agent claiming one
of those crawlers from any other IP is flagged as impersonation. See
[Verified crawlers](BOT_TRAFFIC.md#verified-crawlers).

## Server-wide windows

These rules combine records across clients and imported files in the same
database, including events without a client IP. The resulting alert has no
single source IP; an IP filter excludes it. Use one database per server context.

| Rule ID | Qualifying evidence | Threshold / window | Severity | Review context |
| --- | --- | --- | --- | --- |
| `APACHE-SERVER-ERRORS` | HTTP 500-599 access responses | 20 / 60s | High | Check deployments, upstream failures, overload, and the corresponding Apache error records. |
| `APACHE-ERROR-BURST` | Parsed error, crit, alert, or emerg levels | 10 / 60s | High | Check module messages and server health. Words such as error in a notice message do not count. |

Warn, notice, info, debug, and trace records remain searchable evidence but do
not count toward the error burst. Defaults classify both burst alerts as high,
including when an individual error record has an emergency level.

## Evidence and analyst decisions

The detector inspects logged targets, methods, response statuses, and error
levels. Request bodies, cookies, response content, and application login
outcomes represented as 200/302 are unavailable in the supported formats.
Referrers, user agents, and error messages are not scanned as request targets.
Deeper encoding and application-specific obfuscation can evade the signatures.
HTTP status meanings follow [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.2);
error levels follow [Apache LogLevel](https://httpd.apache.org/docs/2.4/mod/core.html#loglevel).

Only new and investigating alerts extend automatically. Matching open incidents
within their correlation gap merge under the smallest ID and retain all evidence;
former IDs continue to resolve. Resolved and false-positive alerts preserve their
evidence and status during rescans. Fresh imported records can create a new
incident for review even for a previously reviewed time period. An explicit
status change to new or investigating reopens an alert.

See the [demo evidence map](../examples/README.md),
[workflow verification guide](VERIFICATION.md), and
[Python configuration examples](../README.md#apache-detections).
