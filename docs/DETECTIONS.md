# Apache detection catalog

Apache Analyzer has 11 built-in rules. Alerts identify evidence for review;
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
from [demo_access.txt](../examples/demo_access.txt), not requests to execute.

| Rule ID | Match | Demo target or method | Severity | Review context |
| --- | --- | --- | --- | --- |
| `APACHE-TRAVERSAL` | Parent-directory segments with slash or backslash separators | `/files/..%2Fprivate/report.txt` | High | Check the exact target and application path handling; text mentions of dots alone do not qualify. |
| `APACHE-SQL-INJECTION` | Selected SQL syntax, including UNION SELECT, literal comparisons, delay calls, and stacked statements | `/?id=1+UNION+SELECT+1` | High | Compare with permitted search/report inputs; a quote or the word select alone does not match. |
| `APACHE-XSS` | Script tags, HTML event-handler attributes, or JavaScript URIs | `/?q=%3Cscript%3EDEMO%3C%2Fscript%3E` | High | Check whether the input was reflected or rendered elsewhere; access logs do not contain the response body. |
| `APACHE-SENSITIVE-FILE` | Known configuration, credential, repository, database, and backup path components or suffixes | `/.env` | Medium | Check whether the resource is intentionally public. Query mentions of a filename do not qualify. |
| `APACHE-UNUSUAL-METHOD` | A parsed method outside the configured expected set | `TRACE / HTTP/1.1` | Medium | Check WebDAV, proxy, or application methods that the server intentionally accepts. |

Expected methods are GET, HEAD, POST, PUT, DELETE, PATCH, and OPTIONS;
comparisons are case-sensitive. Request signatures group by logged IP, otherwise
logged hostname, otherwise an unattributed group. Their default correlation gap
is 300 seconds. More than one signature can link the same event to different
alerts. XSS inspection also decodes bounded HTML entity references.

Sensitive paths include `.git`, `.svn`, `.hg`, `.env` variants, `.htaccess`,
`.htpasswd`, `wp-config.php`, `config.php`, `web.config`, `id_rsa`, and
`id_ed25519`, plus suffixes `.sql`, `.sqlite`, `.sqlite3`, `.db`, `.bak`,
`.old`, `.orig`, `.swp`, and `~`. Filename comparisons ignore case.

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
