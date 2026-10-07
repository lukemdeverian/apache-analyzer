# Apache demonstration files

These files contain synthetic records, invented messages, and documentation
addresses. The IPv4 ranges follow [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737.html)
and the IPv6 addresses use the prefix in [RFC 3849](https://www.rfc-editor.org/rfc/rfc3849.html).
Importing the files reads their text; it does not send the logged requests or
execute their targets. No real Apache server is needed.

Use the [demo walkthrough](../docs/VERIFICATION.md) to select a fresh, separate
SQLite database and load the files. The [detection catalog](../docs/DETECTIONS.md)
explains what each alert means and what to review.

| File | Format | Imported events | Malformed / blank lines | Alerts in a fresh database |
| --- | --- | --- | --- | --- |
| [demo_access.txt](demo_access.txt) | Common and combined access | 185 | 1 / 1 | 10 |
| [demo_error.txt](demo_error.txt) | Standard error, timezone UTC | 10 | 1 / 1 | 1 |
| [benign_access.txt](benign_access.txt) | Common and combined access | 9 | 0 / 0 | 0 |
| [benign_error.txt](benign_error.txt) | Standard error, timezone UTC | 4 | 0 / 0 | 0 |

Importing the two demo files once with default rules produces **195 events,
11 new alerts, 29 distinct logged IPs, 6 high alerts, and 5 medium alerts**.
Both files deliberately start with a malformed line followed by a blank line
so their summaries demonstrate rejection counts. All timestamps are on
2026-10-06; use UTC for the error log and clear dashboard date filters.

The expected evidence is listed below. Every rule produces one alert. Line
numbers are physical file lines, including the initial malformed and blank
lines. All rows refer to demo_access.txt except the final error-log row.

| Rule | Evidence lines | Evidence records | Logged source |
| --- | --- | --- | --- |
| `APACHE-PATH-ENUMERATION` | 3-12 | 10 | 192.0.2.10 |
| `APACHE-HTTP-ERRORS` | 13-32 | 20 | 192.0.2.20 |
| `APACHE-AUTH-FAILURES` | 33-42 | 10 | 192.0.2.30 |
| `APACHE-REQUEST-BURST` | 43-162 | 120 | 192.0.2.40 |
| `APACHE-TRAVERSAL` | 163 | 1 | 192.0.2.50 |
| `APACHE-SQL-INJECTION` | 164 | 1 | 192.0.2.51 |
| `APACHE-XSS` | 165 | 1 | 2001:db8::52 |
| `APACHE-SENSITIVE-FILE` | 166 | 1 | 192.0.2.53 |
| `APACHE-UNUSUAL-METHOD` | 167 | 1 | 192.0.2.54 |
| `APACHE-SERVER-ERRORS` | 168-187 | 20 | Server-wide |
| `APACHE-ERROR-BURST` | demo_error.txt: 3-12 | 10 | Server-wide |

[expected.json](expected.json) records the import counts, alert counts, source
IPs, evidence ranges, and first/last timestamps used by the workflow checks.
It is verification metadata, not an input log file.

The benign samples include sparse traffic, ordinary search text, one 401
challenge, expected HTTP methods, a logged hostname, and non-severe Apache
error levels. Importing both into an empty database produces **13 events and
zero alerts**. Loading them before the two demo files produces **208 events
and the same 11 demo alerts**.

These counts assume each file is imported once with the built-in defaults.
Repeating an import adds events and can extend alerts or meet additional
thresholds. Repeating detection without adding events leaves existing alerts
and analyst statuses unchanged.
