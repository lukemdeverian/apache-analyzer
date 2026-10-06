# Apache Analyzer

A local Apache log analyzer inspired by [Nightwatch](https://github.com/lukemdeverian/nightwatch).
It is being built in 10 reviewable increments, with a pause after each increment
so you can commit the changes yourself. See [ROADMAP.md](ROADMAP.md) for the sequence.

The target application accepts Apache access and error log files, stores evidence
in SQLite, detects suspicious Apache activity, and presents alerts in a local
Flask dashboard. It runs directly on Python without Docker or a database server.
The initial implementation is written specifically for this repository, using
Nightwatch's separation of parsing, storage, detection, and presentation as a reference.

## Current progress: increment 9 of 10

Implemented:

- Flask application factory and a JSON health endpoint.
- Environment configuration with validation and local defaults.
- Development entry point and configuration example.
- Isolated tests for startup settings and application health.
- Apache common/combined access and standard/legacy error parsers.
- Normalized UTC event records with original evidence and optional file/line provenance.
- Synthetic fixtures covering escaped fields, IPv6, missing values, and malformed records.
- SQLite event and alert storage with versioned schema initialization.
- Atomic alert/evidence writes, foreign-key protection, and indexed query helpers.
- Persistence, filtering, transaction rollback, and database CLI tests.
- Streaming Apache file ingestion with an explicit access/error format selection.
- Human-readable and JSON import summaries, bounded line reads, and rejection counts.
- Atomic file imports with file/line provenance and optional error-log UTC offsets.
- Four behavioral detection rules with configurable thresholds and rolling time windows.
- Read-only findings containing rule details, logged IP, timestamps, and full evidence IDs.
- Detection checks for thresholds, boundary times, benign traffic, and out-of-order imports.
- Five request signatures for traversal, SQL injection, XSS, sensitive files, and unusual methods.
- Server-wide windows for HTTP 5xx responses and severe Apache error-log records.
- Bounded inspection decoding, preserved original evidence, and configurable expected HTTP methods.
- Automatic detection and persistent alert correlation during CLI file imports.
- Replay deduplication, backfill handling, complete evidence links, and atomic pipeline rollback.
- Analyst status commands, preserved merged-alert references, and a version 1-to-2 schema upgrade.
- Paginated JSON APIs for events, alerts, chronological evidence, and analyst status changes.
- Default rule catalog and database statistics with source-IP and date filters.
- API validation, JSON error responses, consistent read snapshots, and atomic status updates.
- Local dashboard with overview charts, filters, paginated lists, and alert/event details.
- Browser imports with explicit Apache format selection, size limits, rejection counts, and atomic analysis.
- Literal raw-evidence rendering, analyst status controls, responsive layout, and real-browser checks.

File ingestion, detection/correlation, and analyst status updates are available
through the dashboard, CLI, and Python. Investigation APIs are also available
over HTTP. Demo logs and the final workflow guide are planned for increment 10.
The dashboard HTML, `GET /health`, and `GET /api/rules` load without opening a
database; dashboard data requests require an initialized schema.

## Run locally

Use Python 3.11 or newer. From this directory in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -m flask --app app init-db
.\.venv\Scripts\python.exe run.py
```

Open <http://127.0.0.1:5000/> for the dashboard. The health check is available
at <http://127.0.0.1:5000/health>:

```json
{"service": "apache-analyzer", "status": "ok"}
```

For macOS or Linux, replace the virtual environment executable with
`.venv/bin/python` and copy the configuration using `cp .env.example .env`.
For running without development tools, install `requirements.txt` instead.

If your Python installation does not include pip, the equivalent setup with uv is:

```powershell
uv venv .venv
uv pip install --python .\.venv\Scripts\python.exe -r requirements-dev.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -m flask --app app init-db
.\.venv\Scripts\python.exe run.py
```

## Configuration

`run.py` loads `.env` from the project directory. Existing environment variables
take precedence over that file. The Flask CLI also loads `.env` when run from
this directory. Settings are read when the app is created.

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_HOST` | `127.0.0.1` | Local listening address |
| `APP_PORT` | `5000` | Listening port, from 1 through 65535 |
| `APP_DEBUG` | `false` | Development debugger and automatic reload |
| `DATABASE_PATH` | `apache_analyzer.sqlite3` | Local SQLite file; relative paths resolve under `instance/` |

Debug values accept `true`/`false`, `1`/`0`, `yes`/`no`, or `on`/`off`,
case-insensitively. Invalid settings stop startup with a named validation error.
The intended runtime is a local development application; authentication and
remote deployment are outside the current scope.

## Use the dashboard

Start the server and open <http://127.0.0.1:5000/> in a modern browser. The
dashboard uses bundled HTML, CSS, and JavaScript; no Node.js installation,
frontend build, or external assets are needed to run the application.

1. Select **Import logs**, choose a plain UTF-8 Apache file, and explicitly
   select **Apache access log** or **Apache error log**. For error logs, enter
   the server's fixed UTC offset, such as `-07:00`, or leave `UTC`.
2. Select **Import and analyze**. The summary shows imported records, blank and
   rejected lines, new alerts, and correlated alert updates. The overview refreshes
   after a successful import. Reimporting adds another copy of the file's events.
3. Browse **Alerts** and filter by status, severity, or rule. Open an alert to
   review detection details and its linked evidence, then save an analyst status.
4. Select **View record** to inspect the raw log, source label, line number,
   and parsed fields. **Events** also lets you browse evidence independently of
   alerts, including records that did not trigger a rule.

The shared source-IP and UTC date filters apply to overview counts and record
lists. Alert date filters select **first_seen**; event date filters select their
timestamps. The overview includes all analyst statuses in the selected history;
its open-alert count includes new and investigating alerts. Alert-specific
filters affect the alert list. **Clear** resets all filters. Lists and linked
evidence use 25-record pages; **Refresh** picks up changes made through the CLI.
**Detection rules** describes all 11 built-in defaults. Alert details can also
be opened directly using a URL such as `/#alerts/1`, including former merged IDs.

Browser files are limited to 10 MiB, with an additional 64 KiB allowance for
multipart request metadata. Each physical log line uses the CLI's default
64 KiB limit; oversized lines are counted and skipped. Compressed files and
custom Apache log layouts are not supported. Files without any supported
records are rejected with a summary and leave the database unchanged.

Uploads are copied to unique temporary files under `instance/uploads/` and
removed before the import commits. Events and their alert changes commit
together; read, storage, analysis, or cleanup failures roll back the import.
Stored provenance uses `upload:<unique-id>/<sanitized-filename>` and the original
physical line number, so repeated filenames remain distinguishable after the
temporary copy is removed. CLI imports continue to record their absolute paths.

Requests, messages, filenames, and raw logs are displayed as literal text.
Missing databases show initialization guidance; initialize explicitly with
`flask --app app init-db` before importing. The dashboard does not initialize
or upgrade storage automatically.

## Import Apache log files

Run `init-db` to initialize the database or upgrade one from an earlier increment,
then choose the log type explicitly. Imports now detect and save alerts automatically.
You can try the committed synthetic fixtures:

```powershell
.\.venv\Scripts\python.exe -m flask --app app ingest .\tests\fixtures\access_combined.txt --format access
.\.venv\Scripts\python.exe -m flask --app app ingest .\tests\fixtures\error_standard.txt --format error --error-timezone=-07:00 --json
```

Replace the fixture path with your Apache log file. File extensions do not affect
parser selection. Common/combined access records use `--format access`; standard
and legacy error records use `--format error`. Files are read as UTF-8 text, with
LF or CRLF line endings, an optional initial UTF-8 signature, and an optional
unterminated final line. The importer reads regular files and preserves their
contents. Each stored event includes the resolved source path, its physical line
number, and raw evidence. The initial UTF-8 signature is retained in raw evidence.

`--error-timezone` accepts `UTC` (the default) or a signed offset such as `-07:00`
or `+05:30`. It applies that fixed offset to every error timestamp in the file.
Access timestamps use their own logged offsets. The chosen error timezone is
included in both the summary and stored records.

Each record is limited to 65536 bytes by default, excluding its line ending.
Change this with `--max-line-bytes`, from 1 through 1048576. Oversized lines are
drained through bounded reads and counted once; the remaining file continues to
be processed. The file reader uses bounded buffers; detection retains evidence
in active time windows while scanning.

The successful summary reports:

| Field | Meaning |
| --- | --- |
| `lines_read` | Physical lines encountered, including blanks and rejected records |
| `imported_events` | Records saved by this import |
| `blank_lines` | Empty or whitespace-only lines skipped |
| `malformed_lines` | Lines that do not match the selected Apache layout |
| `encoding_error_lines` | Lines that cannot be decoded as UTF-8 |
| `oversized_lines` | Lines larger than the chosen byte limit |
| `invalid_value_lines` | Parsed values that cannot be represented in storage, such as oversized integers |
| `rejected_lines` | Total malformed, encoding-error, oversized, and invalid-value lines |

Add `--json` to print the successful summary as JSON. It also contains
`source_file`, `log_type`, `assumed_timezone`, and a nested `detection` summary.
Blank and rejected lines are
skipped; an import must contain at least one usable Apache record to succeed.
An empty file, a wrong format choice, or unrelated log content produces a
nonzero exit code with a rejection summary.

Each file and its detection scan are saved in a single transaction. A file-read,
detector, or database failure rolls back that import's events and all alert/evidence
creations, updates, and merges from the scan. Earlier imports remain intact.
Repeating a successful import appends new events, which count as fresh evidence.
Collection is batch-oriented: the importer reads to EOF and does not follow
log rotation. Each scan replays all stored evidence in timestamp order, so late
imports can complete earlier detection windows. Scan time therefore grows with
stored history.

Both import summaries and explicit detection scans report:

| Detection field | Meaning |
| --- | --- |
| `findings` | Qualifying request/window findings examined across stored history |
| `alerts_created` | New alert records created |
| `alert_updates` | Correlation update operations, including multiple updates to the same alert |
| `alerts_merged` | Open alert records combined into retained alerts |
| `findings_unchanged` | Findings whose evidence was already represented by the same rule/group |

Analyze previously stored records without importing another file:

```powershell
.\.venv\Scripts\python.exe -m flask --app app detect --json
```

Repeating `detect` with unchanged evidence and settings creates no duplicate
alerts, evidence links, or status changes.

## Local storage

Storage uses Python's built-in SQLite module without an ORM or extra database
dependency. Database connections open on demand and close at the end of the
Flask application context. Initialize the configured database with:

```powershell
.\.venv\Scripts\python.exe -m flask --app app init-db
```

This creates the database file, parent directory, tables, and indexes. Schema
version 2 adds `alert_merges` to retain references to combined alert IDs.
For an owned version 1 database, the same command upgrades it atomically while
preserving events, alerts, statuses, and evidence links. Run it once when updating
from increment 6 or earlier. Repeating it preserves existing data. A failed upgrade
rolls back the new schema and version together. The application identifier and
version marker reject unrelated, unrecognized, and unsupported databases.

`DATABASE_PATH` accepts a filesystem path. Database URLs and SQLite URI options
are rejected. Tests can use `connect_database(":memory:")` directly for isolated
in-memory storage.

`SQLiteStore` provides these helpers:

| Helper | Behavior |
| --- | --- |
| `insert_event(event)` / `get_event(id)` | Save and retrieve every normalized field plus raw evidence |
| `list_events(...)` / `count_events(...)` | Filter by source IP, log type, and inclusive timestamp range |
| `iter_events(...)` | Stream all events matching those filters in timestamp/ID order without a page limit |
| `insert_alert(alert, event_ids)` / `get_alert(id)` | Atomically save an alert and links to existing evidence |
| `correlate_alert(alert, event_ids, max_gap_seconds=...)` | Create, extend, or merge open alerts for fresh evidence in the same rule/group |
| `set_alert_status(id, status)` | Set an analyst status while preserving evidence and detection times |
| `list_alerts(...)` / `count_alerts(...)` | Filter by source IP, rule, severity, status, and inclusive first-seen range |
| `get_alert_events(id, ...)` | Retrieve linked evidence in timestamp/ID order |
| `statistics(...)` | Aggregate event and alert totals by source IP and inclusive date range |

List helpers default to 100 records and accept `limit` (1–1000) and `offset`.
Event and alert lists sort chronologically with stable ID ordering; set
`newest_first=True` to reverse the order. Time filters require timezone-aware
datetimes. Timestamps are stored in a fixed UTC format that preserves microseconds.
Results include the database ID and the typed `event` or `alert` value; stored
alerts also include an evidence `event_count`. Missing event/alert IDs return
`None`, and missing alert evidence returns an empty list.

After initializing the database, a Python caller can persist parsed evidence:

```python
from app import create_app
from app.database import get_database, transaction
from app.parsers import parse_apache_line
from app.storage import SQLiteStore

app = create_app()
with app.app_context():
    connection = get_database()
    store = SQLiteStore(connection)
    event = parse_apache_line(
        '192.0.2.10 - - [06/Oct/2026:09:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234',
        "access", source_file="access.log", line_number=1,
    )
    if event is not None:
        with transaction(connection):
            event_id = store.insert_event(event)
        print(store.get_event(event_id))
```

Standalone event writes commit immediately. Use `transaction(connection)` to
commit a batch together or roll it back on an exception. Alert creation requires
at least one existing event and deduplicates its evidence IDs. Invalid evidence
links roll back the entire alert creation, including when it runs inside a larger
transaction. Raw `ingest_file(...)` remains an evidence-only helper; the CLI uses
`analyze_file(...)` to import and run the persistent detection pipeline together.

## Apache detections

The detector scans stored Apache access and error records and returns findings
for eleven rule types. These four behavioral thresholds apply to one logged IP
in a rolling window:

| Rule ID | Condition | Default threshold / window | Severity |
| --- | --- | --- | --- |
| `APACHE-PATH-ENUMERATION` | HTTP 403/404 responses across at least 5 distinct paths | 10 responses / 300 seconds | Medium |
| `APACHE-HTTP-ERRORS` | HTTP 403/404 responses, including repeats of one path | 20 responses / 300 seconds | Medium |
| `APACHE-AUTH-FAILURES` | HTTP 401 responses to the same path | 10 responses / 300 seconds | High |
| `APACHE-REQUEST-BURST` | Access records regardless of response status | 120 records / 60 seconds | Medium |

Distinct paths and authentication grouping use the parsed path exactly as logged,
excluding its query string. Percent encoding and case remain significant. A
missing path or a non-path target such as `OPTIONS *` does not qualify for the
path-enumeration or authentication rule. Records with a missing request still
count toward repeated 403/404 errors and volume. IP-based rules skip records
where only a hostname is logged.

HTTP 401 indicates missing valid authentication credentials and can include an
initial authentication challenge; HTTP 403 indicates refusal of the request.
These meanings follow [HTTP Semantics, RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.2).
The authentication rule therefore counts 401 responses. Login outcomes represented
by 200/302 responses cannot be inferred from these access logs. Busy legitimate
clients, shared proxy addresses, and broken links can also produce these patterns;
findings identify evidence to review rather than establish an attack.

Seven additional rules inspect individual requests or server-wide bursts:

| Rule ID | Condition | Default threshold / window | Severity |
| --- | --- | --- | --- |
| `APACHE-TRAVERSAL` | Parent-directory segments in a path or query, including Windows separators | One matching request | High |
| `APACHE-SQL-INJECTION` | Selected SQL syntax signatures in a path or query | One matching request | High |
| `APACHE-XSS` | Script tags, HTML event-handler attributes, or JavaScript URIs in a path or query | One matching request | High |
| `APACHE-SENSITIVE-FILE` | Configuration, credential, repository, database, or backup paths | One matching request | Medium |
| `APACHE-UNUSUAL-METHOD` | A method outside the configured expected set | One matching request | Medium |
| `APACHE-SERVER-ERRORS` | HTTP 500-599 access responses across clients | 20 responses / 60 seconds | High |
| `APACHE-ERROR-BURST` | Apache `error`, `crit`, `alert`, or `emerg` records across modules and clients | 10 records / 60 seconds | High |

Request signatures inspect the original path/query and up to two percent-decoding
passes. Literal `+` becomes a space in the first query-decoding pass; it remains
literal in paths and when produced by percent decoding. XSS inspection also
decodes bounded HTML entity references; oversized numeric references remain
unchanged. Inspection never changes the stored target, path, query, or raw log.
Signatures are checked regardless of response status, and a 200 response alone
does not prove successful exploitation. Request signatures can also inspect
records with a hostname or no logged IP.

SQL signatures cover `UNION [ALL] SELECT`, including simple comment separators;
numeric or quoted-literal `AND`/`OR` comparisons; `sleep`, `pg_sleep`, and
`benchmark` calls with a numeric argument; and selected semicolon-prefixed
statements such as `DROP TABLE`, `INSERT INTO`, `DELETE FROM`, and `UPDATE ... SET`.
A quote or the word `select` alone does not trigger the rule. The signature
examples draw on OWASP's [traversal tests](https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include.md),
[SQL injection tests](https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md),
and [XSS tests](https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting.md).
These are selected heuristics rather than an exhaustive signature set.

Sensitive-file matching uses path components rather than query mentions. It
checks `.git`, `.svn`, and `.hg` directories; `.env` and `.env.*`; `.htaccess`,
`.htpasswd`, `wp-config.php`, `config.php`, `web.config`, `id_rsa`, and `id_ed25519`;
and filenames ending in `.sql`, `.sqlite`, `.sqlite3`, `.db`, `.bak`, `.old`,
`.orig`, `.swp`, or `~`. Filename comparisons ignore case. Legitimate public
downloads or tutorial requests can match these signatures.

Expected methods default to `GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `PATCH`, and
`OPTIONS`. Method names are case-sensitive. `TRACE`, `CONNECT`, WebDAV methods,
and custom tokens therefore produce review findings by default; configure
`allowed_methods` for servers that intentionally use them.

Server burst rules combine evidence from all imported files in this database,
including records without a client IP. Their findings use `source_ip=None` and
a server grouping key. The error-log rule uses parsed severity rather than words
in the message; `warn`, `notice`, `info`, `debug`, and trace levels do not count.
Severity meanings follow the [Apache LogLevel documentation](https://httpd.apache.org/docs/2.4/mod/core.html#loglevel).
These bursts can indicate operational failures as well as suspicious activity.

Only logged paths, queries, methods, statuses, and error levels are available.
Request bodies, cookies, and response content are outside the supported layouts.
Referrers, user agents, and error messages are not scanned as request targets.
Encoding deeper than two percent-decoding passes and application-specific
obfuscation can evade the request signatures.

After importing logs, run the detector from Python:

```python
from app import create_app
from app.database import get_database
from app.detection import DetectionEngine
from app.storage import SQLiteStore

app = create_app()
with app.app_context():
    store = SQLiteStore(get_database())
    for finding in DetectionEngine().iter_findings(store):
        print(finding.rule_id, finding.source_ip, finding.event_count)
        print(finding.description, finding.event_ids)
```

The configured database must already be initialized. A `DetectionFinding` includes
the rule ID, title, severity, description, grouping key, source IP, first/last
matching timestamps, threshold/window, distinct-path count, anchor event ID, and
every matching event ID. Retrieve raw evidence and provenance with
`store.get_event(event_id)`. Scanning does not create or update stored alerts.
Single-request findings contain one event ID, `threshold=1`, and
`window_seconds=None`.

Records are processed by UTC timestamp, with database ID breaking ties. Both
window boundaries are inclusive. Findings use matching records through the
current anchor and exclude later records. For window rules, every new qualifying
record at or above the threshold emits a finding. The persistent pipeline correlates
these findings into alerts. Different rule types can describe the same evidence.

`iter_findings(store, start=..., end=..., source_ip=...)` filters emitted anchors.
Time filters require timezone-aware datetimes. A start filter loads earlier
context for the longest configured window so it does not lose relevant evidence.
An IP filter excludes server-wide findings, which have no single source IP.
The scan streams all matching events, retaining active windows instead of loading
the entire database. Keep the connection open and consume or close the iterator.
Evidence is not truncated by the storage list helpers' 1000-record limit.

Override thresholds through Python; `engine.rules` exposes the active catalog:

```python
from app.detection import DetectionEngine, RuleSettings

engine = DetectionEngine({
    "APACHE-PATH-ENUMERATION": RuleSettings(threshold=8, window_seconds=120, min_distinct_paths=4),
    "APACHE-AUTH-FAILURES": RuleSettings(threshold=6, window_seconds=180),
    "APACHE-ERROR-BURST": RuleSettings(threshold=15, window_seconds=120),
})
```

Window thresholds must be positive integers. Windows accept 1 through 86400 seconds.
Only path enumeration accepts a distinct-path setting above 1, and that setting
cannot exceed its request threshold. Single-request signatures have no threshold
overrides; their catalog entries have `settings=None`. Unknown window rule IDs
and invalid settings raise `ValueError`. Overrides affect that engine instance
without changing defaults. Configure expected methods separately:

```python
from app.detection import DetectionEngine
from app.signatures import DEFAULT_ALLOWED_METHODS

engine = DetectionEngine(allowed_methods=DEFAULT_ALLOWED_METHODS | {"PROPFIND", "REPORT"})
```

The method collection must contain valid, nonempty HTTP method tokens.
The detector groups across imported files in the same database, so use logs from
the same server context. Reimporting a file adds duplicate evidence that also
counts toward detection thresholds.

## Alert correlation and investigation

Alerts group by rule ID and the finding's grouping key. Only `new` and
`investigating` alerts are extended automatically. Their evidence intervals join
when separated by no more than the rule's configured window, inclusive at the
boundary. Single-request signatures use a 300-second correlation gap by default.
Evidence IDs are unique within each alert, and its first/last timestamps cover
all correlated findings. The stored evidence count can exceed a single window's
request count.

Late imports can connect previously separate open alerts. Those alerts combine
under the smallest existing ID, retaining that alert's creation time, all linked
evidence, the highest severity, and `investigating` status if any combined alert
had that status. Former IDs resolve to the retained alert for reads, evidence,
and status changes; they are reserved and never reused for another alert.

A finding whose entire evidence set is already represented by the same rule/group
causes no write. `resolved` and `false_positive` alerts keep their status, metadata,
and evidence during scans. Fresh evidence can create or extend an open alert for
review, including older records newly imported into a previously reviewed period.
These decisions apply to the current rules and settings; scans retain prior alerts
if the detection configuration later changes.

Use an existing alert ID to record an analyst decision:

```powershell
.\.venv\Scripts\python.exe -m flask --app app alert-status 1 investigating
.\.venv\Scripts\python.exe -m flask --app app alert-status 1 resolved
```

Statuses are `new`, `investigating`, `resolved`, and `false_positive`. Explicitly
setting a closed alert back to `new` or `investigating` reopens it for correlation.
Missing IDs and invalid statuses report a nonzero exit code. Merged IDs report
the retained ID when a status is changed. Status changes preserve evidence,
first/last timestamps, and creation time.

The Python pipeline accepts a custom detector and request correlation gap:

```python
from dotenv import load_dotenv
from app import create_app
from app.database import get_database
from app.detection import DetectionEngine, RuleSettings
from app.pipeline import analyze_file, detect_events
from app.storage import SQLiteStore

load_dotenv(".env")
app = create_app()
with app.app_context():
    store = SQLiteStore(get_database())
    engine = DetectionEngine({"APACHE-AUTH-FAILURES": RuleSettings(6, 180)})
    result = analyze_file("tests/fixtures/access_combined.txt", "access", store,
                          engine=engine, request_correlation_seconds=120)
    print(result.as_dict())
    print(detect_events(store, engine=engine, request_correlation_seconds=120).as_dict())
    for stored in store.list_alerts():
        print(stored.id, stored.alert.rule_id, stored.alert.status, stored.event_count)
```

The database must already be initialized or upgraded. Request correlation gaps
accept integer seconds from 1 through 86400. Both pipeline helpers honor a
caller's outer `transaction(connection)`, allowing the caller to roll back an
entire import/scan together. `DetectionEngine.iter_findings(...)` remains read-only
for callers who only want to inspect findings.

## Investigation APIs

Run `init-db`, import Apache files through the CLI, and start `run.py` before
querying the APIs at <http://127.0.0.1:5000>. This increment uses the existing
version 2 database schema; no new migration is required.

| Method | Endpoint | Result |
| --- | --- | --- |
| GET | `/api/events` | Paginated parsed records with raw evidence and provenance |
| GET | `/api/events/<id>` | One event in an `item` object |
| GET | `/api/alerts` | Paginated alerts with evidence counts |
| GET | `/api/alerts/<id>` | One alert in `item`, plus `requested_id` |
| GET | `/api/alerts/<id>/events` | Paginated chronological evidence for an alert |
| PATCH | `/api/alerts/<id>/status` | Persist an analyst status and return the updated alert |
| GET | `/api/rules` | All 11 default rule definitions and their settings |
| GET | `/api/stats` | Event and alert totals, date ranges, and grouped counts |
| POST | `/api/imports` | Import one Apache file and return its analysis summary |

Event and alert lists accept `limit` (default 100, range 1–1000), `offset`
(default 0, nonnegative SQLite integer), and `order=asc|desc` (default `desc`).
Events sort by timestamp and ID; alerts sort by first-seen timestamp and ID.
Alert evidence accepts `limit` and `offset` and always sorts by timestamp and
ID ascending. An offset beyond the results returns an empty page.

List responses use this structure; `total` counts every matching row before
pagination, and `has_more` indicates whether another page is available:

```json
{
  "items": [],
  "pagination": {
    "limit": 100,
    "offset": 0,
    "total": 0,
    "returned": 0,
    "has_more": false
  }
}
```

Filters may be combined:

| Endpoint | Additional query parameters |
| --- | --- |
| `/api/events` | `source_ip`, `log_type=access|error`, `start`, `end` |
| `/api/alerts` | `source_ip`, `rule_id`, `severity`, `status`, `start`, `end` |
| `/api/stats` | `source_ip`, `start`, `end` |

Source IPs must be IPv4 or IPv6 literals; IPv6 spelling is normalized before
matching. Rule IDs match exactly and may contain 1–128 characters. Severity
values are `low`, `medium`, `high`, or `critical`; statuses are `new`,
`investigating`, `resolved`, or `false_positive`.

`start` and `end` are inclusive RFC 3339 timestamps with seconds, optional
1–6 fractional digits, and `Z` or an explicit offset. Examples are
`2026-10-06T09:00:00Z` and `2026-10-06T02:00:00-07:00`. URL-encode a positive
offset's `+` as `%2B`. Dates filter event timestamps and alert **first_seen**,
including in statistics. A source-IP filter excludes server-wide alerts that
have no single source IP. Unknown or repeated query parameters are rejected.

All returned timestamps use UTC with six fractional digits and `Z`. Event
objects include every normalized parser field; unavailable fields are `null`.
`raw_log` preserves the decoded original record, and `source_file` and
`line_number` identify its provenance. Alert objects include detection fields,
status, creation time, and `event_count`; fetch their evidence through the
separate endpoint to page through large incidents. List and statistics reads
use a consistent database snapshot and do not run detection or change records.

Merged alert IDs remain usable for detail, evidence, and status requests.
Responses include the original `requested_id` and the surviving canonical ID
in `item.id` or `alert_id`. Lists and statistics count surviving alerts only.
An evidence response contains `alert_id`, `requested_id`, `items`, and
`pagination`.

```powershell
Invoke-RestMethod 'http://127.0.0.1:5000/api/alerts?status=new&limit=25'
Invoke-RestMethod 'http://127.0.0.1:5000/api/events?log_type=error&order=asc'
Invoke-RestMethod 'http://127.0.0.1:5000/api/stats'

# Replace 1 with an existing alert ID.
Invoke-RestMethod 'http://127.0.0.1:5000/api/alerts/1/events?limit=25'
Invoke-RestMethod -Uri 'http://127.0.0.1:5000/api/alerts/1/status' `
  -Method Patch -ContentType 'application/json' -Body '{"status":"investigating"}'
```

Status updates require a JSON object containing exactly `status`, with a body
of at most 1 KiB. They are atomic and preserve evidence and detection timestamps.
Sending the current status again leaves the alert unchanged.

Statistics return `events` and `alerts` objects. Events include `total`,
`distinct_source_ips` (excluding missing IPs), `by_log_type`, `first_seen`, and
`last_seen`. Alerts include `total`, `open` (new plus investigating),
`by_status`, `by_severity`, `by_rule_id`, `first_seen`, and `last_seen`.
Counts include all matching records, independent of page limits. Log types,
statuses, and severities include zero counts; `by_rule_id` lists rules present
in matching alerts. Empty date ranges are `null`. Alert `last_seen` is the
latest evidence time among alerts selected by their first-seen time.

The rule catalog is marked `configuration: "defaults"`. It includes titles,
descriptions, severity, log type, rule kind, grouping, window settings or
`null` for request signatures, expected HTTP methods, and the default request
correlation gap. Custom Python engine settings are not persisted, so this
endpoint describes the built-in defaults.

API errors are JSON, including missing routes and unsupported HTTP methods:

```json
{"error": {"code": "invalid_request", "message": "limit must be an integer between 1 and 1000."}}
```

Invalid parameters or JSON return 400, missing records return 404, unsupported
methods return 405, oversized status bodies return 413, and status requests
without a JSON content type return 415. Missing or incompatible schemas return
503 with `database_not_ready` and initialization guidance; other database
failures return 503 with `database_unavailable`. Internal database details are
logged locally and omitted from error responses. Investigation responses use
`Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

### Upload API

`POST /api/imports` accepts `multipart/form-data` with exactly one `file`, a
required `log_type=access|error`, and an optional `error_timezone=UTC` or signed
fixed UTC offset. It uses the built-in detection defaults. Send the header
`X-Apache-Upload: 1`; the dashboard does this automatically. If an `Origin`
header is present, it must match the application's origin. Cross-origin access
is not enabled. No query parameters or server-side file paths are accepted.

```powershell
curl.exe -H 'X-Apache-Upload: 1' `
  -F 'file=@C:\logs\access.log' -F 'log_type=access' `
  http://127.0.0.1:5000/api/imports
```

A successful import returns 201 with a `summary` object containing the same
line counts and nested `detection` counters as the CLI JSON output. Its
`source_file` is the persistent upload label. A file without usable records
returns 422 with `error.code: "no_apache_records"` and a `summary` containing
rejection counts. Invalid form fields return 400, a missing upload header or
foreign origin returns 403, oversized files/forms return 413, and a non-multipart
body returns 415. Database failures retain the investigation API's 503 behavior.

Python callers can pass `source_label` to `ingest_file(...)` or
`analyze_file(...)` to identify a temporary file's records without persisting
its temporary path. The default remains the resolved input file path.

## Parse an Apache record

The parsers operate on one line at a time and do not read files, open a database,
or make network requests. Choose the log type explicitly:

```python
from app.parsers import parse_apache_line

line = '192.0.2.10 - - [06/Oct/2026:09:00:01 -0700] "GET /index.html HTTP/1.1" 200 1234'
event = parse_apache_line(line, "access", source_file="access.log", line_number=1)
if event is not None:
    print(event.timestamp.isoformat(), event.source_ip, event.path, event.status_code)
```

| Log type | Supported layouts | Parsed details |
| --- | --- | --- |
| `access` | Common and combined access formats | Logged host/IP, user, request, method, target, path, query, protocol, response status/body bytes, optional referrer/user-agent |
| `error` | Typical Apache 2.4 `[time] [module:level] [pid ...] [client ...] message` and legacy `[time] [level] [client ...] message` | Module, level, optional process/thread ID, client address/port, Apache error code, full message |

In error records, process/thread IDs and the client block may be absent.
Arbitrary custom `LogFormat`/`ErrorLogFormat` layouts, virtual-host prefixes,
and multiline messages are outside the supported formats. A server that emits
these layouts is required: common/combined access syntax is shared by other
HTTP servers, so a line alone cannot prove which server wrote it.
The layout reference is the [Apache logging documentation](https://httpd.apache.org/docs/2.4/logs.html).

Access timestamps use their logged UTC offset. The supported error timestamps
have no offset: pass `error_timezone` as a `datetime.tzinfo` object for the
Apache server's timezone. It defaults to UTC, and `event.assumed_timezone`
records that assumption. The analyzer never uses the workstation timezone to
guess the server timezone. Both log types produce timezone-aware UTC timestamps.

```python
from datetime import timedelta, timezone

event = parse_apache_line(
    '[Tue Oct 06 09:01:02.123456 2026] [core:error] [pid 4120] AH00126: Invalid URI',
    "error",
    error_timezone=timezone(timedelta(hours=-7)),
)
```

IPv4 and IPv6 are supported without DNS lookups. Access-log hostnames are
preserved separately when no IP is logged. Apache 2.4 client endpoints treat
a valid final decimal component as a port; legacy bare IPv6 addresses remain
whole. Bracketed IPv6 endpoints avoid address/port ambiguity.

Malformed log records return `None`; unsupported log types or invalid parser
options raise an error. Missing or malformed HTTP requests inside otherwise
valid access records are retained as evidence. A dash response-byte count means
zero body bytes. Apache field escapes are decoded once for access fields;
percent encoding and path dot segments remain intact. Raw logs preserve their
original escaping and whitespace, with only the final line ending removed.

## Verify

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The tests use in-memory databases and temporary paths and do not need a running
server, existing logs, or an existing database. Local configuration, environments,
databases, and imported logs are excluded from version control.

An optional browser check exercises imports, filters, pagination, status saves,
raw evidence, rejection summaries, and mobile layout in a real Chromium browser:

```powershell
node tests\browser_dashboard.mjs
```

This check requires Node.js 22 or newer and defaults to Microsoft Edge on
Windows. Set `BROWSER_PATH` to another Chromium browser executable and `PYTHON`
to another Python executable if needed. `APACHE_BROWSER_DEBUG_PORT` optionally
selects a free debugging port, such as `9224`, instead of an automatic port.
It starts its own server on an available
local port with a temporary database and browser profile, then removes the test
data. It does not use `.env`, the running application, or existing imported logs.
