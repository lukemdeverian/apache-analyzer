# Apache Analyzer

A local Apache log analyzer inspired by [Nightwatch](https://github.com/lukemdeverian/nightwatch).
It is being built in 10 reviewable increments, with a pause after each increment
so you can commit the changes yourself. See [ROADMAP.md](ROADMAP.md) for the sequence.

The target application accepts Apache access and error log files, stores evidence
in SQLite, detects suspicious Apache activity, and presents alerts in a local
Flask dashboard. It runs directly on Python without Docker or a database server.
The initial implementation is written specifically for this repository, using
Nightwatch's separation of parsing, storage, detection, and presentation as a reference.

## Current progress: increment 5 of 10

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

File ingestion is available through the CLI; behavioral detection is available
through Python. Automatic alert saving and correlation, APIs, and the dashboard
are planned in subsequent increments. The only HTTP route currently available is
`GET /health`, which works without opening a database.

## Run locally

Use Python 3.11 or newer. From this directory in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -m flask --app app init-db
.\.venv\Scripts\python.exe run.py
```

Open <http://127.0.0.1:5000/health> to check the application:

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

## Import Apache log files

Initialize the database once with `init-db`, then choose the log type explicitly.
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
be processed. Memory usage does not grow with the number of imported records.

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
`source_file`, `log_type`, and `assumed_timezone`. Blank and rejected lines are
skipped; an import must contain at least one usable Apache record to succeed.
An empty file, a wrong format choice, or unrelated log content produces a
nonzero exit code with a rejection summary.

Each file is saved in a single transaction. A file-read or database failure
rolls back all events from that import and reports a nonzero exit code. Earlier
imports remain intact. Repeating a successful import appends new events.
Collection is batch-oriented: the importer reads to EOF and does not follow
log rotation. Automatic alert detection is added in later increments.

## Local storage

Storage uses Python's built-in SQLite module without an ORM or extra database
dependency. Database connections open on demand and close at the end of the
Flask application context. Initialize the configured database with:

```powershell
.\.venv\Scripts\python.exe -m flask --app app init-db
```

This creates the database file, parent directory, tables, and indexes. Repeating
the command preserves existing events and alerts. The schema has an application
identifier and version marker; unrelated, unrecognized, or incompatible databases
are rejected. Schema migrations are not implemented in this increment.

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
| `list_alerts(...)` / `count_alerts(...)` | Filter by source IP, rule, severity, status, and inclusive first-seen range |
| `get_alert_events(id, ...)` | Retrieve linked evidence in timestamp/ID order |

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
transaction. There is no automatic detection or alert correlation yet.

## Behavioral detections

The detector scans stored Apache access records and returns findings for these
four patterns. Each threshold applies to one logged IP in a rolling window:

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
where only a hostname is logged. Error-log detections are added in increment 6.

HTTP 401 indicates missing valid authentication credentials and can include an
initial authentication challenge; HTTP 403 indicates refusal of the request.
These meanings follow [HTTP Semantics, RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.2).
The authentication rule therefore counts 401 responses. Login outcomes represented
by 200/302 responses cannot be inferred from these access logs. Busy legitimate
clients, shared proxy addresses, and broken links can also produce these patterns;
findings identify evidence to review rather than establish an attack.

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

Records are processed by UTC timestamp, with database ID breaking ties. Both
window boundaries are inclusive. Findings use matching records through the
current anchor and exclude later records. At and above the threshold, every
new qualifying record emits a finding; overlapping findings will be correlated
and saved in increment 7. Different rule types can describe the same evidence.

`iter_findings(store, start=..., end=..., source_ip=...)` filters emitted anchors.
Time filters require timezone-aware datetimes. A start filter loads earlier
context for the longest configured window so it does not lose relevant evidence.
The scan streams all matching events, retaining active windows instead of loading
the entire database. Keep the connection open and consume or close the iterator.
Evidence is not truncated by the storage list helpers' 1000-record limit.

Override thresholds through Python; `engine.rules` exposes the active catalog:

```python
from app.detection import DetectionEngine, RuleSettings

engine = DetectionEngine({
    "APACHE-PATH-ENUMERATION": RuleSettings(threshold=8, window_seconds=120, min_distinct_paths=4),
    "APACHE-AUTH-FAILURES": RuleSettings(threshold=6, window_seconds=180),
})
```

Thresholds must be positive integers. Windows accept 1 through 86400 seconds.
Only path enumeration accepts a distinct-path setting above 1, and that setting
cannot exceed its request threshold. Unknown rule IDs and invalid settings raise
`ValueError`. Overrides affect that engine instance without changing defaults.
The detector groups across imported files in the same database, so use logs from
the same server context. Reimporting a file adds duplicate evidence that also
counts toward detection thresholds.

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
