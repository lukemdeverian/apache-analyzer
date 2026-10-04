# Apache Analyzer

A local Apache log analyzer inspired by [Nightwatch](https://github.com/lukemdeverian/nightwatch).
It is being built in 10 reviewable increments, with a pause after each increment
so you can commit the changes yourself. See [ROADMAP.md](ROADMAP.md) for the sequence.

The target application accepts Apache access and error log files, stores evidence
in SQLite, detects suspicious Apache activity, and presents alerts in a local
Flask dashboard. It runs directly on Python without Docker or a database server.
The initial implementation is written specifically for this repository, using
Nightwatch's separation of parsing, storage, detection, and presentation as a reference.

## Current progress: increment 2 of 10

Implemented:

- Flask application factory and a JSON health endpoint.
- Environment configuration with validation and local defaults.
- Development entry point and configuration example.
- Isolated tests for startup settings and application health.
- Apache common/combined access and standard/legacy error parsers.
- Normalized UTC event records with original evidence and optional file/line provenance.
- Synthetic fixtures covering escaped fields, IPv6, missing values, and malformed records.

File ingestion, storage, detection, APIs, and the dashboard are planned in
subsequent increments. `DATABASE_PATH` reserves the local storage location;
this increment does not create a database. The only route currently available
is `GET /health`. Parsing is available through the Python interface below.

## Run locally

Use Python 3.11 or newer. From this directory in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
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
.\.venv\Scripts\python.exe run.py
```

## Configuration

`run.py` loads `.env` from the project directory. Existing environment variables
take precedence over that file. Settings are read when the app is created.

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_HOST` | `127.0.0.1` | Local listening address |
| `APP_PORT` | `5000` | Listening port, from 1 through 65535 |
| `APP_DEBUG` | `false` | Development debugger and automatic reload |
| `DATABASE_PATH` | `apache_analyzer.sqlite3` | Future SQLite file; relative paths resolve under `instance/` |

Debug values accept `true`/`false`, `1`/`0`, `yes`/`no`, or `on`/`off`,
case-insensitively. Invalid settings stop startup with a named validation error.
The intended runtime is a local development application; authentication and
remote deployment are outside the current scope.

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

The tests use temporary paths and do not need a running server, existing logs,
or a database. Local configuration, environments, databases, and imported logs
are excluded from version control.
