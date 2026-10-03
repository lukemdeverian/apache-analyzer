# Apache Analyzer

A local Apache log analyzer inspired by [Nightwatch](https://github.com/lukemdeverian/nightwatch).
It is being built in 10 reviewable increments, with a pause after each increment
so you can commit the changes yourself. See [ROADMAP.md](ROADMAP.md) for the sequence.

The target application accepts Apache access and error log files, stores evidence
in SQLite, detects suspicious Apache activity, and presents alerts in a local
Flask dashboard. It runs directly on Python without Docker or a database server.
The initial implementation is written specifically for this repository, using
Nightwatch's separation of parsing, storage, detection, and presentation as a reference.

## Current progress: increment 1 of 10

Implemented:

- Flask application factory and a JSON health endpoint.
- Environment configuration with validation and local defaults.
- Development entry point and configuration example.
- Isolated tests for startup settings and application health.

Log parsing, ingestion, storage, detection, APIs, and the dashboard are planned
in subsequent increments. `DATABASE_PATH` reserves the local storage location;
this increment does not create a database. The only route currently available
is `GET /health`.

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

## Verify

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The tests use temporary paths and do not need a running server, existing logs,
or a database. Local configuration, environments, databases, and imported logs
are excluded from version control.
