# Demo and workflow verification

This walkthrough uses the committed synthetic Apache files and a fresh,
separate SQLite database. It leaves your normal database and `.env` unchanged.
The [example manifest](../examples/expected.json) records the expected results;
the [detection catalog](DETECTIONS.md) explains all 11 rules.

## Start an isolated demo

From the repository directory in a **new PowerShell terminal**, use the
existing Python environment to select a uniquely named demo database. The
database file is created under `instance/`. Environment overrides below apply
to this terminal only. Port 5050 keeps the demo separate from the default port.

```powershell
$env:DATABASE_PATH = 'apache_demo_' + [guid]::NewGuid().ToString('N') + '.sqlite3'
$env:APP_PORT = '5050'
.\.venv\Scripts\python.exe -m flask --app app init-db
.\.venv\Scripts\python.exe -m flask --app app ingest .\examples\demo_access.txt --format access --json
.\.venv\Scripts\python.exe -m flask --app app ingest .\examples\demo_error.txt --format error --error-timezone=UTC --json
.\.venv\Scripts\python.exe -m flask --app app detect --json
.\.venv\Scripts\python.exe run.py
```

For macOS/Linux, start a new shell and use these overrides before the same
commands with `.venv/bin/python` and forward-slash paths:

```sh
export DATABASE_PATH="apache_demo_$(date +%s)_$$.sqlite3"
export APP_PORT=5050
```

Open <http://127.0.0.1:5050/>. Before analyst status changes, expect:

| Result | Expected |
| --- | --- |
| Imported events | 195: 185 access and 10 error |
| Open alerts | 11, all new |
| High / medium alerts | 6 / 5 |
| Logged IPs | 29 |
| Alert counts by rule | One for each of the 11 defaults |
| Rejected / blank lines per demo file | 1 / 1 |
| Explicit detect after both imports | 11 findings unchanged; 0 creations, updates, or merges |

The records are dated 2026-10-06. Clear date filters and use UTC for the error
file to reproduce the manifest. Reimporting adds events, so start another fresh
demo database to reproduce these initial totals.

Alternatively, initialize an empty database and upload the two demo files
through **Import logs**, selecting access and error explicitly. Use UTC for
the error file. This produces the same counts with unique upload source labels.

## Review and triage

1. Open **Alerts** and filter for **High request volume**. Its evidence count
   is 120. Open it and use Next to reach the last evidence page, containing
   records 101-120; all records remain available beyond the first page.
2. Select **View record** to inspect the original combined log, source label,
   and physical line number. Compare it with the file and the
   [evidence map](../examples/README.md).
3. Save **Investigating**, then **Resolved** or **False positive**. The evidence
   and first/last detection times remain intact; the open-alert count decreases
   when the alert is closed. A status filter makes that decision easy to find.
4. Open **Events**, select the error log type, and inspect module, level,
   assumed timezone, and raw message. Individual request signatures are in
   separate access events; the two server-wide alerts have no single source IP.

With the server running, another terminal can inspect the same data over HTTP:

```powershell
Invoke-RestMethod 'http://127.0.0.1:5050/api/stats'
Invoke-RestMethod 'http://127.0.0.1:5050/api/alerts?limit=4&offset=4'
Invoke-RestMethod 'http://127.0.0.1:5050/api/alerts?rule_id=APACHE-XSS'
```

To check persistence, stop the server with Ctrl+C in the demo terminal and run
`detect --json` again using the full Python/Flask command above. It must leave
the saved decisions and evidence unchanged. Start `run.py` again and inspect
the same alert. `init-db` is also safe to repeat for an owned current schema;
it preserves existing evidence and decisions.

## Compare benign traffic

In the demo terminal after stopping its server, choose another fresh database:

```powershell
$env:DATABASE_PATH = 'apache_benign_' + [guid]::NewGuid().ToString('N') + '.sqlite3'
.\.venv\Scripts\python.exe -m flask --app app init-db
.\.venv\Scripts\python.exe -m flask --app app ingest .\examples\benign_access.txt --format access --json
.\.venv\Scripts\python.exe -m flask --app app ingest .\examples\benign_error.txt --format error --error-timezone=UTC --json
.\.venv\Scripts\python.exe -m flask --app app detect --json
```

Expect 13 events and zero alerts. One 401 challenge, ordinary search words,
expected methods, and non-severe error messages do not meet these defaults.
Loading the two main demo files afterward gives 208 events and 11 alerts.

## Automated checks

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pytest tests\test_demo_workflow.py -q
```

The full suite covers parsers, configuration, storage/migrations, bounded
ingestion, rule thresholds and time boundaries, signatures, correlation,
merged IDs, analyst statuses, APIs, and upload rollback. The demo workflow
checks load the committed files through CLI and upload APIs in both import
orders, page through every event and evidence record, match raw logs to their
original lines, save decisions through both interfaces, reject a wrong-format
file without changing earlier data, and reopen the database. Both benign
samples are checked before importing the alert-producing samples.

The optional browser check needs Node.js 22+ and a Chromium browser:

```powershell
node tests\browser_dashboard.mjs
```

It uses its own server, temporary databases, and temporary browser profile.
It verifies browser uploads, filters, pagination, literal script evidence,
status updates, error feedback, catalog recovery, and mobile layout. It then
uploads gzip-compressed copies of the published demo into a second empty database
and reviews all 120 burst records, their compressed-file provenance, and a saved
analyst decision. It also checks damaged-gzip feedback. No existing
application data or browser profile is used.

The default browser is Microsoft Edge on Windows. Set `BROWSER_PATH` for
another Chromium executable and `PYTHON` for another Python environment.
If automatic debugging ports are unavailable, select an unused local port:

```powershell
$env:APACHE_BROWSER_DEBUG_PORT = '9224'
node tests\browser_dashboard.mjs
```

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Database schema is missing or incompatible | Run init-db in the terminal using the intended DATABASE_PATH. Owned version 1 databases upgrade in place; unrelated or future schemas are refused. |
| No supported Apache records | Check access/error selection, UTF-8 content (plain or gzip-compressed), and the supported common/combined or standard/legacy layouts. Combined access logs also accept trailing `name:"value"` or `name:token` fields; other custom layouts remain unsupported. |
| Demo counts differ | Use a fresh database, import each file once with default rules, choose UTC for error timestamps, and clear filters. |
| CLI changes are missing from the dashboard | Select Refresh; confirm both processes use the same database path. |
| Browser file is too large | Use the streaming CLI for files over 10 MiB. Both paths rescan stored history, so scan time grows with the database. |
| Gzip log exceeds its decompressed limit | Browser gzip uploads can expand to 100 MiB. For larger local gzip logs, use the CLI with --max-decompressed-bytes set to the desired positive byte limit. |
| Cannot read gzip log | Obtain a complete, valid gzip file. Truncation, corruption, or checksum errors reject the entire import and preserve previously stored data. |
| Port already in use | Choose an unused APP_PORT and use that port in the browser and API URLs. |

Closing the demo terminal restores your ordinary environment for later runs.
Demo databases remain under `instance/` for inspection and are ignored by Git.
