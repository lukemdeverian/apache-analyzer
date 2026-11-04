# Two-domain analysis

The study uses two fixed profiles:

| Website | Hostname | Supplied provider label | ID |
| --- | --- | --- | --- |
| Chronoscrate | chronoscrate.xyz | Dynadot | chronoscrate |
| La Jolla Seals | protectlajollaseals.xyz | Namecheap | la_jolla_seals |

Provider names are study metadata supplied by the user. The analyzer does not
query DNS or verify the authoritative nameservers or registrar. Comparisons show
observed website traffic, not a causal DNS/provider effect. Site content,
popularity, hosting, collection coverage, and observation period can also differ.

## Start and import

Run initialization once after upgrading, then start normally:

```powershell
.\.venv\Scripts\python.exe -m flask --app app init-db
.\.venv\Scripts\python.exe run.py
```

`init-db` initializes or upgrades both website databases without clearing records.
Use `init-db --domain la_jolla_seals` to initialize only that site if needed.
Uploads never initialize a database automatically.

1. Open **Import logs** and choose the file.
2. Explicitly choose the **Website** and access/error format. The website field
   starts blank for every import; filenames and IP addresses never decide it.
3. Import and analyze. The summary identifies the website and supplied provider,
   and the active website switches to the imported site.

Plain UTF-8 and gzip files work for both sites with the existing upload limits.
Errors, rejection counts, and temporary-file cleanup follow the existing import
rules. A missing, unknown, or repeated website field is rejected before writing
the file or opening a database. The selected site is also shown in failed
wrong-format summaries.

## Isolation and existing traffic

All pre-existing data belongs to **Chronoscrate**. Its configured `DATABASE_PATH`
continues to point to the same database. No records are moved or reimported.
La Jolla Seals uses a separate database in the same folder, with
`__la_jolla_seals` inserted before the extension. With default configuration:

- `instance/apache_analyzer.sqlite3`: Chronoscrate.
- `instance/apache_analyzer__la_jolla_seals.sqlite3`: La Jolla Seals.

For `DATABASE_PATH=study.sqlite3`, the second file is
`instance/study__la_jolla_seals.sqlite3`. Back up both files when retaining the
complete study. Both use version 3, with import fingerprints and ownership checks;
foreign or incompatible databases are refused.

Run init-db after upgrading from version 1 or 2. The upgrade preserves records,
recognizes older imports with usable provenance, and does not delete existing
duplicates. [Duplicate prevention](DUPLICATE_IMPORTS.md) is scoped independently
to each website; the same file can be imported once per website and log type.

Each site has independent events, thresholds, server-wide alerts, correlation,
evidence links, analyst statuses, bot assessments, and ban candidates. A shared
IP can be normal on one site and confirmed on the other. CSS from one site cannot
clear the other site's risk, and requests cannot combine across sites to meet
a detection threshold. Absolute CSS request targets must match the selected
site's hostname. Origin-form Apache logs omit the host, so correct file selection
is essential; mixed-domain files must be separated before importing.

Record IDs are local to a website. Alert 1 on Chronoscrate can differ from alert 1
on La Jolla Seals. The dashboard scopes detail links and status changes using
the website selector. La Jolla Seals bookmarks include the query parameter,
for example `/?domain_id=la_jolla_seals#alerts/1`.

## Review and compare

The **Website** selector scopes overview counts, events, alerts, bot assessments,
evidence, status changes, and exports. Clearing IP/date/category filters keeps
the selected website. Exports contain candidates only for that site; the second
site's dashboard download is `ban-candidates-la_jolla_seals.txt`.

**Domain comparison** always shows both sites with the same source-IP and UTC
date filters. It includes:

- Parsed access requests and alert counts.
- Alerts per 1,000 access requests, to contextualize different request volumes.
- Counts of confirmed, suspected, and normal IPs.
- Confirmed-bot IP percentage among assessed IPs, not percentage of requests.

Rates with a zero denominator are unavailable rather than invented zeros.
Alert counts include all analyst statuses and server-wide issues, and use alert
first-seen times. Bot categories exclude false positives and use linked evidence
within the selected history. Alert groups can contain many requests, and one
request can trigger multiple rules; the alert rate is not a malicious-request
percentage. Each site's statistics and assessment counts are read together.
Choose comparable collection periods when interpreting the differences.

## CLI and API

CLI commands default to Chronoscrate for compatibility. Explicitly select the
site with `--domain` when importing or investigating the second domain:

```powershell
.\.venv\Scripts\python.exe -m flask --app app ingest C:\logs\seals.log.gz --domain la_jolla_seals --format access --json
.\.venv\Scripts\python.exe -m flask --app app detect --domain la_jolla_seals --json
.\.venv\Scripts\python.exe -m flask --app app alert-status --domain la_jolla_seals 1 false_positive
```

`POST /api/imports` now requires multipart `domain_id`, in addition to `file`
and `log_type`. The usual upload header and optional error timezone still apply.
Successful summaries include `domain_id` and the profile metadata.

```powershell
curl.exe -H 'X-Apache-Upload: 1' -F 'file=@C:\logs\seals.log.gz' -F 'domain_id=la_jolla_seals' -F 'log_type=access' http://127.0.0.1:5000/api/imports
```

Investigation endpoints accept `domain_id` as a query parameter, including
details, linked evidence, status PATCH requests, statistics, bot assessments,
and exports. Omitted query parameters default to Chronoscrate for compatibility.
Responses expose the selected scope through `X-Analyzer-Domain` when resolved.

- `GET /api/domains`: both profiles and the default ID; opens no database.
- `GET /api/domains/comparison`: both sites' comparison statistics. Accepts only
  `source_ip`, `start`, and `end`; a domain filter is intentionally not accepted.

```powershell
Invoke-RestMethod 'http://127.0.0.1:5000/api/events?domain_id=la_jolla_seals'
Invoke-RestMethod 'http://127.0.0.1:5000/api/bots?domain_id=la_jolla_seals'
Invoke-RestMethod 'http://127.0.0.1:5000/api/domains/comparison'
```

A missing or incompatible database returns 503 with initialization guidance,
including when comparison cannot read one of the sites. It never falls back to
the other site's database. Direct Python callers select a connection with
`get_database(domain_id)` and pass the selected hostname to `assess_bots` if
calling the classifier directly. Pure parsers and storage types remain reusable.
