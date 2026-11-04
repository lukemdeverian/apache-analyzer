# Duplicate import prevention

Repeated files are skipped **per website and Apache log type**. Renaming a file,
recompressing it as gzip, or uploading it through another intake path does not
create another copy of the same accepted traffic.

Identical lines inside a file are **retained and flagged**, not removed. Apache
records with identical timestamps and fields can represent genuine separate
requests. They continue to count toward detection rules until reviewed.

## Upgrade and start

Stop the server and run:

```powershell
.\.venv\Scripts\python.exe -m flask --app app init-db
.\.venv\Scripts\python.exe run.py
```

Schema version 3 adds an import registry and repeated-line links to each site's
database. Initialization upgrades owned versions 1 and 2 atomically per database
while preserving events, alerts, analyst statuses, merge aliases, and evidence.
Both website databases are initialized by default. Unrelated/future schemas are
still refused. No existing event or alert is deleted.

The upgrade reconstructs older file-import sequences where stored source labels
and physical line numbers provide usable provenance. A changed source, restarted
line sequence, or event-ID gap starts another group. These legacy fingerprints
can recognize an unchanged file on its next upload without the original file
still being present. Missing provenance or a changed accepted-record sequence
cannot be reliably reconstructed. Legacy registry counters that were never
stored remain unknown rather than fabricated.

**Existing duplicates remain in the database**, including their effects on
alerts and bot classifications. This feature prevents another repeated import;
it does not retrospectively clean or recalculate historical duplicate data.

## File identity

Two SHA-256 fingerprints are recorded during streaming:

- The entire decompressed byte stream, including rejected and oversized lines.
- The sequence of accepted raw records, preserving record order and the number
  of occurrences while ignoring final line endings and the initial UTF-8 BOM.

A match on either fingerprint, within the same website and log type, is treated
as an already imported file. Thus LF/CRLF conversion, a UTF-8 signature, or
different blank/malformed framing does not append the same accepted records.
The accepted-record fingerprint also supports legacy imports without saved
original file bytes. Access and error interpretations remain separately scoped.

Changing the timezone or line limit does not force another import of identical
file content; the original interpretation remains. Use a separate analysis
database when deliberately reprocessing under different settings. Changing rule
settings can be followed by an explicit `detect` command on stored evidence.

Gzip is still fully read and validated: a damaged or truncated copy fails rather
than being silently accepted as a duplicate. Compressed/decompressed and line
limits remain enforced. No complete file or unbounded set of line hashes is
held in Python memory; repeated-record lookup uses indexed SQLite metadata.

The same traffic may be imported once for each website. This is independent of
filenames and source IPs, so selecting the correct website remains essential.

## Repeated lines and overlap

During a new import, each accepted line is compared with earlier lines in that
file. Every occurrence after the first is flagged and linked to the first event.
All event IDs, raw evidence, timestamps, physical line numbers, and detector
counts remain intact. Differences in timestamps or any other raw field make
records distinct. Blank, malformed, encoding-invalid, and numeric-invalid lines
do not become event-level repetition flags.

This is **whole-import prevention**, not global line suppression. Partially
overlapping, appended, reordered, or otherwise different accepted sequences are
not automatically trimmed. An input containing one occurrence differs from one
containing two occurrences. Such files can be new imports, and may contain
overlap with earlier files. This conservative policy avoids guessing which
identical requests were genuine; it is not incremental log-tail ingestion.

## Dashboard and CLI

A new file shows **New import** and the count of **Repeated lines retained for
review**. If present, **Review repeated lines** opens a paginated table with the
first and repeated physical line numbers. Both link to original raw evidence.
The summary includes up to 20 samples; the review endpoint paginates all flags.

A repeated file shows **Already imported; no changes**, the original import ID,
original source label, and skipped-event count. It does not rerun detection,
extend alerts, reopen closed alerts, or modify analyst decisions. Existing
repeated-line flags remain reviewable through the original import.

CLI imports also succeed as no-ops for already imported files. Human output
identifies the original import; `--json` includes the structured result. New
imports report repeated lines retained for review.

## API contract

`POST /api/imports` returns:

- **201** for a new import, including files with retained repeated lines.
- **200** for a duplicate-file no-op. `imported_events` is zero and all nested
  detection counters are zero.
- The existing 400/403/413/415/422/503 errors for invalid input or failures.

Successful summaries include:

| Field | Meaning |
| --- | --- |
| `import_id` | Saved new import ID; null for a duplicate attempt |
| `duplicate_file` | Whether this file was already represented |
| `duplicate_of_import_id` / `duplicate_of_source_file` | Original import for a skipped file |
| `skipped_duplicate_events` | Accepted records from this attempt that were not appended |
| `duplicate_lines` | Repeated occurrences retained in the saved/original import |
| `duplicate_line_samples` | Up to 20 repeated/original event IDs and physical line-number pairs |

For a duplicate attempt, scan/rejection counts describe the attempted file;
line-review samples refer to stable event IDs in the original import. The
zero-imported count does not mean the file had no usable records.

`GET /api/imports/<id>/duplicates` accepts `domain_id`, `limit` (1–1000), and
`offset`. It returns import/source metadata, repeated/original event ID pairs,
and pagination. Import IDs are local to each website. Existing event-detail
endpoints expose the linked records. Query validation and error handling match
other investigation endpoints; an unknown import returns 404.

Fingerprints, flags, events, and detection writes share transaction boundaries.
Read, gzip, parsing, storage, detector, cleanup, or outer-transaction failures do
not reserve a successful fingerprint, so a corrected retry can succeed. Concurrent
same-site uploads are serialized by SQLite and cannot both append the same file.
