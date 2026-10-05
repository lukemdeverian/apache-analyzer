# Incremental build plan

Build approximately 10 commits. Complete one increment at a time, verify its
behavior, then stop and suggest a commit message. The user creates each commit;
continue with the next increment when the user asks to proceed.

## Scope

- Accept Apache access and error log files through explicit file ingestion.
- Support common and combined access formats and documented standard error formats.
- Preserve raw evidence, parsed timestamps, source files, and line numbers.
- Use Python, Flask, SQLite, and a small HTML/CSS/JavaScript dashboard.
- Run locally without Docker, PostgreSQL, SSH log ingestion, or network telemetry ingestion.
- Expand Apache detections beyond Nightwatch's two web rules.
- Verify detection thresholds, time boundaries, benign cases, and malformed input
  with synthetic logs. Pattern alerts describe suspicious requests, not proof of compromise.

## Increments

| # | Deliverable | Suggested commit message | Status |
| --- | --- | --- | --- |
| 1 | Runnable application, local configuration, health endpoint, setup instructions | `chore: scaffold local Apache analyzer application` | Complete |
| 2 | Apache access/error parsers, normalized event records, raw evidence, parser fixtures | `feat: parse Apache access and error logs` | Complete |
| 3 | SQLite event and alert storage, schema initialization, query helpers | `feat: persist Apache events and alerts in SQLite` | Complete |
| 4 | Streaming file ingestion CLI, explicit format selection, provenance, import summary | `feat: ingest Apache log files from the command line` | Complete |
| 5 | Behavioral rules for path enumeration, repeated HTTP errors, authentication failures, request bursts | `feat: detect suspicious Apache request patterns` | Planned |
| 6 | Additional alerts for traversal, SQL injection and XSS probes, sensitive files, unusual methods, server/error-log bursts | `feat: expand Apache security and server error detections` | Planned |
| 7 | Detection pipeline integration, alert correlation, evidence linking, analyst statuses | `feat: correlate Apache detections and manage alert status` | Planned |
| 8 | Paginated APIs for events, alerts, evidence, rules, statistics, and status updates | `feat: expose Apache investigation APIs` | Planned |
| 9 | Local dashboard with bounded file upload, overview, filters, alert details, raw evidence | `feat: add Apache analysis dashboard and file imports` | Planned |
| 10 | Safe Apache demo logs, full workflow regression checks, detection catalog, final usage documentation | `docs: complete Apache analyzer demo and verification guide` | Planned |

## Verification strategy

Keep each increment runnable. Add checks where they protect substantive behavior:
parser edge cases, storage correctness, file-import failures, detection windows
and thresholds, correlation, input validation, and the complete ingestion-to-alert
workflow. Use synthetic fixtures rather than real access logs. Update this plan
and the README at each checkpoint to distinguish available functionality from
upcoming work.
