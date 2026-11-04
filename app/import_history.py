"""Transactional import fingerprints and repeated-line evidence."""

import hashlib
import sqlite3
from datetime import datetime, timezone

SAMPLE_LIMIT = 20
COUNT_FIELDS = (
    "lines_read", "imported_events", "blank_lines", "malformed_lines",
    "encoding_error_lines", "oversized_lines", "invalid_value_lines", "duplicate_lines",
)


def record_digest(raw_log: str) -> bytes:
    # Raw evidence retains its BOM. The parser has already removed final line
    # endings; ignore the optional UTF-8 signature when comparing records.
    return hashlib.sha256(raw_log.removeprefix("\ufeff").encode("utf-8")).digest()


def start_import(
    connection: sqlite3.Connection, source_file: str, log_type: str,
    assumed_timezone: str | None, max_line_bytes: int | None, *, legacy: bool = False,
) -> int:
    cursor = connection.execute(
        "INSERT INTO imports (source_file, log_type, assumed_timezone, max_line_bytes, legacy, recorded_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (source_file, log_type, assumed_timezone, max_line_bytes, int(legacy),
         datetime.now(timezone.utc).isoformat(timespec="microseconds")),
    )
    return cursor.lastrowid


def record_import_event(
    connection: sqlite3.Connection, import_id: int, event_id: int, raw_log: str,
) -> tuple[bytes, bool]:
    digest = record_digest(raw_log)
    previous = connection.execute(
        "SELECT event_id FROM import_lines WHERE import_id = ? AND record_sha256 = ? "
        "ORDER BY event_id LIMIT 1", (import_id, digest.hex()),
    ).fetchone()
    connection.execute(
        "INSERT INTO import_lines (import_id, event_id, record_sha256, duplicate_of_event_id) VALUES (?, ?, ?, ?)",
        (import_id, event_id, digest.hex(), previous["event_id"] if previous is not None else None),
    )
    return digest, previous is not None


def finish_import(
    connection: sqlite3.Connection, import_id: int, records_sha256: str,
    counts: dict, content_sha256: str | None = None,
) -> None:
    fields = {key: value for key, value in counts.items() if key in COUNT_FIELDS}
    fields.update(records_sha256=records_sha256, content_sha256=content_sha256)
    connection.execute(
        "UPDATE imports SET " + ", ".join(name + " = ?" for name in fields) + " WHERE id = ?",
        (*fields.values(), import_id),
    )


def find_duplicate_import(
    connection: sqlite3.Connection, import_id: int, log_type: str,
    content_sha256: str, records_sha256: str,
) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT * FROM imports WHERE id != ? AND log_type = ? "
        "AND (content_sha256 = ? OR records_sha256 = ?) ORDER BY id LIMIT 1",
        (import_id, log_type, content_sha256, records_sha256),
    ).fetchone()


def duplicate_line_page(
    connection: sqlite3.Connection, import_id: int, *, limit: int = SAMPLE_LIMIT, offset: int = 0,
) -> list[dict]:
    return [dict(row) for row in connection.execute(
        "SELECT l.event_id, e.line_number, l.duplicate_of_event_id AS original_event_id, "
        "o.line_number AS original_line_number "
        "FROM import_lines l JOIN events e ON e.id = l.event_id "
        "JOIN events o ON o.id = l.duplicate_of_event_id "
        "WHERE l.import_id = ? ORDER BY e.line_number, l.event_id LIMIT ? OFFSET ?",
        (import_id, limit, offset),
    )]


def backfill_legacy_imports(connection: sqlite3.Connection) -> None:
    """Recognize old import sequences without changing or removing any event.

    Old uploads have unique source labels; CLI file imports have increasing
    physical line numbers. A changed source, ID gap, or restarted line sequence
    starts another group. Missing provenance is left unclaimed.
    """
    cursor = connection.execute(
        "SELECT e.id, e.source_file, e.log_type, e.assumed_timezone, e.line_number, e.raw_log "
        "FROM events e WHERE e.source_file IS NOT NULL AND TRIM(e.source_file) != '' "
        "AND e.line_number IS NOT NULL "
        "AND NOT EXISTS (SELECT 1 FROM import_lines l WHERE l.event_id = e.id) ORDER BY e.id",
    )
    import_id = None
    identity = None
    previous_id = previous_line = 0
    fingerprint = None
    counts = {}
    try:
        for row in cursor:
            key = (row["source_file"], row["log_type"], row["assumed_timezone"])
            if key != identity or row["line_number"] <= previous_line or row["id"] != previous_id + 1:
                if import_id is not None:
                    finish_import(connection, import_id, fingerprint.hexdigest(), counts)
                import_id = start_import(connection, *key, None, legacy=True)
                identity = key
                fingerprint = hashlib.sha256()
                counts = {"imported_events": 0, "duplicate_lines": 0}
            digest, repeated = record_import_event(connection, import_id, row["id"], row["raw_log"])
            fingerprint.update(digest)
            counts["imported_events"] += 1
            counts["duplicate_lines"] += repeated
            previous_id, previous_line = row["id"], row["line_number"]
        if import_id is not None:
            finish_import(connection, import_id, fingerprint.hexdigest(), counts)
    finally:
        cursor.close()
