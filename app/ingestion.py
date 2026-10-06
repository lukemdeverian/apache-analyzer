"""Stream explicitly selected Apache log files into local event storage."""

import os
import re
import stat
from collections.abc import Iterator
from dataclasses import asdict, dataclass, replace
from datetime import timedelta, timezone, tzinfo
from pathlib import Path
from typing import BinaryIO

from app.database import transaction
from app.events import ApacheLogType
from app.parsers import parse_apache_line
from app.storage import SQLiteStore

DEFAULT_MAX_LINE_BYTES = 64 * 1024
MAX_LINE_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class ImportSummary:
    source_file: str
    log_type: ApacheLogType
    assumed_timezone: str | None
    lines_read: int
    imported_events: int
    blank_lines: int
    malformed_lines: int
    encoding_error_lines: int
    oversized_lines: int
    invalid_value_lines: int

    @property
    def rejected_lines(self) -> int:
        return (
            self.malformed_lines + self.encoding_error_lines
            + self.oversized_lines + self.invalid_value_lines
        )

    def as_dict(self) -> dict[str, str | int | None]:
        return {**asdict(self), "rejected_lines": self.rejected_lines}


class NoApacheRecordsError(ValueError):
    """A file had no supported, persistable Apache records for the chosen type."""

    def __init__(self, summary: ImportSummary):
        self.summary = summary
        super().__init__(
            f"No Apache {summary.log_type} records were imported. "
            f"Read {summary.lines_read} lines: {summary.rejected_lines} rejected, "
            f"{summary.blank_lines} blank. Check the file content and --format."
        )


def parse_error_timezone(value: str) -> timezone:
    """Accept UTC or a fixed UTC offset, without depending on local timezone data."""
    value = value.strip()
    if value.upper() == "UTC":
        return timezone.utc
    match = re.fullmatch(r"([+-])([0-9]{2}):([0-9]{2})", value)
    if match is None or int(match[2]) > 23 or int(match[3]) > 59:
        raise ValueError("Use UTC or a signed UTC offset such as -07:00 or +05:30.")
    offset = timedelta(hours=int(match[2]), minutes=int(match[3]))
    return timezone(-offset if match[1] == "-" else offset)


def _line_content(line: bytes) -> bytes:
    return line.removesuffix(b"\n").removesuffix(b"\r")


def _bounded_lines(stream: BinaryIO, limit: int) -> Iterator[tuple[int, bytes | None]]:
    """Yield physical lines, draining oversized records with bounded reads."""
    line_number = 0
    while chunk := stream.readline(limit + 2):
        line_number += 1
        if len(_line_content(chunk)) > limit:
            while chunk and not chunk.endswith(b"\n"):
                chunk = stream.readline(limit + 2)
            yield line_number, None
        else:
            yield line_number, chunk


def ingest_file(
    path: str | Path, log_type: ApacheLogType, store: SQLiteStore, *,
    error_timezone: tzinfo = timezone.utc,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    source_label: str | None = None,
) -> ImportSummary:
    """Import a plain UTF-8 Apache file atomically and preserve file provenance.

    Malformed, oversized, invalid UTF-8, and out-of-range numeric records are
    counted and skipped. Read/storage failures roll back this entire import.
    At least one supported record must be stored for the import to succeed.
    Repeating an import creates additional events; file deduplication is absent.
    source_label overrides file provenance for a caller-owned temporary file.
    """
    if log_type not in ("access", "error"):
        raise ValueError("Unsupported Apache log type; choose 'access' or 'error'.")
    if type(max_line_bytes) is not int or not 1 <= max_line_bytes <= MAX_LINE_BYTES:
        raise ValueError(f"max_line_bytes must be an integer between 1 and {MAX_LINE_BYTES}.")
    if source_label is not None and (
        not isinstance(source_label, str) or not source_label.strip()
        or len(source_label) > 1024 or "\0" in source_label
    ):
        raise ValueError("source_label must be nonempty text of at most 1024 characters without NUL.")
    source = Path(path).expanduser().resolve(strict=True)
    if not source.is_file():
        raise ValueError("Apache ingestion requires a regular log file.")
    provenance = str(source) if source_label is None else source_label
    counts = {
        "lines_read": 0, "imported_events": 0, "blank_lines": 0,
        "malformed_lines": 0, "encoding_error_lines": 0, "oversized_lines": 0,
        "invalid_value_lines": 0,
    }

    def summary() -> ImportSummary:
        return ImportSummary(
            source_file=provenance, log_type=log_type,
            assumed_timezone=str(error_timezone) if log_type == "error" else None,
            **counts,
        )

    with transaction(store.connection):
        with source.open("rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("Apache ingestion requires a regular log file.")
            for line_number, raw_line in _bounded_lines(stream, max_line_bytes):
                counts["lines_read"] += 1
                if raw_line is None:
                    counts["oversized_lines"] += 1
                    continue
                try:
                    text = raw_line.decode("utf-8")
                except UnicodeDecodeError:
                    counts["encoding_error_lines"] += 1
                    continue
                # A file's UTF-8 signature is not part of the first logged host.
                # Keep it in raw evidence while removing it for parsing only.
                parse_text = text.removeprefix("\ufeff") if line_number == 1 else text
                if not parse_text.strip():
                    counts["blank_lines"] += 1
                    continue
                event = parse_apache_line(
                    parse_text, log_type, source_file=provenance, line_number=line_number,
                    error_timezone=error_timezone,
                )
                if event is None:
                    counts["malformed_lines"] += 1
                    continue
                if parse_text != text:
                    event = replace(event, raw_log=text.removesuffix("\n").removesuffix("\r"))
                try:
                    store.insert_event(event)
                except ValueError:
                    counts["invalid_value_lines"] += 1
                    continue
                counts["imported_events"] += 1
            if counts["imported_events"] == 0:
                raise NoApacheRecordsError(summary())
    return summary()
