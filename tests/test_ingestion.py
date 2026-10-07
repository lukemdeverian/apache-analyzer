import gzip
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.database import connect_database, initialize_database, transaction
from app.ingestion import (
    MAX_LINE_BYTES, DecompressedLogTooLargeError, InvalidGzipError,
    NoApacheRecordsError, ingest_file, parse_error_timezone,
)
from app.parsers import parse_access_line
from app.storage import SQLiteStore

LINE = b'192.0.2.10 - - [06/Oct/2026:09:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234'
ERROR = b"[Tue Oct 06 09:01:02.123456 2026] [core:error] [pid 4120] AH00126: Invalid URI"
FIXTURES = Path(__file__).with_name("fixtures")


@pytest.fixture
def store():
    connection = connect_database(":memory:")
    initialize_database(connection)
    yield SQLiteStore(connection)
    connection.close()


@pytest.mark.parametrize("filename, log_type", [
    ("access_common.txt", "access"), ("access_combined.txt", "access"),
    ("access_combined_extended.txt", "access"),
    ("error_standard.txt", "error"), ("error_legacy.txt", "error"),
])
def test_imports_supported_formats_with_file_and_line_provenance(store, filename, log_type):
    source = FIXTURES / filename
    original = source.read_bytes()

    summary = ingest_file(source, log_type, store)

    assert summary.lines_read == summary.imported_events == 3
    assert summary.rejected_lines == summary.blank_lines == 0
    assert summary.source_file == str(source.resolve())
    assert summary.log_type == log_type
    events = store.list_events()
    assert {item.event.line_number for item in events} == {1, 2, 3}
    assert all(item.event.source_file == str(source.resolve()) for item in events)
    assert source.read_bytes() == original


@pytest.mark.parametrize("filename,log_type", [
    ("access_common.txt", "access"), ("access_combined.txt", "access"),
    ("access_combined_extended.txt", "access"),
    ("error_standard.txt", "error"), ("error_legacy.txt", "error"),
])
@pytest.mark.parametrize("extension", [".log.gz", ".tmp"])
def test_gzip_formats_preserve_decompressed_evidence_and_compressed_source(
    store, tmp_path, filename, log_type, extension,
):
    content = (FIXTURES / filename).read_bytes()
    original = gzip.compress(content, mtime=0)
    source = tmp_path / ("compressed" + extension)
    source.write_bytes(original)

    summary = ingest_file(source, log_type, store)

    assert summary.lines_read == summary.imported_events == 3
    assert summary.rejected_lines == summary.blank_lines == 0
    assert summary.source_file == str(source.resolve())
    for item in store.list_events():
        event = item.event
        assert event.raw_log == content.decode("utf-8").splitlines()[event.line_number - 1]
        assert event.source_file == str(source.resolve())
    assert source.read_bytes() == original
    assert list(tmp_path.iterdir()) == [source]


def test_gzip_bom_crlf_invalid_encoding_and_oversized_lines_keep_physical_numbers(store, tmp_path):
    content = b"\xef\xbb\xbf" + LINE + b"\r\n \r\nbad\xff\n" + b"x" * 300 + b"\n" + LINE
    source = tmp_path / "mixed.log.gz"
    source.write_bytes(gzip.compress(content, mtime=0))

    summary = ingest_file(source, "access", store, max_line_bytes=len(LINE) + 3)

    assert summary.lines_read == 5 and summary.imported_events == 2
    assert summary.blank_lines == summary.encoding_error_lines == summary.oversized_lines == 1
    assert summary.rejected_lines == 2
    first, last = store.list_events()
    assert first.event.line_number == 1 and last.event.line_number == 5
    assert first.event.raw_log == "\ufeff" + LINE.decode()
    assert first.event.source_ip == "192.0.2.10" and last.event.raw_log == LINE.decode()


def test_concatenated_gzip_members_form_one_continuous_log_stream(store, tmp_path):
    split = len(LINE) // 2
    source = tmp_path / "rotated.log.gz"
    source.write_bytes(
        gzip.compress(LINE[:split], mtime=0)
        + gzip.compress(LINE[split:] + b"\n" + LINE + b"\n", mtime=0)
    )

    summary = ingest_file(source, "access", store)

    assert summary.lines_read == summary.imported_events == 2
    assert [item.event.line_number for item in store.list_events()] == [1, 2]
    assert all(item.event.raw_log == LINE.decode() for item in store.list_events())


@pytest.mark.parametrize("damage", ["header", "deflate", "truncated", "checksum", "size", "trailing", "last_member"])
def test_damaged_gzip_rolls_back_all_imported_evidence(store, tmp_path, damage):
    previous = store.insert_event(parse_access_line(LINE.decode()))
    original = gzip.compress((LINE + b"\n") * 100, mtime=0)
    if damage == "header":
        content = original[:2] + b"\x00" + original[3:]
    elif damage == "deflate":
        content = b"\x1f\x8b\x08\x00" + b"\x00" * 6 + b"\x07"
    elif damage == "truncated":
        content = original[:-1]
    elif damage == "checksum":
        content = original[:-8] + bytes([original[-8] ^ 1]) + original[-7:]
    elif damage == "size":
        content = original[:-4] + bytes([original[-4] ^ 1]) + original[-3:]
    elif damage == "trailing":
        content = original + b"not a gzip member"
    else:
        content = original + original[:-1]
    source = tmp_path / "damaged.gz"
    source.write_bytes(content)
    before = list(store.connection.iterdump())

    with pytest.raises(InvalidGzipError, match="damaged, incomplete"):
        ingest_file(source, "access", store)

    assert list(store.connection.iterdump()) == before
    assert store.get_event(previous) is not None and not store.connection.in_transaction


@pytest.mark.parametrize("ending", [b"", b"\n", b"\r\n"])
def test_exact_gzip_decompressed_limit_is_accepted(store, tmp_path, ending):
    content = LINE + ending
    source = tmp_path / "exact.gz"
    source.write_bytes(gzip.compress(content, mtime=0))
    assert ingest_file(source, "access", store, max_decompressed_bytes=len(content)).imported_events == 1


@pytest.mark.parametrize("tail", [b"\n", b"x" * 1000, b"\n" * 1000])
def test_gzip_decompressed_limit_counts_blank_and_rejected_bytes_and_rolls_back(store, tmp_path, tail):
    previous = store.insert_event(parse_access_line(LINE.decode()))
    content = LINE + b"\n" + tail
    source = tmp_path / "expanded.gz"
    source.write_bytes(gzip.compress(content, mtime=0))
    before = list(store.connection.iterdump())
    with pytest.raises(DecompressedLogTooLargeError, match="decompressed size limit"):
        ingest_file(source, "access", store, max_decompressed_bytes=len(LINE) + 1)
    assert list(store.connection.iterdump()) == before
    assert store.get_event(previous) is not None


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, None])
def test_invalid_decompressed_limits_are_rejected_before_file_lookup(store, tmp_path, limit):
    with pytest.raises(ValueError, match="max_decompressed_bytes"):
        ingest_file(tmp_path / "missing.gz", "access", store, max_decompressed_bytes=limit)


@pytest.mark.parametrize("content,log_type,lines", [(b"", "access", 0), (ERROR, "access", 1)])
def test_gzip_with_no_matching_records_retains_rejection_summary(store, tmp_path, content, log_type, lines):
    source = tmp_path / "wrong.gz"
    source.write_bytes(gzip.compress(content, mtime=0))
    with pytest.raises(NoApacheRecordsError) as failure:
        ingest_file(source, log_type, store)
    assert failure.value.summary.lines_read == lines
    assert failure.value.summary.rejected_lines == lines
    assert store.count_events() == 0


def test_gzip_decompressed_limit_does_not_cap_plain_cli_files(store, tmp_path):
    source = tmp_path / "plain.log.gz"
    source.write_bytes(LINE + b"\n" + LINE)
    assert ingest_file(source, "access", store, max_decompressed_bytes=1).imported_events == 2


def test_mixed_file_counts_rejection_reasons_without_losing_line_numbers(store, tmp_path):
    limit = len(LINE) + 16
    too_large = LINE.replace(b"1234", b"9223372036854775808")
    # The invalid numeric record must fit the byte limit so it reaches storage.
    limit = max(limit, len(too_large))
    payload = b"\n".join([LINE, b" \t", b"not Apache", b"bad\xff", b"x" * (limit * 3), too_large, LINE])
    source = tmp_path / "mixed.txt"
    source.write_bytes(payload)

    summary = ingest_file(source, "access", store, max_line_bytes=limit)

    assert summary.lines_read == 7
    assert summary.imported_events == 2
    assert summary.blank_lines == 1
    assert summary.malformed_lines == 1
    assert summary.encoding_error_lines == 1
    assert summary.oversized_lines == 1
    assert summary.invalid_value_lines == 1
    assert summary.rejected_lines == 4
    assert summary.as_dict()["rejected_lines"] == 4
    assert summary.imported_events + summary.blank_lines + summary.rejected_lines == summary.lines_read
    assert [item.event.line_number for item in store.list_events()] == [1, 7]
    assert source.read_bytes() == payload


@pytest.mark.parametrize("ending", [b"", b"\n", b"\r\n"])
def test_exact_byte_limit_accepts_final_line_with_or_without_line_ending(store, tmp_path, ending):
    source = tmp_path / "boundary.txt"
    source.write_bytes(LINE + ending)

    summary = ingest_file(source, "access", store, max_line_bytes=len(LINE))

    assert summary.imported_events == 1
    assert summary.oversized_lines == 0
    assert store.list_events()[0].event.raw_log == LINE.decode("utf-8")


@pytest.mark.parametrize("ending", [b"", b"\n", b"\r\n"])
def test_oversized_records_are_drained_as_one_physical_line(store, tmp_path, ending):
    source = tmp_path / "oversized.txt"
    payload = LINE + b"\n" + b"x" * (len(LINE) * 20) + ending
    if ending:
        payload += LINE
    source.write_bytes(payload)

    summary = ingest_file(source, "access", store, max_line_bytes=len(LINE))

    assert summary.oversized_lines == 1
    assert summary.imported_events == (2 if ending else 1)
    assert summary.lines_read == (3 if ending else 2)
    assert [item.event.line_number for item in store.list_events()] == ([1, 3] if ending else [1])


def test_utf8_signature_does_not_pollute_the_host_and_remains_in_raw_evidence(store, tmp_path):
    source = tmp_path / "with_bom.txt"
    source.write_bytes(b"\xef\xbb\xbf" + LINE + b"\r\n")

    summary = ingest_file(source, "access", store)

    assert summary.imported_events == 1
    event = store.list_events()[0].event
    assert event.source_ip == "192.0.2.10"
    assert event.raw_log == "\ufeff" + LINE.decode("utf-8")


def test_error_timezone_is_recorded_and_converted_to_utc(store, tmp_path):
    source = tmp_path / "error.txt"
    source.write_bytes(ERROR)
    assumed = timezone(timedelta(hours=-7))

    summary = ingest_file(source, "error", store, error_timezone=assumed)

    assert summary.assumed_timezone == "UTC-07:00"
    event = store.list_events()[0].event
    assert event.timestamp == datetime(2026, 10, 6, 16, 1, 2, 123456, tzinfo=timezone.utc)
    assert event.assumed_timezone == summary.assumed_timezone


@pytest.mark.parametrize("contents, log_type, expected_lines, expected_rejected, expected_blank", [
    (b"", "access", 0, 0, 0),
    (b"\n \t\r\n", "access", 2, 0, 2),
    (b"Oct 6 09:00:00 host sshd[1]: Failed password for user\n", "access", 1, 1, 0),
    (b'{"source": "network_telemetry"}\n', "access", 1, 1, 0),
    (ERROR, "access", 1, 1, 0),
    (LINE, "error", 1, 1, 0),
    (b"\xff\xfeinvalid", "access", 1, 1, 0),
])
def test_no_matching_records_fail_without_changing_existing_evidence(
    store, tmp_path, contents, log_type, expected_lines, expected_rejected, expected_blank,
):
    previous = store.insert_event(parse_access_line(LINE.decode("utf-8")))
    source = tmp_path / "unsupported.txt"
    source.write_bytes(contents)

    with pytest.raises(NoApacheRecordsError) as failure:
        ingest_file(source, log_type, store)

    assert failure.value.summary.lines_read == expected_lines
    assert failure.value.summary.rejected_lines == expected_rejected
    assert failure.value.summary.blank_lines == expected_blank
    assert failure.value.summary.imported_events == 0
    assert [item.id for item in store.list_events()] == [previous]
    assert not store.connection.in_transaction


def test_sqlite_failure_rolls_back_the_import_and_keeps_previous_events(store, tmp_path):
    previous = store.insert_event(parse_access_line(LINE.decode("utf-8")))
    store.connection.execute(
        "CREATE TRIGGER fail_event BEFORE INSERT ON events WHEN NEW.path = '/fail' "
        "BEGIN SELECT RAISE(ABORT, 'synthetic storage failure'); END"
    )
    source = tmp_path / "failure.txt"
    source.write_bytes(LINE + b"\n" + LINE.replace(b"/index.html", b"/fail"))

    with pytest.raises(sqlite3.IntegrityError, match="synthetic storage failure"):
        ingest_file(source, "access", store)

    assert [item.id for item in store.list_events()] == [previous]
    assert not store.connection.in_transaction


class GuardedReader:
    """Enforce the bounded-read contract and optionally simulate a read failure."""

    def __init__(self, stream, limit, fail_at=None):
        self.stream = stream
        self.limit = limit
        self.fail_at = fail_at
        self.calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *error):
        return self.stream.__exit__(*error)

    def fileno(self):
        return self.stream.fileno()

    def peek(self, size):
        assert size == 2, "Only the gzip header may be inspected before streaming"
        return self.stream.peek(size)

    def readline(self, size=-1):
        assert 0 < size <= self.limit + 2, "Importer attempted an unbounded read"
        self.calls += 1
        if self.calls == self.fail_at:
            raise OSError("synthetic read failure")
        return self.stream.readline(size)

    def read(self, *args):
        raise AssertionError("Importer must not read the entire file")

    def readlines(self, *args):
        raise AssertionError("Importer must not collect the entire file")


def guard_source(monkeypatch, source, limit, fail_at=None):
    original_open = Path.open
    readers = []

    def guarded_open(path, *args, **kwargs):
        stream = original_open(path, *args, **kwargs)
        if path == source:
            reader = GuardedReader(stream, limit, fail_at=fail_at)
            readers.append(reader)
            return reader
        return stream

    monkeypatch.setattr(Path, "open", guarded_open)
    return readers


def test_large_file_and_oversized_line_use_only_bounded_reads(store, tmp_path, monkeypatch):
    source = tmp_path / "large.txt"
    source.write_bytes(b"x" * (1024 * 1024) + b"\n" + (LINE + b"\n") * 2000)
    readers = guard_source(monkeypatch, source, len(LINE))

    summary = ingest_file(source, "access", store, max_line_bytes=len(LINE))

    assert summary.imported_events == 2000
    assert summary.oversized_lines == 1
    assert summary.lines_read == 2001
    assert readers[0].calls > summary.lines_read
    assert readers[0].stream.closed
    assert store.count_events() == 2000


def test_large_gzip_and_oversized_record_use_bounded_decompressed_reads(store, tmp_path, monkeypatch):
    from app import ingestion

    source = tmp_path / "large.gz"
    source.write_bytes(gzip.compress(b"x" * (1024 * 1024) + b"\n" + (LINE + b"\n") * 2000, mtime=0))
    original = gzip.GzipFile
    readers = []

    def guarded_gzip(*args, **kwargs):
        reader = GuardedReader(original(*args, **kwargs), len(LINE))
        readers.append(reader)
        return reader

    monkeypatch.setattr(ingestion.gzip, "GzipFile", guarded_gzip)
    summary = ingest_file(source, "access", store, max_line_bytes=len(LINE))
    assert summary.imported_events == 2000 and summary.oversized_lines == 1
    assert summary.lines_read == 2001 and readers[0].calls > summary.lines_read
    assert readers[0].stream.closed and store.count_events() == 2000


def test_read_failure_rolls_back_preceding_imported_lines(store, tmp_path, monkeypatch):
    previous = store.insert_event(parse_access_line(LINE.decode("utf-8")))
    source = tmp_path / "unreadable.txt"
    source.write_bytes(LINE + b"\n" + LINE)
    readers = guard_source(monkeypatch, source, len(LINE), fail_at=2)

    with pytest.raises(OSError, match="synthetic read failure"):
        ingest_file(source, "access", store, max_line_bytes=len(LINE))

    assert [item.id for item in store.list_events()] == [previous]
    assert readers[0].stream.closed
    assert not store.connection.in_transaction


def test_import_respects_the_callers_outer_transaction(store, tmp_path):
    source = tmp_path / "access.txt"
    source.write_bytes(LINE)

    with pytest.raises(RuntimeError, match="outer failure"):
        with transaction(store.connection):
            ingest_file(source, "access", store)
            assert store.count_events() == 1
            raise RuntimeError("outer failure")

    assert store.count_events() == 0


def test_repeating_an_import_appends_events(store, tmp_path):
    source = tmp_path / "access.txt"
    source.write_bytes(LINE)

    first = ingest_file(source, "access", store)
    second = ingest_file(source, "access", store)

    assert first.imported_events == second.imported_events == 1
    assert store.count_events() == 2


def test_missing_files_and_directories_are_rejected(store, tmp_path):
    with pytest.raises(FileNotFoundError):
        ingest_file(tmp_path / "missing.txt", "access", store)
    with pytest.raises(ValueError, match="regular log file"):
        ingest_file(tmp_path, "access", store)
    assert store.count_events() == 0


@pytest.mark.parametrize("limit", [0, -1, MAX_LINE_BYTES + 1, True, 1.5])
def test_invalid_byte_limits_are_rejected(store, tmp_path, limit):
    with pytest.raises(ValueError, match="max_line_bytes"):
        ingest_file(tmp_path / "missing.txt", "access", store, max_line_bytes=limit)


def test_non_apache_source_is_rejected_before_reading_a_file(store, tmp_path):
    with pytest.raises(ValueError, match="Unsupported Apache log type"):
        ingest_file(tmp_path / "missing.txt", "linux_auth", store)


@pytest.mark.parametrize("value, expected", [
    ("UTC", timezone.utc), (" utc ", timezone.utc),
    ("-07:00", timezone(timedelta(hours=-7))),
    ("+05:30", timezone(timedelta(hours=5, minutes=30))),
    ("+00:00", timezone.utc),
])
def test_fixed_error_timezones(value, expected):
    assert parse_error_timezone(value) == expected


@pytest.mark.parametrize("value", ["", "local", "America/Los_Angeles", "+24:00", "-00:60", "0700", "-7:00"])
def test_invalid_error_timezones(value):
    with pytest.raises(ValueError, match="signed UTC offset"):
        parse_error_timezone(value)
