"""Import idempotency, retained repeated lines, and non-destructive upgrades."""

import gzip
import io
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from app import create_app
from app.database import SCHEMA_VERSION, connect_database, initialize_database
from app.ingestion import InvalidGzipError, ingest_file
from app.parsers import parse_access_line
from app.pipeline import analyze_file, detect_events
from app.storage import SQLiteStore

DOMAIN = "chronoscrate"
LINE = b'192.0.2.10 - - [06/Oct/2026:09:00:00 +0000] "GET /index.html HTTP/1.1" 200 123\n'
PROBE = LINE.replace(b"/index.html", b"/.env")
HEADERS = {"X-Apache-Upload": "1"}


@pytest.fixture
def workspace(tmp_path):
    path = tmp_path / "events.sqlite3"
    app = create_app({"TESTING": True, "DATABASE_PATH": str(path)})
    app.instance_path = str(tmp_path / "instance")
    initialized = app.test_cli_runner().invoke(args=["init-db"])
    assert initialized.exit_code == 0, initialized.output
    connection = connect_database(path)
    yield app, SQLiteStore(connection), tmp_path
    connection.close()


def upload(app, content, *, filename="access.log", domain=DOMAIN, log_type="access"):
    return app.test_client().post("/api/imports", headers=HEADERS, data={
        "file": (io.BytesIO(content), filename), "domain_id": domain, "log_type": log_type,
    })


@pytest.mark.parametrize("variant", ["same", "renamed", "gzip", "gzip-metadata", "line-endings", "bom", "blank-malformed"])
def test_same_records_are_imported_once_regardless_of_name_or_wrapping(workspace, variant):
    app, store, _ = workspace
    content = LINE + PROBE
    first = upload(app, content)
    assert first.status_code == 201
    before = list(store.connection.iterdump())
    if variant == "gzip":
        content = gzip.compress(content, mtime=0)
    elif variant == "gzip-metadata":
        content = gzip.compress(content, mtime=123456)
    elif variant == "line-endings":
        content = content.replace(b"\n", b"\r\n")
    elif variant == "bom":
        content = b"\xef\xbb\xbf" + content
    elif variant == "blank-malformed":
        content = b"\nnot Apache\n" + LINE + b"\n" + PROBE
    result = upload(app, content, filename="renamed.txt" if variant != "same" else "access.log")
    assert result.status_code == 200
    summary = result.json["summary"]
    assert summary["duplicate_file"] and summary["imported_events"] == 0
    assert summary["skipped_duplicate_events"] == 2
    assert summary["duplicate_of_import_id"] == first.json["summary"]["import_id"]
    assert summary["duplicate_of_source_file"] == first.json["summary"]["source_file"]
    assert all(value == 0 for value in summary["detection"].values())
    assert list(store.connection.iterdump()) == before
    assert list((Path(app.instance_path) / "uploads").iterdir()) == []


def test_identical_lines_with_same_timestamp_are_kept_and_linked_for_review(workspace):
    app, store, _ = workspace
    response = upload(app, PROBE * 3)
    summary = response.json["summary"]
    assert response.status_code == 201 and summary["imported_events"] == 3
    assert summary["duplicate_lines"] == 2 and not summary["duplicate_file"]
    assert store.count_events() == 3
    alert, = store.list_alerts()
    assert alert.event_count == 3
    assert summary["duplicate_line_samples"] == [
        {"event_id": 2, "line_number": 2, "original_event_id": 1, "original_line_number": 1},
        {"event_id": 3, "line_number": 3, "original_event_id": 1, "original_line_number": 1},
    ]
    review = app.test_client().get(f"/api/imports/{summary['import_id']}/duplicates")
    assert review.status_code == 200 and review.json["pagination"]["total"] == 2
    assert review.json["items"] == summary["duplicate_line_samples"]
    assert review.headers["X-Analyzer-Domain"] == DOMAIN
    for item in review.json["items"]:
        assert store.get_event(item["event_id"]).event.raw_log == store.get_event(item["original_event_id"]).event.raw_log
        assert store.get_event(item["event_id"]).event.timestamp == store.get_event(item["original_event_id"]).event.timestamp


def test_warning_samples_are_bounded_but_review_paginates_all_repetitions(workspace):
    app, _, _ = workspace
    summary = upload(app, LINE * 30).json["summary"]
    assert summary["duplicate_lines"] == 29 and len(summary["duplicate_line_samples"]) == 20
    identities = []
    for offset in range(0, 29, 7):
        page = app.test_client().get(f"/api/imports/{summary['import_id']}/duplicates?limit=7&offset={offset}").json
        assert page["pagination"]["total"] == 29
        identities += [item["event_id"] for item in page["items"]]
    assert identities == list(range(2, 31))
    duplicate = upload(app, gzip.compress(LINE * 30), filename="copy.gz")
    assert duplicate.status_code == 200 and duplicate.json["summary"]["duplicate_lines"] == 29
    assert duplicate.json["summary"]["duplicate_line_samples"] == summary["duplicate_line_samples"]


def test_same_file_is_allowed_once_per_domain_and_reviews_do_not_cross_domains(workspace):
    app, store, _ = workspace
    first = upload(app, PROBE * 2)
    other = upload(app, PROBE * 2, domain="la_jolla_seals")
    assert first.status_code == other.status_code == 201
    assert first.json["summary"]["import_id"] == other.json["summary"]["import_id"] == 1
    for domain in (DOMAIN, "la_jolla_seals"):
        duplicate = upload(app, PROBE * 2, domain=domain)
        assert duplicate.status_code == 200 and duplicate.json["summary"]["duplicate_file"]
        assert duplicate.json["summary"]["domain_id"] == domain
    # A second primary import has an ID absent in the secondary database.
    fresh = upload(app, PROBE.replace(b"09:00:00", b"09:00:01") * 2)
    identity = fresh.json["summary"]["import_id"]
    assert app.test_client().get(f"/api/imports/{identity}/duplicates?domain_id=la_jolla_seals").status_code == 404
    assert store.count_events() == 4


def test_partial_overlap_and_changed_multiplicity_are_not_silently_discarded(workspace):
    app, store, _ = workspace
    first = upload(app, LINE)
    repeated = upload(app, LINE * 2)
    overlap = upload(app, LINE + PROBE)
    assert first.status_code == repeated.status_code == overlap.status_code == 201
    assert repeated.json["summary"]["duplicate_lines"] == 1
    assert overlap.json["summary"]["duplicate_lines"] == 0
    assert store.count_events() == 5


def test_file_identity_and_review_state_survive_process_restart(workspace):
    app, store, _ = workspace
    first = upload(app, PROBE * 2)
    before = list(store.connection.iterdump())
    reopened = create_app({"TESTING": True, "DATABASE_PATH": app.config["DATABASE_PATH"]})
    reopened.instance_path = app.instance_path
    duplicate = upload(reopened, PROBE * 2, filename="copy.log")
    assert duplicate.status_code == 200 and duplicate.json["summary"]["duplicate_file"]
    assert duplicate.json["summary"]["duplicate_of_import_id"] == first.json["summary"]["import_id"]
    assert list(store.connection.iterdump()) == before


def test_duplicate_file_does_not_rescan_or_change_closed_alerts(workspace, monkeypatch):
    from app import pipeline

    app, store, tmp_path = workspace
    path = tmp_path / "probe.txt"
    path.write_bytes(PROBE)
    analyze_file(path, "access", store)
    alert, = store.list_alerts()
    store.set_alert_status(alert.id, "false_positive")
    before = list(store.connection.iterdump())

    def unexpected_detection(*args, **kwargs):
        pytest.fail("A duplicate import must not rerun detection.")

    monkeypatch.setattr(pipeline, "detect_events", unexpected_detection)
    result = analyze_file(path, "access", store)
    assert result.import_summary.duplicate_file
    assert list(store.connection.iterdump()) == before


def test_failed_detection_does_not_poison_fingerprint_or_retry(workspace, monkeypatch):
    from app import pipeline

    _, store, tmp_path = workspace
    path = tmp_path / "retry.txt"
    path.write_bytes(PROBE * 2)
    original = pipeline.detect_events
    before = list(store.connection.iterdump())

    def fail(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("Synthetic detection failure")

    with monkeypatch.context() as patch:
        patch.setattr(pipeline, "detect_events", fail)
        with pytest.raises(RuntimeError, match="Synthetic"):
            analyze_file(path, "access", store)
    assert list(store.connection.iterdump()) == before
    retried = analyze_file(path, "access", store)
    assert not retried.import_summary.duplicate_file and retried.import_summary.imported_events == 2


def test_bad_gzip_is_still_validated_before_duplicate_detection(workspace):
    app, store, _ = workspace
    assert upload(app, gzip.compress(PROBE)).status_code == 201
    before = list(store.connection.iterdump())
    damaged = upload(app, gzip.compress(PROBE)[:-1])
    assert damaged.status_code == 422 and damaged.json["error"]["code"] == "invalid_gzip"
    assert list(store.connection.iterdump()) == before


def test_cli_duplicate_is_successful_noop_and_reports_original_import(workspace):
    app, store, tmp_path = workspace
    path = tmp_path / "cli.txt"
    path.write_bytes(LINE * 2)
    cli = app.test_cli_runner()
    args = ["ingest", str(path), "--format", "access"]
    first = cli.invoke(args=args)
    assert first.exit_code == 0 and "Repeated lines retained for review: 1" in first.output
    before = list(store.connection.iterdump())
    second = cli.invoke(args=args)
    assert second.exit_code == 0 and "Already imported; skipped 2" in second.output
    assert list(store.connection.iterdump()) == before


def test_changing_error_timezone_does_not_duplicate_identical_evidence(workspace):
    app, store, tmp_path = workspace
    path = tmp_path / "error.txt"
    path.write_bytes(b"[Tue Oct 06 09:00:00.000000 2026] [core:error] AH00001: Synthetic\n")
    cli = app.test_cli_runner()
    assert cli.invoke(args=["ingest", str(path), "--format", "error"]).exit_code == 0
    before = list(store.connection.iterdump())
    result = cli.invoke(args=["ingest", str(path), "--format", "error", "--error-timezone=-07:00"])
    assert result.exit_code == 0 and "Already imported" in result.output
    assert list(store.connection.iterdump()) == before


def test_full_content_hash_blocks_retry_with_different_line_limit(workspace):
    _, store, tmp_path = workspace
    content = LINE + LINE.replace(b"/index.html", b"/" + b"x" * 300)
    path = tmp_path / "limits.txt"
    path.write_bytes(content)
    first = ingest_file(path, "access", store, max_line_bytes=len(LINE))
    assert first.imported_events == first.oversized_lines == 1
    before = list(store.connection.iterdump())
    retried = ingest_file(path, "access", store, max_line_bytes=1024)
    assert retried.duplicate_file and retried.imported_events == 0
    assert list(store.connection.iterdump()) == before


def test_same_mixed_file_can_be_imported_once_for_each_explicit_format(workspace):
    app, store, _ = workspace
    content = LINE + b"[Tue Oct 06 09:00:00.000000 2026] [core:error] AH00001: Synthetic\n"
    assert upload(app, content, log_type="access").status_code == 201
    assert upload(app, content, log_type="error").status_code == 201
    assert upload(app, content, log_type="access").status_code == 200
    assert store.count_events() == 2


@pytest.mark.parametrize("version", [1, 2])
def test_upgrade_recognizes_legacy_imports_and_preserves_historical_duplicates(tmp_path, version):
    path = tmp_path / "legacy.sqlite3"
    connection = connect_database(path)
    initialize_database(connection)
    store = SQLiteStore(connection)
    # Two old imports of the same file; preserve all six existing events.
    for _ in range(2):
        for number, raw in enumerate((LINE, LINE, PROBE), 1):
            store.insert_event(parse_access_line(raw.decode(), source_file="upload:legacy/access.log", line_number=number))
    detect_events(store)
    alert, = store.list_alerts()
    store.set_alert_status(alert.id, "false_positive")
    original_alert = store.get_alert(alert.id)
    connection.execute("DROP TABLE import_lines")
    connection.execute("DROP TABLE imports")
    if version == 1:
        connection.execute("DROP TABLE alert_merges")
    connection.execute(f"PRAGMA user_version = {version}")
    initialize_database(connection)
    upgraded = SQLiteStore(connection)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert upgraded.count_events() == 6 and upgraded.get_alert(alert.id) == original_alert
    assert connection.execute("SELECT COUNT(*) FROM imports WHERE legacy = 1").fetchone()[0] == 2
    source = tmp_path / "renamed.txt"
    source.write_bytes(LINE + LINE + PROBE)
    before = list(connection.iterdump())
    repeated = analyze_file(source, "access", upgraded)
    assert repeated.import_summary.duplicate_file and repeated.import_summary.skipped_duplicate_events == 3
    assert repeated.import_summary.duplicate_lines == 1
    assert list(connection.iterdump()) == before
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    initialize_database(connection)
    assert list(connection.iterdump()) == before
    connection.close()


def test_failed_migration_rolls_back_registry_tables_and_version(tmp_path, monkeypatch):
    from app import database

    connection = connect_database(":memory:")
    initialize_database(connection)
    store = SQLiteStore(connection)
    store.insert_event(parse_access_line(LINE.decode(), source_file="old.log", line_number=1))
    connection.execute("DROP TABLE import_lines")
    connection.execute("DROP TABLE imports")
    connection.execute("PRAGMA user_version = 2")
    before = list(connection.iterdump())
    original = database.backfill_legacy_imports

    def fail(*args):
        original(*args)
        raise sqlite3.OperationalError("Synthetic migration failure")

    monkeypatch.setattr(database, "backfill_legacy_imports", fail)
    with pytest.raises(sqlite3.OperationalError, match="Synthetic migration"):
        initialize_database(connection)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
    assert list(connection.iterdump()) == before
    connection.close()


def test_unprovenanced_legacy_events_are_preserved_without_guessing_file_identity(tmp_path):
    connection = connect_database(":memory:")
    initialize_database(connection)
    store = SQLiteStore(connection)
    store.insert_event(parse_access_line(LINE.decode()))
    connection.execute("DROP TABLE import_lines")
    connection.execute("DROP TABLE imports")
    connection.execute("PRAGMA user_version = 2")
    initialize_database(connection)
    assert SQLiteStore(connection).count_events() == 1
    assert connection.execute("SELECT COUNT(*) FROM imports").fetchone()[0] == 0
    connection.close()


def test_concurrent_same_domain_uploads_commit_exactly_once(workspace, monkeypatch):
    from app import uploads

    app, store, _ = workspace
    barrier = Barrier(2)
    original = uploads.analyze_file

    def synchronize(*args, **kwargs):
        barrier.wait(timeout=10)
        return original(*args, **kwargs)

    monkeypatch.setattr(uploads, "analyze_file", synchronize)
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: upload(app, PROBE * 5), range(2)))
    assert sorted(response.status_code for response in responses) == [200, 201]
    assert store.count_events() == 5 and store.count_alerts() == 1
    assert store.connection.execute("SELECT COUNT(*) FROM imports").fetchone()[0] == 1


@pytest.mark.parametrize("path,status", [
    ("/api/imports/0/duplicates", 400), ("/api/imports/bad/duplicates", 400),
    ("/api/imports/999/duplicates", 404), ("/api/imports/1/duplicates?limit=0", 400),
    ("/api/imports/1/duplicates?offset=-1", 400), ("/api/imports/1/duplicates?unknown=1", 400),
    ("/api/imports/1/duplicates?domain_id=unknown", 400),
])
def test_repeated_line_review_validates_ids_and_pagination(workspace, path, status):
    app, _, _ = workspace
    assert upload(app, LINE).status_code == 201
    assert app.test_client().get(path).status_code == status
