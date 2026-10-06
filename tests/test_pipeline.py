import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app.database import connect_database, initialize_database, transaction
from app.detection import DetectionEngine
from app.ingestion import NoApacheRecordsError, ingest_file
from app.pipeline import analyze_file, detect_events
from app.signatures import DEFAULT_ALLOWED_METHODS
from app.storage import SQLiteStore

BASE = datetime(2026, 10, 6, 9, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def store():
    connection = connect_database(":memory:")
    initialize_database(connection)
    yield SQLiteStore(connection)
    connection.close()


def access_line(target="/private", *, status=200, method="GET", ip="192.0.2.10", seconds=0):
    stamp = BASE + timedelta(seconds=seconds)
    return f'{ip} - - [06/Oct/2026:{stamp:%H:%M:%S} +0000] "{method} {target} HTTP/1.1" {status} 0'


def file(tmp_path, name, lines):
    path = tmp_path / name
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def test_import_and_detection_can_persist_all_eleven_rule_types(store, tmp_path):
    lines = []
    cases = [
        ("APACHE-PATH-ENUMERATION", 10, 404, "192.0.2.30"),
        ("APACHE-HTTP-ERRORS", 20, 403, "192.0.2.31"),
        ("APACHE-AUTH-FAILURES", 10, 401, "192.0.2.32"),
        ("APACHE-REQUEST-BURST", 120, 200, "192.0.2.33"),
    ]
    for rule_id, count, status, ip in cases:
        lines.extend(access_line(
            f"/missing-{index % 5}" if rule_id == "APACHE-PATH-ENUMERATION" else "/private",
            status=status, ip=ip,
        ) for index in range(count))
    lines.extend([
        access_line("/../private.txt"), access_line("/?id=1+UNION+SELECT+1"),
        access_line("/?q=%3Cscript%3Ealert(1)%3C/script%3E"),
        access_line("/.env"), access_line(method="TRACE"),
    ])
    lines.extend(access_line(status=503, ip=f"192.0.2.{index + 40}") for index in range(20))
    access_path = file(tmp_path, "all-access.txt", lines)
    error_path = file(tmp_path, "all-error.txt", [
        "[Tue Oct 06 09:00:00.000000 2026] [core:error] AH00001: Synthetic failure"
    ] * 10)

    imported = analyze_file(access_path, "access", store)
    errors = analyze_file(error_path, "error", store)

    assert imported.import_summary.imported_events == 185
    assert imported.detection.alerts_created == 10
    assert errors.import_summary.imported_events == 10
    assert errors.detection.alerts_created == 1
    assert store.count_alerts() == 11
    alerts = store.list_alerts()
    assert {item.alert.rule_id for item in alerts} == {rule.rule_id for rule in DetectionEngine().rules}
    assert all(item.alert.status == "new" for item in alerts)
    for stored in alerts:
        evidence = store.get_alert_events(stored.id, limit=1000)
        assert len(evidence) == stored.event_count
        assert all(item.event.source_file in {str(access_path.resolve()), str(error_path.resolve())} for item in evidence)
        assert all(item.event.line_number > 0 for item in evidence)
    before = store.connection.total_changes
    rerun = detect_events(store)
    assert rerun.findings == rerun.findings_unchanged == 11
    assert rerun.alerts_created == rerun.alert_updates == rerun.alerts_merged == 0
    assert store.connection.total_changes == before
    assert store.list_alerts() == alerts


def test_threshold_can_be_reached_across_separate_imported_files(store, tmp_path):
    first_path = file(tmp_path, "first.txt", [access_line(status=401)] * 9)
    last_path = file(tmp_path, "last.txt", [access_line(status=401, seconds=1)])
    assert analyze_file(first_path, "access", store).detection.alerts_created == 0

    summary = analyze_file(last_path, "access", store)

    assert summary.detection.alerts_created == 1
    alert, = store.list_alerts()
    assert alert.alert.rule_id == "APACHE-AUTH-FAILURES"
    assert alert.event_count == 10
    assert {item.event.source_file for item in store.get_alert_events(alert.id)} == {str(first_path.resolve()), str(last_path.resolve())}


def test_late_imports_create_new_windows_and_add_context_to_existing_alerts(store, tmp_path):
    later = file(tmp_path, "later.txt", [access_line(status=401, seconds=10)] * 9)
    older = file(tmp_path, "older.txt", [access_line(status=401)])
    assert analyze_file(later, "access", store).detection.alerts_created == 0
    assert analyze_file(older, "access", store).detection.alerts_created == 1
    original, = store.list_alerts()
    assert original.alert.first_seen == BASE
    assert original.alert.last_seen == BASE + timedelta(seconds=10)
    oldest = file(tmp_path, "oldest.txt", [access_line(status=401, seconds=-1)])

    summary = analyze_file(oldest, "access", store)

    assert summary.detection.alerts_created == 0
    assert summary.detection.alert_updates == 1
    current, = store.list_alerts()
    assert current.id == original.id
    assert current.alert.first_seen == BASE - timedelta(seconds=1)
    assert current.alert.last_seen == original.alert.last_seen
    assert current.event_count == 11
    assert detect_events(store).alert_updates == 0


def test_reimport_appends_events_and_extends_existing_open_alert(store, tmp_path):
    path = file(tmp_path, "probe.txt", [access_line("/.env")])
    first = analyze_file(path, "access", store)
    second = analyze_file(path, "access", store)
    assert first.detection.alerts_created == 1
    assert second.detection.alerts_created == 0 and second.detection.alert_updates == 1
    assert store.count_events() == 2 and store.count_alerts() == 1
    assert store.list_alerts()[0].event_count == 2


@pytest.mark.parametrize("status", ["resolved", "false_positive"])
def test_replay_preserves_closed_status_and_fresh_requests_create_new_alert(store, tmp_path, status):
    path = file(tmp_path, "probe.txt", [access_line("/.env")])
    analyze_file(path, "access", store)
    original, = store.list_alerts()
    store.set_alert_status(original.id, status)
    closed = store.get_alert(original.id)
    assert detect_events(store).findings_unchanged == 1
    assert store.get_alert(original.id) == closed

    summary = analyze_file(path, "access", store)

    assert summary.detection.alerts_created == 1
    assert store.count_alerts() == 2
    assert store.get_alert(original.id) == closed
    assert store.list_alerts(status="new")[0].event_count == 1


def test_alert_failure_rolls_back_new_import_and_prior_alert_update(store, tmp_path):
    first_path = file(tmp_path, "first.txt", [access_line("/.env")])
    analyze_file(first_path, "access", store)
    before = store.list_alerts()
    store.connection.execute(
        "CREATE TRIGGER fail_sql BEFORE INSERT ON alerts WHEN NEW.rule_id = 'APACHE-SQL-INJECTION' "
        "BEGIN SELECT RAISE(ABORT, 'synthetic alert failure'); END"
    )
    new_path = file(tmp_path, "new.txt", [
        access_line("/.env", seconds=1), access_line("/?id=1+UNION+SELECT+1", seconds=2),
    ])

    with pytest.raises(sqlite3.IntegrityError, match="synthetic alert failure"):
        analyze_file(new_path, "access", store)

    assert store.count_events() == 1
    assert store.list_alerts() == before
    assert store.list_alerts()[0].event_count == 1
    assert not store.connection.in_transaction


def test_scan_failure_rolls_back_bridge_merge_aliases_and_imported_events(store, tmp_path):
    original = file(tmp_path, "original.txt", [access_line("/.env"), access_line("/.env", seconds=600)])
    analyze_file(original, "access", store)
    before = store.list_alerts()
    assert len(before) == 2
    store.connection.execute(
        "CREATE TRIGGER fail_sql BEFORE INSERT ON alerts WHEN NEW.rule_id = 'APACHE-SQL-INJECTION' "
        "BEGIN SELECT RAISE(ABORT, 'stop after merge'); END"
    )
    new_path = file(tmp_path, "bridge.txt", [
        access_line("/.env", seconds=300), access_line("/?id=1+UNION+SELECT+1", seconds=601),
    ])

    with pytest.raises(sqlite3.IntegrityError, match="stop after merge"):
        analyze_file(new_path, "access", store)

    assert store.count_events() == 2
    assert store.list_alerts() == before
    assert store.get_alert(before[1].id).id == before[1].id
    assert store.connection.execute("SELECT COUNT(*) FROM alert_merges").fetchone()[0] == 0


class BreakingEngine(DetectionEngine):
    def iter_findings(self, store):
        iterator = super().iter_findings(store)
        try:
            yield next(iterator)
            raise RuntimeError("synthetic detector failure")
        finally:
            iterator.close()


def test_detector_failure_rolls_back_new_events_and_alerts(store, tmp_path):
    path = file(tmp_path, "probe.txt", [access_line("/.env")])
    with pytest.raises(RuntimeError, match="synthetic detector failure"):
        analyze_file(path, "access", store, engine=BreakingEngine())
    assert store.count_events() == store.count_alerts() == 0
    assert not store.connection.in_transaction


def test_failed_explicit_scan_preserves_existing_raw_import(store, tmp_path):
    path = file(tmp_path, "probe.txt", [access_line("/.env")])
    ingest_file(path, "access", store)
    with pytest.raises(RuntimeError, match="synthetic detector failure"):
        detect_events(store, engine=BreakingEngine())
    assert store.count_events() == 1
    assert store.count_alerts() == 0


def test_empty_or_wrong_format_import_leaves_prior_alerts_unchanged(store, tmp_path):
    path = file(tmp_path, "probe.txt", [access_line("/.env")])
    analyze_file(path, "access", store)
    before = store.list_alerts()
    empty = file(tmp_path, "empty.txt", [])
    for source, log_type in ((empty, "access"), (path, "error")):
        with pytest.raises(NoApacheRecordsError):
            analyze_file(source, log_type, store)
    assert store.count_events() == 1
    assert store.list_alerts() == before


def test_caller_can_roll_back_complete_import_and_detection(store, tmp_path):
    path = file(tmp_path, "probe.txt", [access_line("/.env")])
    with pytest.raises(RuntimeError, match="outer rollback"):
        with transaction(store.connection):
            analyze_file(path, "access", store)
            assert store.count_events() == store.count_alerts() == 1
            raise RuntimeError("outer rollback")
    assert store.count_events() == store.count_alerts() == 0


def test_custom_request_correlation_gap_and_method_configuration(store, tmp_path):
    path = file(tmp_path, "probes.txt", [
        access_line("/.env"), access_line("/.env", seconds=11), access_line(method="PROPFIND"),
    ])
    engine = DetectionEngine(allowed_methods=DEFAULT_ALLOWED_METHODS | {"PROPFIND"})
    summary = analyze_file(path, "access", store, engine=engine, request_correlation_seconds=10)
    assert summary.detection.alerts_created == 2
    assert store.count_alerts(rule_id="APACHE-SENSITIVE-FILE") == 2
    assert store.count_alerts(rule_id="APACHE-UNUSUAL-METHOD") == 0


@pytest.mark.parametrize("gap", [0, -1, 86401, True, "300"])
def test_invalid_correlation_settings_fail_before_file_reads_or_writes(store, tmp_path, gap):
    with pytest.raises(ValueError, match="request_correlation_seconds"):
        analyze_file(tmp_path / "missing.txt", "access", store, request_correlation_seconds=gap)
    with pytest.raises(ValueError, match="request_correlation_seconds"):
        detect_events(store, request_correlation_seconds=gap)
    assert store.count_events() == store.count_alerts() == 0


def test_pipeline_results_survive_database_reopening(tmp_path):
    database_path = tmp_path / "analysis.sqlite3"
    source = file(tmp_path, "probe.txt", [access_line("/.env")])
    connection = connect_database(database_path)
    try:
        initialize_database(connection)
        store = SQLiteStore(connection)
        analyze_file(source, "access", store)
        original, = store.list_alerts()
        store.set_alert_status(original.id, "investigating")
    finally:
        connection.close()
    reopened = connect_database(database_path)
    try:
        store = SQLiteStore(reopened)
        assert store.get_alert(original.id).alert.status == "investigating"
        assert store.get_alert_events(original.id)[0].event.source_file == str(source.resolve())
        assert detect_events(store).findings_unchanged == 1
    finally:
        reopened.close()
