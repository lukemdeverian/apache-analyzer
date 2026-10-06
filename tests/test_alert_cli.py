import json
from pathlib import Path

import pytest

from app import create_app
from app.database import connect_database
from app.ingestion import ingest_file
from app.storage import SQLiteStore


@pytest.fixture
def app(tmp_path):
    return create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "events.sqlite3")})


def initialize(app):
    result = app.test_cli_runner().invoke(args=["init-db"])
    assert result.exit_code == 0, result.output


def source(tmp_path, name="probe.txt", targets=("/.env",), times=("09:00:00",)):
    path = tmp_path / name
    path.write_text("\n".join(
        f'192.0.2.10 - - [06/Oct/2026:{stamp} +0000] "GET {target} HTTP/1.1" 404 0'
        for target, stamp in zip(targets, times, strict=True)
    ), encoding="utf-8")
    return path


def import_source(app, path, *options):
    return app.test_cli_runner().invoke(args=["ingest", str(path), "--format", "access", *options])


def test_ingest_json_reports_persisted_alerts_and_explicit_detect_is_idempotent(app, tmp_path):
    initialize(app)
    path = source(tmp_path, targets=("/.env", "/.env"), times=("09:00:00", "09:00:01"))
    imported = import_source(app, path, "--json")
    assert imported.exit_code == 0, imported.output
    summary = json.loads(imported.output)
    assert summary["imported_events"] == 2
    assert summary["detection"] == {
        "findings": 2, "alerts_created": 1, "alert_updates": 1, "alerts_merged": 0, "findings_unchanged": 0,
    }
    detected = app.test_cli_runner().invoke(args=["detect", "--json"])
    assert detected.exit_code == 0, detected.output
    assert json.loads(detected.output) == {
        "findings": 2, "alerts_created": 0, "alert_updates": 0, "alerts_merged": 0, "findings_unchanged": 2,
    }
    connection = connect_database(app.config["DATABASE_PATH"])
    try:
        store = SQLiteStore(connection)
        alert, = store.list_alerts()
        assert alert.alert.rule_id == "APACHE-SENSITIVE-FILE" and alert.event_count == 2
        assert [item.event.line_number for item in store.get_alert_events(alert.id)] == [1, 2]
    finally:
        connection.close()


def test_human_import_and_detection_summaries_report_alert_activity(app, tmp_path):
    initialize(app)
    imported = import_source(app, source(tmp_path))
    assert imported.exit_code == 0
    assert "alerts created=1" in imported.output
    detected = app.test_cli_runner().invoke(args=["detect"])
    assert detected.exit_code == 0
    assert "unchanged findings=1" in detected.output


def test_explicit_detection_can_analyze_evidence_imported_without_pipeline(app, tmp_path):
    initialize(app)
    path = source(tmp_path)
    connection = connect_database(app.config["DATABASE_PATH"])
    try:
        store = SQLiteStore(connection)
        ingest_file(path, "access", store)
        assert store.count_alerts() == 0
    finally:
        connection.close()
    result = app.test_cli_runner().invoke(args=["detect", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["alerts_created"] == 1


@pytest.mark.parametrize("status", ["new", "investigating", "resolved", "false_positive"])
def test_status_command_persists_analyst_choice(app, tmp_path, status):
    initialize(app)
    assert import_source(app, source(tmp_path)).exit_code == 0
    result = app.test_cli_runner().invoke(args=["alert-status", "1", status])
    assert result.exit_code == 0, result.output
    assert f"Alert 1 status: {status}" in result.output
    connection = connect_database(app.config["DATABASE_PATH"])
    try:
        assert SQLiteStore(connection).get_alert(1).alert.status == status
    finally:
        connection.close()


def test_status_command_accepts_a_merged_id_and_reports_canonical_id(app, tmp_path):
    initialize(app)
    first = source(tmp_path, "first.txt", ("/.env", "/.env"), ("09:00:00", "09:10:00"))
    bridge = source(tmp_path, "bridge.txt", ("/.env",), ("09:05:00",))
    assert import_source(app, first).exit_code == 0
    merged = import_source(app, bridge, "--json")
    assert merged.exit_code == 0, merged.output
    assert json.loads(merged.output)["detection"]["alerts_merged"] == 1

    result = app.test_cli_runner().invoke(args=["alert-status", "2", "investigating"])

    assert result.exit_code == 0, result.output
    assert "Alert 1 status: investigating" in result.output


@pytest.mark.parametrize("args", [
    ["alert-status", "0", "new"], ["alert-status", "-1", "new"],
    ["alert-status", str(2**63), "new"], ["alert-status", "1", "closed"],
    ["alert-status", "true", "resolved"],
])
def test_invalid_status_arguments_fail_before_opening_database(app, args):
    result = app.test_cli_runner().invoke(args=args)
    assert result.exit_code == 2
    assert not Path(app.config["DATABASE_PATH"]).exists()


def test_unknown_alert_reports_failure_without_creating_an_alert(app):
    initialize(app)
    result = app.test_cli_runner().invoke(args=["alert-status", "123", "resolved"])
    assert result.exit_code == 1
    assert "Alert 123 was not found" in result.output
    connection = connect_database(app.config["DATABASE_PATH"])
    try:
        assert SQLiteStore(connection).count_alerts() == 0
    finally:
        connection.close()


def test_alert_creation_failure_rolls_back_cli_import(app, tmp_path):
    initialize(app)
    connection = connect_database(app.config["DATABASE_PATH"])
    connection.execute(
        "CREATE TRIGGER fail_alert BEFORE INSERT ON alerts "
        "BEGIN SELECT RAISE(ABORT, 'synthetic alert failure'); END"
    )
    connection.close()
    result = import_source(app, source(tmp_path))
    assert result.exit_code == 1
    assert "synthetic alert failure" in result.output
    assert "No events from this import were saved" in result.output
    assert "alert changes were rolled back" in result.output
    connection = connect_database(app.config["DATABASE_PATH"])
    try:
        store = SQLiteStore(connection)
        assert store.count_events() == store.count_alerts() == 0
    finally:
        connection.close()


def test_explicit_detection_failure_preserves_existing_events(app, tmp_path):
    initialize(app)
    connection = connect_database(app.config["DATABASE_PATH"])
    try:
        store = SQLiteStore(connection)
        ingest_file(source(tmp_path), "access", store)
        connection.execute(
            "CREATE TRIGGER fail_alert BEFORE INSERT ON alerts "
            "BEGIN SELECT RAISE(ABORT, 'synthetic alert failure'); END"
        )
    finally:
        connection.close()
    result = app.test_cli_runner().invoke(args=["detect"])
    assert result.exit_code == 1
    assert "Alert changes from this scan were rolled back" in result.output
    connection = connect_database(app.config["DATABASE_PATH"])
    try:
        store = SQLiteStore(connection)
        assert store.count_events() == 1
        assert store.count_alerts() == 0
    finally:
        connection.close()


def test_detect_without_initialized_schema_reports_setup_command(app):
    result = app.test_cli_runner().invoke(args=["detect"])
    assert result.exit_code == 1
    assert "init-db" in result.output


@pytest.mark.parametrize("command", ["detect", "alert-status"])
def test_analysis_command_help_does_not_open_database(app, command):
    result = app.test_cli_runner().invoke(args=[command, "--help"])
    assert result.exit_code == 0
    assert not Path(app.config["DATABASE_PATH"]).exists()
