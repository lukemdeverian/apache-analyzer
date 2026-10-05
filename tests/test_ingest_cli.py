import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app import create_app
from app.database import connect_database
from app.storage import SQLiteStore

FIXTURES = Path(__file__).with_name("fixtures")


@pytest.fixture
def app(tmp_path):
    return create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "events.sqlite3")})


def initialize(app):
    result = app.test_cli_runner().invoke(args=["init-db"])
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize("filename, log_type", [("access_combined.txt", "access"), ("error_standard.txt", "error")])
def test_json_summary_and_persisted_cli_events(app, filename, log_type):
    initialize(app)
    source = FIXTURES / filename

    result = app.test_cli_runner().invoke(args=["ingest", str(source), "--format", log_type, "--json"])

    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    assert summary["source_file"] == str(source.resolve())
    assert summary["log_type"] == log_type
    assert summary["lines_read"] == summary["imported_events"] == 3
    assert summary["rejected_lines"] == summary["blank_lines"] == 0
    connection = connect_database(app.config["DATABASE_PATH"])
    try:
        assert SQLiteStore(connection).count_events(log_type=log_type) == 3
    finally:
        connection.close()


def test_human_summary_and_error_timezone_option(app):
    initialize(app)

    result = app.test_cli_runner().invoke(args=[
        "ingest", str(FIXTURES / "error_standard.txt"), "--format", "error", "--error-timezone=-07:00",
    ])

    assert result.exit_code == 0, result.output
    assert "Imported 3 Apache error events" in result.output
    assert "Lines read: 3; rejected: 0; blank: 0" in result.output
    assert "Assumed error timezone: UTC-07:00" in result.output
    connection = connect_database(app.config["DATABASE_PATH"])
    try:
        event = SQLiteStore(connection).get_event(1).event
        assert event.timestamp == datetime(2026, 10, 6, 16, 1, 2, 123456, tzinfo=timezone.utc)
    finally:
        connection.close()


@pytest.mark.parametrize("options", [
    [], ["--format", "auto"], ["--format", "linux_auth"], ["--format", "network_telemetry"],
    ["--format", "access", "--error-timezone", "local"],
    ["--format", "access", "--max-line-bytes", "0"],
    ["--format", "access", "--max-line-bytes", "1048577"],
])
def test_invalid_options_fail_before_opening_the_database(app, options):
    result = app.test_cli_runner().invoke(args=["ingest", str(FIXTURES / "access_common.txt"), *options])

    assert result.exit_code == 2
    assert "Error:" in result.output
    assert not Path(app.config["DATABASE_PATH"]).exists()


def test_missing_path_and_directory_fail_before_database_creation(app, tmp_path):
    for source in (tmp_path / "missing.txt", tmp_path):
        result = app.test_cli_runner().invoke(args=["ingest", str(source), "--format", "access"])
        assert result.exit_code == 2
    assert not Path(app.config["DATABASE_PATH"]).exists()


def test_uninitialized_database_has_actionable_cli_error(app):
    result = app.test_cli_runner().invoke(args=["ingest", str(FIXTURES / "access_common.txt"), "--format", "access"])

    assert result.exit_code == 1
    assert "init-db" in result.output
    assert "No events from this import were saved" in result.output


def test_wrong_format_returns_failure_with_rejection_summary(app):
    initialize(app)

    result = app.test_cli_runner().invoke(args=["ingest", str(FIXTURES / "error_standard.txt"), "--format", "access"])

    assert result.exit_code == 1
    assert "No Apache access records were imported" in result.output
    assert "Read 3 lines: 3 rejected, 0 blank" in result.output
    connection = connect_database(app.config["DATABASE_PATH"])
    try:
        assert SQLiteStore(connection).count_events() == 0
    finally:
        connection.close()


def test_database_failure_is_reported_and_rolls_back_cli_import(app):
    initialize(app)
    connection = connect_database(app.config["DATABASE_PATH"])
    connection.execute(
        "CREATE TRIGGER fail_second_event BEFORE INSERT ON events WHEN NEW.line_number = 2 "
        "BEGIN SELECT RAISE(ABORT, 'synthetic storage failure'); END"
    )
    connection.close()

    result = app.test_cli_runner().invoke(args=["ingest", str(FIXTURES / "access_common.txt"), "--format", "access"])

    assert result.exit_code == 1
    assert "synthetic storage failure" in result.output
    assert "No events from this import were saved" in result.output
    connection = connect_database(app.config["DATABASE_PATH"])
    try:
        assert SQLiteStore(connection).count_events() == 0
    finally:
        connection.close()


def test_ingest_command_help_documents_required_format_and_limits(app):
    result = app.test_cli_runner().invoke(args=["ingest", "--help"])

    assert result.exit_code == 0
    assert "--format [access|error]" in result.output
    assert "[required]" in result.output
    assert "--error-timezone" in result.output
    assert "--max-line-bytes" in result.output
    assert "--json" in result.output
    assert not Path(app.config["DATABASE_PATH"]).exists()
