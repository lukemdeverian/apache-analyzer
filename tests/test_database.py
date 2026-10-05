import sqlite3

import pytest

from app import create_app
from app.database import (
    APPLICATION_ID, SCHEMA_VERSION, connect_database, get_database, initialize_database,
)
from app.parsers import parse_access_line
from app.storage import SQLiteStore

LINE = '192.0.2.10 - - [06/Oct/2026:09:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234'


def test_initialization_creates_versioned_schema_and_enables_foreign_keys():
    connection = connect_database(":memory:")
    try:
        initialize_database(connection)

        tables = {
            row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert tables == {"events", "alerts", "alert_events"}
        assert connection.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert not connection.in_transaction
    finally:
        connection.close()


def test_reinitialization_preserves_evidence():
    connection = connect_database(":memory:")
    try:
        initialize_database(connection)
        store = SQLiteStore(connection)
        event = parse_access_line(LINE)
        event_id = store.insert_event(event)

        initialize_database(connection)

        assert store.count_events() == 1
        assert store.get_event(event_id).event == event
    finally:
        connection.close()


@pytest.mark.parametrize("foreign_application, version", [(123, 0), (APPLICATION_ID, 2)])
def test_incompatible_databases_are_rejected_without_changes(foreign_application, version):
    connection = connect_database(":memory:")
    try:
        connection.execute("CREATE TABLE unrelated (value TEXT)")
        connection.execute("INSERT INTO unrelated VALUES ('keep me')")
        connection.execute(f"PRAGMA application_id = {foreign_application}")
        connection.execute(f"PRAGMA user_version = {version}")

        with pytest.raises(RuntimeError, match="incompatible"):
            initialize_database(connection)

        assert connection.execute("SELECT value FROM unrelated").fetchone()[0] == "keep me"
        assert connection.execute("PRAGMA user_version").fetchone()[0] == version
        assert connection.execute("PRAGMA application_id").fetchone()[0] == foreign_application
        assert not connection.in_transaction
    finally:
        connection.close()


@pytest.mark.parametrize("table_name", ["events", "sqlitex_custom"])
def test_unversioned_existing_tables_are_not_adopted_or_removed(table_name):
    connection = connect_database(":memory:")
    try:
        connection.execute(f"CREATE TABLE {table_name} (value TEXT)")
        connection.execute(f"INSERT INTO {table_name} VALUES ('original')")

        with pytest.raises(RuntimeError, match="unrecognized"):
            initialize_database(connection)

        assert connection.execute(f"SELECT value FROM {table_name}").fetchone()[0] == "original"
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    finally:
        connection.close()


def test_schema_initialization_failure_rolls_back_all_tables(monkeypatch, tmp_path):
    schema = tmp_path / "broken.sql"
    schema.write_text("CREATE TABLE partial (id INTEGER);\nCREATE TABLE invalid (broken SQL !!!);\n", encoding="utf-8")
    monkeypatch.setattr("app.database.SCHEMA_PATH", schema)
    connection = connect_database(":memory:")
    try:
        with pytest.raises(sqlite3.OperationalError):
            initialize_database(connection)

        assert connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'").fetchone()[0] == 0
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert connection.execute("PRAGMA application_id").fetchone()[0] == 0
        assert not connection.in_transaction
    finally:
        connection.close()


def test_queries_require_an_initialized_compatible_schema():
    connection = connect_database(":memory:")
    try:
        with pytest.raises(RuntimeError, match="init-db"):
            SQLiteStore(connection)
    finally:
        connection.close()


@pytest.mark.parametrize("path", ["", "  ", "postgresql://localhost/events", "file:events.sqlite3?mode=memory"])
def test_non_file_database_targets_are_rejected(path):
    with pytest.raises(ValueError, match="DATABASE_PATH"):
        connect_database(path)


def test_flask_connection_is_lazy_reused_and_closed(tmp_path):
    database_path = tmp_path / "nested" / "events.sqlite3"
    app = create_app({"TESTING": True, "DATABASE_PATH": str(database_path)})
    assert not database_path.parent.exists()

    with app.app_context():
        connection = get_database()
        assert connection is get_database()
        assert database_path.exists()

    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")


def test_flask_database_url_override_is_rejected_before_creating_directories(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": "postgresql://localhost/events"})
    app.instance_path = str(tmp_path / "not_created")

    with app.app_context(), pytest.raises(ValueError, match="DATABASE_PATH"):
        get_database()

    assert not (tmp_path / "not_created").exists()


def test_flask_connections_are_isolated_between_applications(tmp_path):
    first = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "first.sqlite3")})
    second = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "second.sqlite3")})

    with first.app_context():
        first_connection = get_database()
        initialize_database(first_connection)
        SQLiteStore(first_connection).insert_event(parse_access_line(LINE))
        with second.app_context():
            second_connection = get_database()
            initialize_database(second_connection)
            assert second_connection is not first_connection
            assert SQLiteStore(second_connection).count_events() == 0
        assert SQLiteStore(first_connection).count_events() == 1


def test_init_db_cli_creates_database_and_is_repeatable(tmp_path):
    database_path = tmp_path / "nested" / "events.sqlite3"
    app = create_app({"TESTING": True, "DATABASE_PATH": str(database_path)})
    runner = app.test_cli_runner()

    first = runner.invoke(args=["init-db"])
    second = runner.invoke(args=["init-db"])

    assert first.exit_code == second.exit_code == 0
    assert "Initialized SQLite database" in first.output
    assert database_path.exists()
    connection = connect_database(database_path)
    try:
        assert SQLiteStore(connection).count_events() == 0
    finally:
        connection.close()


def test_init_db_cli_reports_incompatible_schema(tmp_path):
    database_path = tmp_path / "events.sqlite3"
    connection = connect_database(database_path)
    connection.execute("PRAGMA user_version = 99")
    connection.close()
    app = create_app({"TESTING": True, "DATABASE_PATH": str(database_path)})

    result = app.test_cli_runner().invoke(args=["init-db"])

    assert result.exit_code == 1
    assert "incompatible schema" in result.output
