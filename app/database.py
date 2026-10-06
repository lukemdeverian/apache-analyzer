"""Lazy SQLite connections, atomic transactions, and explicit schema setup."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import click
from flask import Flask, current_app, g
from flask.cli import with_appcontext

SCHEMA_VERSION = 2
APPLICATION_ID = 0x41504143  # APAC: identifies databases owned by this application.
SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def connect_database(path: str | Path) -> sqlite3.Connection:
    """Open a local database with foreign keys and explicit transaction control."""
    database = str(path)
    if not database.strip() or "://" in database or database.startswith("file:"):
        raise ValueError("DATABASE_PATH must be a local file path or ':memory:'.")
    if database != ":memory:":
        database_path = Path(database).expanduser().resolve()
        database_path.parent.mkdir(parents=True, exist_ok=True)
        database = str(database_path)
    # Keep the same behavior on Python 3.11 and newer versions that expose
    # autocommit. isolation_level=None lets our SAVEPOINTs control transactions.
    options = {}
    if hasattr(sqlite3, "LEGACY_TRANSACTION_CONTROL"):
        options["autocommit"] = sqlite3.LEGACY_TRANSACTION_CONTROL
    connection = sqlite3.connect(database, timeout=5.0, isolation_level=None, **options)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise RuntimeError("This SQLite installation must support foreign keys.")
    except BaseException:
        connection.close()
        raise
    return connection


@contextmanager
def transaction(connection: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Commit a group of writes together; nested failures roll back locally."""
    connection.execute("SAVEPOINT apache_analyzer_write")
    try:
        yield connection
        connection.execute("RELEASE SAVEPOINT apache_analyzer_write")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK TO SAVEPOINT apache_analyzer_write")
            connection.execute("RELEASE SAVEPOINT apache_analyzer_write")
        raise


def require_schema(connection: sqlite3.Connection) -> None:
    application_id = connection.execute("PRAGMA application_id").fetchone()[0]
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if application_id != APPLICATION_ID or version != SCHEMA_VERSION:
        raise RuntimeError(
            "Database schema is missing or incompatible. Run 'flask --app app init-db' "
            "to initialize a new database or upgrade this application's version 1 database. "
            "Other incompatible databases require a migration."
        )


def initialize_database(connection: sqlite3.Connection) -> None:
    """Initialize version 2 or upgrade owned version 1 without clearing evidence."""
    with transaction(connection):
        application_id = connection.execute("PRAGMA application_id").fetchone()[0]
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if application_id not in (0, APPLICATION_ID) or version not in (0, 1, SCHEMA_VERSION):
            raise RuntimeError("Refusing to initialize a database with an incompatible schema.")
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT GLOB 'sqlite_*'"
        ).fetchall()
        if (version == 0 and tables) or (version in (1, SCHEMA_VERSION) and application_id != APPLICATION_ID):
            raise RuntimeError("Refusing to initialize a database with an unrecognized schema.")

        statement = ""
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        for line in schema.splitlines(keepends=True):
            statement += line
            if sqlite3.complete_statement(statement):
                connection.execute(statement)
                statement = ""
        if statement.strip():
            raise RuntimeError("The application schema contains an incomplete SQL statement.")
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def get_database() -> sqlite3.Connection:
    """Reuse one connection within the current Flask application context."""
    if "apache_database" not in g:
        path = str(current_app.config["DATABASE_PATH"])
        if "://" in path or path.startswith("file:"):
            raise ValueError("DATABASE_PATH must be a local file path or ':memory:'.")
        if path != ":memory:" and not Path(path).is_absolute():
            path = str(Path(current_app.instance_path) / path)
        g.apache_database = connect_database(path)
    return g.apache_database


def close_database(error: BaseException | None = None) -> None:
    connection = g.pop("apache_database", None)
    if connection is not None:
        connection.close()


@click.command("init-db")
@with_appcontext
def init_database_command() -> None:
    """Initialize or upgrade the local schema without removing existing records."""
    try:
        initialize_database(get_database())
    except (sqlite3.Error, OSError, ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Initialized SQLite database: {current_app.config['DATABASE_PATH']}")


def init_app(app: Flask) -> None:
    app.teardown_appcontext(close_database)
    app.cli.add_command(init_database_command)
