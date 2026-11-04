"""Lazy SQLite connections, atomic transactions, and explicit schema setup."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import click
from flask import Flask, current_app, g
from flask.cli import with_appcontext

from app.domains import DEFAULT_DOMAIN, DOMAINS, DOMAIN_IDS, get_domain
from app.import_history import backfill_legacy_imports

SCHEMA_VERSION = 3
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
            "to initialize a new database or upgrade this application's version 1 or 2 database. "
            "Other incompatible databases require a migration."
        )


def initialize_database(connection: sqlite3.Connection) -> None:
    """Initialize version 3 or upgrade owned versions 1/2 without clearing evidence."""
    with transaction(connection):
        application_id = connection.execute("PRAGMA application_id").fetchone()[0]
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if application_id not in (0, APPLICATION_ID) or version not in (0, 1, 2, SCHEMA_VERSION):
            raise RuntimeError("Refusing to initialize a database with an incompatible schema.")
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT GLOB 'sqlite_*'"
        ).fetchall()
        if (version == 0 and tables) or (version in (1, 2, SCHEMA_VERSION) and application_id != APPLICATION_ID):
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
        if version in (1, 2):
            backfill_legacy_imports(connection)
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def domain_database_path(domain_id: str = DEFAULT_DOMAIN) -> str:
    """Keep the legacy database for Chronoscrate; isolate the second site."""
    get_domain(domain_id)
    path = str(current_app.config["DATABASE_PATH"])
    if "://" in path or path.startswith("file:"):
        raise ValueError("DATABASE_PATH must be a local file path or ':memory:'.")
    if path == ":memory:":
        return path
    target = Path(path)
    if not target.is_absolute():
        target = Path(current_app.instance_path) / target
    if domain_id != DEFAULT_DOMAIN:
        target = target.with_name(f"{target.stem}__{domain_id}{target.suffix}")
    return str(target)


def get_database(domain_id: str = DEFAULT_DOMAIN) -> sqlite3.Connection:
    """Reuse an independent connection for each domain in this context."""
    path = domain_database_path(domain_id)
    connections = g.setdefault("apache_databases", {})
    if domain_id not in connections:
        connections[domain_id] = connect_database(path)
    return connections[domain_id]


def close_database(error: BaseException | None = None) -> None:
    for connection in g.pop("apache_databases", {}).values():
        connection.close()


@click.command("init-db")
@click.option("--domain", "domain_id", type=click.Choice(DOMAIN_IDS), help="Initialize only this site; default is both.")
@with_appcontext
def init_database_command(domain_id: str | None) -> None:
    """Initialize or upgrade the local schema without removing existing records."""
    try:
        for domain in DOMAINS:
            if domain_id is None or domain.id == domain_id:
                initialize_database(get_database(domain.id))
                click.echo(f"Initialized SQLite database: {domain_database_path(domain.id)} ({domain.name})")
    except (sqlite3.Error, OSError, ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc


def init_app(app: Flask) -> None:
    app.teardown_appcontext(close_database)
    app.cli.add_command(init_database_command)
