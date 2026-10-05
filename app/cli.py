"""Local file-ingestion commands."""

import json
import sqlite3
from datetime import tzinfo
from pathlib import Path

import click
from flask import Flask
from flask.cli import with_appcontext

from app.database import get_database
from app.events import ApacheLogType
from app.ingestion import DEFAULT_MAX_LINE_BYTES, MAX_LINE_BYTES, ingest_file, parse_error_timezone
from app.storage import SQLiteStore


def _timezone_option(context, parameter, value):
    try:
        return parse_error_timezone(value)
    except ValueError as exc:
        raise click.BadParameter(str(exc), ctx=context, param=parameter) from exc


@click.command("ingest")
@click.argument(
    "log_file",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True, path_type=Path),
)
@click.option(
    "--format", "log_type", required=True, type=click.Choice(("access", "error")),
    help="Apache log type. Access supports common/combined; error supports standard/legacy.",
)
@click.option(
    "--error-timezone", default="UTC", show_default=True, callback=_timezone_option,
    help="Error timestamps only: UTC or a fixed offset such as -07:00 or +05:30.",
)
@click.option(
    "--max-line-bytes", default=DEFAULT_MAX_LINE_BYTES, show_default=True,
    type=click.IntRange(1, MAX_LINE_BYTES), help="Maximum log record bytes, excluding its line ending.",
)
@click.option("--json", "json_output", is_flag=True, help="Print the successful import summary as JSON.")
@with_appcontext
def ingest_command(
    log_file: Path, log_type: ApacheLogType, error_timezone: tzinfo,
    max_line_bytes: int, json_output: bool,
) -> None:
    """Import an Apache LOG_FILE into the initialized local database."""
    try:
        store = SQLiteStore(get_database())
        result = ingest_file(
            log_file, log_type, store, error_timezone=error_timezone,
            max_line_bytes=max_line_bytes,
        )
    except (sqlite3.Error, OSError, ValueError, RuntimeError) as exc:
        raise click.ClickException(f"{exc} No events from this import were saved.") from exc
    if json_output:
        click.echo(json.dumps(result.as_dict(), indent=2))
        return
    click.echo(f"Imported {result.imported_events} Apache {result.log_type} events from {result.source_file}")
    if result.assumed_timezone is not None:
        click.echo(f"Assumed error timezone: {result.assumed_timezone}")
    click.echo(
        f"Lines read: {result.lines_read}; rejected: {result.rejected_lines}; blank: {result.blank_lines}"
    )
    click.echo(
        f"Rejected lines: malformed={result.malformed_lines}, encoding={result.encoding_error_lines}, "
        f"oversized={result.oversized_lines}, invalid_values={result.invalid_value_lines}"
    )


def init_app(app: Flask) -> None:
    app.cli.add_command(ingest_command)
