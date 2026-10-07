"""Local Apache ingestion, detection, and analyst status commands."""

import json
import sqlite3
from datetime import tzinfo
from pathlib import Path

import click
from flask import Flask
from flask.cli import with_appcontext

from app.alerts import ALERT_STATUSES, AlertStatus
from app.database import get_database
from app.events import ApacheLogType
from app.ingestion import (
    DEFAULT_MAX_DECOMPRESSED_BYTES, DEFAULT_MAX_LINE_BYTES, MAX_LINE_BYTES, parse_error_timezone,
)
from app.pipeline import DetectionSummary, analyze_file, detect_events
from app.storage import SQLiteStore


def _timezone_option(context, parameter, value):
    try:
        return parse_error_timezone(value)
    except ValueError as exc:
        raise click.BadParameter(str(exc), ctx=context, param=parameter) from exc


def _echo_detection_summary(result: DetectionSummary) -> None:
    click.echo(
        f"Detection: findings={result.findings}; alerts created={result.alerts_created}; "
        f"alert updates={result.alert_updates}; alerts merged={result.alerts_merged}; "
        f"unchanged findings={result.findings_unchanged}"
    )


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
@click.option(
    "--max-decompressed-bytes", default=DEFAULT_MAX_DECOMPRESSED_BYTES, show_default=True,
    type=click.IntRange(1), help="Maximum total decompressed bytes for gzip logs.",
)
@click.option("--json", "json_output", is_flag=True, help="Print the successful import summary as JSON.")
@with_appcontext
def ingest_command(
    log_file: Path, log_type: ApacheLogType, error_timezone: tzinfo,
    max_line_bytes: int, max_decompressed_bytes: int, json_output: bool,
) -> None:
    """Import plain or gzip Apache LOG_FILE and detect/correlate alerts atomically."""
    try:
        store = SQLiteStore(get_database())
        result = analyze_file(
            log_file, log_type, store, error_timezone=error_timezone,
            max_line_bytes=max_line_bytes,
            max_decompressed_bytes=max_decompressed_bytes,
        )
    except (sqlite3.Error, OSError, ValueError, RuntimeError) as exc:
        raise click.ClickException(
            f"{exc} No events from this import were saved; alert changes were rolled back."
        ) from exc
    if json_output:
        click.echo(json.dumps(result.as_dict(), indent=2))
        return
    imported = result.import_summary
    click.echo(f"Imported {imported.imported_events} Apache {imported.log_type} events from {imported.source_file}")
    if imported.assumed_timezone is not None:
        click.echo(f"Assumed error timezone: {imported.assumed_timezone}")
    click.echo(
        f"Lines read: {imported.lines_read}; rejected: {imported.rejected_lines}; blank: {imported.blank_lines}"
    )
    click.echo(
        f"Rejected lines: malformed={imported.malformed_lines}, encoding={imported.encoding_error_lines}, "
        f"oversized={imported.oversized_lines}, invalid_values={imported.invalid_value_lines}"
    )
    _echo_detection_summary(result.detection)


@click.command("detect")
@click.option("--json", "json_output", is_flag=True, help="Print detection counts as JSON.")
@with_appcontext
def detect_command(json_output: bool) -> None:
    """Detect and correlate alerts from all stored Apache evidence."""
    try:
        result = detect_events(SQLiteStore(get_database()))
    except (sqlite3.Error, OSError, ValueError, RuntimeError) as exc:
        raise click.ClickException(f"{exc} Alert changes from this scan were rolled back.") from exc
    if json_output:
        click.echo(json.dumps(result.as_dict(), indent=2))
    else:
        _echo_detection_summary(result)


@click.command("alert-status")
@click.argument("alert_id", type=click.IntRange(1, 2**63 - 1))
@click.argument("status", type=click.Choice(ALERT_STATUSES))
@with_appcontext
def alert_status_command(alert_id: int, status: AlertStatus) -> None:
    """Set ALERT_ID to new, investigating, resolved, or false_positive."""
    try:
        stored = SQLiteStore(get_database()).set_alert_status(alert_id, status)
    except (sqlite3.Error, OSError, ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc
    if stored is None:
        raise click.ClickException(f"Alert {alert_id} was not found.")
    click.echo(f"Alert {stored.id} status: {stored.alert.status}")


def init_app(app: Flask) -> None:
    app.cli.add_command(ingest_command)
    app.cli.add_command(detect_command)
    app.cli.add_command(alert_status_command)
