"""Local Apache ingestion, detection, and analyst status commands."""

import json
import sqlite3
from datetime import tzinfo
from pathlib import Path

import click
from flask import Flask, current_app
from flask.cli import with_appcontext

from app.alerts import ALERT_STATUSES, AlertStatus
from app.bots import assess_bots
from app.database import domain_database_path, get_database
from app.domains import DEFAULT_DOMAIN, DOMAINS, DOMAIN_IDS
from app.events import ApacheLogType
from app.ingestion import (
    DEFAULT_MAX_DECOMPRESSED_BYTES, DEFAULT_MAX_LINE_BYTES, MAX_LINE_BYTES, parse_error_timezone,
)
from app.pipeline import DetectionSummary, analyze_file, detect_events
from app.storage import SQLiteStore
from app.threat_intel import (
    DEFAULT_KEYS_PATH, PROVIDER_LABELS, PROVIDERS, ThreatIntelConfigError, cache_path_for, check_ips,
    eligible_ip, load_keys, read_reputation,
)


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
@click.option("--domain", "domain_id", type=click.Choice(DOMAIN_IDS), default=DEFAULT_DOMAIN, show_default=True)
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
    max_line_bytes: int, max_decompressed_bytes: int, json_output: bool, domain_id: str,
) -> None:
    """Import plain or gzip Apache LOG_FILE and detect/correlate alerts atomically."""
    try:
        store = SQLiteStore(get_database(domain_id))
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
        click.echo(json.dumps({**result.as_dict(), "domain_id": domain_id}, indent=2))
        return
    imported = result.import_summary
    if imported.duplicate_file:
        click.echo(
            f"Already imported; skipped {imported.skipped_duplicate_events} duplicate events. "
            f"Original import #{imported.duplicate_of_import_id}: {imported.duplicate_of_source_file}"
        )
        return
    click.echo(f"Imported {imported.imported_events} Apache {imported.log_type} events from {imported.source_file}")
    if imported.assumed_timezone is not None:
        click.echo(f"Assumed error timezone: {imported.assumed_timezone}")
    click.echo(f"Repeated lines retained for review: {imported.duplicate_lines}")
    click.echo(
        f"Lines read: {imported.lines_read}; rejected: {imported.rejected_lines}; blank: {imported.blank_lines}"
    )
    click.echo(
        f"Rejected lines: malformed={imported.malformed_lines}, encoding={imported.encoding_error_lines}, "
        f"oversized={imported.oversized_lines}, invalid_values={imported.invalid_value_lines}"
    )
    _echo_detection_summary(result.detection)


@click.command("detect")
@click.option("--domain", "domain_id", type=click.Choice(DOMAIN_IDS), default=DEFAULT_DOMAIN, show_default=True)
@click.option("--json", "json_output", is_flag=True, help="Print detection counts as JSON.")
@with_appcontext
def detect_command(json_output: bool, domain_id: str) -> None:
    """Detect and correlate alerts from all stored Apache evidence."""
    try:
        result = detect_events(SQLiteStore(get_database(domain_id)))
    except (sqlite3.Error, OSError, ValueError, RuntimeError) as exc:
        raise click.ClickException(f"{exc} Alert changes from this scan were rolled back.") from exc
    if json_output:
        click.echo(json.dumps(result.as_dict(), indent=2))
    else:
        _echo_detection_summary(result)


@click.command("alert-status")
@click.option("--domain", "domain_id", type=click.Choice(DOMAIN_IDS), default=DEFAULT_DOMAIN, show_default=True)
@click.argument("alert_id", type=click.IntRange(1, 2**63 - 1))
@click.argument("status", type=click.Choice(ALERT_STATUSES))
@with_appcontext
def alert_status_command(alert_id: int, status: AlertStatus, domain_id: str) -> None:
    """Set ALERT_ID to new, investigating, resolved, or false_positive."""
    try:
        stored = SQLiteStore(get_database(domain_id)).set_alert_status(alert_id, status)
    except (sqlite3.Error, OSError, ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc
    if stored is None:
        raise click.ClickException(f"Alert {alert_id} was not found.")
    click.echo(f"Alert {stored.id} status: {stored.alert.status}")


@click.command("threat-intel")
@click.option("--domain", "domain_id", type=click.Choice(DOMAIN_IDS), help="Check only this site; default is both.")
@click.option("--refresh", is_flag=True, help="Re-check IPs even when a cached result is under 7 days old.")
@click.option("--limit", type=click.IntRange(1), help="Maximum number of IPs to look up in this run.")
@click.option("--json", "json_output", is_flag=True, help="Print the lookup summary as JSON.")
@with_appcontext
def threat_intel_command(domain_id: str | None, refresh: bool, limit: int | None, json_output: bool) -> None:
    """Check unconfirmed public IPs against AbuseIPDB and AlienVault OTX."""
    try:
        keys = load_keys(current_app.config.get("THREAT_INTEL_KEYS_PATH", DEFAULT_KEYS_PATH))
    except ThreatIntelConfigError as exc:
        raise click.ClickException(str(exc)) from exc
    if not any(keys.values()):
        raise click.ClickException("No API keys are configured. Add them to threat_intel_keys.toml.")
    try:
        cache_path = cache_path_for(domain_database_path(DEFAULT_DOMAIN))
        reputation = read_reputation(cache_path)
        addresses = []
        for domain in DOMAINS:
            if domain_id is None or domain.id == domain_id:
                items, _ = assess_bots(
                    SQLiteStore(get_database(domain.id)), hostname=domain.hostname, reputation=reputation,
                )
                addresses += [
                    item["source_ip"] for item in items
                    if item["classification"] != "confirmed_bot" and eligible_ip(item["source_ip"])
                ]
        result = check_ips(addresses, keys=keys, cache_path=cache_path, refresh=refresh, limit=limit)
    except (sqlite3.Error, OSError, ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc
    if json_output:
        click.echo(json.dumps(result, indent=2))
        return
    click.echo(
        f"Public unconfirmed IPs: {result['public_ips']}; needing lookup: {result['needing_lookup']}; "
        f"looked up: {result['processed']}; remaining: {result['remaining']}"
    )
    for provider in PROVIDERS:
        info = result["providers"][provider]
        line = (
            f"{PROVIDER_LABELS[provider]}: checked={result['checked'][provider]}, errors={result['errors'][provider]}, "
            f"keys={info['keys_configured']}, rate-limited={info['keys_rate_limited']}, rejected={info['keys_rejected']}"
        )
        if info["stopped"]:
            line += f" (stopped: {info['stopped'].replace('_', ' ')})"
        click.echo(line)


def init_app(app: Flask) -> None:
    app.cli.add_command(ingest_command)
    app.cli.add_command(detect_command)
    app.cli.add_command(alert_status_command)
    app.cli.add_command(threat_intel_command)
