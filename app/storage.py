"""Typed SQLite writes and bounded, parameterized evidence queries."""

import sqlite3
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
from typing import Any

from app.alerts import ALERT_STATUSES, SEVERITIES, Alert, AlertStatus, Severity
from app.database import require_schema, transaction
from app.events import ApacheEvent, ApacheLogType

_EVENT_COLUMNS = tuple(field.name for field in fields(ApacheEvent))
_ALERT_COLUMNS = tuple(field.name for field in fields(Alert))
_EVENT_INSERT = (
    f"INSERT INTO events ({', '.join(_EVENT_COLUMNS)}) "
    f"VALUES ({', '.join(':' + column for column in _EVENT_COLUMNS)})"
)
_ALERT_INSERT = (
    f"INSERT INTO alerts (id, {', '.join(_ALERT_COLUMNS)}) "
    f"VALUES (:id, {', '.join(':' + column for column in _ALERT_COLUMNS)})"
)
_ALERT_SELECT = (
    "SELECT a.*, (SELECT COUNT(*) FROM alert_events ae WHERE ae.alert_id = a.id) "
    "AS event_count FROM alerts a"
)


@dataclass(frozen=True, slots=True)
class StoredEvent:
    id: int
    event: ApacheEvent


@dataclass(frozen=True, slots=True)
class StoredAlert:
    id: int
    alert: Alert
    event_count: int


@dataclass(frozen=True, slots=True)
class AlertWrite:
    alert_id: int | None = None
    created: bool = False
    updated: bool = False
    merged_alerts: int = 0


def _utc_text(value: datetime, name: str) -> str:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime.")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _page(limit: int, offset: int) -> None:
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("limit must be an integer between 1 and 1000.")
    if type(offset) is not int or offset < 0:
        raise ValueError("offset must be a nonnegative integer.")


def _evidence_ids(event_ids: Iterable[int]) -> tuple[int, ...]:
    values = tuple(event_ids)
    if not values or any(type(value) is not int or not 1 <= value < 2**63 for value in values):
        raise ValueError("An alert requires positive SQLite event IDs as evidence.")
    return tuple(dict.fromkeys(values))


def _alert_data(alert: Alert) -> dict[str, Any]:
    if alert.severity not in SEVERITIES or alert.status not in ALERT_STATUSES:
        raise ValueError("Invalid alert severity or status.")
    for name in ("rule_id", "title", "description", "grouping_key"):
        if not isinstance(getattr(alert, name), str) or not getattr(alert, name).strip():
            raise ValueError(f"Alert {name} must not be empty.")
    data = {name: getattr(alert, name) for name in _ALERT_COLUMNS}
    for name in ("first_seen", "last_seen", "created_at"):
        data[name] = _utc_text(data[name], name)
    if data["first_seen"] > data["last_seen"]:
        raise ValueError("first_seen must not be later than last_seen.")
    return data


def _shift_time(value: datetime, seconds: int) -> datetime:
    value = value.astimezone(timezone.utc)
    try:
        return value + timedelta(seconds=seconds)
    except OverflowError:
        limit = datetime.min if seconds < 0 else datetime.max
        return limit.replace(tzinfo=timezone.utc)


def _where(
    filters: dict[str, Any], time_column: str,
    start: datetime | None, end: datetime | None,
) -> tuple[str, list[Any]]:
    # Column names come only from fixed mappings below; all values are bound.
    clauses, parameters = [], []
    for column, value in filters.items():
        if value is not None:
            clauses.append(f"{column} = ?")
            parameters.append(value)
    start_text = _utc_text(start, "start") if start is not None else None
    end_text = _utc_text(end, "end") if end is not None else None
    if start_text is not None and end_text is not None and start_text > end_text:
        raise ValueError("start must not be later than end.")
    if start_text is not None:
        clauses.append(f"{time_column} >= ?")
        parameters.append(start_text)
    if end_text is not None:
        clauses.append(f"{time_column} <= ?")
        parameters.append(end_text)
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), parameters


def _event_filters(source_ip, log_type, start, end):
    if log_type is not None and log_type not in ("access", "error"):
        raise ValueError("log_type must be 'access' or 'error'.")
    return _where({"source_ip": source_ip, "log_type": log_type}, "timestamp", start, end)


def _alert_filters(source_ip, rule_id, severity, status, start, end):
    if severity is not None and severity not in SEVERITIES:
        raise ValueError("severity must be low, medium, high, or critical.")
    if status is not None and status not in ALERT_STATUSES:
        raise ValueError("status must be new, investigating, resolved, or false_positive.")
    return _where(
        {"a.source_ip": source_ip, "a.rule_id": rule_id, "a.severity": severity, "a.status": status},
        "a.first_seen", start, end,
    )


def _stored_event(row: sqlite3.Row) -> StoredEvent:
    data = dict(row)
    event_id = data.pop("id")
    data["timestamp"] = datetime.fromisoformat(data["timestamp"])
    return StoredEvent(id=event_id, event=ApacheEvent(**data))


def _stored_alert(row: sqlite3.Row) -> StoredAlert:
    data = dict(row)
    alert_id, event_count = data.pop("id"), data.pop("event_count")
    for name in ("first_seen", "last_seen", "created_at"):
        data[name] = datetime.fromisoformat(data[name])
    return StoredAlert(id=alert_id, alert=Alert(**data), event_count=event_count)


class SQLiteStore:
    """Evidence repository; use transaction(connection) for grouped writes.

    A standalone event write commits immediately. Alert creation is atomic,
    including its evidence links. Neither operation commits a caller's outer
    transaction, allowing later file ingestion to control batch boundaries.
    """

    def __init__(self, connection: sqlite3.Connection):
        require_schema(connection)
        self.connection = connection

    def insert_event(self, event: ApacheEvent) -> int:
        data = {name: getattr(event, name) for name in _EVENT_COLUMNS}
        data["timestamp"] = _utc_text(event.timestamp, "timestamp")
        for name in ("line_number", "source_port", "status_code", "response_bytes", "process_id"):
            value = data[name]
            if value is not None and (type(value) is not int or not -(2**63) <= value < 2**63):
                raise ValueError(f"{name} must fit in a SQLite signed 64-bit integer.")
        cursor = self.connection.execute(_EVENT_INSERT, data)
        return cursor.lastrowid

    def get_event(self, event_id: int) -> StoredEvent | None:
        row = self.connection.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        return _stored_event(row) if row is not None else None

    def list_events(
        self, *, source_ip: str | None = None, log_type: ApacheLogType | None = None,
        start: datetime | None = None, end: datetime | None = None,
        limit: int = 100, offset: int = 0, newest_first: bool = False,
    ) -> list[StoredEvent]:
        _page(limit, offset)
        where, parameters = _event_filters(source_ip, log_type, start, end)
        direction = "DESC" if newest_first else "ASC"
        rows = self.connection.execute(
            f"SELECT * FROM events{where} ORDER BY timestamp {direction}, id {direction} LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        ).fetchall()
        return [_stored_event(row) for row in rows]

    def count_events(
        self, *, source_ip: str | None = None, log_type: ApacheLogType | None = None,
        start: datetime | None = None, end: datetime | None = None,
    ) -> int:
        where, parameters = _event_filters(source_ip, log_type, start, end)
        return self.connection.execute(f"SELECT COUNT(*) FROM events{where}", parameters).fetchone()[0]

    def iter_events(
        self, *, source_ip: str | None = None, log_type: ApacheLogType | None = None,
        start: datetime | None = None, end: datetime | None = None,
    ) -> Iterator[StoredEvent]:
        """Stream all matching evidence in timestamp/ID order, without a page cap.

        Keep the connection open while iterating. Close the iterator if stopping
        early; exhausting it also closes its cursor. This read does not commit.
        """
        where, parameters = _event_filters(source_ip, log_type, start, end)
        cursor = self.connection.execute(
            f"SELECT * FROM events{where} ORDER BY timestamp, id", parameters,
        )
        try:
            for row in cursor:
                yield _stored_event(row)
        finally:
            cursor.close()

    def insert_alert(self, alert: Alert, event_ids: Iterable[int]) -> int:
        evidence_ids = _evidence_ids(event_ids)
        data = _alert_data(alert)
        with transaction(self.connection):
            # Reserve merged IDs too: an old reference must never name a new alert.
            highest_id = self.connection.execute(
                "SELECT MAX(value) FROM (SELECT MAX(id) AS value FROM alerts "
                "UNION ALL SELECT MAX(former_id) AS value FROM alert_merges)",
            ).fetchone()[0] or 0
            if highest_id == 2**63 - 1:
                raise ValueError("The SQLite alert ID space is exhausted.")
            data["id"] = highest_id + 1
            cursor = self.connection.execute(_ALERT_INSERT, data)
            alert_id = cursor.lastrowid
            self.connection.executemany(
                "INSERT INTO alert_events (alert_id, event_id) VALUES (?, ?)",
                ((alert_id, event_id) for event_id in evidence_ids),
            )
        return alert_id

    def _represented_evidence(self, alert: Alert, evidence_ids: tuple[int, ...]) -> set[int]:
        represented = set()
        # Stay below SQLite installations' parameter limits for large windows.
        for offset in range(0, len(evidence_ids), 500):
            batch = evidence_ids[offset:offset + 500]
            rows = self.connection.execute(
                "SELECT DISTINCT ae.event_id FROM alert_events ae JOIN alerts a ON a.id = ae.alert_id "
                "WHERE a.rule_id = ? AND a.grouping_key = ? "
                f"AND ae.event_id IN ({', '.join('?' for _ in batch)})",
                (alert.rule_id, alert.grouping_key, *batch),
            )
            represented.update(row[0] for row in rows)
        return represented

    def _related_open_alerts(self, alert: Alert, max_gap_seconds: int) -> list[StoredAlert]:
        first, last = alert.first_seen, alert.last_seen
        related: dict[int, StoredAlert] = {}
        while True:
            rows = self.connection.execute(
                _ALERT_SELECT + " WHERE a.rule_id = ? AND a.grouping_key = ? "
                "AND a.status IN ('new', 'investigating') AND a.first_seen <= ? AND a.last_seen >= ?",
                (
                    alert.rule_id, alert.grouping_key,
                    _utc_text(_shift_time(last, max_gap_seconds), "end"),
                    _utc_text(_shift_time(first, -max_gap_seconds), "start"),
                ),
            ).fetchall()
            previous_count = len(related)
            for row in rows:
                stored = _stored_alert(row)
                related[stored.id] = stored
                first = min(first, stored.alert.first_seen)
                last = max(last, stored.alert.last_seen)
            if len(related) == previous_count:
                return sorted(related.values(), key=lambda item: item.id)

    def correlate_alert(
        self, alert: Alert, event_ids: Iterable[int], *, max_gap_seconds: int,
    ) -> AlertWrite:
        """Create or extend an open incident when a finding has fresh evidence.

        Matching rule/group intervals within max_gap_seconds join together.
        Evidence already represented by that rule/group, including closed
        alerts, causes no write. Resolved/false-positive rows stay untouched.
        Bridged open incidents retain the smallest ID and all evidence, with
        investigating status winning over new. The entire operation is atomic.
        """
        evidence_ids = _evidence_ids(event_ids)
        data = _alert_data(alert)
        if alert.status != "new":
            raise ValueError("A detection candidate must have status 'new'.")
        if type(max_gap_seconds) is not int or not 1 <= max_gap_seconds <= 86400:
            raise ValueError("max_gap_seconds must be an integer between 1 and 86400.")
        with transaction(self.connection):
            if self._represented_evidence(alert, evidence_ids) == set(evidence_ids):
                return AlertWrite()
            related = self._related_open_alerts(alert, max_gap_seconds)
            if related:
                target = related[0]
                alert_id = target.id
                for other in related[1:]:
                    self.connection.execute(
                        "INSERT INTO alert_events (alert_id, event_id) "
                        "SELECT ?, event_id FROM alert_events WHERE alert_id = ? "
                        "ON CONFLICT(alert_id, event_id) DO NOTHING",
                        (alert_id, other.id),
                    )
                    self.connection.execute(
                        "UPDATE alert_merges SET alert_id = ? WHERE alert_id = ?", (alert_id, other.id),
                    )
                    self.connection.execute(
                        "INSERT INTO alert_merges (former_id, alert_id, merged_at) VALUES (?, ?, ?)",
                        (other.id, alert_id, _utc_text(datetime.now(timezone.utc), "merged_at")),
                    )
                    self.connection.execute("DELETE FROM alerts WHERE id = ?", (other.id,))
                self.connection.executemany(
                    "INSERT INTO alert_events (alert_id, event_id) VALUES (?, ?) "
                    "ON CONFLICT(alert_id, event_id) DO NOTHING",
                    ((alert_id, event_id) for event_id in evidence_ids),
                )
                first = min([data["first_seen"], *(_utc_text(item.alert.first_seen, "first_seen") for item in related)])
                last = max([data["last_seen"], *(_utc_text(item.alert.last_seen, "last_seen") for item in related)])
                status = "investigating" if any(item.alert.status == "investigating" for item in related) else "new"
                severity = max([alert.severity, *(item.alert.severity for item in related)], key=SEVERITIES.index)
                self.connection.execute(
                    "UPDATE alerts SET title = ?, severity = ?, first_seen = ?, last_seen = ?, status = ? WHERE id = ?",
                    (alert.title, severity, first, last, status, alert_id),
                )
            else:
                alert_id = self.insert_alert(alert, evidence_ids)
            count = self.connection.execute(
                "SELECT COUNT(*) FROM alert_events WHERE alert_id = ?", (alert_id,),
            ).fetchone()[0]
            self.connection.execute(
                "UPDATE alerts SET description = ? WHERE id = ?",
                (f"Correlated {count} Apache evidence records. Detection: {alert.description}", alert_id),
            )
            return AlertWrite(
                alert_id=alert_id, created=not related, updated=bool(related),
                merged_alerts=max(0, len(related) - 1),
            )

    def set_alert_status(self, alert_id: int, status: AlertStatus) -> StoredAlert | None:
        """Set an analyst status without changing evidence or detection times."""
        if type(alert_id) is not int or not 1 <= alert_id < 2**63:
            raise ValueError("alert_id must be a positive SQLite integer.")
        if status not in ALERT_STATUSES:
            raise ValueError("status must be new, investigating, resolved, or false_positive.")
        with transaction(self.connection):
            stored = self.get_alert(alert_id)
            if stored is not None and stored.alert.status != status:
                self.connection.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, stored.id))
                stored = self.get_alert(alert_id)
            return stored

    def _canonical_alert_id(self, alert_id: int) -> int:
        row = self.connection.execute("SELECT alert_id FROM alert_merges WHERE former_id = ?", (alert_id,)).fetchone()
        return row[0] if row is not None else alert_id

    def get_alert(self, alert_id: int) -> StoredAlert | None:
        row = self.connection.execute(_ALERT_SELECT + " WHERE a.id = ?", (self._canonical_alert_id(alert_id),)).fetchone()
        return _stored_alert(row) if row is not None else None

    def list_alerts(
        self, *, source_ip: str | None = None, rule_id: str | None = None,
        severity: Severity | None = None, status: AlertStatus | None = None,
        start: datetime | None = None, end: datetime | None = None,
        limit: int = 100, offset: int = 0, newest_first: bool = False,
    ) -> list[StoredAlert]:
        _page(limit, offset)
        where, parameters = _alert_filters(source_ip, rule_id, severity, status, start, end)
        direction = "DESC" if newest_first else "ASC"
        rows = self.connection.execute(
            f"{_ALERT_SELECT}{where} ORDER BY a.first_seen {direction}, a.id {direction} LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        ).fetchall()
        return [_stored_alert(row) for row in rows]

    def count_alerts(
        self, *, source_ip: str | None = None, rule_id: str | None = None,
        severity: Severity | None = None, status: AlertStatus | None = None,
        start: datetime | None = None, end: datetime | None = None,
    ) -> int:
        where, parameters = _alert_filters(source_ip, rule_id, severity, status, start, end)
        return self.connection.execute(
            f"SELECT COUNT(*) FROM alerts a{where}", parameters,
        ).fetchone()[0]

    def get_alert_events(self, alert_id: int, *, limit: int = 100, offset: int = 0) -> list[StoredEvent]:
        _page(limit, offset)
        rows = self.connection.execute(
            "SELECT e.* FROM events e JOIN alert_events ae ON ae.event_id = e.id "
            "WHERE ae.alert_id = ? ORDER BY e.timestamp, e.id LIMIT ? OFFSET ?",
            (self._canonical_alert_id(alert_id), limit, offset),
        ).fetchall()
        return [_stored_event(row) for row in rows]

    def statistics(
        self, *, source_ip: str | None = None,
        start: datetime | None = None, end: datetime | None = None,
    ) -> dict[str, Any]:
        """Aggregate all matching rows, independently of list pagination.

        Event dates filter timestamp; alert dates filter first_seen. A source
        filter excludes server-wide alerts that have no single source IP.
        Use a surrounding transaction for a consistent snapshot of all counts.
        """
        event_where, event_values = _event_filters(source_ip, None, start, end)
        alert_where, alert_values = _alert_filters(source_ip, None, None, None, start, end)
        events = dict(self.connection.execute(
            "SELECT COUNT(*) AS total, COUNT(DISTINCT source_ip) AS distinct_source_ips, "
            f"MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen FROM events{event_where}",
            event_values,
        ).fetchone())
        alerts = dict(self.connection.execute(
            "SELECT COUNT(*) AS total, MIN(a.first_seen) AS first_seen, "
            f"MAX(a.last_seen) AS last_seen FROM alerts a{alert_where}", alert_values,
        ).fetchone())
        # Columns and table names are fixed here; user values stay bound.
        for column, defaults in (
            ("log_type", ("access", "error")),
            ("status", ALERT_STATUSES),
            ("severity", SEVERITIES),
            ("rule_id", ()),
        ):
            is_event = column == "log_type"
            table, prefix = ("events", "") if is_event else ("alerts a", "a.")
            where, values = (event_where, event_values) if is_event else (alert_where, alert_values)
            counts = dict.fromkeys(defaults, 0)
            counts.update(
                (row[0], row[1]) for row in self.connection.execute(
                    f"SELECT {prefix}{column}, COUNT(*) FROM {table}{where} "
                    f"GROUP BY {prefix}{column} ORDER BY {prefix}{column}", values,
                )
            )
            (events if is_event else alerts)["by_" + column] = counts
        alerts["open"] = alerts["by_status"]["new"] + alerts["by_status"]["investigating"]
        for aggregate in (events, alerts):
            for name in ("first_seen", "last_seen"):
                if aggregate[name] is not None:
                    aggregate[name] = datetime.fromisoformat(aggregate[name])
        return {"events": events, "alerts": alerts}
