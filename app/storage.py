"""Typed SQLite writes and bounded, parameterized evidence queries."""

import sqlite3
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, fields
from datetime import datetime, timezone
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
    f"INSERT INTO alerts ({', '.join(_ALERT_COLUMNS)}) "
    f"VALUES ({', '.join(':' + column for column in _ALERT_COLUMNS)})"
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


def _utc_text(value: datetime, name: str) -> str:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime.")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _page(limit: int, offset: int) -> None:
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("limit must be an integer between 1 and 1000.")
    if type(offset) is not int or offset < 0:
        raise ValueError("offset must be a nonnegative integer.")


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
        evidence_ids = tuple(event_ids)
        if not evidence_ids or any(type(value) is not int or value < 1 for value in evidence_ids):
            raise ValueError("An alert requires positive event IDs as evidence.")
        evidence_ids = tuple(dict.fromkeys(evidence_ids))
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
        with transaction(self.connection):
            cursor = self.connection.execute(_ALERT_INSERT, data)
            alert_id = cursor.lastrowid
            self.connection.executemany(
                "INSERT INTO alert_events (alert_id, event_id) VALUES (?, ?)",
                ((alert_id, event_id) for event_id in evidence_ids),
            )
        return alert_id

    def get_alert(self, alert_id: int) -> StoredAlert | None:
        row = self.connection.execute(_ALERT_SELECT + " WHERE a.id = ?", (alert_id,)).fetchone()
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
            (alert_id, limit, offset),
        ).fetchall()
        return [_stored_event(row) for row in rows]
