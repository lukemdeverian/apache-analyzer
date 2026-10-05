import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.alerts import Alert
from app.database import connect_database, initialize_database, transaction
from app.parsers import parse_access_line, parse_apache_line
from app.storage import SQLiteStore

BASE = datetime(2026, 10, 6, 9, 0, 0, tzinfo=timezone.utc)
LINE = '192.0.2.10 - - [06/Oct/2026:09:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234'
FIXTURES = Path(__file__).with_name("fixtures")


@pytest.fixture
def connection():
    connection = connect_database(":memory:")
    initialize_database(connection)
    yield connection
    connection.close()


@pytest.fixture
def store(connection):
    return SQLiteStore(connection)


def make_event(seconds=0, source_ip="192.0.2.10"):
    return replace(parse_access_line(LINE), timestamp=BASE + timedelta(seconds=seconds), source_ip=source_ip)


def make_alert(**overrides):
    return Alert(**{
        "rule_id": "TEST-001", "title": "Synthetic alert", "description": "Synthetic evidence for storage tests.",
        "severity": "medium", "grouping_key": "ip:192.0.2.10", "source_ip": "192.0.2.10",
        "first_seen": BASE, "last_seen": BASE + timedelta(seconds=3), "created_at": BASE,
        **overrides,
    })


@pytest.mark.parametrize("filename, log_type", [
    ("access_common.txt", "access"), ("access_combined.txt", "access"),
    ("error_standard.txt", "error"), ("error_legacy.txt", "error"),
])
def test_every_parsed_field_round_trips_through_storage(store, filename, log_type):
    lines = (FIXTURES / filename).read_text(encoding="utf-8").splitlines(keepends=True)
    for line_number, line in enumerate(lines, start=1):
        event = parse_apache_line(line, log_type, source_file=filename, line_number=line_number)
        assert event is not None

        event_id = store.insert_event(event)

        assert store.get_event(event_id).event == event
    assert store.count_events() == len(lines)


def test_committed_events_alerts_and_evidence_survive_reopening(tmp_path):
    database_path = tmp_path / "storage" / "events.sqlite3"
    event, alert = make_event(), make_alert()
    first = connect_database(database_path)
    try:
        initialize_database(first)
        store = SQLiteStore(first)
        with transaction(first):
            event_id = store.insert_event(event)
            alert_id = store.insert_alert(alert, [event_id])
    finally:
        first.close()

    reopened = connect_database(database_path)
    try:
        store = SQLiteStore(reopened)
        assert store.get_event(event_id).event == event
        assert store.get_alert(alert_id).alert == alert
        assert store.get_alert(alert_id).event_count == 1
        assert [item.id for item in store.get_alert_events(alert_id)] == [event_id]
    finally:
        reopened.close()


def test_event_filters_are_inclusive_and_use_utc_with_microseconds(store):
    first = store.insert_event(make_event())
    middle = store.insert_event(replace(make_event(1), timestamp=BASE + timedelta(seconds=1, microseconds=1)))
    store.insert_event(make_event(2))
    store.insert_event(make_event(1, source_ip="192.0.2.20"))
    offset_start = BASE.astimezone(timezone(timedelta(hours=5, minutes=30)))
    end = BASE + timedelta(seconds=1, microseconds=1)

    filters = {"source_ip": "192.0.2.10", "log_type": "access", "start": offset_start, "end": end}
    assert [item.id for item in store.list_events(**filters)] == [first, middle]
    assert store.count_events(**filters) == 2
    assert store.count_events(log_type="error") == 0


def test_event_pagination_is_stable_for_equal_timestamps(store):
    late = store.insert_event(make_event(2))
    first = store.insert_event(make_event())
    second = store.insert_event(make_event())

    assert [item.id for item in store.list_events(limit=1)] == [first]
    assert [item.id for item in store.list_events(limit=1, offset=1)] == [second]
    assert [item.id for item in store.list_events(newest_first=True)] == [late, second, first]
    assert store.count_events() == 3


def test_event_iterator_streams_beyond_page_limit_in_timestamp_id_order(store):
    with transaction(store.connection):
        ids = [store.insert_event(make_event(index % 3)) for index in range(1201)]
    results = list(store.iter_events())
    assert len(results) == 1201
    assert [item.id for item in results] == sorted(ids, key=lambda event_id: ((event_id - ids[0]) % 3, event_id))


def test_event_iterator_uses_inclusive_utc_and_source_filters(store):
    store.insert_event(make_event())
    middle = store.insert_event(make_event(1))
    store.insert_event(make_event(2))
    store.insert_event(make_event(1, source_ip="192.0.2.20"))
    timestamp = (BASE + timedelta(seconds=1)).astimezone(timezone(timedelta(hours=5, minutes=30)))
    assert [item.id for item in store.iter_events(
        start=timestamp, end=timestamp, source_ip="192.0.2.10", log_type="access",
    )] == [middle]
    assert list(store.iter_events(log_type="error")) == []


@pytest.mark.parametrize("filters", [
    {"log_type": "ssh"}, {"start": BASE.replace(tzinfo=None)},
    {"start": BASE + timedelta(seconds=1), "end": BASE},
])
def test_event_iterator_rejects_invalid_filters(store, filters):
    with pytest.raises(ValueError):
        list(store.iter_events(**filters))


def test_missing_records_return_none_or_empty_evidence(store):
    assert store.get_event(1234) is None
    assert store.get_alert(1234) is None
    assert store.get_alert_events(1234) == []


def test_alert_evidence_is_unique_and_ordered_by_event_time(store):
    late = store.insert_event(make_event(3))
    early = store.insert_event(make_event())
    alert = make_alert()

    alert_id = store.insert_alert(alert, [late, early, early])

    assert store.get_alert(alert_id).alert == alert
    assert store.get_alert(alert_id).event_count == 2
    assert [item.id for item in store.get_alert_events(alert_id)] == [early, late]
    assert [item.id for item in store.get_alert_events(alert_id, limit=1, offset=1)] == [late]


def test_alert_filters_counts_and_pagination(store):
    event_id = store.insert_event(make_event())
    first = store.insert_alert(make_alert(), [event_id])
    second = store.insert_alert(make_alert(rule_id="TEST-002", severity="high", status="investigating"), [event_id])
    store.insert_alert(make_alert(source_ip=None, grouping_key="server", first_seen=BASE + timedelta(seconds=2)), [event_id])

    filters = {
        "source_ip": "192.0.2.10", "rule_id": "TEST-002", "severity": "high",
        "status": "investigating", "start": BASE, "end": BASE,
    }
    assert [item.id for item in store.list_alerts(**filters)] == [second]
    assert store.count_alerts(**filters) == 1
    assert store.count_alerts() == 3
    assert [item.id for item in store.list_alerts(limit=1, offset=1)] == [second]
    assert store.list_alerts(newest_first=True)[-1].id == first


def test_bound_query_values_and_untrusted_evidence_cannot_execute_sql(store):
    malicious = "'; DROP TABLE events; --"
    event = replace(make_event(), raw_log=malicious, user_agent=malicious, path=malicious)
    event_id = store.insert_event(event)
    alert_id = store.insert_alert(make_alert(title=malicious, description=malicious), [event_id])

    assert store.get_event(event_id).event == event
    assert store.get_alert(alert_id).alert.title == malicious
    assert store.list_events(source_ip="' OR 1=1 --") == []
    assert store.count_events(source_ip="' OR 1=1 --") == 0
    assert store.list_alerts(rule_id="' OR 1=1 --") == []
    assert store.count_alerts(rule_id="' OR 1=1 --") == 0
    assert store.count_events() == store.count_alerts() == 1


def test_outer_transaction_rolls_back_events_alerts_and_evidence(store, connection):
    with pytest.raises(RuntimeError, match="stop import"):
        with transaction(connection):
            event_id = store.insert_event(make_event())
            store.insert_alert(make_alert(), [event_id])
            raise RuntimeError("stop import")

    assert store.count_events() == 0
    assert store.count_alerts() == 0
    assert connection.execute("SELECT COUNT(*) FROM alert_events").fetchone()[0] == 0
    assert not connection.in_transaction


def test_failed_alert_links_roll_back_locally_inside_outer_transaction(store, connection):
    with transaction(connection):
        event_id = store.insert_event(make_event())
        with pytest.raises(sqlite3.IntegrityError):
            store.insert_alert(make_alert(), [event_id, 9999])
        assert store.count_alerts() == 0
        assert connection.execute("SELECT COUNT(*) FROM alert_events").fetchone()[0] == 0
        store.insert_event(make_event(1))

    assert store.count_events() == 2
    assert not connection.in_transaction


def test_failed_standalone_alert_creation_leaves_no_partial_alert(store, connection):
    event_id = store.insert_event(make_event())
    with pytest.raises(sqlite3.IntegrityError):
        store.insert_alert(make_alert(), [event_id, 9999])

    assert store.count_events() == 1
    assert store.count_alerts() == 0
    assert not connection.in_transaction


def test_foreign_keys_protect_evidence_and_remove_links_with_alert(store, connection):
    event_id = store.insert_event(make_event())
    alert_id = store.insert_alert(make_alert(), [event_id])

    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("DELETE FROM events WHERE id = ?", (event_id,))
    connection.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))

    assert store.get_event(event_id) is not None
    assert connection.execute("SELECT COUNT(*) FROM alert_events").fetchone()[0] == 0


@pytest.mark.parametrize("changes", [
    {"timestamp": BASE.replace(tzinfo=None)},
    {"response_bytes": 2**63},
    {"line_number": True},
])
def test_invalid_event_values_are_rejected_before_insertion(store, changes):
    with pytest.raises(ValueError):
        store.insert_event(replace(make_event(), **changes))
    assert store.count_events() == 0


@pytest.mark.parametrize("changes", [
    {"log_type": "linux_auth"}, {"status_code": 99}, {"response_bytes": -1}, {"line_number": 0},
])
def test_database_constraints_reject_invalid_event_records(store, changes):
    with pytest.raises(sqlite3.IntegrityError):
        store.insert_event(replace(make_event(), **changes))
    assert store.count_events() == 0


@pytest.mark.parametrize("changes", [
    {"severity": "urgent"}, {"status": "closed"}, {"rule_id": ""}, {"grouping_key": " "},
    {"first_seen": BASE.replace(tzinfo=None)}, {"first_seen": BASE + timedelta(seconds=4)},
])
def test_invalid_alerts_are_rejected_without_writes(store, changes):
    event_id = store.insert_event(make_event())
    with pytest.raises(ValueError):
        store.insert_alert(make_alert(**changes), [event_id])
    assert store.count_alerts() == 0


@pytest.mark.parametrize("event_ids", [[], [0], [-1], [True], ["1"], [1, True]])
def test_alerts_require_valid_evidence_ids(store, event_ids):
    with pytest.raises(ValueError, match="event IDs"):
        store.insert_alert(make_alert(), event_ids)
    assert store.count_alerts() == 0


@pytest.mark.parametrize("pagination", [
    {"limit": 0}, {"limit": 1001}, {"limit": True}, {"offset": -1}, {"offset": 0.5},
])
def test_queries_require_bounded_integer_pagination(store, pagination):
    with pytest.raises(ValueError):
        store.list_events(**pagination)
    with pytest.raises(ValueError):
        store.list_alerts(**pagination)
    with pytest.raises(ValueError):
        store.get_alert_events(1, **pagination)


@pytest.mark.parametrize("filters", [
    {"start": BASE.replace(tzinfo=None)}, {"start": BASE + timedelta(seconds=1), "end": BASE},
])
def test_invalid_time_filters_are_rejected_for_lists_and_counts(store, filters):
    for query in (store.list_events, store.count_events, store.list_alerts, store.count_alerts):
        with pytest.raises(ValueError):
            query(**filters)


def test_unsupported_filter_values_are_rejected(store):
    with pytest.raises(ValueError, match="log_type"):
        store.list_events(log_type="network_telemetry")
    with pytest.raises(ValueError, match="severity"):
        store.list_alerts(severity="urgent")
    with pytest.raises(ValueError, match="status"):
        store.count_alerts(status="closed")
