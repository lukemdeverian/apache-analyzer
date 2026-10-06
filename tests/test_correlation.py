import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.alerts import ALERT_STATUSES, Alert
from app.database import connect_database, initialize_database, transaction
from app.parsers import parse_access_line
from app.storage import SQLiteStore

BASE = datetime(2026, 10, 6, 9, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def store():
    connection = connect_database(":memory:")
    initialize_database(connection)
    yield SQLiteStore(connection)
    connection.close()


def event(store, seconds=0):
    value = parse_access_line('192.0.2.10 - - [06/Oct/2026:09:00:00 +0000] "GET /.env HTTP/1.1" 404 0')
    return store.insert_event(replace(value, timestamp=BASE + timedelta(seconds=seconds)))


def candidate(first=0, last=None, **overrides):
    return Alert(**{
        "rule_id": "APACHE-SENSITIVE-FILE", "title": "Sensitive-file request",
        "description": "Request matched a configuration file path.", "severity": "medium",
        "grouping_key": "ip:192.0.2.10", "source_ip": "192.0.2.10",
        "first_seen": BASE + timedelta(seconds=first),
        "last_seen": BASE + timedelta(seconds=first if last is None else last),
        "created_at": BASE, **overrides,
    })


def correlate(store, value, ids, gap=300):
    return store.correlate_alert(value, ids, max_gap_seconds=gap)


def test_new_alert_and_repeated_finding_have_unique_evidence_and_no_replay_writes(store):
    ids = [event(store), event(store, 1)]
    write = correlate(store, candidate(0, 1), [*ids, ids[0]])
    assert write.created and not write.updated and write.merged_alerts == 0
    stored = store.get_alert(write.alert_id)
    assert stored.event_count == 2
    assert "Correlated 2 Apache evidence records" in stored.alert.description
    before = store.connection.total_changes

    replay = correlate(store, candidate(0, 1), ids)

    assert replay.alert_id is None
    assert not replay.created and not replay.updated
    assert store.connection.total_changes == before
    assert store.get_alert(write.alert_id) == stored


def test_fresh_evidence_extends_open_alert_and_preserves_investigation_and_creation_time(store):
    first = event(store, 10)
    write = correlate(store, candidate(10), [first])
    store.set_alert_status(write.alert_id, "investigating")
    second = event(store, 20)

    updated = correlate(store, candidate(10, 20, created_at=BASE + timedelta(days=1)), [first, second])

    assert updated.alert_id == write.alert_id and updated.updated and not updated.created
    stored = store.get_alert(write.alert_id)
    assert stored.alert.status == "investigating"
    assert stored.alert.created_at == BASE
    assert stored.alert.first_seen == BASE + timedelta(seconds=10)
    assert stored.alert.last_seen == BASE + timedelta(seconds=20)
    assert stored.event_count == 2
    assert [item.id for item in store.get_alert_events(write.alert_id)] == [first, second]
    assert not correlate(store, candidate(10), [first]).updated
    assert store.get_alert(write.alert_id) == stored


@pytest.mark.parametrize("seconds, merges", [(59, True), (60, True), (60.000001, False)])
def test_correlation_gap_is_inclusive_and_separates_later_incidents(store, seconds, merges):
    first = correlate(store, candidate(), [event(store)], gap=60)
    second = correlate(store, candidate(seconds), [event(store, seconds)], gap=60)
    assert second.updated == merges
    assert second.created != merges
    assert store.count_alerts() == (1 if merges else 2)
    if merges:
        assert second.alert_id == first.alert_id


def test_rule_and_group_scopes_keep_distinct_alerts_separate(store):
    evidence = event(store)
    first = correlate(store, candidate(), [evidence])
    other_rule = correlate(store, candidate(rule_id="APACHE-TRAVERSAL"), [evidence])
    other_group = correlate(store, candidate(grouping_key="host:client.example.test", source_ip=None), [evidence])
    assert {first.alert_id, other_rule.alert_id, other_group.alert_id} == {1, 2, 3}
    assert store.count_alerts() == 3


def test_late_evidence_extends_first_seen_without_shrinking_last_seen(store):
    first = correlate(store, candidate(10, 20), [event(store, 10), event(store, 20)])
    late = event(store, 5)
    update = correlate(store, candidate(5), [late])
    assert update.alert_id == first.alert_id
    stored = store.get_alert(first.alert_id)
    assert stored.alert.first_seen == BASE + timedelta(seconds=5)
    assert stored.alert.last_seen == BASE + timedelta(seconds=20)
    assert stored.alert.created_at == BASE
    assert stored.event_count == 3


def test_bridged_open_alerts_merge_evidence_and_old_ids_redirect_without_reuse(store):
    first_id, last_id = event(store), event(store, 600)
    first = correlate(store, candidate(), [first_id])
    last = correlate(store, candidate(600, severity="high"), [last_id])
    store.set_alert_status(last.alert_id, "investigating")
    bridge_id = event(store, 300)

    merged = correlate(store, candidate(300), [bridge_id])

    assert merged.alert_id == first.alert_id
    assert merged.updated and merged.merged_alerts == 1
    assert store.count_alerts() == 1
    assert store.get_alert(last.alert_id) == store.get_alert(first.alert_id)
    result = store.get_alert(first.alert_id)
    assert result.alert.status == "investigating"
    assert result.alert.severity == "high"
    assert result.alert.created_at == BASE
    assert result.alert.first_seen == BASE
    assert result.alert.last_seen == BASE + timedelta(seconds=600)
    assert result.event_count == 3
    assert [item.id for item in store.get_alert_events(last.alert_id)] == [first_id, bridge_id, last_id]
    assert store.set_alert_status(last.alert_id, "resolved").id == first.alert_id
    new = correlate(store, candidate(900, grouping_key="ip:192.0.2.20"), [event(store, 900)])
    assert new.alert_id > last.alert_id
    assert store.get_alert(last.alert_id).id == first.alert_id


def test_aliases_are_flattened_when_their_target_is_merged_again(store):
    earliest = correlate(store, candidate(), [event(store)])
    middle = correlate(store, candidate(1000), [event(store, 1000)])
    latest = correlate(store, candidate(1060), [event(store, 1060)], gap=50)
    merged = correlate(store, candidate(1030), [event(store, 1030)], gap=50)
    assert merged.alert_id == middle.alert_id
    assert store.get_alert(latest.alert_id).id == middle.alert_id

    final = correlate(store, candidate(0, 1000), [event(store, 500)], gap=50)

    assert final.alert_id == earliest.alert_id
    assert store.get_alert(middle.alert_id).id == earliest.alert_id
    assert store.get_alert(latest.alert_id).id == earliest.alert_id
    assert store.count_alerts() == 1
    assert store.get_alert(earliest.alert_id).event_count == 5


@pytest.mark.parametrize("status", ["resolved", "false_positive"])
def test_closed_alerts_are_preserved_and_fresh_evidence_creates_a_separate_alert(store, status):
    old_event = event(store)
    first = correlate(store, candidate(), [old_event])
    store.set_alert_status(first.alert_id, status)
    original = store.get_alert(first.alert_id)
    assert not correlate(store, candidate(), [old_event]).created
    fresh = event(store, 1)

    second = correlate(store, candidate(0, 1), [old_event, fresh])

    assert second.created and second.alert_id != first.alert_id
    assert store.get_alert(first.alert_id) == original
    assert store.get_alert(second.alert_id).alert.status == "new"
    assert store.get_alert(second.alert_id).event_count == 2


def test_closed_alert_is_not_merged_by_a_bridge_to_an_open_alert(store):
    closed = correlate(store, candidate(), [event(store)])
    store.set_alert_status(closed.alert_id, "resolved")
    original = store.get_alert(closed.alert_id)
    open_alert = correlate(store, candidate(600), [event(store, 600)])
    merged = correlate(store, candidate(300), [event(store, 300)])
    assert merged.alert_id == open_alert.alert_id and merged.merged_alerts == 0
    assert store.count_alerts() == 2
    assert store.get_alert(closed.alert_id) == original


def test_failed_link_rolls_back_merges_aliases_and_updates_together(store):
    first = correlate(store, candidate(), [event(store)])
    last = correlate(store, candidate(600), [event(store, 600)])
    before = store.list_alerts()
    bridge = event(store, 300)
    store.connection.execute(
        "CREATE TRIGGER fail_bridge BEFORE INSERT ON alert_events "
        f"WHEN NEW.event_id = {bridge} BEGIN SELECT RAISE(ABORT, 'synthetic link failure'); END"
    )

    with pytest.raises(sqlite3.IntegrityError, match="synthetic link failure"):
        correlate(store, candidate(300), [bridge])

    assert store.list_alerts() == before
    assert store.get_alert(last.alert_id).id == last.alert_id
    assert store.get_alert(first.alert_id).event_count == 1
    assert store.connection.execute("SELECT COUNT(*) FROM alert_merges").fetchone()[0] == 0
    assert not store.connection.in_transaction


def test_missing_evidence_failure_is_local_to_caller_transaction(store):
    with transaction(store.connection):
        saved = event(store)
        with pytest.raises(sqlite3.IntegrityError):
            correlate(store, candidate(), [saved, 99999])
        assert store.count_alerts() == 0
        assert store.connection.in_transaction
        valid = correlate(store, candidate(), [saved])
    assert store.get_alert(valid.alert_id).event_count == 1


def test_large_evidence_windows_work_with_legacy_sqlite_parameter_limit(store):
    store.connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)
    with transaction(store.connection):
        ids = [event(store) for _ in range(1501)]
    write = correlate(store, candidate(), ids)
    assert store.get_alert(write.alert_id).event_count == 1501
    assert not correlate(store, candidate(), ids).updated
    assert store.count_alerts() == 1


@pytest.mark.parametrize("status", ALERT_STATUSES)
def test_status_changes_preserve_all_detection_fields_and_evidence(store, status):
    evidence = event(store)
    write = correlate(store, candidate(), [evidence])
    before = store.get_alert(write.alert_id)
    changed = store.set_alert_status(write.alert_id, status)
    assert changed.alert == replace(before.alert, status=status)
    assert changed.event_count == 1
    assert [item.id for item in store.get_alert_events(write.alert_id)] == [evidence]
    changes = store.connection.total_changes
    assert store.set_alert_status(write.alert_id, status) == changed
    assert store.connection.total_changes == changes


def test_missing_status_target_returns_none(store):
    assert store.set_alert_status(123, "resolved") is None
    assert store.count_alerts() == 0


@pytest.mark.parametrize("alert_id, status", [
    (True, "new"), (0, "new"), (-1, "new"), (2**63, "new"), ("1", "new"),
    (1, "closed"), (1, "resolved'; DELETE FROM alerts; --"), (1, None),
])
def test_invalid_status_updates_are_rejected_without_writes(store, alert_id, status):
    correlate(store, candidate(), [event(store)])
    before = store.list_alerts()
    with pytest.raises(ValueError):
        store.set_alert_status(alert_id, status)
    assert store.list_alerts() == before


@pytest.mark.parametrize("gap", [0, -1, 86401, True, 1.5])
def test_invalid_correlation_gaps_are_rejected(store, gap):
    evidence = event(store)
    with pytest.raises(ValueError, match="max_gap_seconds"):
        correlate(store, candidate(), [evidence], gap=gap)
    assert store.count_alerts() == 0


@pytest.mark.parametrize("value", [
    candidate(status="resolved"), candidate(title=""), candidate(severity="urgent"),
    candidate(first_seen=BASE.replace(tzinfo=None)), candidate(2, 1),
])
def test_invalid_candidates_fail_before_changes(store, value):
    with pytest.raises(ValueError):
        correlate(store, value, [event(store)])
    assert store.count_alerts() == 0


@pytest.mark.parametrize("timestamp", [
    datetime.min.replace(tzinfo=timezone.utc), datetime.max.replace(tzinfo=timezone.utc),
])
def test_correlation_supports_timestamp_extremes(store, timestamp):
    evidence = event(store)
    write = correlate(store, candidate(first_seen=timestamp, last_seen=timestamp), [evidence])
    assert store.get_alert(write.alert_id).alert.first_seen == timestamp
