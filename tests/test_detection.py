from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.database import connect_database, initialize_database, transaction
from app.detection import BEHAVIORAL_RULES, DetectionEngine, RuleSettings
from app.ingestion import ingest_file
from app.parsers import parse_access_line, parse_error_line
from app.storage import SQLiteStore

BASE = datetime(2026, 10, 6, 9, 0, 0, tzinfo=timezone.utc)
ENUMERATION = "APACHE-PATH-ENUMERATION"
HTTP_ERRORS = "APACHE-HTTP-ERRORS"
AUTH = "APACHE-AUTH-FAILURES"
BURST = "APACHE-REQUEST-BURST"
CASES = [
    (ENUMERATION, 10, 300, 404),
    (HTTP_ERRORS, 20, 300, 403),
    (AUTH, 10, 300, 401),
    (BURST, 120, 60, 200),
]


@pytest.fixture
def store():
    connection = connect_database(":memory:")
    initialize_database(connection)
    yield SQLiteStore(connection)
    connection.close()


def make_event(seconds=0, *, status=404, target="/missing", ip="192.0.2.10", missing_request=False):
    timestamp = BASE + timedelta(seconds=seconds)
    stamp = f"{timestamp.day:02}/Oct/2026:{timestamp:%H:%M:%S} +0000"
    request = "-" if missing_request else f"GET {target} HTTP/1.1"
    line = f'{ip} - - [{stamp}] "{request}" {status} 0'
    event = parse_access_line(line, source_file="synthetic-access.txt", line_number=1)
    assert event is not None
    return replace(event, timestamp=timestamp)


def add_requests(store, count, *, rule_id=None, seconds=0, status=404, ip="192.0.2.10"):
    ids = []
    with transaction(store.connection):
        for index in range(count):
            target = f"/missing-{index % 5}" if rule_id == ENUMERATION else "/private"
            event = make_event(seconds, status=status, target=target, ip=ip)
            ids.append(store.insert_event(replace(event, line_number=index + 1)))
    return ids


def findings(store, rule_id=None, *, engine=None, **filters):
    results = list((engine or DetectionEngine()).iter_findings(store, **filters))
    return [item for item in results if rule_id is None or item.rule_id == rule_id]


@pytest.mark.parametrize("rule_id, threshold, window, status", CASES)
def test_defaults_trigger_at_threshold_with_exact_evidence_and_no_database_writes(
    store, rule_id, threshold, window, status,
):
    ids = add_requests(store, threshold - 1, rule_id=rule_id, status=status)
    assert findings(store) == []
    anchor = store.insert_event(make_event(1, status=status, target="/private"))
    changes = store.connection.total_changes

    result, = findings(store)

    assert result.rule_id == rule_id
    assert result.event_ids == tuple([*ids, anchor])
    assert result.anchor_event_id == anchor
    assert result.event_count == threshold
    assert result.threshold == threshold
    assert result.window_seconds == window
    assert result.source_ip == "192.0.2.10"
    assert result.first_seen == BASE
    assert result.last_seen == BASE + timedelta(seconds=1)
    assert str(threshold) in result.description
    assert result.severity == ("high" if rule_id == AUTH else "medium")
    assert result.grouping_key == "ip:192.0.2.10" + ("|path:/private" if rule_id == AUTH else "")
    assert all(store.get_event(event_id).event.source_file == "synthetic-access.txt" for event_id in result.event_ids)
    assert store.count_alerts() == 0
    assert store.connection.total_changes == changes


@pytest.mark.parametrize("rule_id, threshold, window, status", CASES)
@pytest.mark.parametrize("extra_seconds, expected", [(0, True), (0.000001, False)])
def test_window_includes_exact_boundary_but_excludes_older_evidence(
    store, rule_id, threshold, window, status, extra_seconds, expected,
):
    ids = add_requests(store, threshold - 1, rule_id=rule_id, status=status)
    anchor = store.insert_event(make_event(window + extra_seconds, status=status, target="/private"))

    results = findings(store, rule_id)

    assert bool(results) == expected
    if expected:
        assert results[0].event_ids == tuple([*ids, anchor])


@pytest.mark.parametrize("rule_id, threshold, window, status", CASES)
def test_each_rule_keeps_different_ips_separate(store, rule_id, threshold, window, status):
    add_requests(store, threshold - 1, rule_id=rule_id, status=status)
    store.insert_event(make_event(1, status=status, target="/private", ip="192.0.2.20"))
    assert findings(store) == []


@pytest.mark.parametrize("rule_id, threshold, window, status", CASES)
def test_hostnames_without_logged_ips_do_not_trigger_ip_rules(store, rule_id, threshold, window, status):
    add_requests(store, threshold, rule_id=rule_id, status=status, ip="client.example.test")
    assert findings(store) == []


@pytest.mark.parametrize("rule_id, threshold, window, status", CASES)
def test_ipv6_clients_are_supported(store, rule_id, threshold, window, status):
    add_requests(store, threshold, rule_id=rule_id, status=status, ip="2001:db8::10")
    result, = findings(store, rule_id)
    assert result.source_ip == "2001:db8::10"
    assert result.grouping_key.startswith("ip:2001:db8::10")


def test_error_log_records_do_not_contribute_to_access_rules(store):
    ids = add_requests(store, 9, status=401)
    error = parse_error_line(
        "[Tue Oct 06 09:00:01.000000 2026] [auth_basic:error] [pid 4120] "
        "[client 192.0.2.10:52102] AH01617: authentication failure"
    )
    assert error is not None
    for _ in range(120):
        store.insert_event(error)
    assert findings(store, AUTH) == []
    assert findings(store, BURST) == []
    anchor = store.insert_event(make_event(2, status=401, target="/private"))
    result, = findings(store, AUTH)
    assert result.rule_id == AUTH
    assert result.event_ids == tuple([*ids, anchor])


def test_enumeration_requires_both_request_count_and_distinct_failed_paths(store):
    ids = [store.insert_event(make_event(status=404, target=f"/missing-{index % 4}")) for index in range(10)]
    assert findings(store, ENUMERATION) == []
    anchor = store.insert_event(make_event(1, status=403, target="/fifth"))
    result, = findings(store, ENUMERATION)
    assert result.event_ids == tuple([*ids, anchor])
    assert result.distinct_path_count == 5
    assert "11 HTTP 403/404 responses across 5 distinct paths" in result.description


def test_query_strings_do_not_inflate_distinct_paths(store):
    for index in range(15):
        store.insert_event(make_event(target=f"/search?q={index}"))
    assert findings(store) == []


def test_successful_browsing_does_not_trigger_failed_path_rules(store):
    for index in range(119):
        store.insert_event(make_event(status=200, target=f"/page-{index}"))
    assert findings(store) == []


def test_http_error_rule_accepts_repeated_paths_and_mixed_403_404_responses(store):
    ids = [store.insert_event(make_event(status=403 if index % 2 else 404)) for index in range(20)]
    result, = findings(store)
    assert result.rule_id == HTTP_ERRORS
    assert result.event_ids == tuple(ids)
    assert result.distinct_path_count == 1


@pytest.mark.parametrize("status", [200, 302, 400, 401, 405, 429, 500, 503])
def test_other_statuses_do_not_count_as_403_404_errors(store, status):
    add_requests(store, 19, status=404)
    store.insert_event(make_event(status=status))
    assert findings(store, HTTP_ERRORS) == []


def test_authentication_failures_are_grouped_by_path_and_ignore_queries(store):
    ids = [store.insert_event(make_event(status=401, target=f"/private?retry={index}")) for index in range(9)]
    other = store.insert_event(make_event(status=401, target="/other"))
    assert findings(store) == []
    anchor = store.insert_event(make_event(1, status=401, target="/private?retry=9"))
    result, = findings(store)
    assert result.rule_id == AUTH
    assert result.grouping_key == "ip:192.0.2.10|path:/private"
    assert result.event_ids == tuple([*ids, anchor])
    assert other not in result.event_ids


def test_forbidden_and_login_success_responses_are_not_authentication_failures(store):
    add_requests(store, 9, status=401)
    for status in (200, 302, 403):
        store.insert_event(make_event(status=status, target="/private"))
    assert findings(store) == []


@pytest.mark.parametrize("target", ["*", "example.test:443"])
def test_non_path_request_targets_are_not_authentication_or_enumeration_paths(store, target):
    for status in (401, 404):
        for _ in range(10):
            store.insert_event(make_event(status=status, target=target))
    assert findings(store) == []


def test_missing_requests_are_retained_in_error_and_volume_evidence(store):
    ids = [store.insert_event(make_event(status=404, missing_request=True)) for _ in range(20)]
    result, = findings(store)
    assert result.rule_id == HTTP_ERRORS
    assert result.event_ids == tuple(ids)
    assert result.distinct_path_count == 0
    add_requests(store, 100, status=200)
    burst, = findings(store, BURST)
    assert burst.event_count == 120
    assert burst.event_ids[:20] == tuple(ids)


def test_missing_requests_are_not_assigned_an_authentication_path(store):
    for _ in range(10):
        store.insert_event(make_event(status=401, missing_request=True))
    assert findings(store) == []


def test_spread_out_successful_requests_do_not_trigger_volume_rule(store):
    for seconds in range(240):
        store.insert_event(make_event(seconds, status=200))
    assert findings(store) == []


def test_expired_paths_no_longer_satisfy_distinct_path_condition(store):
    for index in range(4):
        store.insert_event(make_event(target=f"/old-{index}"))
    add_requests(store, 10, seconds=301, status=404)
    assert findings(store) == []


def test_later_records_do_not_cause_early_findings_and_out_of_order_imports_are_sorted(store):
    later = store.insert_event(make_event(2, status=401, target="/private"))
    earlier = add_requests(store, 9, status=401)
    results = findings(store)
    result, = results
    assert result.rule_id == AUTH
    assert result.anchor_event_id == later
    assert result.event_ids == tuple([*earlier, later])
    assert result.first_seen == BASE
    assert result.last_seen == BASE + timedelta(seconds=2)


def test_equal_timestamp_anchors_use_stable_id_order_and_preserve_overlapping_findings(store):
    ids = add_requests(store, 12, status=401)
    results = findings(store)
    assert [item.anchor_event_id for item in results] == ids[9:]
    assert [item.event_count for item in results] == [10, 11, 12]
    assert results == findings(store)
    assert store.count_alerts() == 0


def test_filtered_scan_loads_prior_context_but_only_emits_anchors_in_requested_range(store):
    ids = add_requests(store, 9, status=401)
    first = store.insert_event(make_event(10, status=401, target="/private"))
    last = store.insert_event(make_event(20, status=401, target="/private"))
    store.insert_event(make_event(21, status=401, target="/private"))
    for _ in range(10):
        store.insert_event(make_event(10, status=401, target="/private", ip="192.0.2.20"))
    offset = timezone(timedelta(hours=-7))

    results = findings(
        store, start=(BASE + timedelta(seconds=10)).astimezone(offset),
        end=BASE + timedelta(seconds=20), source_ip="192.0.2.10",
    )

    assert [item.anchor_event_id for item in results] == [first, last]
    assert results[0].event_ids == tuple([*ids, first])
    assert results[1].event_ids == tuple([*ids, first, last])


def test_start_context_respects_exact_window_boundary(store):
    add_requests(store, 9, status=401)
    anchor = store.insert_event(make_event(300, status=401, target="/private"))
    result, = findings(store, start=BASE + timedelta(seconds=300), end=BASE + timedelta(seconds=300))
    assert result.anchor_event_id == anchor
    assert result.event_count == 10


def test_scan_and_window_subtraction_support_earliest_storable_timestamp(store):
    timestamp = datetime.min.replace(tzinfo=timezone.utc)
    for _ in range(10):
        store.insert_event(replace(make_event(status=401, target="/private"), timestamp=timestamp))
    result, = findings(store, start=timestamp, end=timestamp)
    assert result.first_seen == timestamp
    assert result.last_seen == timestamp


def test_detection_does_not_truncate_evidence_at_storage_page_limit(store):
    ids = add_requests(store, 1501, status=200)
    engine = DetectionEngine({BURST: RuleSettings(1501, 60)})
    result, = findings(store, engine=engine)
    assert result.rule_id == BURST
    assert result.event_count == 1501
    assert result.event_ids == tuple(ids)


def test_custom_thresholds_and_windows_are_isolated_from_defaults(store):
    engine = DetectionEngine({AUTH: RuleSettings(2, 1)})
    ids = add_requests(store, 1, status=401)
    anchor = store.insert_event(make_event(1, status=401, target="/private"))
    result, = findings(store, engine=engine)
    assert result.event_ids == tuple([*ids, anchor])
    assert result.window_seconds == 1
    assert result.threshold == 2
    assert findings(store) == []
    assert next(rule for rule in BEHAVIORAL_RULES if rule.rule_id == AUTH).settings == RuleSettings(10, 300)


def test_filtered_scan_warms_up_using_custom_longer_window(store):
    ids = add_requests(store, 1, status=401)
    anchor = store.insert_event(make_event(600, status=401, target="/private"))
    engine = DetectionEngine({AUTH: RuleSettings(2, 600)})
    result, = findings(store, engine=engine, start=BASE + timedelta(seconds=600))
    assert result.event_ids == tuple([*ids, anchor])


def test_custom_distinct_path_threshold_is_applied(store):
    engine = DetectionEngine({ENUMERATION: RuleSettings(3, 10, 2)})
    ids = add_requests(store, 3, status=404)
    assert findings(store, engine=engine) == []
    anchor = store.insert_event(make_event(1, target="/another"))
    result, = findings(store, engine=engine)
    assert result.rule_id == ENUMERATION
    assert result.event_ids == tuple([*ids, anchor])
    assert result.distinct_path_count == 2


def test_nonmatching_anchor_does_not_reemit_prior_authentication_finding(store):
    add_requests(store, 10, status=401)
    store.insert_event(make_event(1, status=200, target="/private"))
    assert findings(store, start=BASE + timedelta(seconds=1)) == []


def test_empty_database_returns_no_findings(store):
    assert findings(store) == []


@pytest.mark.parametrize("filters", [
    {"start": BASE.replace(tzinfo=None)}, {"end": BASE.replace(tzinfo=None)},
    {"start": "2026-10-06"}, {"end": 5},
    {"start": BASE + timedelta(seconds=1), "end": BASE},
])
def test_invalid_detection_time_filters_fail_without_writes(store, filters):
    changes = store.connection.total_changes
    with pytest.raises(ValueError):
        findings(store, **filters)
    assert store.connection.total_changes == changes


@pytest.mark.parametrize("overrides", [
    {"threshold": 0}, {"threshold": -1}, {"threshold": True}, {"threshold": 1.5},
    {"window_seconds": 0}, {"window_seconds": -1}, {"window_seconds": 86401},
    {"window_seconds": True}, {"window_seconds": "300"},
    {"min_distinct_paths": 0}, {"min_distinct_paths": 11},
    {"min_distinct_paths": True}, {"min_distinct_paths": 1.5},
])
def test_invalid_rule_settings_are_rejected(overrides):
    with pytest.raises(ValueError):
        RuleSettings(**{"threshold": 10, "window_seconds": 300, **overrides})


@pytest.mark.parametrize("settings", [
    {"unknown": RuleSettings(1, 1)}, {AUTH: {"threshold": 1, "window_seconds": 1}},
    {AUTH: RuleSettings(2, 300, 2)}, {HTTP_ERRORS: RuleSettings(2, 300, 2)},
    {BURST: RuleSettings(2, 60, 2)},
])
def test_invalid_engine_overrides_are_rejected(settings):
    with pytest.raises(ValueError):
        DetectionEngine(settings)


def test_synthetic_file_can_be_imported_and_reviewed_for_all_four_rule_types(store, tmp_path):
    events = []
    for ip_suffix, (rule_id, threshold, _, status) in enumerate(CASES, start=30):
        ip = f"192.0.2.{ip_suffix}"
        for index in range(threshold):
            target = f"/missing-{index % 5}" if rule_id == ENUMERATION else "/private"
            events.append(make_event(index % 10, status=status, target=target, ip=ip))
    events.extend(make_event(index, status=200, ip="192.0.2.34") for index in range(20))
    path = tmp_path / "behavioral-access.txt"
    path.write_text("\n".join(event.raw_log for event in reversed(events)), encoding="utf-8")

    summary = ingest_file(path, "access", store)
    results = findings(store)

    assert summary.imported_events == 180
    assert {item.rule_id for item in results} == {ENUMERATION, HTTP_ERRORS, AUTH, BURST}
    assert len(results) == 4
    assert store.count_alerts() == 0
    for result in results:
        evidence = [store.get_event(event_id).event for event_id in result.event_ids]
        assert all(event.source_file == str(path.resolve()) for event in evidence)
        assert all(event.line_number > 0 for event in evidence)
        assert {event.source_ip for event in evidence} == {result.source_ip}
