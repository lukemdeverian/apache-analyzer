import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app import create_app
from app.alerts import ALERT_STATUSES, SEVERITIES, Alert
from app.database import connect_database, initialize_database, transaction
from app.detection import DetectionEngine
from app.parsers import parse_access_line, parse_error_line
from app.pipeline import analyze_file, detect_events
from app.storage import SQLiteStore

BASE = datetime(2026, 10, 6, 9, tzinfo=timezone.utc)
IP = "192.0.2.10"
V6 = "2001:db8::1"


def stamp(seconds=0):
    return (BASE + timedelta(seconds=seconds)).isoformat(timespec="microseconds").replace("+00:00", "Z")


@pytest.fixture
def api_store(tmp_path):
    path = tmp_path / "api.sqlite3"
    app = create_app({"TESTING": True, "DATABASE_PATH": str(path)})
    connection = connect_database(path)
    initialize_database(connection)
    store = SQLiteStore(connection)
    yield app, store
    connection.close()


@pytest.fixture
def seeded(api_store):
    app, store = api_store
    access = [
        f'{IP} - alice [06/Oct/2026:09:00:00 +0000] "GET /private HTTP/1.1" 401 23 '
        '"https://example.test/" "Synthetic browser"',
        f'{V6} - - [06/Oct/2026:09:00:01 +0000] "GET /.env HTTP/1.1" 200 -',
        f'{IP} - - [06/Oct/2026:09:00:01 +0000] '
        '"GET /../private?q=%3Cscript%3E HTTP/1.1" 403 0',
        'client.example - - [06/Oct/2026:09:00:02 +0000] "GET /static HTTP/1.1" 200 0',
    ]
    errors = [
        '[Tue Oct 06 09:00:03.123456 2026] [core:error] [pid 123:tid 0x456] '
        'AH00001: Synthetic failure <script>alert(1)</script>',
        f'[Tue Oct 06 09:00:04.000000 2026] [authz_core:error] [client {IP}:4321] '
        'AH01630: Synthetic denial',
    ]
    event_ids = [
        store.insert_event(parse_access_line(line, source_file="access.txt", line_number=index))
        for index, line in enumerate(access, 1)
    ] + [
        store.insert_event(parse_error_line(line, source_file="error.txt", line_number=index))
        for index, line in enumerate(errors, 1)
    ]
    alerts = [
        Alert(
            rule_id="APACHE-AUTH-FAILURES", title="Authentication failures", description="Synthetic auth",
            severity="high", grouping_key=f"ip:{IP}|path:/private", source_ip=IP,
            first_seen=BASE, last_seen=BASE + timedelta(seconds=1), created_at=BASE,
        ),
        Alert(
            rule_id="APACHE-SENSITIVE-FILE", title="Sensitive-file request", description="Synthetic probe",
            severity="medium", grouping_key=f"ip:{V6}", source_ip=V6, status="investigating",
            first_seen=BASE + timedelta(seconds=1), last_seen=BASE + timedelta(seconds=1), created_at=BASE,
        ),
        Alert(
            rule_id="APACHE-ERROR-BURST", title="Error burst", description="Synthetic server issue",
            severity="high", grouping_key="server:apache-errors", status="resolved",
            first_seen=BASE + timedelta(seconds=3), last_seen=BASE + timedelta(seconds=4), created_at=BASE,
        ),
    ]
    proof = [(event_ids[0], event_ids[2]), (event_ids[1],), (event_ids[4], event_ids[5])]
    alert_ids = [store.insert_alert(alert, evidence) for alert, evidence in zip(alerts, proof)]
    return app.test_client(), store, event_ids, alert_ids


def assert_error(response, status, code=None):
    assert response.status_code == status
    assert response.mimetype == "application/json"
    assert set(response.json) == {"error"}
    assert set(response.json["error"]) == {"code", "message"}
    assert response.json["error"]["message"]
    if code:
        assert response.json["error"]["code"] == code
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_event_pages_have_stable_ties_exact_totals_and_exhaustion(seeded):
    client, _, event_ids, _ = seeded
    first = client.get("/api/events?limit=2").json
    second = client.get("/api/events?limit=2&offset=2").json
    last = client.get("/api/events?limit=2&offset=4").json
    assert [item["id"] for page in (first, second, last) for item in page["items"]] == event_ids[::-1]
    assert first["pagination"] == {"limit": 2, "offset": 0, "returned": 2, "total": 6, "has_more": True}
    assert last["pagination"]["has_more"] is False
    assert client.get("/api/events?offset=6").json["items"] == []
    assert client.get("/api/events?offset=9223372036854775807").json["pagination"] == {
        "limit": 100, "offset": 2**63 - 1, "returned": 0, "total": 6, "has_more": False,
    }
    ascending = client.get("/api/events?order=asc&limit=1000").json
    assert [item["id"] for item in ascending["items"]] == event_ids


@pytest.mark.parametrize("query,positions", [
    ("source_ip=192.0.2.10", [5, 2, 0]),
    ("source_ip=2001:0db8:0000:0000:0000:0000:0000:0001", [1]),
    ("log_type=error", [5, 4]),
    ("log_type=access", [3, 2, 1, 0]),
    ("source_ip=192.0.2.10&log_type=access", [2, 0]),
    ("start=2026-10-06T09:00:01Z&end=2026-10-06T09:00:01Z", [2, 1]),
    ("start=2026-10-06T02:00:01-07:00&end=2026-10-06T09:00:01.000000Z", [2, 1]),
    ("start=2026-10-06T09:00:03.123456Z", [5, 4]),
    ("end=2026-10-06T09:00:03.123455Z", [3, 2, 1, 0]),
    ("source_ip=192.0.2.99", []),
])
def test_event_filters_are_inclusive_normalized_and_count_all_matches(seeded, query, positions):
    client, _, event_ids, _ = seeded
    response = client.get("/api/events?" + query)
    assert response.status_code == 200
    assert [item["id"] for item in response.json["items"]] == [event_ids[index] for index in positions]
    assert response.json["pagination"]["total"] == len(positions)
    limited = client.get("/api/events?" + query + "&limit=1").json
    assert limited["pagination"]["total"] == len(positions)
    assert limited["pagination"]["returned"] == min(1, len(positions))


def test_event_details_preserve_both_log_types_evidence_and_null_fields(seeded):
    client, store, event_ids, _ = seeded
    access = client.get(f"/api/events/{event_ids[0]}")
    assert access.status_code == 200
    assert access.json["item"]["raw_log"] == store.get_event(event_ids[0]).event.raw_log
    assert access.json["item"]["timestamp"] == stamp()
    assert access.json["item"]["source_file"] == "access.txt"
    assert access.json["item"]["line_number"] == 1
    assert access.json["item"]["username"] == "alice"
    assert access.json["item"]["response_bytes"] == 23
    assert access.json["item"]["user_agent"] == "Synthetic browser"
    assert access.json["item"]["message"] is None
    error = client.get(f"/api/events/{event_ids[4]}").json["item"]
    assert error["raw_log"] == store.get_event(event_ids[4]).event.raw_log
    assert error["message"] == "AH00001: Synthetic failure <script>alert(1)</script>"
    assert error["timestamp"] == "2026-10-06T09:00:03.123456Z"
    assert error["source_file"] == "error.txt" and error["line_number"] == 1
    assert error["error_code"] == "AH00001"
    assert error["thread_id"] == "0x456" and error["process_id"] == 123
    assert error["request"] is None and error["source_ip"] is None
    assert error["assumed_timezone"] == "UTC"
    hostname = client.get(f"/api/events/{event_ids[3]}").json["item"]
    assert hostname["source_host"] == "client.example" and hostname["source_ip"] is None
    probe = client.get(f"/api/events/{event_ids[2]}").json["item"]
    assert probe["path"] == "/../private" and probe["query_string"] == "q=%3Cscript%3E"
    assert access.headers["Cache-Control"] == "no-store"
    assert access.headers["X-Content-Type-Options"] == "nosniff"
    assert "Access-Control-Allow-Origin" not in access.headers


@pytest.mark.parametrize("query,positions", [
    ("", [2, 1, 0]),
    ("order=asc", [0, 1, 2]),
    ("source_ip=192.0.2.10", [0]),
    ("source_ip=2001:0db8:0:0:0:0:0:1", [1]),
    ("rule_id=APACHE-SENSITIVE-FILE", [1]),
    ("severity=high", [2, 0]),
    ("status=investigating", [1]),
    ("status=resolved", [2]),
    ("status=new&severity=high&source_ip=192.0.2.10", [0]),
    ("start=2026-10-06T09:00:01Z&end=2026-10-06T09:00:01Z", [1]),
    ("end=2026-10-06T09:00:00Z", [0]),
    ("rule_id=UNRECOGNIZED-HISTORICAL-RULE", []),
    ("rule_id=' OR 1=1 --", []),
    ("severity=critical", []),
])
def test_alert_filters_and_pagination_use_first_seen(seeded, query, positions):
    client, _, _, alert_ids = seeded
    response = client.get("/api/alerts?" + query)
    assert response.status_code == 200
    assert [item["id"] for item in response.json["items"]] == [alert_ids[index] for index in positions]
    assert response.json["pagination"]["total"] == len(positions)
    paged = client.get("/api/alerts?" + query + "&limit=1&offset=1").json
    assert paged["pagination"]["total"] == len(positions)
    assert [item["id"] for item in paged["items"]] == [alert_ids[index] for index in positions[1:2]]


def test_alert_details_and_chronological_evidence_have_bounded_pages(seeded):
    client, _, event_ids, alert_ids = seeded
    detail = client.get(f"/api/alerts/{alert_ids[0]}").json
    assert detail["requested_id"] == alert_ids[0]
    assert detail["item"]["id"] == alert_ids[0] and detail["item"]["event_count"] == 2
    assert detail["item"]["first_seen"] == stamp() and detail["item"]["last_seen"] == stamp(1)
    assert detail["item"]["created_at"] == stamp()
    assert detail["item"]["status"] == "new"
    first = client.get(f"/api/alerts/{alert_ids[0]}/events?limit=1").json
    second = client.get(f"/api/alerts/{alert_ids[0]}/events?limit=1&offset=1").json
    assert first["alert_id"] == first["requested_id"] == alert_ids[0]
    assert [first["items"][0]["id"], second["items"][0]["id"]] == [event_ids[0], event_ids[2]]
    assert first["pagination"]["total"] == 2 and first["pagination"]["has_more"] is True
    assert second["pagination"]["has_more"] is False
    assert client.get(f"/api/alerts/{alert_ids[0]}/events?offset=2").json["items"] == []


@pytest.mark.parametrize("status", ALERT_STATUSES)
def test_status_patch_persists_and_preserves_all_detection_fields(seeded, status):
    client, store, event_ids, alert_ids = seeded
    original = store.get_alert(alert_ids[0])
    response = client.patch(f"/api/alerts/{alert_ids[0]}/status", json={"status": status})
    assert response.status_code == 200
    assert response.json["item"]["status"] == status
    assert response.json["item"]["id"] == response.json["requested_id"] == alert_ids[0]
    assert store.get_alert(alert_ids[0]) == replace(original, alert=replace(original.alert, status=status))
    assert [item.id for item in store.get_alert_events(alert_ids[0])] == [event_ids[0], event_ids[2]]
    assert client.get(f"/api/alerts/{alert_ids[0]}").json["item"]["status"] == status
    again = client.patch(f"/api/alerts/{alert_ids[0]}/status", json={"status": status})
    assert again.json == response.json
    assert store.count_alerts() == 3


def test_stats_cover_all_rows_with_zero_categories_and_separate_date_semantics(seeded):
    client, _, _, _ = seeded
    stats = client.get("/api/stats").json
    assert stats["events"] == {
        "total": 6, "distinct_source_ips": 2, "by_log_type": {"access": 4, "error": 2},
        "first_seen": stamp(), "last_seen": stamp(4),
    }
    assert stats["alerts"] == {
        "total": 3, "open": 2, "first_seen": stamp(), "last_seen": stamp(4),
        "by_status": {"new": 1, "investigating": 1, "resolved": 1, "false_positive": 0},
        "by_severity": {"low": 0, "medium": 1, "high": 2, "critical": 0},
        "by_rule_id": {"APACHE-AUTH-FAILURES": 1, "APACHE-SENSITIVE-FILE": 1, "APACHE-ERROR-BURST": 1},
    }
    source = client.get("/api/stats?source_ip=192.0.2.10").json
    assert source["events"]["total"] == 3 and source["events"]["distinct_source_ips"] == 1
    assert source["alerts"]["total"] == 1 and source["alerts"]["by_rule_id"] == {"APACHE-AUTH-FAILURES": 1}
    time_range = client.get("/api/stats?start=2026-10-06T09:00:01Z&end=2026-10-06T09:00:01Z").json
    assert time_range["events"]["total"] == 2 and time_range["alerts"]["total"] == 1
    assert time_range["alerts"]["by_status"]["investigating"] == 1
    assert time_range["alerts"]["last_seen"] == stamp(1)
    none = client.get("/api/stats?source_ip=192.0.2.99").json
    assert none["events"]["total"] == none["alerts"]["total"] == 0
    assert none["events"]["first_seen"] is None and none["alerts"]["last_seen"] is None


def test_stats_and_evidence_do_not_stop_at_the_storage_page_limit(api_store):
    app, store = api_store
    event = parse_access_line(f'{IP} - - [06/Oct/2026:09:00:00 +0000] "GET /.env HTTP/1.1" 200 0')
    alert = Alert(
        rule_id="APACHE-SENSITIVE-FILE", title="Sensitive-file request", description="Synthetic evidence",
        severity="medium", grouping_key=f"ip:{IP}", source_ip=IP,
        first_seen=BASE, last_seen=BASE, created_at=BASE,
    )
    with transaction(store.connection):
        event_ids = [store.insert_event(event) for _ in range(1005)]
        sensitive_id = store.insert_alert(alert, event_ids)
        for index in range(1004):
            store.insert_alert(
                replace(alert, status="resolved" if index % 2 else "investigating"),
                [event_ids[index]],
            )
    client = app.test_client()
    assert client.get("/api/events?limit=1").json["pagination"]["total"] == 1005
    assert client.get("/api/alerts?limit=1").json["pagination"]["total"] == 1005
    stats = client.get("/api/stats").json
    assert stats["events"]["total"] == 1005 and stats["events"]["by_log_type"]["access"] == 1005
    evidence = client.get(f"/api/alerts/{sensitive_id}/events?offset=1000&limit=1000").json
    assert [item["id"] for item in evidence["items"]] == event_ids[1000:]
    assert evidence["pagination"]["total"] == 1005 and evidence["pagination"]["has_more"] is False
    assert stats["alerts"]["total"] == 1005 and stats["alerts"]["open"] == 503
    assert stats["alerts"]["by_status"] == {
        "new": 1, "investigating": 502, "resolved": 502, "false_positive": 0,
    }
    assert stats["alerts"]["by_rule_id"] == {"APACHE-SENSITIVE-FILE": 1005}


def test_empty_database_has_empty_pages_and_defined_statistics(api_store):
    app, _ = api_store
    client = app.test_client()
    for endpoint in ("events", "alerts"):
        result = client.get("/api/" + endpoint).json
        assert result == {
            "items": [], "pagination": {"limit": 100, "offset": 0, "returned": 0, "total": 0, "has_more": False},
        }
    stats = client.get("/api/stats").json
    assert stats["events"]["total"] == stats["events"]["distinct_source_ips"] == 0
    assert stats["events"]["by_log_type"] == {"access": 0, "error": 0}
    assert stats["events"]["first_seen"] is None and stats["events"]["last_seen"] is None
    assert stats["alerts"]["total"] == stats["alerts"]["open"] == 0
    assert stats["alerts"]["by_status"] == dict.fromkeys(ALERT_STATUSES, 0)
    assert stats["alerts"]["by_severity"] == dict.fromkeys(SEVERITIES, 0)
    assert stats["alerts"]["by_rule_id"] == {}


def test_rules_describe_all_eleven_defaults_without_creating_storage(tmp_path):
    database = tmp_path / "missing" / "api.sqlite3"
    app = create_app({"TESTING": True, "DATABASE_PATH": str(database)})
    response = app.test_client().get("/api/rules")
    assert response.status_code == 200
    assert not database.parent.exists()
    catalog = response.json
    engine = DetectionEngine()
    assert catalog["configuration"] == "defaults"
    assert catalog["allowed_methods"] == sorted(engine.allowed_methods)
    assert catalog["request_correlation_seconds"] == 300
    items = {item["rule_id"]: item for item in catalog["items"]}
    assert set(items) == {rule.rule_id for rule in engine.rules}
    assert len(items) == 11
    assert items["APACHE-PATH-ENUMERATION"]["settings"] == {
        "threshold": 10, "window_seconds": 300, "min_distinct_paths": 5,
    }
    assert items["APACHE-AUTH-FAILURES"]["grouping"] == "source_ip_and_path"
    assert items["APACHE-ERROR-BURST"]["log_type"] == "error"
    assert items["APACHE-ERROR-BURST"]["levels"] == ["error", "crit", "alert", "emerg"]
    assert items["APACHE-SERVER-ERRORS"]["grouping"] == "server"
    assert items["APACHE-SERVER-ERRORS"]["status_codes"] == list(range(500, 600))
    assert items["APACHE-XSS"]["settings"] is None and items["APACHE-XSS"]["kind"] == "request"
    assert all("matcher" not in item for item in items.values())


@pytest.mark.parametrize("endpoint", ["events", "alerts"])
@pytest.mark.parametrize("query", [
    "limit=0", "limit=1001", "limit=-1", "limit=1.5", "limit=true", "limit=",
    "offset=-1", "offset=9223372036854775808", "offset=1e3", "offset=١",
    "limit=" + "9" * 5000, "order=random", "order=DESC",
    "source_ip=", "source_ip=example.test", "source_ip=192.0.2.1:80",
    "source_ip=2001:db8::1%25zone", "source_ip=' OR 1=1 --",
    "start=2026-10-06", "start=2026-10-06T09:00:00", "end=",
    "end=2026-02-30T09:00:00Z", "start=2026-10-06T09:00:00+24:00",
    "end=2026-10-06T09:00:00%2B00:60", "start=0001-01-01T00:00:00%2B01:00",
    "start=2026-10-06T09:00:00.1234567Z",
    "start=2026-10-07T09:00:00Z&end=2026-10-06T09:00:00Z",
    "limit=1&limit=2", "source_ip=192.0.2.10&source_ip=192.0.2.99",
    "unknown=value", "limit=10&unknown=value",
])
def test_invalid_common_query_parameters_fail_before_database_access(tmp_path, endpoint, query):
    path = tmp_path / "absent" / "api.sqlite3"
    app = create_app({"TESTING": True, "DATABASE_PATH": str(path)})
    assert_error(app.test_client().get(f"/api/{endpoint}?{query}"), 400, "invalid_request")
    assert not path.parent.exists()


@pytest.mark.parametrize("endpoint,query", [
    ("events", "log_type=ssh"), ("events", "log_type="), ("events", "status=new"),
    ("alerts", "severity=urgent"), ("alerts", "status=closed"), ("alerts", "log_type=access"),
    ("alerts", "rule_id="), ("alerts", "rule_id=%20"), ("alerts", "rule_id=" + "x" * 129),
    ("stats", "limit=10"), ("stats", "source_ip=hostname"), ("stats", "start=invalid"),
    ("rules", "limit=10"), ("rules", "unknown=1"),
    ("events/1", "limit=10"), ("alerts/1", "status=new"),
    ("alerts/1/events", "order=desc"), ("alerts/1/events", "source_ip=192.0.2.10"),
    ("alerts/1/events", "offset=-1"), ("alerts/1/events", "limit=1001"),
])
def test_endpoint_specific_query_validation(api_store, endpoint, query):
    app, _ = api_store
    assert_error(app.test_client().get(f"/api/{endpoint}?{query}"), 400, "invalid_request")


@pytest.mark.parametrize("identity", ["0", "-1", "abc", "1.2", "9223372036854775808", "9" * 5000])
@pytest.mark.parametrize("endpoint", ["events/{id}", "alerts/{id}", "alerts/{id}/events"])
def test_invalid_identity_never_reaches_sqlite(api_store, endpoint, identity):
    app, _ = api_store
    assert_error(app.test_client().get("/api/" + endpoint.format(id=identity)), 400, "invalid_request")


@pytest.mark.parametrize("body", [
    {}, [], None, "resolved", 1, True,
    {"status": None}, {"status": False}, {"status": []}, {"status": {}},
    {"status": "closed"}, {"status": "Resolved"}, {"status": ""},
    {"status": "resolved", "severity": "critical"}, {"other": "resolved"},
])
def test_invalid_status_body_leaves_alert_unchanged(seeded, body):
    client, store, _, alert_ids = seeded
    original = store.get_alert(alert_ids[0])
    response = client.patch(f"/api/alerts/{alert_ids[0]}/status", data=client.application.json.dumps(body),
                            content_type="application/json")
    assert_error(response, 400, "invalid_request")
    assert store.get_alert(alert_ids[0]) == original


@pytest.mark.parametrize("body,content_type,status", [
    ('{"status":', "application/json", 400),
    ('', "application/json", 400),
    ('{"status":"resolved"}', "text/plain", 415),
    ('status=resolved', "application/x-www-form-urlencoded", 415),
    ('{"status":"resolved"}', None, 415),
    ('{"status":"resolved","padding":"' + "x" * 1100 + '"}', "application/json", 413),
])
def test_status_patch_requires_small_valid_json(seeded, body, content_type, status):
    client, store, _, alert_ids = seeded
    before = store.get_alert(alert_ids[0])
    response = client.patch(f"/api/alerts/{alert_ids[0]}/status", data=body, content_type=content_type)
    assert_error(response, status)
    assert store.get_alert(alert_ids[0]) == before


def test_status_query_and_id_validation_precede_writes(seeded):
    client, store, _, alert_ids = seeded
    before = store.get_alert(alert_ids[0])
    assert_error(client.patch(f"/api/alerts/{alert_ids[0]}/status?status=resolved",
                              json={"status": "resolved"}), 400)
    assert_error(client.patch("/api/alerts/9223372036854775808/status", json={"status": "resolved"}), 400)
    assert store.get_alert(alert_ids[0]) == before


@pytest.mark.parametrize("endpoint", ["events/999", "alerts/999", "alerts/999/events",
                                     "events/9223372036854775807", "alerts/9223372036854775807"])
def test_missing_records_are_json_404(api_store, endpoint):
    app, _ = api_store
    assert_error(app.test_client().get("/api/" + endpoint), 404, "not_found")


def test_missing_status_target_is_json_404(api_store):
    app, _ = api_store
    assert_error(app.test_client().patch("/api/alerts/999/status", json={"status": "resolved"}),
                 404, "not_found")


def test_routing_errors_preserve_http_headers_and_do_not_change_other_routes(api_store):
    app, _ = api_store
    client = app.test_client()
    assert_error(client.get("/api/missing"), 404, "not_found")
    assert_error(client.get("/api"), 404, "not_found")
    wrong_method = client.post("/api/events", json={})
    assert_error(wrong_method, 405, "method_not_allowed")
    assert "GET" in wrong_method.headers["Allow"] and "HEAD" in wrong_method.headers["Allow"]
    assert_error(client.get("/api/alerts/1/status"), 405)
    assert client.get("/unrelated").mimetype == "text/html"
    assert client.get("/api-other").mimetype == "text/html"
    assert client.get("/health").json == {"service": "apache-analyzer", "status": "ok"}
    assert client.head("/api/events").status_code == 200


@pytest.mark.parametrize("endpoint", ["events", "events/1", "alerts", "alerts/1", "alerts/1/events", "stats"])
def test_uninitialized_database_has_actionable_json_error(tmp_path, endpoint):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "uninitialized.sqlite3")})
    response = app.test_client().get("/api/" + endpoint)
    assert_error(response, 503, "database_not_ready")
    assert "flask --app app init-db" in response.json["error"]["message"]
    assert str(tmp_path) not in response.get_data(as_text=True)


def test_sqlite_failure_does_not_expose_database_details_and_patch_rolls_back(seeded):
    client, store, _, alert_ids = seeded
    before = store.get_alert(alert_ids[0])
    store.connection.execute(
        "CREATE TRIGGER fail_status AFTER UPDATE OF status ON alerts "
        "BEGIN SELECT RAISE(ABORT, 'private database implementation detail'); END"
    )
    response = client.patch(f"/api/alerts/{alert_ids[0]}/status", json={"status": "resolved"})
    assert_error(response, 503, "database_unavailable")
    assert "private database" not in response.get_data(as_text=True)
    assert store.get_alert(alert_ids[0]) == before
    store.connection.execute("DROP TRIGGER fail_status")
    assert client.patch(f"/api/alerts/{alert_ids[0]}/status", json={"status": "resolved"}).status_code == 200


def test_api_transaction_rolls_back_a_write_followed_by_failure(seeded, monkeypatch):
    client, store, _, alert_ids = seeded
    original = store.get_alert(alert_ids[0])

    def fail_after_write(self, identity, status):
        self.connection.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, identity))
        raise sqlite3.OperationalError("Synthetic failure after writing")

    monkeypatch.setattr(SQLiteStore, "set_alert_status", fail_after_write)
    assert_error(client.patch(f"/api/alerts/{alert_ids[0]}/status", json={"status": "resolved"}),
                 503, "database_unavailable")
    assert store.get_alert(alert_ids[0]) == original


def test_version_one_is_not_automatically_upgraded_by_investigation_requests(seeded):
    client, store, _, alert_ids = seeded
    original = store.get_alert(alert_ids[0])
    store.connection.execute("DROP TABLE alert_merges")
    store.connection.execute("PRAGMA user_version = 1")
    assert_error(client.get("/api/alerts"), 503, "database_not_ready")
    assert store.connection.execute("PRAGMA user_version").fetchone()[0] == 1
    assert client.get("/api/rules").status_code == client.get("/health").status_code == 200
    result = client.application.test_cli_runner().invoke(args=["init-db"])
    assert result.exit_code == 0
    assert client.get("/api/alerts").status_code == 200
    assert store.get_alert(alert_ids[0]) == original


def test_investigation_reads_do_not_change_persisted_evidence_or_alerts(seeded):
    client, store, event_ids, alert_ids = seeded
    before = list(store.connection.iterdump())
    for endpoint in (
        "/api/events", f"/api/events/{event_ids[0]}", "/api/alerts",
        f"/api/alerts/{alert_ids[0]}", f"/api/alerts/{alert_ids[0]}/events", "/api/stats", "/api/rules",
    ):
        assert client.get(endpoint).status_code == 200
    assert list(store.connection.iterdump()) == before


def test_database_connection_failure_is_json_without_private_path(tmp_path):
    # A directory cannot be opened as a SQLite database.
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path)})
    response = app.test_client().get("/api/stats")
    assert_error(response, 503, "database_unavailable")
    assert str(tmp_path) not in response.get_data(as_text=True)


def test_import_merge_evidence_and_status_are_available_through_old_id(api_store, tmp_path):
    app, store = api_store
    first = tmp_path / "first.txt"
    later = tmp_path / "later.txt"
    bridge = tmp_path / "bridge.txt"
    for path, minute in ((first, "00"), (later, "10"), (bridge, "05")):
        path.write_text(
            f'{IP} - - [06/Oct/2026:09:{minute}:00 +0000] "GET /.env HTTP/1.1" 404 0\n',
            encoding="utf-8",
        )
        analyze_file(path, "access", store)
    alias = store.connection.execute("SELECT former_id, alert_id FROM alert_merges").fetchone()
    former, canonical = alias
    assert store.count_alerts() == 1
    client = app.test_client()
    detail = client.get(f"/api/alerts/{former}").json
    assert detail["requested_id"] == former and detail["item"]["id"] == canonical
    assert detail["item"]["event_count"] == 3
    evidence = client.get(f"/api/alerts/{former}/events").json
    assert evidence["alert_id"] == canonical and evidence["requested_id"] == former
    assert [item["source_file"] for item in evidence["items"]] == [
        str(first.resolve()), str(bridge.resolve()), str(later.resolve()),
    ]
    assert all(item["line_number"] == 1 for item in evidence["items"])
    updated = client.patch(f"/api/alerts/{former}/status", json={"status": "false_positive"})
    assert updated.status_code == 200
    assert updated.json["requested_id"] == former and updated.json["item"]["id"] == canonical
    assert store.get_alert(canonical).alert.status == "false_positive"
    assert client.get("/api/alerts").json["pagination"]["total"] == 1
    assert client.get("/api/stats").json["alerts"]["by_status"]["false_positive"] == 1
    before = store.connection.total_changes
    assert detect_events(store).findings_unchanged == 3
    assert store.connection.total_changes == before
