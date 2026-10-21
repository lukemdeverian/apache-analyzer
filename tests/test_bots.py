from dataclasses import replace
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

import pytest

from app import create_app
from app.alerts import Alert
from app.bots import assess_bots
from app.database import connect_database, initialize_database
from app.parsers import access_extensions, parse_access_line
from app.pipeline import detect_events
from app.storage import SQLiteStore

BASE = datetime(2026, 10, 21, 9, tzinfo=timezone.utc)
IP = "192.0.2.10"


@pytest.fixture
def workspace(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "bots.sqlite3")})
    connection = connect_database(app.config["DATABASE_PATH"])
    initialize_database(connection)
    yield app.test_client(), SQLiteStore(connection)
    connection.close()


def event(target="/", *, ip=IP, status=200, seconds=0, method="GET", extensions="", combined=True):
    stamp = BASE + timedelta(seconds=seconds)
    line = f'{ip} - - [{stamp:%d/%b/%Y:%H:%M:%S} +0000] "{method} {target} HTTP/1.1" {status} 128'
    if combined:
        line += ' "-" "Synthetic browser"' + extensions
    result = parse_access_line(line, source_file="synthetic-bots.log", line_number=seconds + 1)
    assert result is not None
    return result


def assessment(store, **filters):
    items, summary = assess_bots(store, **filters)
    assert summary["total"] == len(items)
    return items[0]


@pytest.mark.parametrize("target", ["/", "/?campaign=test", "/checkout", "/checkout/", "/checkout?cart=1",
                                         "https://chronoscrate.xyz/", "https://chronoscrate.xyz/checkout"])
def test_successful_known_page_is_not_bot_without_risk(workspace, target):
    _, store = workspace
    identity = store.insert_event(event(target))
    result = assessment(store)
    assert result["classification"] == "not_a_bot" and result["recommendation"] == "allow_and_monitor"
    assert result["home_requests"] + result["checkout_requests"] == 1
    assert any(proof["event_id"] == identity for proof in result["browsing_evidence"])
    assert result["language_logged_requests"] == 0


@pytest.mark.parametrize("target,status,method", [
    ("/checkout/admin", 200, "GET"), ("/CHECKOUT", 200, "GET"), ("/checkout", 404, "GET"),
    ("/", 500, "GET"), ("/", 301, "GET"), ("/", 200, "POST"), ("/", 200, "HEAD"),
    ("https://other.example/checkout", 200, "GET"), ("https://chronoscrate.xyz.attacker.example/", 200, "GET"),
    ("https://user@chronoscrate.xyz/", 200, "GET"), ("https://chronoscrate.xyz:99999/", 200, "GET"),
    ("/%63heckout", 200, "GET"), ("*", 200, "OPTIONS"),
])
def test_other_targets_failed_or_non_get_requests_are_not_positive(workspace, target, status, method):
    _, store = workspace
    store.insert_event(event(target, status=status, method=method))
    result = assessment(store)
    assert result["classification"] == "suspected_bot"
    assert result["recommendation"] == "monitor_or_challenge"


@pytest.mark.parametrize("language", ["en-US,en;q=0.9", "fr-FR", "zh-CN", "ar", "pt-BR", "de;q=0.2"])
def test_language_and_html_css_sequence_counts_equally_for_all_languages(workspace, language):
    _, store = workspace
    for item in [
        event("/about.html", extensions=f' lang:"{language}"'),
        event("/static/main.css?v=1", seconds=300, status=304),
    ]:
        store.insert_event(item)
    result = assessment(store)
    assert result["classification"] == "not_a_bot"
    assert result["browser_asset_sequence"] and result["home_requests"] == result["checkout_requests"] == 0
    assert result["language_requests"] == 1 and result["html_requests"] == result["css_requests"] == 1


@pytest.mark.parametrize("extensions", [
    "", ' lang:"-"', ' lang:""', ' lang:"*"', ' lang:"en;q=0"', ' lang:"nonsense!!!"',
    ' lang:"<script>DEMO</script>"', ' lang:"en" lang:"fr"', ' lang:"en" accept-language:"fr"',
])
def test_missing_or_ambiguous_language_does_not_complete_browsing_sequence(workspace, extensions):
    _, store = workspace
    store.insert_event(event("/about.html", extensions=extensions))
    store.insert_event(event("/style.css", seconds=1))
    assert assessment(store)["classification"] == "suspected_bot"


@pytest.mark.parametrize("language_name", ["lang", "accept-language", "accept_language", "LANG"])
def test_language_field_aliases_are_supported_from_existing_raw_logs(workspace, language_name):
    _, store = workspace
    store.insert_event(event("/about", extensions=f' {language_name}:"en-US" sfd:"document"'))
    store.insert_event(event("/assets/theme", seconds=1, extensions=' sfd:"style"'))
    assert assessment(store)["classification"] == "not_a_bot"


def test_old_asset_fetches_do_not_complete_sequence_and_proof_matches_actual_window(workspace):
    _, store = workspace
    store.insert_event(event("/old.html", extensions=' lang:"en"'))
    store.insert_event(event("/old.css", seconds=301))
    assert assessment(store)["classification"] == "suspected_bot"
    identities = [
        store.insert_event(event("/current.html", seconds=1000, extensions=' lang:"en"')),
        store.insert_event(event("/current.css", seconds=1001)),
    ]
    result = assessment(store)
    assert result["classification"] == "not_a_bot"
    proof = {record["signal"]: record["event_id"] for record in result["browsing_evidence"]}
    assert proof["html"] == proof["language"] == identities[0] and proof["css"] == identities[1]


@pytest.mark.parametrize("status", ["new", "investigating", "resolved"])
def test_every_ip_risk_alert_overrides_normal_browsing_even_when_resolved(workspace, status):
    client, store = workspace
    store.insert_event(event("/"))
    store.insert_event(event("/checkout", seconds=1))
    store.insert_event(event("/.env", seconds=2))
    detect_events(store)
    alert, = store.list_alerts()
    store.set_alert_status(alert.id, status)
    result = assessment(store)
    assert result["classification"] == "confirmed_bot" and result["risk_alert_count"] == 1
    assert result["recommendation"] == "review_for_block"
    assert result["home_requests"] == result["checkout_requests"] == 1
    assert result["risk_alerts"][0]["rule_id"] == "APACHE-SENSITIVE-FILE"
    assert client.get("/api/bots/export").text == IP + "\n"


def test_false_positive_status_immediately_changes_assessment_and_export(workspace):
    client, store = workspace
    store.insert_event(event("/"))
    store.insert_event(event("/.env", seconds=1))
    detect_events(store)
    alert, = store.list_alerts()
    assert client.get("/api/bots").json["items"][0]["classification"] == "confirmed_bot"
    assert client.patch(f"/api/alerts/{alert.id}/status", json={"status": "false_positive"}).status_code == 200
    result = client.get("/api/bots").json["items"][0]
    assert result["classification"] == "not_a_bot" and result["risk_alert_count"] == 0
    assert client.get("/api/bots/export").text == ""
    store.set_alert_status(alert.id, "new")
    assert assessment(store)["classification"] == "confirmed_bot"


def test_global_server_alert_does_not_assign_individual_blame(workspace):
    client, store = workspace
    store.insert_event(event("/"))
    for seconds in range(20):
        store.insert_event(event("/status", status=503, seconds=seconds + 1))
    detect_events(store)
    alert, = store.list_alerts()
    assert alert.alert.rule_id == "APACHE-SERVER-ERRORS" and alert.alert.source_ip is None
    assert assessment(store)["classification"] == "not_a_bot"
    assert client.get("/api/bots/export").text == ""


def test_date_filters_use_linked_evidence_not_alert_first_seen(workspace):
    client, store = workspace
    for seconds in (0, 100):
        store.insert_event(event("/.env", seconds=seconds))
    detect_events(store)
    alert, = store.list_alerts()
    assert alert.event_count == 2
    result = client.get("/api/bots?start=2026-10-21T09:01:40Z&end=2026-10-21T09:01:40Z")
    assert result.status_code == 200
    item, = result.json["items"]
    assert item["classification"] == "confirmed_bot" and item["request_count"] == 1
    assert item["risk_alerts"][0]["evidence_count"] == 1
    assert item["risk_alerts"][0]["event_id"] == 2
    assert client.get("/api/bots?start=2026-10-21T10:00:00Z").json["items"] == []


def test_ip_aggregation_does_not_mix_language_and_assets_from_other_clients(workspace):
    _, store = workspace
    store.insert_event(event("/about.html", extensions=' lang:"en"'))
    store.insert_event(event("/style.css", ip="192.0.2.11", seconds=1))
    items, summary = assess_bots(store)
    assert summary["by_classification"]["suspected_bot"] == 2
    assert all(item["classification"] == "suspected_bot" for item in items)


def test_unattributed_requests_are_counted_without_an_exportable_address(workspace):
    client, store = workspace
    store.insert_event(event("/", ip="client.example"))
    data = client.get("/api/bots").json
    assert data["items"] == [] and data["summary"]["unattributed_requests"] == 1
    assert client.get("/api/bots/export").text == ""


def test_pagination_filters_summaries_canonical_ipv6_and_export_are_consistent(workspace):
    client, store = workspace
    for number in range(1, 31):
        store.insert_event(event("/.env", ip=f"192.0.2.{number}", seconds=number))
    store.insert_event(event("/", ip="2001:0db8:0:0::1", seconds=31))
    store.insert_event(event("/unknown", ip="198.51.100.1", seconds=32))
    detect_events(store)
    first = client.get("/api/bots?limit=7").json
    assert first["pagination"]["total"] == 32 and first["pagination"]["has_more"]
    assert len(first["items"]) == 7 and all(item["classification"] == "confirmed_bot" for item in first["items"])
    all_addresses = []
    for offset in range(0, 32, 7):
        all_addresses += [item["source_ip"] for item in client.get(f"/api/bots?limit=7&offset={offset}").json["items"]]
    assert len(set(all_addresses)) == 32
    normal = client.get("/api/bots?classification=not_a_bot&source_ip=2001:0db8::1").json
    assert normal["items"][0]["source_ip"] == "2001:db8::1"
    assert normal["summary"]["total"] == normal["pagination"]["total"] == 1
    filtered = client.get("/api/bots?classification=suspected_bot").json
    assert filtered["pagination"]["total"] == 1 and filtered["summary"]["total"] == 32
    exported = client.get("/api/bots/export")
    assert exported.mimetype == "text/plain" and "ban-candidates.txt" in exported.headers["Content-Disposition"]
    assert exported.headers["Cache-Control"] == "no-store"
    assert exported.text.splitlines() == [f"192.0.2.{number}" for number in range(1, 31)]
    assert all(ip_address(address) for address in exported.text.splitlines())


def test_risk_evidence_samples_are_bounded_but_total_is_not_page_limited(workspace):
    client, store = workspace
    identity = store.insert_event(event("/.env"))
    for number in range(15):
        store.insert_alert(Alert(
            rule_id=f"SYNTHETIC-{number}", title="Synthetic risk", description="Synthetic",
            severity="low", grouping_key=f"ip:{IP}|test:{number}", source_ip=IP,
            first_seen=BASE, last_seen=BASE,
        ), [identity])
    item, = client.get("/api/bots?limit=1").json["items"]
    assert item["risk_alert_count"] == 15 and len(item["risk_alerts"]) == 10
    assert item["classification"] == "confirmed_bot"


@pytest.mark.parametrize("path", [
    "/api/bots?classification=human", "/api/bots?classification=confirmed_bot&classification=not_a_bot",
    "/api/bots?source_ip=hostname", "/api/bots?limit=0", "/api/bots?offset=-1",
    "/api/bots?order=random", "/api/bots?unknown=1",
    "/api/bots?start=2026-10-22T00:00:00Z&end=2026-10-21T00:00:00Z",
    "/api/bots/export?classification=suspected_bot", "/api/bots/export?source_ip=bad",
])
def test_bot_api_rejects_invalid_queries(workspace, path):
    client, _ = workspace
    response = client.get(path)
    assert response.status_code == 400 and response.json["error"]["code"] == "invalid_request"


def test_bot_endpoints_require_initialization_without_creating_data(tmp_path):
    path = tmp_path / "uninitialized.sqlite3"
    client = create_app({"TESTING": True, "DATABASE_PATH": str(path)}).test_client()
    for endpoint in ("/api/bots", "/api/bots/export"):
        response = client.get(endpoint)
        assert response.status_code == 503 and response.json["error"]["code"] == "database_not_ready"


def test_named_field_reader_handles_escaping_bom_and_duplicates_without_modifying_evidence():
    record = event(extensions=r' LANG:"en-US" chua:"\"Browser\"" lang:"fr" note:"literal\\value"')
    original = record.raw_log
    fields = access_extensions("\ufeff" + original)
    assert "lang" not in fields and fields["chua"] == '"Browser"'
    assert fields["note"] == r"literal\value"
    assert record.raw_log == original
    assert access_extensions("unrelated lang:en") == {}
