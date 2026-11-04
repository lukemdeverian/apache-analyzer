"""Domain selection, legacy compatibility, isolation, and study comparisons."""

import gzip
import io
import sqlite3
from pathlib import Path

import pytest
from werkzeug.datastructures import MultiDict

from app import create_app
from app.database import connect_database, domain_database_path, get_database, initialize_database
from app.domains import DOMAINS, get_domain
from app.parsers import parse_access_line
from app.pipeline import detect_events
from app.storage import SQLiteStore

PRIMARY, SECONDARY = "chronoscrate", "la_jolla_seals"
IP = "192.0.2.10"
HEADERS = {"X-Apache-Upload": "1"}


def access(path="/theme.css", *, seconds=0, status=200, ip=IP):
    return (
        f'{ip} - - [06/Oct/2026:09:00:{seconds:02} +0000] '
        f'"GET {path} HTTP/1.1" {status} 123 "-" "Synthetic browser"\n'
    ).encode()


def upload(client, domain_id, content=None, *, log_type="access", filename="shared.log"):
    data = {
        "file": (io.BytesIO(access() if content is None else content), filename),
        "domain_id": domain_id, "log_type": log_type,
    }
    return client.post("/api/imports", data=data, headers=HEADERS)


def scoped(path, domain_id):
    return path + ("&" if "?" in path else "?") + "domain_id=" + domain_id


@pytest.fixture
def workspace(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "events.sqlite3")})
    app.instance_path = str(tmp_path / "instance")
    initialized = app.test_cli_runner().invoke(args=["init-db"])
    assert initialized.exit_code == 0, initialized.output
    with app.app_context():
        paths = {domain.id: domain_database_path(domain.id) for domain in DOMAINS}
    connections = {domain_id: connect_database(path) for domain_id, path in paths.items()}
    stores = {domain_id: SQLiteStore(connection) for domain_id, connection in connections.items()}
    yield app, stores
    for connection in connections.values():
        connection.close()


def test_catalog_and_dashboard_do_not_open_or_initialize_databases(tmp_path):
    database = tmp_path / "missing" / "events.sqlite3"
    client = create_app({"TESTING": True, "DATABASE_PATH": str(database)}).test_client()
    response = client.get("/api/domains")
    assert response.status_code == 200
    assert response.json["default_domain_id"] == PRIMARY
    assert response.json["items"] == [domain.as_dict() for domain in DOMAINS]
    assert response.json["items"][1]["hostname"] == "protectlajollaseals.xyz"
    html = client.get("/").text
    assert 'id="upload-domain" name="domain_id" required' in html
    assert "Dynadot" in html and "Namecheap" in html
    assert not database.parent.exists()


@pytest.mark.parametrize("domain_id", [None, "", "unknown", "La Jolla Seals", "../../outside"])
def test_upload_requires_known_explicit_domain_before_database_access(tmp_path, domain_id):
    database = tmp_path / "missing" / "events.sqlite3"
    app = create_app({"TESTING": True, "DATABASE_PATH": str(database)})
    app.instance_path = str(tmp_path / "instance")
    data = {"file": (io.BytesIO(access()), "access.log"), "log_type": "access"}
    if domain_id is not None:
        data["domain_id"] = domain_id
    response = app.test_client().post("/api/imports", data=data, headers=HEADERS)
    assert response.status_code == 400 and response.json["error"]["code"] == "invalid_request"
    assert not database.parent.exists() and not Path(app.instance_path).exists()


def test_repeated_domain_field_is_rejected(workspace):
    app, stores = workspace
    response = app.test_client().post("/api/imports", data=MultiDict([
        ("file", (io.BytesIO(access()), "access.log")), ("log_type", "access"),
        ("domain_id", PRIMARY), ("domain_id", SECONDARY),
    ]), headers=HEADERS)
    assert response.status_code == 400
    assert all(store.count_events() == 0 for store in stores.values())


def test_same_ip_has_independent_css_classification_risk_and_ban_exports(workspace):
    app, stores = workspace
    client = app.test_client()
    primary = upload(client, PRIMARY)
    secondary = upload(client, SECONDARY, access("/.env"))
    assert primary.status_code == secondary.status_code == 201
    for response, domain_id in ((primary, PRIMARY), (secondary, SECONDARY)):
        assert response.json["summary"]["domain_id"] == domain_id
        assert response.json["summary"]["domain"] == get_domain(domain_id).as_dict()
        assert response.headers["X-Analyzer-Domain"] == domain_id
        assert stores[domain_id].count_events() == 1
    assert stores[PRIMARY].count_alerts() == 0 and stores[SECONDARY].count_alerts() == 1
    normal = client.get(scoped("/api/bots", PRIMARY)).json["items"][0]
    bot = client.get(scoped("/api/bots", SECONDARY)).json["items"][0]
    assert normal["classification"] == "not_a_bot" and bot["classification"] == "confirmed_bot"
    assert client.get(scoped("/api/bots", SECONDARY)).json["policy"]["website"] == "https://protectlajollaseals.xyz"
    assert client.get(scoped("/api/bots/export", PRIMARY)).text == ""
    assert client.get(scoped("/api/bots/export", SECONDARY)).text == IP + "\n"
    assert "ban-candidates-la_jolla_seals.txt" in client.get(
        scoped("/api/bots/export", SECONDARY)
    ).headers["Content-Disposition"]
    assert client.get(scoped("/api/events/1", PRIMARY)).json["item"]["path"] == "/theme.css"
    assert client.get(scoped("/api/events/1", SECONDARY)).json["item"]["path"] == "/.env"
    assert client.get(scoped("/api/alerts/1", PRIMARY)).status_code == 404
    proof = client.get(scoped("/api/alerts/1/events", SECONDARY)).json["items"]
    assert len(proof) == 1 and proof[0]["path"] == "/.env"
    assert proof[0]["source_file"] == secondary.json["summary"]["source_file"]


def test_false_positive_and_same_alert_id_do_not_affect_other_domain(workspace):
    app, stores = workspace
    client = app.test_client()
    for domain_id in (PRIMARY, SECONDARY):
        assert upload(client, domain_id, access() + access("/.env", seconds=1)).status_code == 201
        assert stores[domain_id].get_alert(1).event_count == 1
    response = client.patch(scoped("/api/alerts/1/status", SECONDARY), json={"status": "false_positive"})
    assert response.status_code == 200
    assert stores[SECONDARY].get_alert(1).alert.status == "false_positive"
    assert stores[PRIMARY].get_alert(1).alert.status == "new"
    assert client.get(scoped("/api/bots", PRIMARY)).json["items"][0]["classification"] == "confirmed_bot"
    assert client.get(scoped("/api/bots", SECONDARY)).json["items"][0]["classification"] == "not_a_bot"


@pytest.mark.parametrize("rule,half,status,path", [
    ("APACHE-REQUEST-BURST", 60, 200, "/news"),
    ("APACHE-SERVER-ERRORS", 10, 503, "/status"),
])
def test_detection_windows_and_server_wide_rules_never_combine_domains(workspace, rule, half, status, path):
    app, stores = workspace
    client = app.test_client()
    content = b"".join(access(path, seconds=index, status=status) for index in range(half))
    for domain_id in (PRIMARY, SECONDARY):
        assert upload(client, domain_id, content).status_code == 201
        assert stores[domain_id].count_alerts() == 0
    fresh = b"".join(access(path + "?batch=2", seconds=index, status=status) for index in range(half))
    assert upload(client, PRIMARY, fresh).status_code == 201
    alert, = stores[PRIMARY].list_alerts()
    assert alert.alert.rule_id == rule and alert.event_count == half * 2
    assert stores[SECONDARY].count_alerts() == 0
    assert stores[SECONDARY].count_events() == half


@pytest.mark.parametrize("domain_id", [PRIMARY, SECONDARY])
def test_correlation_and_replay_are_local_to_selected_domain(workspace, domain_id):
    app, stores = workspace
    client = app.test_client()
    other = SECONDARY if domain_id == PRIMARY else PRIMARY
    assert upload(client, other, access("/.env")).status_code == 201
    snapshot = list(stores[other].connection.iterdump())
    for seconds in range(2):
        assert upload(client, domain_id, access("/.env", seconds=seconds)).status_code == 201
    alert, = stores[domain_id].list_alerts()
    assert alert.event_count == 2
    result = app.test_cli_runner().invoke(args=["detect", "--domain", domain_id, "--json"])
    assert result.exit_code == 0, result.output
    assert list(stores[other].connection.iterdump()) == snapshot


@pytest.mark.parametrize("domain_id,hostname", [(PRIMARY, "chronoscrate.xyz"), (SECONDARY, "protectlajollaseals.xyz")])
def test_absolute_css_targets_must_match_selected_domain(workspace, domain_id, hostname):
    app, _ = workspace
    client = app.test_client()
    other_host = "protectlajollaseals.xyz" if domain_id == PRIMARY else "chronoscrate.xyz"
    assert upload(client, domain_id, access(f"https://{other_host}/theme.css")).status_code == 201
    assert client.get(scoped("/api/bots", domain_id)).json["items"][0]["classification"] == "suspected_bot"
    assert upload(client, domain_id, access(f"https://{hostname}/theme.css")).status_code == 201
    assert client.get(scoped("/api/bots", domain_id)).json["items"][0]["classification"] == "not_a_bot"


def test_comparison_has_counts_rates_and_supplied_provider_labels(workspace):
    app, _ = workspace
    client = app.test_client()
    assert upload(client, PRIMARY, access() + access("/", seconds=1)).status_code == 201
    assert upload(client, SECONDARY, access("/.env", seconds=30)).status_code == 201
    response = client.get("/api/domains/comparison")
    assert response.status_code == 200 and "X-Analyzer-Domain" not in response.headers
    first, second = response.json["items"]
    assert first["domain"]["provider"] == "Dynadot" and second["domain"]["provider"] == "Namecheap"
    assert first["access_requests"] == first["events"]["total"] == 2
    assert first["alerts"]["total"] == 0 and first["bots"]["by_classification"]["not_a_bot"] == 1
    assert first["alerts_per_1000_requests"] == first["confirmed_bot_ip_percent"] == 0
    assert second["access_requests"] == second["alerts"]["total"] == 1
    assert second["alerts_per_1000_requests"] == 1000
    assert second["confirmed_bot_ip_percent"] == 100
    filtered = client.get("/api/domains/comparison?end=2026-10-06T09:00:01Z&source_ip=" + IP).json["items"]
    assert filtered[0]["access_requests"] == 2 and filtered[1]["access_requests"] == 0
    assert filtered[1]["alerts_per_1000_requests"] is None
    assert filtered[1]["confirmed_bot_ip_percent"] is None
    assert "do not establish" in response.json["interpretation"]


def test_empty_comparison_does_not_invent_percentages(workspace):
    app, _ = workspace
    for item in app.test_client().get("/api/domains/comparison").json["items"]:
        assert item["access_requests"] == 0 and item["bots"]["total"] == 0
        assert item["alerts_per_1000_requests"] is item["confirmed_bot_ip_percent"] is None


@pytest.mark.parametrize("domain_id", [PRIMARY, SECONDARY])
def test_gzip_error_logs_and_invalid_upload_rollback_stay_in_domain(workspace, domain_id):
    app, stores = workspace
    client = app.test_client()
    error = b"[Tue Oct 06 09:00:00.123456 2026] [core:error] AH00001: Synthetic error\n"
    compressed = gzip.compress(error * 10, mtime=0)
    response = upload(client, domain_id, compressed, log_type="error", filename="error.log.gz")
    assert response.status_code == 201 and response.json["summary"]["domain_id"] == domain_id
    assert stores[domain_id].count_events() == 10 and stores[domain_id].count_alerts() == 1
    snapshots = {key: list(store.connection.iterdump()) for key, store in stores.items()}
    damaged = upload(client, domain_id, compressed[:-1], log_type="error")
    assert damaged.status_code == 422 and damaged.json["error"]["code"] == "invalid_gzip"
    wrong_format = upload(client, domain_id, error)
    assert wrong_format.status_code == 422 and wrong_format.json["summary"]["domain_id"] == domain_id
    assert all(list(store.connection.iterdump()) == snapshots[key] for key, store in stores.items())
    assert list((Path(app.instance_path) / "uploads").iterdir()) == []


def test_old_database_and_statuses_remain_chronoscrate_without_reimport(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    connection = connect_database(path)
    initialize_database(connection)
    store = SQLiteStore(connection)
    identity = store.insert_event(parse_access_line(access().decode()))
    store.insert_event(parse_access_line(access("/.env", seconds=1).decode()))
    detect_events(store)
    store.set_alert_status(1, "false_positive")
    before = list(connection.iterdump())
    connection.close()
    app = create_app({"TESTING": True, "DATABASE_PATH": str(path)})
    result = app.test_cli_runner().invoke(args=["init-db"])
    assert result.exit_code == 0, result.output
    connection = connect_database(path)
    try:
        assert list(connection.iterdump()) == before
    finally:
        connection.close()
    client = app.test_client()
    assert client.get("/api/events/" + str(identity)).json["item"]["path"] == "/theme.css"
    assert client.get("/api/alerts/1").json["item"]["status"] == "false_positive"
    assert client.get(scoped("/api/events", SECONDARY)).json["pagination"]["total"] == 0


def test_connections_are_independent_reused_and_closed_including_memory():
    app = create_app({"TESTING": True, "DATABASE_PATH": ":memory:"})
    with app.app_context():
        first, second = get_database(PRIMARY), get_database(SECONDARY)
        assert first is get_database(PRIMARY) and second is get_database(SECONDARY)
        assert first is not second
        for connection in (first, second):
            initialize_database(connection)
        SQLiteStore(first).insert_event(parse_access_line(access().decode()))
        assert SQLiteStore(second).count_events() == 0
    for connection in (first, second):
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")


def test_cli_selects_domain_for_import_and_analyst_status(workspace, tmp_path):
    app, stores = workspace
    source = tmp_path / "access.txt"
    source.write_bytes(access("/.env"))
    cli = app.test_cli_runner()
    imported = cli.invoke(args=["ingest", str(source), "--format", "access", "--domain", SECONDARY, "--json"])
    assert imported.exit_code == 0, imported.output
    assert '"domain_id": "la_jolla_seals"' in imported.output
    assert stores[PRIMARY].count_events() == 0 and stores[SECONDARY].count_events() == 1
    status = cli.invoke(args=["alert-status", "--domain", SECONDARY, "1", "false_positive"])
    assert status.exit_code == 0, status.output
    assert stores[SECONDARY].get_alert(1).alert.status == "false_positive"


def test_scoped_initialization_and_path_derivation_are_safe(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": "study.sqlite3"})
    app.instance_path = str(tmp_path / "instance")
    cli = app.test_cli_runner()
    result = cli.invoke(args=["init-db", "--domain", SECONDARY])
    assert result.exit_code == 0, result.output
    with app.app_context():
        assert domain_database_path(PRIMARY) == str(Path(app.instance_path) / "study.sqlite3")
        assert domain_database_path(SECONDARY) == str(Path(app.instance_path) / "study__la_jolla_seals.sqlite3")
        assert not Path(domain_database_path(PRIMARY)).exists()
        assert Path(domain_database_path(SECONDARY)).is_file()
        with pytest.raises(ValueError, match="domain_id"):
            get_database("../../outside")


@pytest.mark.parametrize("endpoint", [
    "/api/events", "/api/events/1", "/api/alerts", "/api/alerts/1",
    "/api/alerts/1/events", "/api/stats", "/api/bots", "/api/bots/export", "/api/rules",
])
def test_bad_domain_queries_are_rejected(endpoint, workspace):
    app, _ = workspace
    response = app.test_client().get(endpoint + "?domain_id=unknown")
    assert response.status_code == 400 and response.json["error"]["code"] == "invalid_request"


@pytest.mark.parametrize("query", ["domain_id=chronoscrate", "unknown=1", "start=bad", "source_ip=bad"])
def test_comparison_rejects_invalid_filters(workspace, query):
    app, _ = workspace
    response = app.test_client().get("/api/domains/comparison?" + query)
    assert response.status_code == 400


def test_uninitialized_secondary_does_not_fall_back_to_primary(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "study.sqlite3")})
    initialized = app.test_cli_runner().invoke(args=["init-db", "--domain", PRIMARY])
    assert initialized.exit_code == 0
    client = app.test_client()
    assert client.get("/api/events").status_code == 200
    response = client.get(scoped("/api/events", SECONDARY))
    assert response.status_code == 503 and response.json["error"]["code"] == "database_not_ready"
    assert client.get("/api/domains/comparison").status_code == 503
