"""Unexpected WordPress endpoints override CSS and language observations."""

import io
from urllib.parse import quote

import pytest

from app import create_app
from app.bots import assess_bots
from app.database import connect_database, initialize_database
from app.detection import DetectionEngine
from app.parsers import parse_access_line
from app.storage import SQLiteStore

RULE = "APACHE-WORDPRESS-PROBE"
IP = "192.0.2.91"


def line(target="/wp-admin/install.php?step=1", *, status=404, seconds=0, language="en-us,en;q=0.8", headers=True):
    request = ("GET " + target + " HTTP/1.1").replace("\\", "\\\\").replace('"', '\\"')
    text = f'{IP} - - [24/Sep/2026:09:27:{seconds + 18:02} +0000] "{request}" {status} 493'
    if headers:
        text += ' "-" "http://example.test/wp-admin/install.php?step=1" lang:"' + language + '"'
        text += ' enc:"gzip" sfm:"-" sfs:"-" sfd:"-" sfu:"-" chua:"-" chplat:"-" uir:"-" proto:HTTP/1.1 reqtime:342'
    return text


@pytest.fixture
def store():
    connection = connect_database(":memory:")
    initialize_database(connection)
    yield SQLiteStore(connection)
    connection.close()


@pytest.mark.parametrize("target", [
    "/wp-admin/install.php?step=1", "/wp-admin/setup-config.php", "/wp-admin/upgrade.php",
    "/wp-admin/admin.php", "/wp-admin/index.php", "/wp-admin", "/wp-admin/",
    "/wp-login.php", "/xmlrpc.php", "/blog/wp-admin/install.php", "/WP-ADMIN/INSTALL.PHP",
    "/wp-admin/./install.php", "/wp-admin/install.php/extra", r"/wp-admin\install.php",
    "/%77p-admin/%69nstall.php", "/%2577p-admin/%2569nstall.php",
    "https://chronoscrate.xyz/wp-admin/install.php?step=1",
])
@pytest.mark.parametrize("status", [200, 403, 404, 500])
def test_single_wordpress_probe_matches_regardless_of_status_and_keeps_raw_evidence(store, target, status):
    raw = line(target, status=status)
    event = parse_access_line(raw, source_file="synthetic-wordpress.txt", line_number=1)
    identity = store.insert_event(event)
    before = store.connection.total_changes
    matches = [finding for finding in DetectionEngine().iter_findings(store) if finding.rule_id == RULE]
    finding, = matches
    assert finding.event_ids == (identity,) and finding.threshold == 1
    assert finding.source_ip == IP and finding.severity == "high"
    assert f"response HTTP {status}" in finding.description
    assert store.get_event(identity).event.raw_log == raw
    item, = assess_bots(store)[0]
    assert item["classification"] == "confirmed_bot"
    assert item["wordpress_probe_count"] == 1
    assert item["wordpress_probe_evidence"] == [{"event_id": identity}]
    assert item["risk_alert_count"] == 0
    assert store.connection.total_changes == before


@pytest.mark.parametrize("target", [
    "/", "/checkout", "/wp-admin/css/common.css", "/wp-content/themes/site/style.css",
    "/wp-admin/admin-ajax.php", "/wp-admin/assets/install.php",
    "/my-wp-admin/install.php", "/docs/wp-admin-install.php",
    "/wp-admin/install.php.txt", "/wp-admin/install.php.css", "/wp-login.php.png",
    "/search?next=/wp-admin/install.php", "/search?path=%2Fwp-admin%2Finstall.php",
    "/static/wordpress.js",
])
def test_wordpress_mentions_and_assets_do_not_create_probe_alerts(store, target):
    # The user-agent contains a WordPress URL too: only the actual path is inspected.
    store.insert_event(parse_access_line(line(target, status=200)))
    assert not any(finding.rule_id == RULE for finding in DetectionEngine().iter_findings(store))
    item, = assess_bots(store)[0]
    assert item["classification"] != "confirmed_bot"
    assert item["wordpress_probe_count"] == 0


def test_three_pass_encoding_is_not_decoded_indefinitely(store):
    target = "/wp-admin/install.php"
    for _ in range(3):
        target = quote(target, safe="")
    store.insert_event(parse_access_line(line(target)))
    assert not any(finding.rule_id == RULE for finding in DetectionEngine().iter_findings(store))


@pytest.mark.parametrize("with_css", [False, True])
@pytest.mark.parametrize("language", ["en-us,en;q=0.8,fr;q=0.5,fr-ca;q=0.3", "-", ""])
def test_rescan_flags_preexisting_probe_without_reimport_and_overrides_css_and_language(
    tmp_path, monkeypatch, with_css, language,
):
    from app import detection

    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "events.sqlite3")})
    app.instance_path = str(tmp_path / "instance")
    cli = app.test_cli_runner()
    assert cli.invoke(args=["init-db"]).exit_code == 0
    content = line(language=language) + "\n"
    if with_css:
        content += line("/style.css", status=200, seconds=1) + "\n"
    client = app.test_client()
    with monkeypatch.context() as patch:
        patch.setattr(detection, "REQUEST_RULES", tuple(rule for rule in detection.REQUEST_RULES if rule.rule_id != RULE))
        imported = client.post("/api/imports", data={
            "file": (io.BytesIO(content.encode()), "older-probes.log"),
            "domain_id": "chronoscrate", "log_type": "access",
        }, headers={"X-Apache-Upload": "1"})
        assert imported.status_code == 201
        old = client.get("/api/bots").json["items"][0]
        assert old["classification"] == "confirmed_bot"
        assert old["risk_alert_count"] == 0 and old["wordpress_probe_count"] == 1
    before_events = client.get("/api/stats").json["events"]["total"]
    result = cli.invoke(args=["detect", "--domain", "chronoscrate", "--json"])
    assert result.exit_code == 0, result.output
    item, = client.get("/api/bots").json["items"]
    assert item["classification"] == "confirmed_bot" and item["risk_alert_count"] == 1
    assert item["risk_alerts"][0]["rule_id"] == RULE
    assert client.get("/api/stats").json["events"]["total"] == before_events
    assert client.get("/api/bots/export").text == IP + "\n"
    assert client.get("/api/bots?domain_id=la_jolla_seals").json["items"] == []
    alert_id = item["risk_alerts"][0]["id"]
    proof, = client.get(f"/api/alerts/{alert_id}/events").json["items"]
    assert proof["raw_log"] == line(language=language)
    assert proof["status_code"] == 404
    replay = cli.invoke(args=["detect", "--domain", "chronoscrate", "--json"])
    assert replay.exit_code == 0
    assert client.get("/api/alerts").json["pagination"]["total"] == 1
    assert client.patch(f"/api/alerts/{alert_id}/status", json={"status": "false_positive"}).status_code == 200
    assert client.get("/api/bots").json["items"][0]["classification"] == ("not_a_bot" if with_css else "suspected_bot")


@pytest.mark.parametrize("domain_id", ["chronoscrate", "la_jolla_seals"])
@pytest.mark.parametrize("with_css", [False, True])
def test_reported_install_request_confirms_bot_without_saved_alert(tmp_path, domain_id, with_css):
    from app.database import get_database

    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "events.sqlite3")})
    assert app.test_cli_runner().invoke(args=["init-db"]).exit_code == 0
    # Use the Apache line before chat formatting converted its user-agent URL into a link.
    raw = (
        '162.158.159.181 - - [30/Sep/2026:10:05:49 +0000] '
        '"GET /wp-admin/install.php?step=1 HTTP/1.1" 404 493 "-" '
        '"http://saagarpatel.ca/wp-admin/install.php?step=1" '
        'lang:"en-us,en;q=0.8,fr;q=0.5,fr-ca;q=0.3" enc:"gzip" '
        'sfm:"-" sfs:"-" sfd:"-" sfu:"-" chua:"-" chplat:"-" uir:"-" proto:HTTP/1.1 reqtime:585'
    )
    with app.app_context():
        store = SQLiteStore(get_database(domain_id))
        identity = store.insert_event(parse_access_line(raw))
        if with_css:
            store.insert_event(parse_access_line(line("/style.css", status=200).replace(IP, "162.158.159.181")))
    client = app.test_client()
    query = f"domain_id={domain_id}&source_ip=162.158.159.181"
    item, = client.get("/api/bots?" + query).json["items"]
    assert item["classification"] == "confirmed_bot"
    assert item["recommendation"] == "review_for_block"
    assert item["risk_alert_count"] == 0 and item["wordpress_probe_count"] == 1
    assert item["wordpress_probe_evidence"] == [{"event_id": identity}]
    assert client.get("/api/bots/export?" + query).text == "162.158.159.181\n"
    assert client.get(f"/api/events/{identity}?domain_id={domain_id}").json["item"]["raw_log"] == raw
    assert client.get(f"/api/alerts?domain_id={domain_id}").json["items"] == []
    assert client.get("/api/bots?" + query + "&start=2026-10-01T00:00:00Z").json["items"] == []


def test_dismissed_probe_does_not_exempt_new_requests_and_samples_are_bounded(store):
    from datetime import timedelta

    from app.pipeline import detect_events

    first = parse_access_line(line())
    store.insert_event(first)
    detect_events(store)
    alert, = store.list_alerts()
    store.set_alert_status(alert.id, "false_positive")
    assert assess_bots(store)[0][0]["classification"] == "suspected_bot"
    identities = [store.insert_event(parse_access_line(line(seconds=second))) for second in range(1, 16)]
    before = store.connection.total_changes
    item, = assess_bots(store, start=first.timestamp + timedelta(seconds=1))[0]
    assert item["classification"] == "confirmed_bot"
    assert item["wordpress_probe_count"] == 15
    assert item["wordpress_probe_evidence"] == [{"event_id": identity} for identity in identities[:10]]
    assert store.connection.total_changes == before
