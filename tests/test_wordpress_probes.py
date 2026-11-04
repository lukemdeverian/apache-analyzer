"""Unexpected WordPress endpoints override CSS and language observations."""

import io
from urllib.parse import quote

import pytest

from app import create_app
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
        assert old["classification"] == ("not_a_bot" if with_css else "suspected_bot")
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
