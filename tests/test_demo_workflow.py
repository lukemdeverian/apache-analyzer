"""Public demo files exercised through the supported application interfaces."""

import io
import json
from pathlib import Path

import pytest

from app import create_app
from app.database import connect_database

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
EXPECTED = json.loads((EXAMPLES / "expected.json").read_text(encoding="utf-8"))


@pytest.fixture
def workspace(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "demo.sqlite3")})
    app.instance_path = str(tmp_path / "instance")
    result = app.test_cli_runner().invoke(args=["init-db"])
    assert result.exit_code == 0, result.output
    return app


def import_example(app, intake, name, log_type):
    path = EXAMPLES / name
    if intake == "cli":
        result = app.test_cli_runner().invoke(args=[
            "ingest", str(path), "--format", log_type, "--error-timezone", "UTC", "--json",
        ])
        assert result.exit_code == 0, result.output
        summary = json.loads(result.output)
        assert summary["source_file"] == str(path.resolve())
    else:
        response = app.test_client().post("/api/imports", headers={"X-Apache-Upload": "1"}, data={
            "file": (io.BytesIO(path.read_bytes()), name), "log_type": log_type, "error_timezone": "UTC",
        })
        assert response.status_code == 201, response.json
        summary = response.json["summary"]
        assert summary["source_file"].startswith("upload:")
        assert summary["source_file"].endswith("/" + name)
        assert list((Path(app.instance_path) / "uploads").iterdir()) == []
    return summary


def persisted_snapshot(app):
    connection = connect_database(app.config["DATABASE_PATH"])
    try:
        return list(connection.iterdump())
    finally:
        connection.close()


def all_pages(client, endpoint, limit):
    results = []
    offset = 0
    for _ in range(100):
        response = client.get(endpoint, query_string={"limit": limit, "offset": offset})
        assert response.status_code == 200, response.json
        page = response.json
        assert page["pagination"]["offset"] == offset
        assert page["pagination"]["returned"] == len(page["items"])
        results.extend(page["items"])
        if not page["pagination"]["has_more"]:
            assert len(results) == page["pagination"]["total"]
            return results
        offset += limit
    pytest.fail("Pagination did not finish.")


@pytest.mark.parametrize("intake", ["cli", "upload"])
@pytest.mark.parametrize("reverse_imports", [False, True], ids=["access-first", "error-first"])
def test_public_demo_import_investigate_triage_replay_and_reopen_database(
    workspace, intake, reverse_imports,
):
    app = workspace
    client = app.test_client()
    assert client.get("/").status_code == client.get("/health").status_code == 200
    assert client.get("/api/stats").json["events"]["total"] == 0
    summaries = {}
    files = EXPECTED["files"][::-1] if reverse_imports else EXPECTED["files"]
    for file in files:
        summary = import_example(app, intake, file["name"], file["log_type"])
        for key in ("log_type", "lines_read", "imported_events", "blank_lines", "malformed_lines"):
            assert summary[key] == file[key]
        assert summary["rejected_lines"] == 1
        assert summary["encoding_error_lines"] == summary["oversized_lines"] == summary["invalid_value_lines"] == 0
        assert summary["assumed_timezone"] == ("UTC" if file["log_type"] == "error" else None)
        summaries[file["name"]] = summary
    assert sum(summary["detection"]["alerts_created"] for summary in summaries.values()) == EXPECTED["alerts"]

    stats = client.get("/api/stats").json
    assert stats["events"]["total"] == EXPECTED["events"]
    assert stats["events"]["by_log_type"] == {"access": 185, "error": 10}
    assert stats["events"]["distinct_source_ips"] == EXPECTED["distinct_source_ips"]
    assert stats["alerts"]["total"] == stats["alerts"]["open"] == EXPECTED["alerts"]
    assert stats["alerts"]["by_status"] == {"new": 11, "investigating": 0, "resolved": 0, "false_positive": 0}
    assert stats["alerts"]["by_severity"] == EXPECTED["alerts_by_severity"]
    assert stats["alerts"]["by_rule_id"] == {rule["rule_id"]: 1 for rule in EXPECTED["rules"]}
    catalog = client.get("/api/rules").json["items"]
    assert {rule["rule_id"] for rule in catalog} == set(stats["alerts"]["by_rule_id"])

    alerts = all_pages(client, "/api/alerts", 4)
    assert len({alert["id"] for alert in alerts}) == EXPECTED["alerts"]
    by_rule = {alert["rule_id"]: alert for alert in alerts}
    events = all_pages(client, "/api/events", 37)
    assert len({event["id"] for event in events}) == EXPECTED["events"]
    assert sum(alert["event_count"] for alert in alerts) == EXPECTED["events"]
    for expected in EXPECTED["rules"]:
        alert = by_rule[expected["rule_id"]]
        assert alert["event_count"] == expected["event_count"]
        assert alert["source_ip"] == expected["source_ip"]
        assert alert["first_seen"] == expected["first_seen"] and alert["last_seen"] == expected["last_seen"]
        evidence = all_pages(client, f"/api/alerts/{alert['id']}/events", 7)
        assert len(evidence) == expected["event_count"]
        assert [event["line_number"] for event in evidence] == list(
            range(expected["first_line"], expected["last_line"] + 1),
        )
        original = (EXAMPLES / expected["file"]).read_text(encoding="utf-8").splitlines()
        for event in evidence:
            assert event["source_file"] == summaries[expected["file"]]["source_file"]
            assert event["raw_log"] == original[event["line_number"] - 1]
            assert client.get(f"/api/events/{event['id']}").json["item"] == event
    traversal = by_rule["APACHE-TRAVERSAL"]
    original = client.get(f"/api/alerts/{traversal['id']}").json["item"]
    investigating = client.patch(
        f"/api/alerts/{traversal['id']}/status", json={"status": "investigating"},
    )
    assert investigating.status_code == 200
    assert investigating.json["item"] == {**original, "status": "investigating"}
    resolved = app.test_cli_runner().invoke(args=["alert-status", str(traversal["id"]), "resolved"])
    assert resolved.exit_code == 0, resolved.output
    server_alert = by_rule["APACHE-ERROR-BURST"]
    assert client.patch(f"/api/alerts/{server_alert['id']}/status", json={"status": "false_positive"}).status_code == 200

    before = persisted_snapshot(app)
    scan = app.test_cli_runner().invoke(args=["detect", "--json"])
    assert scan.exit_code == 0, scan.output
    assert json.loads(scan.output) == {
        "findings": 11, "alerts_created": 0, "alert_updates": 0, "alerts_merged": 0, "findings_unchanged": 11,
    }
    assert persisted_snapshot(app) == before
    rejected = client.post("/api/imports", headers={"X-Apache-Upload": "1"}, data={
        "file": (io.BytesIO((EXAMPLES / "demo_error.txt").read_bytes()), "wrong-format.txt"),
        "log_type": "access",
    })
    assert rejected.status_code == 422 and rejected.json["summary"]["imported_events"] == 0
    assert persisted_snapshot(app) == before
    assert list((Path(app.instance_path) / "uploads").iterdir()) == []

    reopened = create_app({"TESTING": True, "DATABASE_PATH": app.config["DATABASE_PATH"]})
    initialized_again = reopened.test_cli_runner().invoke(args=["init-db"])
    assert initialized_again.exit_code == 0, initialized_again.output
    assert persisted_snapshot(reopened) == before
    persisted = reopened.test_client()
    assert persisted.get(f"/api/alerts/{traversal['id']}").json["item"] == {**original, "status": "resolved"}
    reopened_stats = persisted.get("/api/stats").json
    assert reopened_stats["events"] == stats["events"]
    assert reopened_stats["alerts"]["open"] == 9
    assert reopened_stats["alerts"]["by_status"] == {
        "new": 9, "investigating": 0, "resolved": 1, "false_positive": 1,
    }
    assert persisted.get("/api/alerts?status=resolved").json["items"][0]["id"] == traversal["id"]
    connection = connect_database(app.config["DATABASE_PATH"])
    try:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    finally:
        connection.close()


@pytest.mark.parametrize("intake", ["cli", "upload"])
def test_public_benign_samples_and_later_demo_do_not_create_extra_alerts(workspace, intake):
    app = workspace
    client = app.test_client()
    access = import_example(app, intake, "benign_access.txt", "access")
    error = import_example(app, intake, "benign_error.txt", "error")
    assert access["imported_events"] == access["lines_read"] == 9
    assert error["imported_events"] == error["lines_read"] == 4
    assert access["rejected_lines"] == error["rejected_lines"] == 0
    assert access["detection"]["findings"] == error["detection"]["findings"] == 0
    assert client.get("/api/stats").json["events"]["total"] == 13
    assert client.get("/api/alerts").json["pagination"]["total"] == 0
    host = [item for item in client.get("/api/events?log_type=access").json["items"]
            if item["source_host"] == "client.example"][0]
    assert host["source_ip"] is None
    for file in EXPECTED["files"]:
        import_example(app, intake, file["name"], file["log_type"])
    stats = client.get("/api/stats").json
    assert stats["events"]["total"] == 208
    assert stats["alerts"]["total"] == 11
    assert stats["alerts"]["by_rule_id"] == {rule["rule_id"]: 1 for rule in EXPECTED["rules"]}
