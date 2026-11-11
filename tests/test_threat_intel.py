import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from app import create_app
from app.bots import assess_bots
from app.database import connect_database, initialize_database
from app.parsers import parse_access_line
from app.storage import SQLiteStore
from app.threat_intel import (
    CACHE_FILENAME, KeyState, ThreatIntelConfigError, check_ips, load_keys, read_reputation,
)

NOW = datetime(2026, 11, 11, 12, tzinfo=timezone.utc)
PUBLIC = "8.8.8.8"
OTHER = "1.1.1.1"


class FakeProviders:
    """Records requests; responds per provider/key with scripted status codes."""

    def __init__(self, abuse_scores=None, otx_reputation=None, statuses=None):
        self.abuse_scores = abuse_scores or {}
        self.otx_reputation = otx_reputation or {}
        self.statuses = statuses or {}  # key -> status code to return
        self.calls = []

    def __call__(self, url, headers):
        key = headers.get("Key") or headers.get("X-OTX-API-KEY")
        parts = urlsplit(url)
        if parts.hostname == "api.abuseipdb.com":
            provider, address = "abuseipdb", parse_qs(parts.query)["ipAddress"][0]
        else:
            provider, address = "otx", parts.path.split("/")[5]
        self.calls.append((provider, key, address))
        status = self.statuses.get(key, 200)
        if status == "network":
            raise OSError("unreachable")
        if status != 200:
            return status, {"Retry-After": "600"}, b'{"errors": []}'
        if provider == "abuseipdb":
            body = {"data": {"ipAddress": address, "abuseConfidenceScore": self.abuse_scores.get(address, 0)}}
        else:
            body = {"indicator": address, "reputation": self.otx_reputation.get(address, 0)}
        return 200, {}, json.dumps(body).encode()


def run(tmp_path, fetch, keys, addresses=(PUBLIC,), now=NOW, **options):
    options.setdefault("state", KeyState())
    return check_ips(addresses, keys=keys, cache_path=tmp_path / CACHE_FILENAME, fetch=fetch, now=now, **options)


def test_missing_key_file_means_no_keys(tmp_path):
    assert load_keys(tmp_path / "absent.toml") == {"abuseipdb": [], "otx": []}


def test_key_file_sections_are_ordered_trimmed_and_deduplicated(tmp_path):
    path = tmp_path / "keys.toml"
    path.write_text('[abuseipdb]\nkeys = [" a1 ", "a2", "a1", ""]\n\n[otx]\nkeys = ["o1"]\n', encoding="utf-8")
    assert load_keys(path) == {"abuseipdb": ["a1", "a2"], "otx": ["o1"]}


def test_committed_template_parses_with_no_keys():
    template = Path(__file__).resolve().parent.parent / "threat_intel_keys.example.toml"
    assert load_keys(template) == {"abuseipdb": [], "otx": []}


@pytest.mark.parametrize("content", ['[abuseipdb]\nkeys = "single"\n', "[otx]\nkeys = [1]\n", "not toml ["])
def test_invalid_key_file_is_reported(tmp_path, content):
    path = tmp_path / "keys.toml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ThreatIntelConfigError):
        load_keys(path)


@pytest.mark.parametrize("limited_status", [429, 401, 403])
def test_limited_or_rejected_key_rotates_to_next_key_without_stopping(tmp_path, limited_status):
    fetch = FakeProviders(abuse_scores={PUBLIC: 90, OTHER: 5}, statuses={"a1": limited_status})
    state = KeyState()
    result = run(tmp_path, fetch, {"abuseipdb": ["a1", "a2"], "otx": []}, (PUBLIC, OTHER), state=state)
    assert [call[1] for call in fetch.calls] == ["a1", "a2", "a2"]  # a1 is retired after its limit
    assert result["checked"]["abuseipdb"] == 2 and result["remaining"] == 0
    assert result["providers"]["abuseipdb"]["stopped"] is None
    scores = {ip: results[0]["score"] for ip, results in read_reputation(tmp_path / CACHE_FILENAME).items()}
    assert scores == {PUBLIC: 90, OTHER: 5}
    # A later batch skips the retired key until it resets.
    fetch.calls.clear()
    run(tmp_path, fetch, {"abuseipdb": ["a1", "a2"], "otx": []}, ("9.9.9.9",), state=state)
    assert [call[1] for call in fetch.calls] == ["a2"]


def test_exhausted_provider_does_not_stop_the_other_provider(tmp_path):
    fetch = FakeProviders(otx_reputation={PUBLIC: 1, OTHER: 0}, statuses={"a1": 429, "a2": 429})
    result = run(tmp_path, fetch, {"abuseipdb": ["a1", "a2"], "otx": ["o1"]}, (PUBLIC, OTHER))
    assert result["providers"]["abuseipdb"]["stopped"] == "all_keys_rate_limited"
    assert result["checked"] == {"abuseipdb": 0, "otx": 2}
    providers = {ip: [r["provider"] for r in results] for ip, results in read_reputation(tmp_path / CACHE_FILENAME).items()}
    assert providers == {PUBLIC: ["otx"], OTHER: ["otx"]}


def test_repeated_network_failures_stop_that_provider_only(tmp_path):
    fetch = FakeProviders(statuses={"a1": "network"})
    addresses = ("8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9")
    result = run(tmp_path, fetch, {"abuseipdb": ["a1"], "otx": ["o1"]}, addresses)
    assert result["errors"]["abuseipdb"] == 3 and result["providers"]["abuseipdb"]["stopped"] == "repeated_failures"
    assert result["checked"]["otx"] == 4


def test_private_and_documentation_addresses_are_never_sent(tmp_path):
    fetch = FakeProviders()
    result = run(tmp_path, fetch, {"abuseipdb": ["a1"], "otx": ["o1"]}, ("10.0.0.1", "192.0.2.10", "127.0.0.1", "bad"))
    assert fetch.calls == [] and result["public_ips"] == 0


def test_fresh_cache_is_reused_and_refresh_rechecks(tmp_path):
    fetch = FakeProviders()
    keys = {"abuseipdb": ["a1"], "otx": ["o1"]}
    run(tmp_path, fetch, keys)
    assert len(fetch.calls) == 2
    # Cache never expires — same IP is not re-checked without --refresh.
    assert run(tmp_path, fetch, keys)["needing_lookup"] == 0 and len(fetch.calls) == 2
    assert run(tmp_path, fetch, keys, now=NOW + timedelta(days=365))["needing_lookup"] == 0 and len(fetch.calls) == 2
    # --refresh forces a re-check regardless.
    run(tmp_path, fetch, keys, refresh=True)
    assert len(fetch.calls) == 4


def test_batch_limit_reports_remaining_work(tmp_path):
    result = run(tmp_path, FakeProviders(), {"abuseipdb": ["a1"], "otx": []}, ("8.8.8.8", "8.8.4.4", "1.1.1.1"), limit=2)
    assert result["processed"] == 2 and result["remaining"] == 1 and result["can_continue"]


def test_ipv6_uses_the_otx_ipv6_endpoint(tmp_path):
    seen = []

    def fetch(url, headers):
        seen.append(url)
        return 200, {}, b'{"pulse_info": {"count": 0}}'
    run(tmp_path, fetch, {"abuseipdb": [], "otx": ["o1"]}, ("2001:4860:4860::8888",))
    assert "/indicators/IPv6/2001:4860:4860::8888/general" in seen[0]


# Classification


@pytest.fixture
def store(tmp_path):
    connection = connect_database(tmp_path / "bots.sqlite3")
    initialize_database(connection)
    yield SQLiteStore(connection)
    connection.close()


def add(store, ip, target="/", status=200):
    line = f'{ip} - - [21/Oct/2026:09:00:00 +0000] "GET {target} HTTP/1.1" {status} 128 "-" "Synthetic browser"'
    store.insert_event(parse_access_line(line, source_file="synthetic.log", line_number=1))


def reputation_for(provider, score):
    from app.threat_intel import _result
    return {PUBLIC: [_result(provider, score, "2026-11-11T12:00:00+00:00")]}


@pytest.mark.parametrize("provider,score,confirmed", [
    ("abuseipdb", 70, True), ("abuseipdb", 100, True), ("abuseipdb", 69, False),
    ("otx", 1, True), ("otx", 0, False),
])
def test_reputation_thresholds_confirm_bots(store, provider, score, confirmed):
    add(store, PUBLIC)
    items, summary = assess_bots(store, reputation=reputation_for(provider, score))
    assert (items[0]["classification"] == "confirmed_bot") is confirmed
    assert summary["threat_intel_confirmed"] == int(confirmed) and summary["threat_intel_checked"] == 1
    assert items[0]["threat_intel"][0]["score"] == score
    if confirmed:
        assert any(("AbuseIPDB" in reason or "OTX" in reason) for reason in items[0]["reasons"])


def test_reputation_overrides_normal_css_browsing(store):
    add(store, PUBLIC, "/style.css")
    item = assess_bots(store, reputation=reputation_for("abuseipdb", 95))[0][0]
    assert item["classification"] == "confirmed_bot"
    assert "Threat intelligence takes priority over normal browsing signals." in item["reasons"]


# API


@pytest.fixture
def client(tmp_path):
    keys = tmp_path / "keys.toml"
    keys.write_text('[abuseipdb]\nkeys = ["a1", "a2"]\n[otx]\nkeys = ["o1"]\n', encoding="utf-8")
    fetch = FakeProviders(abuse_scores={PUBLIC: 88}, otx_reputation={"9.9.9.9": 1}, statuses={"a1": 429})
    app = create_app({
        "TESTING": True, "DATABASE_PATH": str(tmp_path / "bots.sqlite3"),
        "THREAT_INTEL_KEYS_PATH": str(keys), "THREAT_INTEL_FETCH": fetch,
    })
    connection = connect_database(app.config["DATABASE_PATH"])
    initialize_database(connection)
    store = SQLiteStore(connection)
    add(store, PUBLIC)
    add(store, OTHER, "/style.css")
    add(store, "192.0.2.50")
    yield app.test_client(), fetch, tmp_path
    connection.close()


def post(client, path="/api/bots/threat-intel", **options):
    return client.post(path, json={}, **options)


def test_viewing_assessments_never_calls_providers_or_creates_cache(client):
    http, fetch, tmp_path = client
    assert http.get("/api/bots").status_code == 200
    assert fetch.calls == [] and not (tmp_path / CACHE_FILENAME).exists()


def test_endpoint_checks_ips_and_moves_hits_into_confirmed(client):
    http, fetch, _ = client
    before = http.get("/api/bots").get_json()["summary"]
    response = post(http)
    assert response.status_code == 200
    result = response.get_json()
    assert result["public_ips"] == 2 and result["checked"] == {"abuseipdb": 2, "otx": 2}
    assert result["providers"]["abuseipdb"]["keys_rate_limited"] == 1
    assert "192.0.2.50" not in {call[2] for call in fetch.calls}
    after = http.get("/api/bots").get_json()
    assert after["summary"]["by_classification"]["confirmed_bot"] == before["by_classification"]["confirmed_bot"] + 1
    assert after["summary"]["threat_intel_confirmed"] == 1
    confirmed = next(item for item in after["items"] if item["source_ip"] == PUBLIC)
    assert confirmed["classification"] == "confirmed_bot" and confirmed["threat_intel_hits"] == 1
    assert http.get("/api/bots/export").get_data(as_text=True) == PUBLIC + "\n"
    # Already-confirmed IPs are not re-sent.
    fetch.calls.clear()
    assert post(http, "/api/bots/threat-intel?refresh=true").get_json()["public_ips"] == 1


def test_endpoint_requires_a_json_request(client):
    http, fetch, _ = client
    assert http.post("/api/bots/threat-intel").status_code == 400
    assert http.post("/api/bots/threat-intel", data="{}", content_type="text/plain").status_code == 400
    assert fetch.calls == []


def test_endpoint_reports_missing_keys(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "x.sqlite3"),
                      "THREAT_INTEL_KEYS_PATH": str(tmp_path / "absent.toml")})
    response = post(app.test_client())
    assert response.status_code == 409
    assert response.get_json()["error"]["code"] == "threat_intel_not_configured"
