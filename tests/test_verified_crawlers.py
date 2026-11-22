import json

import pytest

from app import create_app
from app.bots import assess_bots
from app.database import connect_database, initialize_database
from app.parsers import parse_access_line
from app.storage import SQLiteStore
from app.verified_crawlers import (
    RANGES_PATH, SOURCES, CrawlerRanges, crawler_claim, load_ranges, parse_source, update_ranges,
)
from tests.test_threat_intel import FakeProviders

GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
BINGBOT = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
RANGES = CrawlerRanges({"updated": "2026-11-11T00:00:00+00:00", "sources": {
    "google_common": {"creation_time": "2026-11-10T00:00:00", "prefixes": ["66.249.64.0/27", "2001:4860:4801:10::/64"]},
    "bing": {"creation_time": "2024-01-03T00:00:00", "prefixes": ["157.55.39.0/24", "157.55.39.128/25"]},
    "not_a_source": {"prefixes": ["203.0.113.0/24"]},
}})


@pytest.mark.parametrize("user_agent,operator,token", [
    (GOOGLEBOT, "Google", "Googlebot"),
    ("Googlebot-Image/1.0", "Google", "Googlebot-Image"),
    ("Mozilla/5.0 (Linux; Android 6.0.1) Chrome/130.0 Mobile Safari/537.36 (compatible; AdsBot-Google-Mobile)",
     "Google", "AdsBot-Google-Mobile"),
    (BINGBOT, "Microsoft", "bingbot"),
    ("Mozilla/5.0 (compatible; GPTBot/1.4; +https://openai.com/gptbot)", "OpenAI", "GPTBot"),
    ("Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)", "OpenAI", "ChatGPT-User"),
    ("Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 (Applebot/0.1)",
     "Apple", "Applebot"),
    ("DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)", "DuckDuckGo", "DuckDuckBot"),
])
def test_crawler_claims_are_recognized(user_agent, operator, token):
    assert crawler_claim(user_agent).operator == operator and crawler_claim(user_agent).token == token


@pytest.mark.parametrize("user_agent", [None, "", CHROME, "Mozilla/5.0 (compatible; AhrefsBot/7.0)",
                                        "Mozilla/5.0 (compatible; MyGooglebotClone/1.0)"])
def test_other_user_agents_claim_no_verifiable_crawler(user_agent):
    assert crawler_claim(user_agent) is None


def test_lookup_handles_both_families_nested_prefixes_and_unknown_sources():
    assert RANGES.lookup("66.249.64.31")["prefix"] == "66.249.64.0/27"
    assert RANGES.lookup("66.249.64.32") is None
    assert RANGES.lookup("2001:4860:4801:10::abcd")["operator"] == "Google"
    assert RANGES.lookup("::ffff:157.55.39.200")["operator"] == "Microsoft"
    assert RANGES.lookup("157.55.39.200")["prefix"] == "157.55.39.128/25"
    assert RANGES.lookup("203.0.113.9") is None
    assert RANGES.operators == {"Google", "Microsoft"}


def test_vendored_ranges_cover_every_source():
    ranges = load_ranges(RANGES_PATH)
    assert set(ranges.sources) == {source.id for source in SOURCES}
    assert all(entry["prefix_count"] for entry in ranges.sources.values())
    assert ranges.lookup("66.249.66.1")["operator"] == "Google"
    assert ranges.lookup("207.46.13.229")["operator"] == "Microsoft"


@pytest.fixture
def store(tmp_path):
    connection = connect_database(tmp_path / "crawlers.sqlite3")
    initialize_database(connection)
    yield SQLiteStore(connection)
    connection.close()


def add(store, ip, user_agent, target="/", line=1):
    record = f'{ip} - - [21/Oct/2026:09:00:00 +0000] "GET {target} HTTP/1.1" 200 128 "-" "{user_agent}"'
    return store.insert_event(parse_access_line(record, source_file="synthetic.log", line_number=line))


def assess(store, crawlers=RANGES):
    return {item["source_ip"]: item for item in assess_bots(store, crawlers=crawlers)[0]}


def test_ip_in_published_range_is_a_verified_crawler_even_after_a_wordpress_probe(store):
    add(store, "157.55.39.10", BINGBOT)
    add(store, "157.55.39.10", BINGBOT, "/wp-login.php", line=2)
    items, summary = assess_bots(store, crawlers=RANGES)
    item = items[0]
    assert item["classification"] == "verified_crawler" and item["recommendation"] == "allow_or_use_robots_txt"
    assert item["verified_crawler"]["prefix"] == "157.55.39.0/24" and item["impersonation"] is False
    assert item["reasons"][0].startswith("IP is inside 157.55.39.0/24, which Microsoft publishes for bingbot")
    assert "User-Agent also identifies it as bingbot." in item["reasons"]
    assert item["wordpress_probe_count"] == 1
    assert summary["by_classification"]["verified_crawler"] == 1 and summary["ban_candidates"] == 0
    assert summary["declared_agent_confirmed"] == 0


def test_range_alone_verifies_a_user_triggered_fetch_with_a_browser_user_agent(store):
    add(store, "66.249.64.5", CHROME)
    item = assess(store)["66.249.64.5"]
    assert item["classification"] == "verified_crawler" and item["crawler_claims"] == []


def test_claim_from_outside_the_published_ranges_is_impersonation(store):
    add(store, "192.0.2.10", GOOGLEBOT)
    add(store, "192.0.2.10", CHROME, "/style.css", line=2)
    items, summary = assess_bots(store, crawlers=RANGES)
    item = items[0]
    assert item["classification"] == "confirmed_bot" and item["impersonation"] is True
    assert item["crawler_claims"][0] | {"event_id": 0} == {
        "operator": "Google", "token": "Googlebot", "user_agent": GOOGLEBOT, "event_id": 0,
        "requests": 1, "verifiable": True, "impersonation": True,
    }
    assert any("claims Googlebot (Google), but the IP is not in Google's published" in reason for reason in item["reasons"])
    assert summary["impersonation_confirmed"] == 1


def test_claim_for_one_operator_from_another_operators_range_is_impersonation(store):
    add(store, "66.249.64.7", BINGBOT)
    item = assess(store)["66.249.64.7"]
    assert item["classification"] == "verified_crawler" and item["impersonation"] is True


def test_claims_are_not_impersonation_when_that_operators_ranges_are_unavailable(store):
    add(store, "192.0.2.10", GOOGLEBOT)
    item = assess(store, CrawlerRanges({}))["192.0.2.10"]
    assert item["classification"] == "confirmed_bot" and item["impersonation"] is False
    assert item["crawler_claims"][0]["verifiable"] is False


def test_common_format_logs_have_no_claims(store):
    record = '192.0.2.10 - - [21/Oct/2026:09:00:00 +0000] "GET / HTTP/1.1" 200 128'
    store.insert_event(parse_access_line(record, source_file="synthetic.log", line_number=1))
    assert assess(store)["192.0.2.10"]["crawler_claims"] == []


def test_parse_source_validates_the_published_format():
    body = json.dumps({"creationTime": "2026-11-10T00:00:00", "prefixes": [
        {"ipv4Prefix": "66.249.64.0/27"}, {"ipv6Prefix": "2001:4860:4801:10::/64"}, {"ipv4Prefix": "66.249.64.0/27"},
    ]}).encode()
    assert parse_source(body) == {"creation_time": "2026-11-10T00:00:00",
                                  "prefixes": ["2001:4860:4801:10::/64", "66.249.64.0/27"]}
    for invalid in (b"<html>", b'{"prefixes": []}', b'{"prefixes": [{"ipv4Prefix": "not-an-ip"}]}'):
        with pytest.raises((ValueError, KeyError, TypeError)):
            parse_source(invalid)


def test_update_keeps_previous_prefixes_for_a_failed_source(tmp_path):
    path = tmp_path / "ranges.json"
    good = json.dumps({"creationTime": "2026-11-10", "prefixes": [{"ipv4Prefix": "192.0.2.0/24"}]}).encode()
    update_ranges(path, fetch=lambda url: good)

    def fetch(url):
        if "bing.com" in url:
            raise OSError("timed out")
        return json.dumps({"creationTime": "2026-11-11", "prefixes": [{"ipv4Prefix": "198.51.100.0/24"}]}).encode()

    result = update_ranges(path, fetch=fetch)
    failed = [source for source in result["sources"] if not source["ok"]]
    assert [source["source"] for source in failed] == ["bing"] and failed[0]["kept_previous"] is True
    ranges = load_ranges(path)
    assert ranges.lookup("192.0.2.1")["operator"] == "Microsoft"
    assert ranges.lookup("198.51.100.1")["operator"] != "Microsoft"
    assert list(tmp_path.iterdir()) == [path]


def test_api_reports_verified_crawlers_and_never_exports_or_looks_them_up(tmp_path):
    keys = tmp_path / "keys.toml"
    keys.write_text('[abuseipdb]\nkeys = ["a1"]\n', encoding="utf-8")
    fetch = FakeProviders()
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "api.sqlite3"),
                      "THREAT_INTEL_KEYS_PATH": str(keys), "THREAT_INTEL_FETCH": fetch})
    connection = connect_database(app.config["DATABASE_PATH"])
    initialize_database(connection)
    try:
        store = SQLiteStore(connection)
        add(store, "207.46.13.229", BINGBOT)  # inside the vendored bingbot ranges
        add(store, "8.8.4.4", GOOGLEBOT, line=2)
        client = app.test_client()
        body = client.get("/api/bots").get_json()
        export = client.get("/api/bots/export").get_data(as_text=True)
        filtered = client.get("/api/bots?classification=verified_crawler").get_json()
        client.post("/api/bots/threat-intel", json={})
    finally:
        connection.close()
    items = {item["source_ip"]: item for item in body["items"]}
    assert items["207.46.13.229"]["classification"] == "verified_crawler"
    assert items["8.8.4.4"]["classification"] == "confirmed_bot" and items["8.8.4.4"]["impersonation"]
    assert body["summary"]["by_classification"]["verified_crawler"] == 1
    assert body["summary"]["crawler_ranges_updated"] and "crawler_policy" in body["policy"]
    assert export == "8.8.4.4\n"
    assert [item["source_ip"] for item in filtered["items"]] == ["207.46.13.229"]
    assert "207.46.13.229" not in {call[2] for call in fetch.calls}
