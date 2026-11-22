from datetime import datetime, timezone

import pytest

from app.bots import assess_bots
from app.database import connect_database, initialize_database
from app.parsers import parse_access_line
from app.storage import SQLiteStore
from app.user_agents import AI_ROBOTS_PATH, _load_ai_tokens, declared_agent

IP = "192.0.2.10"
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"


@pytest.mark.parametrize("user_agent,category,name", [
    (None, "missing", "-"),
    ("   ", "missing", "-"),
    ("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.4; +https://openai.com/gptbot)",
     "ai_crawler", "GPTBot"),
    ("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
     "ai_crawler", "ClaudeBot"),
    ("Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 "
     "(compatible; Bytespider; spider-feedback@bytedance.com)", "ai_crawler", "Bytespider"),
    ("CCBot/2.0 (https://commoncrawl.org/faq/)", "ai_crawler", "CCBot"),
    ("facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "ai_crawler", "facebookexternalhit"),
    ("sqlmap/1.7.2#stable (https://sqlmap.org)", "scanner", "sqlmap"),
    ("Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))", "scanner", "Nuclei"),
    ("curl/8.4.0", "automation", "curl"),
    ("python-requests/2.31.0", "automation", "python-requests"),
    ("Go-http-client/1.1", "automation", "Go-http-client"),
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
     "automation", "HeadlessChrome"),
    ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "crawler", "Googlebot"),
    ("Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", "crawler", "AhrefsBot"),
    ("Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)", "crawler", "Slurp"),
    ("Hello from Palo Alto Networks, find out more about our scans in https://docs-cortex.paloaltonetworks.com/r/1/"
     "Cortex-Xpanse/Scanning-activity", "scanner", "Palo Alto Networks"),
    ("Mozilla/5.0 (compatible; Infrawatch/1.0; +https://infrawat.ch/)", "scanner", "Infrawatch"),
    ("Hello, World", "scanner", "Hello, World"),
    ("Mozilla/5.0 (X11; Linux x86_64) Chrome/140.0.0.0 Safari/537.36 ModatScanner/1.2 (+https://modat.io/)",
     "scanner", "ModatScanner"),
    ("Mozilla/5.0 (compatible; ExampleScanner/2.0)", "crawler", "ExampleScanner"),
    ("Mozilla/5.0", "automation", "Mozilla/5.0 with no browser details"),
])
def test_declared_automation_is_recognized(user_agent, category, name):
    agent = declared_agent(user_agent)
    assert agent is not None and agent.category == category and agent.name.split(" (")[0] == name


@pytest.mark.parametrize("user_agent", [
    CHROME,
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Linux; Android 9; CUBOT_X19) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36",
    # Electron desktop apps carry ambiguous ai.robots.txt tokens such as "Code" and "Cursor".
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Code/1.95.0 Chrome/128.0 Electron/32.2.1 Safari/537.36",
    "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) Cursor/0.42.3 Chrome/124.0 Electron/30.4.0 Safari/537.36",
    "Synthetic browser",
])
def test_browser_user_agents_are_not_declared_automation(user_agent):
    assert declared_agent(user_agent) is None


def test_vendored_list_loads_without_policy_or_ambiguous_tokens():
    tokens = _load_ai_tokens(AI_ROBOTS_PATH)
    assert len(tokens) > 100 and "gptbot" in tokens and "claudebot" in tokens
    assert not any(token.startswith("__") for token in tokens)
    assert "code" not in tokens and "cursor" not in tokens
    assert tokens["gptbot"] == "OpenAI"


@pytest.fixture
def store(tmp_path):
    connection = connect_database(tmp_path / "bots.sqlite3")
    initialize_database(connection)
    yield SQLiteStore(connection)
    connection.close()


def add(store, user_agent, target="/style.css", *, ip=IP, line=1, combined=True):
    record = f'{ip} - - [21/Oct/2026:09:00:00 +0000] "GET {target} HTTP/1.1" 200 128'
    if combined:
        record += f' "-" "{user_agent}"'
    event = parse_access_line(record, source_file="synthetic.log", line_number=line)
    assert event is not None
    return store.insert_event(event)


def test_declared_user_agent_overrides_css_and_is_exported(store):
    add(store, "python-requests/2.31.0")
    add(store, "python-requests/2.31.0", "/", line=2)
    add(store, CHROME, "/style.css", ip="192.0.2.20", line=3)
    items, summary = assess_bots(store)
    bot = next(item for item in items if item["source_ip"] == IP)
    assert bot["classification"] == "confirmed_bot" and bot["declared_agent_count"] == 2
    assert bot["declared_agents"] == [{
        "category": "automation", "label": "Automation tool or HTTP library", "name": "python-requests",
        "reason": "Automation tool or HTTP library in User-Agent: python-requests.",
        "user_agent": "python-requests/2.31.0", "event_id": bot["declared_agents"][0]["event_id"], "requests": 2,
    }]
    assert "A declared automated User-Agent takes priority over normal browsing signals." in bot["reasons"]
    human = next(item for item in items if item["source_ip"] == "192.0.2.20")
    assert human["classification"] == "not_a_bot" and human["declared_agents"] == []
    assert summary["declared_agent_confirmed"] == 1 and summary["ban_candidates"] == 1


def test_dash_user_agent_confirms_only_in_formats_that_log_it(store):
    add(store, "-")
    add(store, None, ip="192.0.2.30", line=2, combined=False)
    items = {item["source_ip"]: item for item in assess_bots(store)[0]}
    assert items[IP]["classification"] == "confirmed_bot"
    assert items[IP]["declared_agents"][0]["category"] == "missing"
    assert items["192.0.2.30"]["classification"] == "not_a_bot"


def test_unused_browser_connection_timeout_is_not_a_missing_user_agent(store):
    add(store, CHROME, "/styles.css")
    timeout = parse_access_line(f'{IP} - - [21/Oct/2026:09:00:50 +0000] "-" 408 0 "-" "-"', line_number=2)
    store.insert_event(timeout)
    item = assess_bots(store)[0][0]
    assert item["classification"] == "not_a_bot" and item["declared_agent_count"] == 0


def test_distinct_agents_are_sampled_and_bounded(store):
    for number in range(15):
        add(store, f"Agent{number}Bot/1.0", line=number + 1)
    item = assess_bots(store)[0][0]
    assert item["declared_agent_count"] == 15 and len(item["declared_agents"]) == 10


def test_bot_api_exposes_user_agent_evidence(tmp_path):
    from app import create_app
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "api.sqlite3")})
    connection = connect_database(app.config["DATABASE_PATH"])
    initialize_database(connection)
    try:
        add(SQLiteStore(connection), "Mozilla/5.0 (compatible; GPTBot/1.4; +https://openai.com/gptbot)", "/")
        body = app.test_client().get("/api/bots").get_json()
    finally:
        connection.close()
    assert body["summary"]["declared_agent_confirmed"] == 1
    assert body["items"][0]["declared_agents"][0]["name"] == "GPTBot (OpenAI)"
    assert "user_agent_policy" in body["policy"]
