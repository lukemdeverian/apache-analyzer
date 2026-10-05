from dataclasses import replace
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import pytest

from app.database import connect_database, initialize_database, transaction
from app.detection import DetectionEngine, REQUEST_RULES, RuleSettings
from app.ingestion import ingest_file
from app.parsers import parse_access_line, parse_error_line
from app.signatures import DEFAULT_ALLOWED_METHODS
from app.storage import SQLiteStore

BASE = datetime(2026, 10, 6, 9, 0, 0, tzinfo=timezone.utc)
TRAVERSAL = "APACHE-TRAVERSAL"
SQL = "APACHE-SQL-INJECTION"
XSS = "APACHE-XSS"
SENSITIVE = "APACHE-SENSITIVE-FILE"
METHOD = "APACHE-UNUSUAL-METHOD"
SERVER = "APACHE-SERVER-ERRORS"
ERROR = "APACHE-ERROR-BURST"
REQUEST_IDS = {rule.rule_id for rule in REQUEST_RULES}


@pytest.fixture
def store():
    connection = connect_database(":memory:")
    initialize_database(connection)
    yield SQLiteStore(connection)
    connection.close()


def apache_quote(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


def access(target="/index.html", *, method="GET", status=200, ip="192.0.2.10", seconds=0):
    stamp = BASE + timedelta(seconds=seconds)
    request = apache_quote(f"{method} {target} HTTP/1.1")
    line = f'{ip} - - [06/Oct/2026:{stamp:%H:%M:%S} +0000] "{request}" {status} 0'
    event = parse_access_line(line, source_file="security-access.txt", line_number=1)
    assert event is not None
    return replace(event, timestamp=stamp)


def error(*, level="error", ip=None, seconds=0, module="core"):
    client = f"[client {ip}:52102] " if ip is not None else ""
    stamp = BASE + timedelta(seconds=seconds)
    module_prefix = f"{module}:" if module is not None else ""
    line = (
        f"[Tue Oct 06 {stamp:%H:%M:%S.%f} 2026] [{module_prefix}{level}] "
        f"{client}AH00001: Synthetic error condition"
    )
    event = parse_error_line(line, source_file="security-error.txt", line_number=1)
    assert event is not None
    return event


def findings(store, rule_id=None, *, engine=None, **filters):
    values = list((engine or DetectionEngine()).iter_findings(store, **filters))
    return [value for value in values if rule_id is None or value.rule_id == rule_id]


@pytest.mark.parametrize("target", [
    "/../private.txt", "/a/../../private.txt", "/a/..",
    "/%2e%2E%2fprivate.txt", "/%252e%252e%252fprivate.txt",
    r"/..\..\windows\win.ini", "/%2e%2e%5cwindows/win.ini",
    "/read?file=../../private.txt", "/read?file=..%5cwindows%5cwin.ini",
    "/read?file=%252e%252e%255cwindows%255cwin.ini", "/read?file=..&mode=text",
    "http://apache.example.test/../../private.txt",
])
def test_traversal_signatures_in_path_and_query(store, target):
    event_id = store.insert_event(access(target))
    result, = findings(store, TRAVERSAL)
    assert result.event_ids == (event_id,)
    assert "parent-directory segment" in result.description


@pytest.mark.parametrize("target", [
    "/product?id=1%20UNION%20SELECT%201", "/product?id=1+union+all+select+1",
    "/product?id=1%2520UNION%2520SELECT%25201", "/product?id=1/**/UNION/**/SELECT/**/1",
    "/product?id=1%20OR%201=1", "/product?id=1%20AND%201=2",
    "/product?id=1%27+or+%271%27=%271", "/product?id=1%27+OR+%27a%27=%27a%27--",
    "/product?id=1;sleep(1)", "/product?id=pg_sleep(1)", "/product?id=benchmark(1,1)",
    "/product?id=1;%20DROP%20TABLE%20synthetic_table",
    "/product?id=1;%20INSERT%20INTO%20synthetic_table",
    "/product?id=1;%20DELETE%20FROM%20synthetic_table",
    "/product?id=1;%20UPDATE%20synthetic_table%20SET%20value=1",
    "/catalog/1%20UNION%20SELECT%201",
])
def test_sql_signatures_in_path_and_query(store, target):
    event_id = store.insert_event(access(target))
    result, = findings(store, SQL)
    assert result.event_ids == (event_id,)
    assert "signature in the request" in result.description


@pytest.mark.parametrize("payload", [
    "<script>alert(1)</script>", "<ScRiPt >alert(1)</ScRiPt>",
    "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>",
    '" onfocus="alert(1)', "javascript:alert(1)", "&lt;script&gt;alert(1)&lt;/script&gt;",
    "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
])
@pytest.mark.parametrize("double_encoded", [False, True])
def test_xss_signatures_handle_percent_encoding_and_html_entities(store, payload, double_encoded):
    encoded = quote(payload, safe="")
    if double_encoded:
        encoded = quote(encoded, safe="")
    event_id = store.insert_event(access(f"/search?q={encoded}"))
    result, = findings(store, XSS)
    assert result.event_ids == (event_id,)
    assert "signature in the request query" in result.description


def test_xss_signature_can_also_be_in_path(store):
    event_id = store.insert_event(access("/%3Cscript%3Ealert(1)%3C/script%3E"))
    result, = findings(store, XSS)
    assert result.event_ids == (event_id,)
    assert "request path" in result.description


@pytest.mark.parametrize("target", [
    "/.env", "/app/.env.production", "/.ENV", "/%2eenv", "/%252eenv",
    "/.git/config", "/.svn/entries", "/.hg/store", "/.htaccess", "/.htpasswd",
    "/wp-config.php", "/config.php", "/web.config", "/keys/id_rsa", "/keys/id_ed25519",
    "/backup.sql", "/database.sqlite", "/database.sqlite3", "/database.db", "/config.php.bak",
    "/config.php.old", "/config.php.orig", "/.config.php.swp", "/config.php~",
    r"/private\.env", "http://apache.example.test/.git/config",
])
def test_sensitive_file_signatures(store, target):
    event_id = store.insert_event(access(target))
    result, = findings(store, SENSITIVE)
    assert result.event_ids == (event_id,)


@pytest.mark.parametrize("method, target", [
    ("TRACE", "/"), ("CONNECT", "apache.example.test:443"), ("PROPFIND", "/collection/"),
    ("CUSTOM", "/"), ("get", "/"),
])
def test_unusual_methods_are_identified_without_requiring_a_path(store, method, target):
    event_id = store.insert_event(access(target, method=method))
    result, = findings(store, METHOD)
    assert result.event_ids == (event_id,)


@pytest.mark.parametrize("method", sorted(DEFAULT_ALLOWED_METHODS))
def test_common_rest_and_options_methods_are_allowed(store, method):
    store.insert_event(access("*" if method == "OPTIONS" else "/api/items/1", method=method))
    assert findings(store) == []


@pytest.mark.parametrize("target", [
    "/docs/ellipsis...html", "/v1.2.3/", "/folder/.../index.html", "/read?file=report..txt",
    "/search?q=wait...please", "/read?file=folder..%2fname.txt", "/%ZZ/%", "/%FF%FE/index.html",
    "/search?q=O%27Reilly", "/search?q=select+the+union+meeting",
    "/search?q=unionized+selection", "/search?q=or+else", "/search?q=sleeping(1)",
    "/search?q=UNION%2BSELECT", "/search?q=UNION%252BSELECT", "/UNION+SELECT/",
    "/static/scripts.js", "/search?q=scripture", "/search?q=%3Cscripture%3E",
    "/search?q=%3Cb%3Ehello%3C/b%3E", "/api/config", "/static/config.js",
    "/.gitignore", "/.github/workflows/example.yml", "/articles/about-.env-files",
    "/search?q=.env", "/search?q=report.sql", "http://.env/", "/images/a..%26b.png",
])
def test_benign_and_malformed_targets_do_not_match_request_signatures(store, target):
    store.insert_event(access(target))
    assert findings(store) == []


@pytest.mark.parametrize("payload", [
    "&#" + "9" * 10000 + ";", "&#x" + "f" * 10000 + ";",
    "<" + " " * 20000, "UNION" + " " * 20000 + "NOTSELECT",
])
def test_long_malformed_targets_do_not_stop_scan_or_hide_later_findings(store, payload):
    original = access("/?q=" + quote(payload, safe=""))
    first = store.insert_event(original)
    last = store.insert_event(access("/?q=%3Cscript%3Ealert(1)%3C/script%3E", seconds=1))
    result, = findings(store)
    assert result.rule_id == XSS
    assert result.event_ids == (last,)
    assert store.get_event(first).event == original


def test_oversized_numeric_entity_does_not_hide_other_entities_in_same_request(store):
    payload = "&#" + "9" * 10000 + ";&lt;script&gt;alert(1)&lt;/script&gt;"
    event_id = store.insert_event(access("/?q=" + quote(payload, safe="")))
    result, = findings(store)
    assert result.rule_id == XSS
    assert result.event_ids == (event_id,)


@pytest.mark.parametrize("payload", ["../private.txt", "UNION SELECT 1", "<script>alert(1)</script>"])
def test_decoding_is_limited_to_two_percent_encoding_passes(store, payload):
    for _ in range(3):
        payload = quote(payload, safe="")
    store.insert_event(access("/?q=" + payload))
    assert findings(store) == []


@pytest.mark.parametrize("rule_id, target, method", [
    (TRAVERSAL, "/../private.txt", "GET"),
    (SQL, "/?id=1+UNION+SELECT+1", "GET"),
    (XSS, "/?q=%3Cscript%3Ealert(1)%3C/script%3E", "GET"),
    (SENSITIVE, "/.env", "GET"), (METHOD, "/", "TRACE"),
])
@pytest.mark.parametrize("status", [200, 403, 404, 500])
def test_request_findings_do_not_claim_success_and_preserve_evidence(store, rule_id, target, method, status):
    event = access(target, method=method, status=status)
    event_id = store.insert_event(event)
    changes = store.connection.total_changes
    result, = findings(store, rule_id)
    assert result.event_ids == (event_id,)
    assert result.anchor_event_id == event_id
    assert result.first_seen == result.last_seen == event.timestamp
    assert result.threshold == result.event_count == 1
    assert result.window_seconds is None
    assert result.source_ip == event.source_ip
    assert f"response HTTP {status}" in result.description
    assert "success" not in result.description.lower()
    assert store.get_event(event_id).event == event
    assert store.connection.total_changes == changes
    assert store.count_alerts() == 0


def test_multiple_signatures_can_describe_one_request(store):
    event_id = store.insert_event(access("/../.env?q=%3Cscript%3Ealert(1)%3C/script%3E", method="TRACE"))
    results = findings(store)
    assert {result.rule_id for result in results} == {TRAVERSAL, XSS, SENSITIVE, METHOD}
    assert all(result.event_ids == (event_id,) for result in results)


@pytest.mark.parametrize("host, key", [
    ("2001:db8::10", "ip:2001:db8::10"),
    ("client.example.test", "host:client.example.test"), ("-", "server:unattributed-requests"),
])
def test_single_request_signatures_support_ipv6_and_missing_ips(store, host, key):
    store.insert_event(access("/.env", ip=host))
    result, = findings(store)
    assert result.grouping_key == key
    if not key.startswith("ip:"):
        assert result.source_ip is None


def test_referrers_user_agents_and_error_messages_are_not_request_targets(store):
    event = replace(access(), referrer="http://example.test/../.env", user_agent="<script>alert(1)</script>")
    store.insert_event(event)
    store.insert_event(replace(error(), message="../.env UNION SELECT 1 <script>alert(1)</script>"))
    assert findings(store) == []


def test_missing_request_does_not_invent_a_method_or_signature(store):
    event = parse_access_line('192.0.2.10 - - [06/Oct/2026:09:00:00 +0000] "-" 408 0')
    assert event is not None
    store.insert_event(event)
    assert findings(store) == []


def test_signature_scan_filters_anchors_and_does_not_aggregate_matching_requests(store):
    store.insert_event(access("/.env"))
    selected = store.insert_event(access("/.env", seconds=1))
    store.insert_event(access("/.env", seconds=2))
    store.insert_event(access("/.env", seconds=1, ip="192.0.2.20"))
    result, = findings(store, start=BASE + timedelta(seconds=1), end=BASE + timedelta(seconds=1), source_ip="192.0.2.10")
    assert result.event_ids == (selected,)
    assert result.event_count == 1


def test_custom_allowed_methods_are_case_sensitive_and_do_not_change_defaults(store):
    store.insert_event(access(method="PROPFIND"))
    engine = DetectionEngine(allowed_methods=(*DEFAULT_ALLOWED_METHODS, "PROPFIND"))
    assert findings(store, engine=engine) == []
    assert len(findings(store, METHOD)) == 1
    store.insert_event(access(method="propfind"))
    assert len(findings(store, METHOD, engine=engine)) == 1


@pytest.mark.parametrize("allowed_methods", ["GET", b"GET", [], [""], ["GE T"], ["GET", None], [True], 5])
def test_invalid_allowed_methods_are_rejected(allowed_methods):
    with pytest.raises(ValueError, match="allowed_methods"):
        DetectionEngine(allowed_methods=allowed_methods)


@pytest.mark.parametrize("rule_id", sorted(REQUEST_IDS))
def test_request_signatures_reject_threshold_overrides(rule_id):
    with pytest.raises(ValueError, match="request signatures"):
        DetectionEngine({rule_id: RuleSettings(2, 60)})


@pytest.mark.parametrize("rule_id, threshold", [(SERVER, 20), (ERROR, 10)])
@pytest.mark.parametrize("extra_seconds, expected", [(0, True), (0.000001, False)])
def test_server_burst_threshold_and_inclusive_window_across_clients(store, rule_id, threshold, extra_seconds, expected):
    make = (lambda index: access(status=500 + index % 4, ip=f"192.0.2.{index + 10}")) if rule_id == SERVER else (
        lambda index: error(level=("error", "crit", "alert", "emerg")[index % 4], ip=f"192.0.2.{index + 10}")
    )
    ids = [store.insert_event(make(index)) for index in range(threshold - 1)]
    assert findings(store, rule_id) == []
    anchor_event = make(threshold)
    anchor = store.insert_event(replace(anchor_event, timestamp=BASE + timedelta(seconds=60 + extra_seconds)))
    results = findings(store, rule_id)
    assert bool(results) == expected
    if expected:
        result, = results
        assert result.event_ids == tuple([*ids, anchor])
        assert result.event_count == threshold
        assert result.source_ip is None
        assert result.grouping_key == ("server:http-5xx" if rule_id == SERVER else "server:apache-errors")
        assert result.severity == "high"
        assert result.window_seconds == 60
        assert result.first_seen == BASE
        assert result.last_seen == anchor_event.timestamp + timedelta(seconds=60)


def test_server_error_rule_counts_only_5xx_access_responses(store):
    ids = [store.insert_event(access(status=500)) for _ in range(19)]
    for status in (200, 302, 400, 401, 403, 404, 429, 499):
        store.insert_event(access(status=status))
    store.insert_event(error())
    assert findings(store, SERVER) == []
    anchor = store.insert_event(access(status=599))
    result, = findings(store, SERVER)
    assert result.event_ids == tuple([*ids, anchor])


def test_server_error_burst_can_include_hostname_only_or_unattributed_clients(store):
    ids = [
        store.insert_event(access(status=500, ip=host))
        for host in ("client.example.test", "-") for _ in range(10)
    ]
    result, = findings(store)
    assert result.rule_id == SERVER
    assert result.event_ids == tuple(ids)
    assert result.source_ip is None


@pytest.mark.parametrize("rule_id", [SERVER, ERROR])
def test_server_bursts_reject_distinct_path_overrides(rule_id):
    with pytest.raises(ValueError, match="Only the path-enumeration"):
        DetectionEngine({rule_id: RuleSettings(10, 60, 2)})


@pytest.mark.parametrize("level", ["warn", "notice", "info", "debug", "trace1", "trace8"])
def test_lower_error_log_levels_do_not_trigger_error_burst(store, level):
    for _ in range(10):
        store.insert_event(error(level=level))
    assert findings(store) == []


def test_error_burst_supports_no_client_and_legacy_records_across_modules(store):
    ids = [store.insert_event(error(module=module)) for module in ("core", "proxy", "auth_basic", None) for _ in range(2)]
    ids.extend(store.insert_event(error(ip="192.0.2.10", module="core")) for _ in range(2))
    changes = store.connection.total_changes
    result, = findings(store)
    assert result.rule_id == ERROR
    assert result.event_ids == tuple(ids)
    assert result.source_ip is None
    assert result.distinct_path_count == 0
    assert "Apache error/crit/alert/emerg records" in result.description
    assert store.connection.total_changes == changes


@pytest.mark.parametrize("rule_id, make", [
    (SERVER, lambda: access(status=503)), (ERROR, error),
])
def test_server_scans_sort_out_of_order_and_load_context_for_filters(store, rule_id, make):
    engine = DetectionEngine({rule_id: RuleSettings(2, 120)})
    later = store.insert_event(replace(make(), timestamp=BASE + timedelta(seconds=120)))
    earlier = store.insert_event(make())
    store.insert_event(replace(make(), timestamp=BASE + timedelta(seconds=121)))
    result, = findings(store, rule_id, engine=engine, start=BASE + timedelta(seconds=120), end=BASE + timedelta(seconds=120))
    assert result.event_ids == (earlier, later)
    assert result.anchor_event_id == later
    assert result.first_seen == BASE


def test_ip_filtered_scans_exclude_server_wide_findings(store):
    for _ in range(20):
        store.insert_event(access(status=503))
    for _ in range(10):
        store.insert_event(error(ip="192.0.2.10"))
    assert {result.rule_id for result in findings(store)} == {SERVER, ERROR}
    assert findings(store, source_ip="192.0.2.10") == []


def test_server_evidence_is_not_capped_at_one_storage_page(store):
    with transaction(store.connection):
        ids = [store.insert_event(error()) for _ in range(1201)]
    engine = DetectionEngine({ERROR: RuleSettings(1201, 60)})
    result, = findings(store, engine=engine)
    assert result.event_ids == tuple(ids)


def test_file_imports_can_be_reviewed_for_all_seven_new_rule_types(store, tmp_path):
    access_events = [
        access("/../private.txt"), access("/?id=1+UNION+SELECT+1"),
        access("/?q=%3Cscript%3Ealert(1)%3C/script%3E"), access("/.env"), access(method="TRACE"),
        *(access(status=503, ip=f"192.0.2.{index + 30}") for index in range(20)),
    ]
    access_path = tmp_path / "security-access.txt"
    access_path.write_text("\n".join(event.raw_log for event in access_events), encoding="utf-8")
    error_path = tmp_path / "security-error.txt"
    error_path.write_text("\n".join(error().raw_log for _ in range(10)), encoding="utf-8")

    assert ingest_file(access_path, "access", store).imported_events == 25
    assert ingest_file(error_path, "error", store).imported_events == 10
    results = findings(store)

    assert {result.rule_id for result in results} == REQUEST_IDS | {SERVER, ERROR}
    assert len(results) == 7
    assert store.count_alerts() == 0
    for result in results:
        evidence = [store.get_event(event_id).event for event_id in result.event_ids]
        assert all(event.source_file in {str(access_path.resolve()), str(error_path.resolve())} for event in evidence)
        assert all(event.line_number > 0 for event in evidence)
