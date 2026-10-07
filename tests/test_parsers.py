from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path

import pytest

from app.parsers import parse_access_line, parse_apache_line, parse_error_line

FIXTURES = Path(__file__).with_name("fixtures")
COMMON = '192.0.2.10 - alex [06/Oct/2026:09:00:01 -0700] "GET /index.html HTTP/1.1" 200 1234'
ERROR = (
    "[Tue Oct 06 09:01:02.123456 2026] [authz_core:error] [pid 4120:tid 8801] "
    "[client 192.0.2.20:52102] AH01630: client denied by server configuration: /srv/www/private"
)


@pytest.mark.parametrize("filename, log_type", [
    ("access_common.txt", "access"), ("access_combined.txt", "access"),
    ("access_combined_extended.txt", "access"),
    ("error_standard.txt", "error"), ("error_legacy.txt", "error"),
])
def test_synthetic_fixture_records(filename, log_type):
    fixture = FIXTURES / filename
    lines = fixture.read_text(encoding="utf-8").splitlines(keepends=True)

    for line_number, line in enumerate(lines, start=1):
        event = parse_apache_line(line, log_type, source_file=str(fixture), line_number=line_number)
        assert event is not None, f"{filename}:{line_number} was not parsed"
        assert event.log_type == log_type
        assert event.timestamp.tzinfo is timezone.utc
        assert event.raw_log == line.removesuffix("\n")
        assert event.source_file == str(fixture)
        assert event.line_number == line_number


def test_common_access_fields_and_negative_utc_offset():
    event = parse_access_line(COMMON)

    assert event is not None
    assert event.log_format == "common"
    assert event.timestamp == datetime(2026, 10, 6, 16, 0, 1, tzinfo=timezone.utc)
    assert event.assumed_timezone is None
    assert event.source_host == event.source_ip == "192.0.2.10"
    assert event.remote_logname is None
    assert event.username == "alex"
    assert event.request == "GET /index.html HTTP/1.1"
    assert event.method == "GET"
    assert event.request_target == event.path == "/index.html"
    assert event.query_string is None
    assert event.protocol == "HTTP/1.1"
    assert event.status_code == 200
    assert event.response_bytes == 1234
    assert event.referrer is None
    assert event.user_agent is None


def test_combined_fields_and_positive_utc_offset():
    line = (FIXTURES / "access_combined.txt").read_text(encoding="utf-8").splitlines()[0]
    event = parse_access_line(line)

    assert event is not None
    assert event.log_format == "combined"
    assert event.timestamp == datetime(2026, 10, 6, 3, 30, 4, tzinfo=timezone.utc)
    assert event.path == "/search"
    assert event.query_string == "q=%27test%27"
    assert event.referrer == "https://example.test/start"
    assert event.user_agent == "ExampleBrowser/1.0"


def test_extended_combined_keeps_core_fields_and_full_raw_evidence():
    line = (FIXTURES / "access_combined_extended.txt").read_text(encoding="utf-8").splitlines()[2]
    event = parse_access_line(line, source_file="bot-tracking.log", line_number=3)

    assert event is not None
    assert event.log_format == "extended_combined"
    assert event.timestamp == datetime(2026, 9, 24, 0, 12, 18, tzinfo=timezone.utc)
    assert event.source_ip == "2001:db8::12" and event.username == "alex"
    assert event.method == "GET" and event.path == event.request_target == "/.env"
    assert event.protocol == "HTTP/2.0" and event.status_code == 404
    assert event.response_bytes == 123 and event.referrer is None
    assert event.user_agent == "ExampleBrowser/2.0"
    assert event.raw_log == line
    assert event.source_file == "bot-tracking.log" and event.line_number == 3


@pytest.mark.parametrize("suffix", [
    ' lang:"en-US,en;q=0.9" enc:"gzip, deflate, br" proto:HTTP/1.1 reqtime:1692',
    ' chua:"\\"Chromium\\";v=\\"125\\"" chplat:"\\"Windows\\""',
    ' lang:"" enc:"-"',
    " proto:HTTP/2 reqtime:-",
    '\ttrace.id:abc-1\tX_Custom:"value with spaces: colon"  ',
    ' note:"literal\\\\backslash and \\x41"',
    " status:500 source_ip:198.51.100.99 proto:HTTP/2",
])
def test_named_extensions_accept_quoted_and_bare_values_without_overriding_core_fields(suffix):
    line = COMMON + ' "-" "ExampleBrowser/1.0"' + suffix
    event = parse_access_line(line)

    assert event is not None
    assert event.log_format == "extended_combined"
    assert event.source_ip == "192.0.2.10" and event.status_code == 200
    assert event.protocol == "HTTP/1.1" and event.path == "/index.html"
    assert event.raw_log == line and event.user_agent == "ExampleBrowser/1.0"


@pytest.mark.parametrize("suffix", [
    " unexpected trailing field", " reqtime:", ' lang:"unterminated',
    ' lang:"ok"junk', ' lang:"ok"reqtime:12', " reqtime:12 unlabeled",
    " =bad:value", " :value", " reqtime=12", ' "extra unlabeled field"',
    ' lang:"ok"\nreqtime:12',
])
def test_malformed_combined_extensions_are_rejected(suffix):
    assert parse_access_line(COMMON + ' "-" "ExampleBrowser/1.0"' + suffix) is None


def test_named_extensions_require_complete_combined_fields():
    assert parse_access_line(COMMON + ' lang:"en-US"') is None
    assert parse_access_line(COMMON + ' "-" lang:"en-US"') is None


def test_apache_escaping_preserves_raw_evidence():
    line = (FIXTURES / "access_combined.txt").read_text(encoding="utf-8").splitlines()[1]
    event = parse_access_line(line)

    assert event is not None
    assert event.user_agent == 'Probe "quoted" \\agent'
    assert event.raw_log == line
    assert event.path == "/%2e%2e/private"
    assert event.query_string == "next=%2Fadmin"
    assert event.referrer is None


@pytest.mark.parametrize("agent, expected", [
    (r"caf\xc3\xa9", "café"),
    (r"line\tvalue\nnext", "line\tvalue\nnext"),
    (r"literal\\x41", r"literal\x41"),
    (r"unknown\u002f", r"unknown\u002f"),
    (r"invalid\xff", r"invalid\xff"),
])
def test_escape_decoding_is_single_pass_and_handles_raw_bytes(agent, expected):
    event = parse_access_line(COMMON + f' "-" "{agent}"')

    assert event is not None
    assert event.user_agent == expected


@pytest.mark.parametrize("target, method, path, query", [
    ("/%2e%2e/admin?x=%3Cscript%3E", "GET", "/%2e%2e/admin", "x=%3Cscript%3E"),
    ("/a/../b", "GET", "/a/../b", None),
    ("//admin", "GET", "//admin", None),
    ("/search?", "GET", "/search", ""),
    ("*", "OPTIONS", "*", None),
    ("example.test:443", "CONNECT", None, None),
    ("http://example.test/a/../b?x=%2f", "GET", "/a/../b", "x=%2f"),
    ("http://example.test?x=1", "GET", "/", "x=1"),
    (r"/bad\x20path", "GET", "/bad path", None),
])
def test_targets_are_separated_without_normalizing_probes(target, method, path, query):
    request = f"{method} {target} HTTP/1.1"
    event = parse_access_line(COMMON.replace("GET /index.html HTTP/1.1", request))

    assert event is not None
    assert event.method == method
    assert event.path == path
    assert event.query_string == query
    assert event.request_target == target.replace(r"\x20", " ")


@pytest.mark.parametrize("request_line, expected", [
    ("-", None),
    ("", ""),
    ("bad request line with extra words", "bad request line with extra words"),
    (r"\x16\x03\x01", "\x16\x03\x01"),
])
def test_unparseable_requests_remain_available_as_access_evidence(request_line, expected):
    line = COMMON.replace("GET /index.html HTTP/1.1", request_line).replace("200 1234", "400 -")
    event = parse_access_line(line)

    assert event is not None
    assert event.request == expected
    assert event.method is None
    assert event.request_target is None
    assert event.path is None
    assert event.status_code == 400
    assert event.response_bytes == 0


def test_request_without_protocol_does_not_invent_one():
    event = parse_access_line(COMMON.replace("GET /index.html HTTP/1.1", "GET /index.html"))

    assert event is not None
    assert event.method == "GET"
    assert event.path == "/index.html"
    assert event.protocol is None


@pytest.mark.parametrize("host, expected_ip", [
    ("2001:0db8:0:0:0:0:0:1", "2001:db8::1"),
    ("client.example.test", None),
    ("-", None),
])
def test_access_hosts_are_preserved_without_dns_lookups(host, expected_ip):
    event = parse_access_line(COMMON.replace("192.0.2.10", host))

    assert event is not None
    assert event.source_host == (None if host == "-" else host)
    assert event.source_ip == expected_ip


@pytest.mark.parametrize("ending", ["", "\n", "\r\n", "\r"])
def test_only_final_line_endings_are_removed(ending):
    line = COMMON + "  "
    event = parse_access_line(line + ending)

    assert event is not None
    assert event.raw_log == line


@pytest.mark.parametrize("line", [
    "", "  ", "this is not an Apache record", ERROR,
    COMMON.replace("06/Oct/2026", "31/Feb/2026"),
    COMMON.replace("Oct", "Bog"),
    COMMON.replace("-0700", "+2400"),
    COMMON.replace("-0700", "+0160"),
    COMMON.replace("09:00:01", "25:00:01"),
    COMMON.replace("200 1234", "099 1234"),
    COMMON.replace("200 1234", "600 1234"),
    COMMON.replace("200 1234", "ok 1234"),
    COMMON.replace("200 1234", "200 -10"),
    COMMON.replace('"GET /index.html HTTP/1.1"', '"GET /index.html HTTP/1.1'),
    COMMON + ' "referrer only"',
    COMMON + " unexpected trailing field",
    COMMON + "\n" + COMMON,
])
def test_malformed_or_unsupported_access_records_are_rejected(line):
    assert parse_access_line(line) is None


def test_standard_error_fields_and_microseconds():
    event = parse_error_line(ERROR, source_file="error.log", line_number=7)

    assert event is not None
    assert event.log_format == "error_2_4"
    assert event.timestamp == datetime(2026, 10, 6, 9, 1, 2, 123456, tzinfo=timezone.utc)
    assert event.assumed_timezone == "UTC"
    assert event.source_ip == event.source_host == "192.0.2.20"
    assert event.source_port == 52102
    assert event.module == "authz_core"
    assert event.level == "error"
    assert event.process_id == 4120
    assert event.thread_id == "8801"
    assert event.error_code == "AH01630"
    assert event.message == "AH01630: client denied by server configuration: /srv/www/private"
    assert event.source_file == "error.log"
    assert event.line_number == 7
    assert event.status_code is None
    assert event.path is None


def test_error_timestamp_uses_supplied_timezone():
    assumed = timezone(timedelta(hours=-7))
    event = parse_apache_line(ERROR, "error", error_timezone=assumed)

    assert event is not None
    assert event.timestamp == datetime(2026, 10, 6, 16, 1, 2, 123456, tzinfo=timezone.utc)
    assert event.assumed_timezone == "UTC-07:00"


def test_server_error_without_client_and_fractional_timestamp_padding():
    line = "[Tue Oct 06 09:01:02.12 2026] [core:notice] [pid 4120] AH00094: Server starting"
    event = parse_error_line(line)

    assert event is not None
    assert event.timestamp.microsecond == 120000
    assert event.source_ip is None
    assert event.source_port is None
    assert event.thread_id is None
    assert event.error_code == "AH00094"


@pytest.mark.parametrize("endpoint, expected_ip, expected_port", [
    ("192.0.2.20", "192.0.2.20", None),
    ("192.0.2.20:0", "192.0.2.20", 0),
    ("192.0.2.20:65535", "192.0.2.20", 65535),
    ("[2001:db8::20]:8080", "2001:db8::20", 8080),
    ("[2001:db8::20]", "2001:db8::20", None),
    ("2001:db8::20:8080", "2001:db8::20", 8080),
    ("::1", "::1", None),
])
def test_error_client_addresses(endpoint, expected_ip, expected_port):
    event = parse_error_line(ERROR.replace("192.0.2.20:52102", endpoint))

    assert event is not None
    assert event.source_ip == expected_ip
    assert event.source_port == expected_port


def test_legacy_error_preserves_bare_ipv6_address():
    line = "[Tue Oct  6 09:10:01 2026] [warn] [client 2001:db8::abcd:12] Request timeout"
    event = parse_error_line(line)

    assert event is not None
    assert event.log_format == "error_legacy"
    assert event.source_ip == "2001:db8::abcd:12"
    assert event.source_port is None
    assert event.module is None
    assert event.process_id is None
    assert event.error_code is None
    assert event.message == "Request timeout"


def test_hexadecimal_thread_id_and_os_error_prefix():
    line = ERROR.replace("tid 8801", "tid 0x1a2B").replace("AH01630:", "(13)Permission denied: AH01630:")
    event = parse_error_line(line)

    assert event is not None
    assert event.thread_id == "0x1a2B"
    assert event.error_code == "AH01630"
    assert event.message.startswith("(13)Permission denied:")


@pytest.mark.parametrize("level", ["emerg", "alert", "crit", "error", "warn", "notice", "info", "debug", "trace1", "trace8"])
def test_apache_error_levels(level):
    event = parse_error_line(ERROR.replace("authz_core:error", f"authz_core:{level}"))

    assert event is not None
    assert event.level == level


@pytest.mark.parametrize("line", [
    "", "not an Apache error record", COMMON,
    ERROR.replace("Oct 06", "Feb 31"),
    ERROR.replace("Oct", "Bog"),
    ERROR.replace("09:01:02", "24:01:02"),
    ERROR.replace(".123456", ".1234567"),
    ERROR.replace("authz_core:error", "authz_core:fatal"),
    ERROR.replace("pid 4120", "pid unknown"),
    ERROR.replace("tid 8801", "tid unknown"),
    ERROR.replace("192.0.2.20:52102", "192.0.2.20:65536"),
    ERROR.replace("192.0.2.20:52102", "192.0.2.20:notaport"),
    ERROR.replace("192.0.2.20:52102", "999.0.2.20:1234"),
    ERROR[:ERROR.index("AH01630:")],
    ERROR + "\n" + ERROR,
])
def test_malformed_or_unsupported_error_records_are_rejected(line):
    assert parse_error_line(line) is None


@pytest.mark.parametrize("log_type", ["linux_auth", "network_telemetry", "auto", "", "ACCESS"])
def test_other_log_sources_are_rejected(log_type):
    with pytest.raises(ValueError, match="Unsupported Apache log type"):
        parse_apache_line(COMMON, log_type)


def test_format_selection_is_explicit():
    assert parse_apache_line(ERROR, "access") is None
    assert parse_apache_line(COMMON, "error") is None


@pytest.mark.parametrize("line_number", [0, -1, 1.5, True, "1"])
def test_invalid_provenance_is_rejected(line_number):
    with pytest.raises(ValueError, match="line_number"):
        parse_access_line(COMMON, line_number=line_number)
    with pytest.raises(ValueError, match="line_number"):
        parse_error_line(ERROR, line_number=line_number)


@pytest.mark.parametrize("invalid_timezone", [None, "UTC", tzinfo()])
def test_invalid_error_timezone_is_rejected(invalid_timezone):
    with pytest.raises(ValueError, match="error_timezone"):
        parse_error_line(ERROR, error_timezone=invalid_timezone)
