import io
import sqlite3
from pathlib import Path

import pytest
from werkzeug.datastructures import MultiDict

from app import create_app
from app.database import connect_database, initialize_database
from app.storage import SQLiteStore
from app.uploads import MAX_UPLOAD_BYTES, MAX_UPLOAD_REQUEST_BYTES

ACCESS = b'192.0.2.10 - - [06/Oct/2026:09:00:00 +0000] "GET /.env HTTP/1.1" 200 0\n'
ERROR = b'[Tue Oct 06 09:00:00.123456 2026] [core:error] AH00001: Synthetic failure\n'
HEADERS = {"X-Apache-Upload": "1"}


@pytest.fixture
def workspace(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "events.sqlite3")})
    app.instance_path = str(tmp_path / "instance")
    connection = connect_database(app.config["DATABASE_PATH"])
    initialize_database(connection)
    yield app, SQLiteStore(connection)
    connection.close()


def upload(client, content=ACCESS, *, filename="access.log", log_type="access", extra=None, headers=None):
    data = {"file": (io.BytesIO(content), filename), "log_type": log_type, **(extra or {})}
    return client.post("/api/imports", data=data, headers=HEADERS if headers is None else headers)


def no_temporary_files(app):
    directory = Path(app.instance_path) / "uploads"
    assert not directory.exists() or list(directory.iterdir()) == []


def test_dashboard_and_assets_work_without_initializing_storage(tmp_path):
    path = tmp_path / "missing" / "events.sqlite3"
    app = create_app({"TESTING": True, "DATABASE_PATH": str(path)})
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200 and response.mimetype == "text/html"
    html = response.get_data(as_text=True)
    assert "<title>Apache Analyzer</title>" in html
    assert 'id="import-dialog"' in html and 'id="raw-log"' in html
    assert 'data-max-upload-bytes="10485760"' in html
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert "object-src 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    for asset, content_type in [
        ("dashboard.js", "javascript"), ("dashboard.css", "text/css"), ("mark.svg", "image/svg+xml"),
    ]:
        result = client.get("/static/" + asset)
        assert result.status_code == 200 and content_type in result.mimetype
    assert not path.parent.exists()


def test_browser_import_persists_detection_and_provenance_without_retaining_upload(workspace):
    app, store = workspace
    client = app.test_client()
    content = b"\xef\xbb\xbf\nnot an Apache record\n" + ACCESS + b"\n"
    response = upload(client, content)
    assert response.status_code == 201
    summary = response.json["summary"]
    assert summary["lines_read"] == 4 and summary["imported_events"] == 1
    assert summary["malformed_lines"] == summary["rejected_lines"] == 1 and summary["blank_lines"] == 2
    assert summary["source_file"].startswith("upload:") and summary["source_file"].endswith("/access.log")
    assert summary["detection"]["alerts_created"] == 1
    event, = store.list_events()
    assert event.event.source_file == summary["source_file"] and event.event.line_number == 3
    assert event.event.raw_log == ACCESS.decode().rstrip("\n")
    assert event.event.log_type == "access" and event.event.source_ip == "192.0.2.10"
    alert, = store.list_alerts()
    assert alert.alert.rule_id == "APACHE-SENSITIVE-FILE" and alert.event_count == 1
    evidence = client.get(f"/api/alerts/{alert.id}/events").json["items"]
    assert evidence[0]["source_file"] == summary["source_file"]
    assert client.get("/api/stats").json["events"]["total"] == 1
    no_temporary_files(app)


def test_error_upload_respects_server_timezone_and_severe_error_detection(workspace):
    app, store = workspace
    response = upload(app.test_client(), ERROR * 10, filename="error.txt", log_type="error",
                      extra={"error_timezone": "-07:00"})
    assert response.status_code == 201
    assert response.json["summary"]["assumed_timezone"] == "UTC-07:00"
    first = store.list_events()[0].event
    assert first.timestamp.isoformat() == "2026-10-06T16:00:00.123456+00:00"
    assert first.assumed_timezone == "UTC-07:00" and first.raw_log == ERROR.decode().rstrip("\n")
    alert, = store.list_alerts()
    assert alert.alert.rule_id == "APACHE-ERROR-BURST" and alert.event_count == 10
    no_temporary_files(app)


def test_reimport_has_unique_provenance_and_correlates_existing_alert(workspace):
    app, store = workspace
    client = app.test_client()
    first = upload(client).json["summary"]
    second = upload(client).json["summary"]
    assert first["source_file"] != second["source_file"]
    assert store.count_events() == 2 and store.count_alerts() == 1
    assert first["detection"]["alerts_created"] == 1
    assert second["detection"]["alerts_created"] == 0 and second["detection"]["alert_updates"] == 1
    assert store.list_alerts()[0].event_count == 2
    no_temporary_files(app)


@pytest.mark.parametrize("filename,basename", [
    ("../../victim.log", "victim.log"),
    (r"C:\\Windows\\system.ini", "system.ini"),
    ("<script>alert(1)</script>.log", "script.log"),
    ("...", "apache.log"),
    ("日志.txt", "txt"),
])
def test_filename_is_a_safe_label_and_never_an_upload_destination(workspace, filename, basename):
    app, store = workspace
    response = upload(app.test_client(), filename=filename)
    assert response.status_code == 201
    label = response.json["summary"]["source_file"]
    assert label.endswith("/" + basename)
    assert "<script>" not in label and "\\" not in label and ".." not in label
    assert store.list_events()[0].event.source_file == label
    no_temporary_files(app)


def test_filename_cannot_overwrite_existing_files(workspace, tmp_path):
    app, _ = workspace
    victim = tmp_path / "victim.log"
    victim.write_text("Keep this file", encoding="utf-8")
    response = upload(app.test_client(), filename=str(victim))
    assert response.status_code == 201
    assert victim.read_text(encoding="utf-8") == "Keep this file"
    no_temporary_files(app)


@pytest.mark.parametrize("content,log_type,rejected,blank", [
    (b"", "access", 0, 0), (b"\n \n", "access", 0, 2),
    (b"GET / HTTP/1.1\n", "access", 1, 0),
    (ERROR, "access", 1, 0), (ACCESS, "error", 1, 0),
    (b"\xff\xfe\x00\x00", "access", 1, 0),
    (b"PK\x03\x04compressed data", "access", 1, 0),
])
def test_files_without_selected_apache_format_return_summary_and_no_writes(
    workspace, content, log_type, rejected, blank,
):
    app, store = workspace
    response = upload(app.test_client(), content, log_type=log_type)
    assert response.status_code == 422
    assert response.json["error"]["code"] == "no_apache_records"
    assert response.json["summary"]["rejected_lines"] == rejected
    assert response.json["summary"]["blank_lines"] == blank
    assert response.json["summary"]["imported_events"] == 0
    assert store.count_events() == store.count_alerts() == 0
    no_temporary_files(app)


def test_invalid_utf8_and_long_lines_are_counted_while_valid_records_import(workspace):
    app, store = workspace
    response = upload(app.test_client(), b"\xff\n" + b"x" * (64 * 1024 + 1) + b"\n" + ACCESS)
    assert response.status_code == 201
    summary = response.json["summary"]
    assert summary["lines_read"] == 3 and summary["imported_events"] == 1
    assert summary["encoding_error_lines"] == summary["oversized_lines"] == 1
    assert summary["rejected_lines"] == 2
    assert store.list_events()[0].event.line_number == 3
    no_temporary_files(app)


def test_exact_ten_mib_file_is_accepted_and_one_extra_byte_is_rejected(workspace):
    app, store = workspace
    client = app.test_client()
    data = ACCESS + b"x" * (MAX_UPLOAD_BYTES - len(ACCESS))
    accepted = upload(client, data)
    assert accepted.status_code == 201
    assert accepted.json["summary"]["imported_events"] == 1
    assert accepted.json["summary"]["oversized_lines"] == 1
    before = list(store.connection.iterdump())
    rejected = upload(client, data + b"x")
    assert rejected.status_code == 413 and rejected.is_json
    assert list(store.connection.iterdump()) == before
    no_temporary_files(app)


def test_total_request_limit_is_enforced_before_file_copy(workspace):
    app, store = workspace
    response = upload(app.test_client(), b"x" * (MAX_UPLOAD_REQUEST_BYTES + 1))
    assert response.status_code == 413 and response.is_json
    assert store.count_events() == 0
    no_temporary_files(app)


@pytest.mark.parametrize("extra,log_type", [
    ({}, "ssh"), ({}, ""), ({"error_timezone": "America/Los_Angeles"}, "error"),
    ({"error_timezone": "+24:00"}, "error"), ({"error_timezone": ""}, "error"),
    ({"unknown": "value"}, "access"), ({"max_line_bytes": "100"}, "access"),
    ({"error_timezone": "x" * 20}, "access"),
])
def test_import_form_validation_precedes_database_and_temporary_file_access(workspace, extra, log_type):
    app, store = workspace
    response = upload(app.test_client(), log_type=log_type, extra=extra)
    assert response.status_code == 400 and response.json["error"]["code"] == "invalid_request"
    assert store.count_events() == store.count_alerts() == 0
    no_temporary_files(app)


@pytest.mark.parametrize("data", [
    {"log_type": "access"},
    {"file": (io.BytesIO(ACCESS), ""), "log_type": "access"},
    {"file": (io.BytesIO(ACCESS), "x" * 257), "log_type": "access"},
    {"file": (io.BytesIO(ACCESS), "access.log")},
    MultiDict([("log_type", "access"), ("log_type", "error"), ("file", (io.BytesIO(ACCESS), "access.log"))]),
    MultiDict([("file", (io.BytesIO(ACCESS), "a.log")), ("file", (io.BytesIO(ACCESS), "b.log")), ("log_type", "access")]),
])
def test_missing_or_duplicate_import_fields_are_rejected(workspace, data):
    app, store = workspace
    response = app.test_client().post("/api/imports", data=data, headers=HEADERS,
                                     content_type="multipart/form-data")
    assert response.status_code == 400 and response.is_json
    assert store.count_events() == 0
    no_temporary_files(app)


def test_form_limits_bound_metadata_and_part_counts(workspace):
    app, store = workspace
    client = app.test_client()
    large_field = upload(client, extra={"error_timezone": "x" * (128 * 1024 + 1)})
    assert large_field.status_code == 413
    many_parts = upload(client, extra={"a": "1", "b": "2", "c": "3"})
    assert many_parts.status_code == 413
    assert store.count_events() == 0
    no_temporary_files(app)


def test_upload_requires_explicit_header_and_rejects_cross_origin_requests(workspace):
    app, store = workspace
    client = app.test_client()
    for headers in ({}, {"X-Apache-Upload": "true"}, {**HEADERS, "Origin": "https://example.test"}):
        response = upload(client, headers=headers)
        assert response.status_code == 403 and response.is_json
    response = upload(client, headers={**HEADERS, "Origin": "http://localhost"})
    assert response.status_code == 201
    assert store.count_events() == 1
    preflight = client.options("/api/imports", headers={
        "Origin": "https://example.test", "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "X-Apache-Upload",
    })
    assert "Access-Control-Allow-Origin" not in preflight.headers
    no_temporary_files(app)


def test_json_and_query_parameters_are_not_import_inputs(workspace):
    app, store = workspace
    client = app.test_client()
    assert client.post("/api/imports", json={"file": "/server/path", "log_type": "access"},
                       headers=HEADERS).status_code == 415
    assert client.post("/api/imports?log_type=access", data={
        "file": (io.BytesIO(ACCESS), "access.log"), "log_type": "access",
    }, headers=HEADERS).status_code == 400
    assert client.get("/api/imports").status_code == 405
    assert store.count_events() == 0
    no_temporary_files(app)


def test_upload_does_not_initialize_a_missing_database(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "missing.sqlite3")})
    app.instance_path = str(tmp_path / "instance")
    response = upload(app.test_client())
    assert response.status_code == 503 and response.json["error"]["code"] == "database_not_ready"
    no_temporary_files(app)


def test_failure_after_detection_rolls_back_import_alert_updates_and_temp_file(workspace, monkeypatch):
    from app import uploads

    app, store = workspace
    client = app.test_client()
    assert upload(client).status_code == 201
    before = list(store.connection.iterdump())
    original = uploads.analyze_file
    copied = []

    def fail_after_detection(path, *args, **kwargs):
        copied.append(Path(path))
        result = original(path, *args, **kwargs)
        assert result.detection.alert_updates == 1
        raise sqlite3.OperationalError("Synthetic failure after analysis")

    monkeypatch.setattr(uploads, "analyze_file", fail_after_detection)
    response = upload(client)
    assert response.status_code == 503 and "Synthetic failure" not in response.get_data(as_text=True)
    assert list(store.connection.iterdump()) == before
    assert copied and all(not path.exists() for path in copied)
    no_temporary_files(app)


def test_cleanup_failure_occurs_before_commit_and_rolls_back_all_import_writes(workspace, monkeypatch):
    app, store = workspace
    original = Path.unlink

    def fail_cleanup(path, *args, **kwargs):
        if path.parent == Path(app.instance_path) / "uploads":
            raise OSError("Synthetic cleanup failure")
        return original(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", fail_cleanup)
        response = upload(app.test_client())
    assert response.status_code == 503
    assert store.count_events() == store.count_alerts() == 0
    # Remove only this test's generated files after restoring unlink.
    for path in (Path(app.instance_path) / "uploads").iterdir():
        path.unlink()


def test_source_label_override_is_validated_before_import_and_preserved(workspace, tmp_path):
    from app.pipeline import analyze_file

    _, store = workspace
    file = tmp_path / "access.txt"
    file.write_bytes(ACCESS)
    for label in ("", " ", "\0bad", "x" * 1025, 1):
        with pytest.raises(ValueError, match="source_label"):
            analyze_file(file, "access", store, source_label=label)
    assert store.count_events() == store.count_alerts() == 0
    result = analyze_file(file, "access", store, source_label="upload:synthetic/access.log")
    assert result.import_summary.source_file == "upload:synthetic/access.log"
    assert store.list_events()[0].event.source_file == result.import_summary.source_file
