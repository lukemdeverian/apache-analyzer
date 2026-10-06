"""Bounded, temporary Apache file uploads with persistent source labels."""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import uuid4

from flask import current_app, request
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import RequestEntityTooLarge, UnsupportedMediaType
from werkzeug.utils import secure_filename

from app.api import APIError, _invalid, _query, _store, api
from app.ingestion import NoApacheRecordsError, parse_error_timezone
from app.pipeline import analyze_file

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_UPLOAD_REQUEST_BYTES = MAX_UPLOAD_BYTES + 64 * 1024


@contextmanager
def _temporary_upload(upload: FileStorage) -> Iterator[Path]:
    directory = Path(current_app.instance_path) / "uploads"
    directory.mkdir(parents=True, exist_ok=True)
    temporary = NamedTemporaryFile(mode="wb", prefix="apache-", suffix=".tmp", dir=directory, delete=False)
    path = Path(temporary.name)
    try:
        with temporary:
            size = 0
            while chunk := upload.stream.read(min(64 * 1024, MAX_UPLOAD_BYTES - size + 1)):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise RequestEntityTooLarge("Apache files must be no larger than 10 MiB.")
                temporary.write(chunk)
        yield path
    finally:
        # Only the unique file created above is removed; client filenames never
        # determine a filesystem path. Cleanup runs before the database commit.
        path.unlink(missing_ok=True)


@api.post("/imports")
def import_file() -> tuple[dict, int]:
    _query(set())
    request.max_content_length = MAX_UPLOAD_REQUEST_BYTES
    request.max_form_memory_size = 128 * 1024
    request.max_form_parts = 4
    # A custom header prevents a cross-origin HTML form from submitting a
    # simple multipart request. The API does not enable cross-origin access.
    if request.headers.get("X-Apache-Upload") != "1":
        raise APIError(403, "upload_header_required", "File imports require X-Apache-Upload: 1.")
    origin = request.headers.get("Origin")
    if origin is not None and origin != request.host_url.rstrip("/"):
        raise APIError(403, "origin_not_allowed", "Import files from this application's origin.")
    if request.mimetype != "multipart/form-data":
        raise UnsupportedMediaType("Use multipart/form-data with a file and log_type.")
    if request.form.keys() - {"log_type", "error_timezone"} or request.files.keys() != {"file"}:
        _invalid("Provide one file and log_type, with an optional error_timezone.")
    if any(len(values) != 1 for _, values in (*request.form.lists(), *request.files.lists())):
        _invalid("Import fields must not be repeated.")
    log_type = request.form.get("log_type")
    if log_type not in ("access", "error"):
        _invalid("log_type must be access or error.")
    timezone_value = request.form.get("error_timezone", "UTC")
    if len(timezone_value) > 16:
        _invalid("error_timezone must be UTC or a signed UTC offset.")
    try:
        error_timezone = parse_error_timezone(timezone_value)
    except ValueError as exc:
        _invalid(str(exc))
    upload = request.files["file"]
    if not upload.filename or len(upload.filename) > 256:
        _invalid("Select a file with a filename of at most 256 characters.")
    basename = upload.filename.replace("\\", "/").rsplit("/", 1)[-1]
    filename = secure_filename(basename)[:128] or "apache.log"
    source_label = f"upload:{uuid4().hex}/{filename}"
    with _store() as store:
        with _temporary_upload(upload) as path:
            try:
                result = analyze_file(path, log_type, store, error_timezone=error_timezone, source_label=source_label)
            except NoApacheRecordsError as exc:
                return {
                    "error": {
                        "code": "no_apache_records",
                        "message": (
                            f"No supported Apache {log_type} records found. "
                            "Check the file content and selected format. No events or alert changes were saved."
                        ),
                    },
                    "summary": exc.summary.as_dict(),
                }, 422
    return {"summary": result.as_dict()}, 201
