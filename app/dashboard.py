"""Local HTML dashboard; all evidence is fetched through the JSON APIs."""

from flask import Blueprint, Flask, Response, render_template

from app.ingestion import DEFAULT_MAX_DECOMPRESSED_BYTES
from app.uploads import MAX_UPLOAD_BYTES

dashboard = Blueprint("dashboard", __name__)


@dashboard.get("/")
def index() -> str:
    return render_template(
        "dashboard.html", max_upload_bytes=MAX_UPLOAD_BYTES,
        max_decompressed_bytes=DEFAULT_MAX_DECOMPRESSED_BYTES,
    )


def init_app(app: Flask) -> None:
    app.register_blueprint(dashboard)

    @app.after_request
    def dashboard_headers(response: Response) -> Response:
        if response.mimetype == "text/html" and response.status_code == 200:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self'; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
            )
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response
