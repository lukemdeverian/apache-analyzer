from app import create_app


def test_health_does_not_require_storage(tmp_path):
    database_path = tmp_path / "not_created" / "events.sqlite3"
    app = create_app({"TESTING": True, "DATABASE_PATH": str(database_path)})

    response = app.test_client().get("/health")

    assert response.status_code == 200
    assert response.is_json
    assert response.get_json() == {"service": "apache-analyzer", "status": "ok"}
    assert not database_path.parent.exists()


def test_factory_isolates_application_configuration():
    first = create_app({"TESTING": True, "APP_PORT": 5050})
    second = create_app({"TESTING": True})

    assert first.config["APP_PORT"] == 5050
    assert second.config["APP_PORT"] == 5000
    assert second.config["APP_HOST"] == "127.0.0.1"
    assert second.config["DEBUG"] is False
