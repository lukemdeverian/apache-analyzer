"""Run the Apache analyzer locally."""

from pathlib import Path

from dotenv import load_dotenv

from app import create_app


def main() -> None:
    load_dotenv(Path(__file__).with_name(".env"))
    app = create_app()
    app.run(
        host=app.config["APP_HOST"],
        port=app.config["APP_PORT"],
        debug=app.config["DEBUG"],
    )


if __name__ == "__main__":
    main()
