"""Isolated server used only by browser_dashboard.mjs."""

import json
import sys
from pathlib import Path

from werkzeug.serving import make_server

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
from app.database import connect_database, initialize_database

if __name__ == "__main__":
    workspace = Path(sys.argv[1]).resolve()
    database = workspace / "browser.sqlite3"
    app = create_app({"DATABASE_PATH": str(database), "DEBUG": False})
    app.instance_path = str(workspace / "instance")
    connection = connect_database(database)
    initialize_database(connection)
    connection.close()
    server = make_server("127.0.0.1", 0, app, threaded=True)
    print(json.dumps({"url": f"http://127.0.0.1:{server.server_port}"}), flush=True)
    server.serve_forever()
