import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify

from server.db import init_db
from server.routes import api_bp

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _resolve_database_path(value: str) -> str:
    """Resolve relative database paths from the repository root."""
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return str(path.resolve())


def create_app(test_config=None):
    """Application factory used by both the server and pytest."""
    load_dotenv()

    app = Flask(__name__)
    default_database_path = os.getenv(
        "EDR_DATABASE_PATH",
        str(PROJECT_ROOT / "data" / "mini_edr.db"),
    )

    app.config.from_mapping(
        EDR_API_TOKEN=os.getenv("EDR_API_TOKEN"),
        DATABASE_PATH=_resolve_database_path(default_database_path),
        OFFLINE_AFTER_SECONDS=int(os.getenv("EDR_OFFLINE_AFTER_SECONDS", "15")),
        MAX_CONTENT_LENGTH=64 * 1024,
    )

    if test_config:
        app.config.update(test_config)

    if app.config["OFFLINE_AFTER_SECONDS"] <= 0:
        raise ValueError("OFFLINE_AFTER_SECONDS must be greater than zero")

    init_db(app.config["DATABASE_PATH"])
    app.register_blueprint(api_bp)

    @app.get("/health")
    def health_check():
        return jsonify({
            "status": "ok",
            "service": "mini-edr-server",
            "version": "0.2.0",
        }), 200

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify({
            "success": False,
            "error": "Request body is too large",
        }), 413

    return app


app = create_app()


if __name__ == "__main__":
    if not app.config.get("EDR_API_TOKEN"):
        raise SystemExit(
            "EDR_API_TOKEN is not configured. Create a .env file before starting the server."
        )

    app.run(
        host=os.getenv("EDR_HOST", "127.0.0.1"),
        port=int(os.getenv("EDR_PORT", "5000")),
        debug=False,
    )
