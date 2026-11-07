import os
from pathlib import Path
import secrets

from dotenv import load_dotenv
from flask import Flask, jsonify

from server.db import init_db
from server.routes import api_bp
from server.web import web_bp

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _resolve_database_path(value: str) -> str:
    """Resolve relative database paths from the repository root."""
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return str(path.resolve())


def _resolve_secret_key(project_root: Path) -> str:
    """Retrieve or persist a stable SECRET_KEY to prevent session invalidation across reboots."""
    env_secret = os.getenv("SECRET_KEY")
    if env_secret and env_secret.strip():
        return env_secret.strip()

    key_file = project_root / "data" / ".secret_key"
    try:
        if key_file.is_file():
            content = key_file.read_text(encoding="utf-8").strip()
            if content:
                return content
        key_file.parent.mkdir(parents=True, exist_ok=True)
        new_key = secrets.token_hex(32)
        key_file.write_text(new_key, encoding="utf-8")
        try:
            key_file.chmod(0o600)
        except OSError:
            pass
        return new_key
    except Exception:
        return secrets.token_hex(32)


def create_app(test_config=None):
    """Application factory used by both the server and pytest."""
    load_dotenv()

    app = Flask(
        __name__,
        template_folder=str(PROJECT_ROOT / "templates"),
        static_folder=str(PROJECT_ROOT / "static"),
    )
    default_database_path = os.getenv(
        "EDR_DATABASE_PATH",
        str(PROJECT_ROOT / "data" / "mini_edr.db"),
    )

    app.config.from_mapping(
        SECRET_KEY=_resolve_secret_key(PROJECT_ROOT),
        EDR_API_TOKEN=os.getenv("EDR_API_TOKEN"),
        DATABASE_PATH=_resolve_database_path(default_database_path),
        OFFLINE_AFTER_SECONDS=int(os.getenv("EDR_OFFLINE_AFTER_SECONDS", "15")),
        MAX_CONTENT_LENGTH=int(os.getenv("EDR_MAX_CONTENT_LENGTH", str(16 * 1024 * 1024))),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("EDR_COOKIE_SECURE", "false").lower() in ("true", "1", "yes"),
        PERMANENT_SESSION_LIFETIME=int(os.getenv("EDR_SESSION_LIFETIME_SECONDS", "3600")),
    )

    if test_config:
        app.config.update(test_config)

    if app.config["OFFLINE_AFTER_SECONDS"] <= 0:
        raise ValueError("OFFLINE_AFTER_SECONDS must be greater than zero")

    # FINDING-PHASE01-05: Enforce token strength policy in factory when not running tests
    if not app.config.get("TESTING"):
        api_token = app.config.get("EDR_API_TOKEN")
        if (
            not isinstance(api_token, str)
            or len(api_token) < 32
            or api_token == "replace-with-a-long-random-token"
        ):
            raise ValueError(
                "EDR_API_TOKEN is missing or too weak (must be >= 32 characters). "
                "Generate a token with 'python -c \"import secrets; print(secrets.token_urlsafe(32))\"' "
                "and set it in your environment or .env file."
            )

    init_db(app.config["DATABASE_PATH"])
    app.register_blueprint(api_bp)
    app.register_blueprint(web_bp)

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

    @app.errorhandler(UnicodeDecodeError)
    def malformed_utf8_error(_error):
        return jsonify({
            "success": False,
            "error": "Malformed UTF-8 encoding in request payload",
        }), 400

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(
        host=os.getenv("EDR_HOST", "127.0.0.1"),
        port=int(os.getenv("EDR_PORT", "5000")),
        debug=False,
    )
