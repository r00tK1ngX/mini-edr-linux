
import os

from dotenv import load_dotenv
from flask import Flask, jsonify

from server.db import init_db
from server.routes import api_bp

load_dotenv()


def create_app():
    app = Flask(__name__)

    app.config["EDR_API_TOKEN"] = os.getenv("EDR_API_TOKEN")

    init_db()
    app.register_blueprint(api_bp)

    @app.get("/health")
    def health_check():
        return jsonify({
            "status": "ok",
            "service": "mini-edr-server",
            "version": "0.1.0"
        }), 200

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )

