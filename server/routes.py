
import os
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request

from server.db import upsert_endpoint

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def is_valid_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
    )


@api_bp.post("/heartbeat")
def heartbeat():
    # Authenticate the Agent using a bearer token.
    expected_token = current_app.config.get("EDR_API_TOKEN")
    authorization = request.headers.get("Authorization", "")
    supplied_token = ""

    if authorization.startswith("Bearer "):
        supplied_token = authorization.removeprefix("Bearer ").strip()

    if not expected_token or supplied_token != expected_token:
        return jsonify({
            "success": False,
            "error": "unauthorized"
        }), 401

    if not request.is_json:
        return jsonify({
            "success": False,
            "error": "Content-Type must be application/json"
        }), 400

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({
            "success": False,
            "error": "Invalid JSON object"
        }), 400

    required_fields = ("agent_id", "hostname", "os")

    for field in required_fields:
        if not isinstance(payload.get(field), str) or not payload[field].strip():
            return jsonify({
                "success": False,
                "error": f"Missing or invalid field: {field}"
            }), 400

    metrics = payload.get("metrics", {})

    if not isinstance(metrics, dict):
        return jsonify({
            "success": False,
            "error": "metrics must be a JSON object"
        }), 400

    metric_fields = (
        "cpu_percent",
        "memory_percent",
        "disk_percent",
        "uptime_seconds"
    )

    for field in metric_fields:
        value = metrics.get(field)

        if value is not None and not is_valid_number(value):
            return jsonify({
                "success": False,
                "error": f"Invalid numeric metric: {field}"
            }), 400

        if value is not None and value < 0:
            return jsonify({
                "success": False,
                "error": f"Metric cannot be negative: {field}"
            }), 400

    for field in ("cpu_percent", "memory_percent", "disk_percent"):
        value = metrics.get(field)
        if value is not None and value > 100:
            return jsonify({
                "success": False,
                "error": f"Metric must be between 0 and 100: {field}"
            }), 400

    endpoint = {
        "agent_id": payload["agent_id"].strip(),
        "hostname": payload["hostname"].strip(),
        "ip_address": payload.get("ip_address"),
        "os": payload["os"].strip(),
        "agent_version": payload.get("agent_version"),
        "cpu_percent": metrics.get("cpu_percent"),
        "memory_percent": metrics.get("memory_percent"),
        "disk_percent": metrics.get("disk_percent"),
        "uptime_seconds": metrics.get("uptime_seconds"),
        # Use server time as the authoritative last-seen time.
        "last_seen": utc_now()
    }

    if not isinstance(endpoint["ip_address"], (str, type(None))):
        return jsonify({
            "success": False,
            "error": "ip_address must be a string or null"
        }), 400

    if not isinstance(endpoint["agent_version"], (str, type(None))):
        return jsonify({
            "success": False,
            "error": "agent_version must be a string or null"
        }), 400

    try:
        saved_endpoint = upsert_endpoint(endpoint)
    except Exception:
        current_app.logger.exception("Failed to save endpoint heartbeat")
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

    return jsonify({
        "success": True,
        "agent_id": saved_endpoint["agent_id"],
        "server_time": saved_endpoint["last_seen"]
    }), 200

