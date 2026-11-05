from datetime import datetime, timezone
from hmac import compare_digest
from ipaddress import ip_address as parse_ip_address
from math import isfinite

from flask import Blueprint, current_app, jsonify, request

from server.db import list_endpoints, upsert_endpoint

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


@api_bp.before_request
def require_agent_token():
    """Protect every Phase 1 API route with a Bearer token."""
    expected_token = current_app.config.get("EDR_API_TOKEN")
    authorization = request.headers.get("Authorization", "")
    scheme, separator, supplied_token = authorization.partition(" ")

    authenticated = (
        isinstance(expected_token, str)
        and bool(expected_token)
        and scheme.lower() == "bearer"
        and bool(separator)
        and bool(supplied_token.strip())
        and compare_digest(
            supplied_token.strip().encode("utf-8"),
            expected_token.encode("utf-8"),
        )
    )

    if not authenticated:
        response = jsonify({
            "success": False,
            "error": "unauthorized",
        })
        response.status_code = 401
        response.headers["WWW-Authenticate"] = 'Bearer realm="mini-edr"'
        return response


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def is_valid_number(value):
    """Reject booleans, non-numeric values, NaN and positive/negative infinity."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return isfinite(value)
    except (OverflowError, TypeError):
        return False


def _error(message, status_code=400):
    return jsonify({"success": False, "error": message}), status_code


def _validate_optional_string(payload, field, max_length):
    value = payload.get(field)
    if value is not None and (
        not isinstance(value, str) or len(value) > max_length
    ):
        return False
    return True


@api_bp.post("/heartbeat")
def heartbeat():
    if not request.is_json:
        return _error("Content-Type must be application/json")

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("Request body must be a valid JSON object")

    required_fields = {
        "agent_id": 128,
        "hostname": 255,
        "os": 100,
    }
    for field, max_length in required_fields.items():
        value = payload.get(field)
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value.strip()) > max_length
        ):
            return _error(f"Missing or invalid field: {field}")

    if not _validate_optional_string(payload, "agent_version", 50):
        return _error("agent_version must be a string of at most 50 characters or null")

    ip_value = payload.get("ip_address")
    if ip_value is not None:
        if not isinstance(ip_value, str) or len(ip_value) > 45:
            return _error("ip_address must be a valid IPv4/IPv6 address or null")
        try:
            ip_value = str(parse_ip_address(ip_value))
        except ValueError:
            return _error("ip_address must be a valid IPv4/IPv6 address or null")

    metrics = payload.get("metrics", {})
    if not isinstance(metrics, dict):
        return _error("metrics must be a JSON object")

    metric_fields = (
        "cpu_percent",
        "memory_percent",
        "disk_percent",
        "uptime_seconds",
    )
    for field in metric_fields:
        value = metrics.get(field)
        if value is None:
            continue
        if not is_valid_number(value):
            return _error(f"Invalid numeric metric: {field}")
        if value < 0:
            return _error(f"Metric cannot be negative: {field}")

    for field in ("cpu_percent", "memory_percent", "disk_percent"):
        value = metrics.get(field)
        if value is not None and value > 100:
            return _error(f"Metric must be between 0 and 100: {field}")

    endpoint = {
        "agent_id": payload["agent_id"].strip(),
        "hostname": payload["hostname"].strip(),
        "ip_address": ip_value,
        "os": payload["os"].strip(),
        "agent_version": payload.get("agent_version"),
        "cpu_percent": metrics.get("cpu_percent"),
        "memory_percent": metrics.get("memory_percent"),
        "disk_percent": metrics.get("disk_percent"),
        "uptime_seconds": metrics.get("uptime_seconds"),
        "last_seen": utc_now(),
    }

    try:
        saved_endpoint = upsert_endpoint(
            endpoint,
            current_app.config["DATABASE_PATH"],
        )
    except Exception:
        current_app.logger.exception("Failed to save endpoint heartbeat")
        return _error("Internal server error", 500)

    return jsonify({
        "success": True,
        "agent_id": saved_endpoint["agent_id"],
        "server_time": saved_endpoint["last_seen"],
    }), 200


@api_bp.get("/endpoints")
def get_endpoints():
    try:
        endpoints = list_endpoints(
            current_app.config["DATABASE_PATH"],
            current_app.config["OFFLINE_AFTER_SECONDS"],
        )
    except Exception:
        current_app.logger.exception("Failed to retrieve endpoints")
        return _error("Internal server error", 500)

    return jsonify({
        "success": True,
        "count": len(endpoints),
        "endpoints": endpoints,
    }), 200
