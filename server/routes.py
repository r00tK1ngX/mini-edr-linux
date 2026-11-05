from datetime import datetime, timezone
from hmac import compare_digest
from ipaddress import ip_address as parse_ip_address
from math import isfinite
from typing import Any, Dict, Optional, Tuple
import uuid

from flask import Blueprint, current_app, jsonify, request

from server.db import get_connection, list_endpoints, upsert_endpoint
from server.repositories.alert_repository import AlertRepository
from server.repositories.baseline_repository import BaselineRepository
from server.repositories.endpoint_repository import EndpointRepository
from server.repositories.event_repository import EventRepository
from server.repositories.metrics_repository import MetricsRepository
from server.repositories.process_repository import ProcessRepository

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


@api_bp.before_request
def require_agent_token():
    """Protect every Phase 1 & Phase 2 API route with a Bearer token."""
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


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_valid_number(value: Any) -> bool:
    """Reject booleans, non-numeric values, NaN and positive/negative infinity."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return isfinite(value)
    except (OverflowError, TypeError):
        return False


def is_valid_uuid4(val: Any) -> bool:
    """Validate that val is a valid UUID version 4 string."""
    if not isinstance(val, str) or not val.strip():
        return False
    try:
        u = uuid.UUID(val.strip(), version=4)
        return str(u).lower() == val.strip().lower()
    except (ValueError, AttributeError, TypeError):
        return False


def is_valid_iso8601_utc(val: Any) -> bool:
    """Validate that val is a valid ISO 8601 UTC timestamp string."""
    if not isinstance(val, str) or not val.strip():
        return False
    try:
        dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
        return dt.tzinfo is not None
    except Exception:
        return False


def is_valid_sha256(val: Any) -> bool:
    """Validate 64-character lowercase hexadecimal SHA-256 string."""
    if not isinstance(val, str) or len(val) != 64:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in val)


def _error(message: str, status_code: int = 400):
    return jsonify({"success": False, "error": message}), status_code


def _validate_optional_string(payload: Dict[str, Any], field: str, max_length: int) -> bool:
    value = payload.get(field)
    if value is not None and (
        not isinstance(value, str) or len(value) > max_length
    ):
        return False
    return True


def _validate_envelope(req) -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[Any, int]]]:
    """Validate standard Phase 2 Message Envelope."""
    if not req.is_json:
        return None, _error("Content-Type must be application/json")

    body = req.get_json(silent=True)
    if not isinstance(body, dict):
        return None, _error("Request body must be a valid JSON object")

    schema_version = body.get("schema_version")
    if schema_version != "1.0":
        return None, _error(f"Unsupported schema_version: '{schema_version}'. Supported version is '1.0'")

    message_id = body.get("message_id")
    if not is_valid_uuid4(message_id):
        return None, _error("message_id must be a valid UUID v4 string")

    agent_id = body.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id.strip() or len(agent_id.strip()) > 128:
        return None, _error("agent_id must be a non-empty string of at most 128 characters")

    collected_at = body.get("collected_at")
    if not is_valid_iso8601_utc(collected_at):
        return None, _error("collected_at must be a valid ISO 8601 UTC timestamp")

    payload = body.get("payload")
    if not isinstance(payload, dict):
        return None, _error("payload must be a JSON object")

    return body, None


def _check_agent_registered(agent_id: str, db_path: str) -> bool:
    repo = EndpointRepository(db_path)
    return repo.get_by_id(agent_id) is not None


# -----------------------------------------------------------------------------
# Phase 1 Routes
# -----------------------------------------------------------------------------

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


# -----------------------------------------------------------------------------
# Phase 2 Telemetry & Events Routes
# -----------------------------------------------------------------------------

@api_bp.post("/telemetry/system")
def ingest_system_telemetry():
    """Ingest endpoint historical system metrics."""
    envelope, err = _validate_envelope(request)
    if err:
        return err

    db_path = current_app.config["DATABASE_PATH"]
    agent_id = envelope["agent_id"].strip()
    if not _check_agent_registered(agent_id, db_path):
        return _error(f"Agent '{agent_id}' is not registered", 404)

    payload = envelope["payload"]
    required_metric_fields = ("cpu_percent", "memory_percent", "disk_percent", "uptime_seconds")
    for field in required_metric_fields:
        if field not in payload:
            return _error(f"Missing required payload field: {field}")
        val = payload[field]
        if not is_valid_number(val):
            return _error(f"Invalid numeric value for field: {field}")
        if val < 0:
            return _error(f"Metric cannot be negative: {field}")

    for field in ("cpu_percent", "memory_percent", "disk_percent"):
        if payload[field] > 100:
            return _error(f"Metric must be between 0 and 100: {field}")

    metrics_repo = MetricsRepository(db_path)
    message_id = envelope["message_id"].strip()

    # Idempotency check
    existing = metrics_repo.get_by_message_id(message_id)
    if existing:
        is_same = (
            existing["agent_id"] == agent_id
            and abs(existing["cpu_percent"] - float(payload["cpu_percent"])) < 1e-4
            and abs(existing["memory_percent"] - float(payload["memory_percent"])) < 1e-4
            and abs(existing["disk_percent"] - float(payload["disk_percent"])) < 1e-4
            and abs(existing["uptime_seconds"] - float(payload["uptime_seconds"])) < 1e-4
        )
        if is_same:
            return jsonify({
                "success": True,
                "message_id": message_id,
                "duplicate": True,
                "received_at": existing["received_at"],
            }), 200
        return _error("Conflict: message_id already exists with different payload", 409)

    received_at = utc_now()
    record = {
        "message_id": message_id,
        "schema_version": envelope["schema_version"],
        "agent_id": agent_id,
        "cpu_percent": float(payload["cpu_percent"]),
        "memory_percent": float(payload["memory_percent"]),
        "disk_percent": float(payload["disk_percent"]),
        "uptime_seconds": float(payload["uptime_seconds"]),
        "collected_at": envelope["collected_at"],
        "received_at": received_at,
    }

    try:
        saved = metrics_repo.record(record)
    except Exception:
        current_app.logger.exception("Failed to record system telemetry")
        return _error("Internal server error", 500)

    return jsonify({
        "success": True,
        "message_id": message_id,
        "duplicate": False,
        "received_at": saved["received_at"],
    }), 201


@api_bp.post("/telemetry/processes")
def ingest_process_telemetry():
    """Ingest endpoint process collection snapshot."""
    envelope, err = _validate_envelope(request)
    if err:
        return err

    db_path = current_app.config["DATABASE_PATH"]
    agent_id = envelope["agent_id"].strip()
    if not _check_agent_registered(agent_id, db_path):
        return _error(f"Agent '{agent_id}' is not registered", 404)

    payload = envelope["payload"]
    if "process_count" not in payload or "processes" not in payload:
        return _error("Payload must contain 'process_count' and 'processes'")

    process_count = payload["process_count"]
    if not isinstance(process_count, int) or isinstance(process_count, bool) or process_count < 0:
        return _error("process_count must be an integer >= 0")

    processes = payload["processes"]
    if not isinstance(processes, list):
        return _error("processes must be an array")

    if len(processes) != process_count:
        return _error(f"process_count ({process_count}) does not match processes length ({len(processes)})")

    # Validate each process observation and check for duplicate PIDs
    seen_pids = set()
    cleaned_processes = []
    for proc in processes:
        if not isinstance(proc, dict):
            return _error("Each process observation must be a JSON object")

        pid = proc.get("pid")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid < 0:
            return _error("Each process must have an integer pid >= 0")

        if pid in seen_pids:
            return _error(f"Duplicate pid {pid} within snapshot")
        seen_pids.add(pid)

        ppid = proc.get("ppid")
        if ppid is not None and (not isinstance(ppid, int) or isinstance(ppid, bool) or ppid < 0):
            return _error("ppid must be an integer >= 0 or null")

        process_name = proc.get("process_name")
        if not isinstance(process_name, str) or not process_name.strip():
            return _error("process_name must be a non-empty string")

        cpu_p = proc.get("cpu_percent")
        if cpu_p is not None and (not is_valid_number(cpu_p) or cpu_p < 0):
            return _error("cpu_percent must be a finite number >= 0 or null")

        mem_p = proc.get("memory_percent")
        if mem_p is not None and (not is_valid_number(mem_p) or mem_p < 0 or mem_p > 100):
            return _error("memory_percent must be a finite number between 0 and 100 or null")

        rss = proc.get("rss_bytes")
        if rss is not None and (not isinstance(rss, int) or isinstance(rss, bool) or rss < 0):
            return _error("rss_bytes must be an integer >= 0 or null")

        started_at = proc.get("process_started_at")
        if started_at is not None and not is_valid_iso8601_utc(started_at):
            return _error("process_started_at must be an ISO 8601 UTC timestamp or null")

        cleaned_processes.append({
            "pid": pid,
            "ppid": ppid,
            "process_name": process_name.strip(),
            "username": proc.get("username"),
            "exe_path": proc.get("exe_path"),
            "cpu_percent": float(cpu_p) if cpu_p is not None else None,
            "memory_percent": float(mem_p) if mem_p is not None else None,
            "rss_bytes": rss,
            "process_started_at": started_at,
        })

    proc_repo = ProcessRepository(db_path)
    message_id = envelope["message_id"].strip()

    # Idempotency check
    existing = proc_repo.get_snapshot_by_message_id(message_id)
    if existing:
        is_same = (
            existing["agent_id"] == agent_id
            and existing["process_count"] == process_count
        )
        if is_same:
            return jsonify({
                "success": True,
                "message_id": message_id,
                "duplicate": True,
                "received_at": existing["received_at"],
            }), 200
        return _error("Conflict: message_id already exists with different payload", 409)

    received_at = utc_now()
    snapshot = {
        "message_id": message_id,
        "schema_version": envelope["schema_version"],
        "agent_id": agent_id,
        "process_count": process_count,
        "collected_at": envelope["collected_at"],
        "received_at": received_at,
    }

    try:
        saved = proc_repo.create_snapshot(snapshot, cleaned_processes)
        try:
            from detection.engine import DetectionEngine
            det_engine = DetectionEngine(db_path)
            det_engine.evaluate_process_snapshot(agent_id, saved["id"], cleaned_processes)
        except Exception as det_exc:
            current_app.logger.warning("Detection engine evaluation error: %s", det_exc)
    except Exception:
        current_app.logger.exception("Failed to record process snapshot")
        return _error("Internal server error", 500)

    return jsonify({
        "success": True,
        "message_id": message_id,
        "duplicate": False,
        "received_at": saved["received_at"],
    }), 201


@api_bp.post("/file-baselines")
def sync_file_baselines():
    """Synchronize file integrity baselines."""
    envelope, err = _validate_envelope(request)
    if err:
        return err

    db_path = current_app.config["DATABASE_PATH"]
    agent_id = envelope["agent_id"].strip()
    if not _check_agent_registered(agent_id, db_path):
        return _error(f"Agent '{agent_id}' is not registered", 404)

    payload = envelope["payload"]
    if "files" not in payload or not isinstance(payload["files"], list):
        return _error("Payload must contain 'files' array")

    files = payload["files"]
    if not files:
        return _error("files array cannot be empty")

    cleaned_files = []
    seen_paths = set()
    for f in files:
        if not isinstance(f, dict):
            return _error("Each file entry must be a JSON object")

        file_path = f.get("file_path")
        if not isinstance(file_path, str) or not file_path.startswith("/"):
            return _error("file_path must be a non-empty absolute path starting with '/'")

        if file_path in seen_paths:
            return _error(f"Duplicate file_path '{file_path}' in baseline batch")
        seen_paths.add(file_path)

        sha256 = f.get("sha256")
        if not is_valid_sha256(sha256):
            return _error(f"sha256 must be a 64-character hexadecimal string for '{file_path}'")

        file_size = f.get("file_size_bytes")
        if not isinstance(file_size, int) or isinstance(file_size, bool) or file_size < 0:
            return _error(f"file_size_bytes must be an integer >= 0 for '{file_path}'")

        mtime_ns = f.get("mtime_ns")
        if not isinstance(mtime_ns, int) or isinstance(mtime_ns, bool) or mtime_ns < 0:
            return _error(f"mtime_ns must be an integer >= 0 for '{file_path}'")

        file_mode = f.get("file_mode")
        if not isinstance(file_mode, int) or isinstance(file_mode, bool) or file_mode < 0 or file_mode > 4095:
            return _error(f"file_mode must be an integer between 0 and 4095 for '{file_path}'")

        state = f.get("state", "present")
        if state not in ("present", "missing"):
            return _error(f"state must be 'present' or 'missing' for '{file_path}'")

        cleaned_files.append({
            "file_path": file_path,
            "sha256": sha256.lower(),
            "file_size_bytes": file_size,
            "mtime_ns": mtime_ns,
            "file_mode": file_mode,
            "state": state,
        })

    baseline_repo = BaselineRepository(db_path)
    now = utc_now()

    # Determine created vs updated
    try:
        with get_connection(db_path) as conn:
            placeholders = ",".join("?" for _ in cleaned_files)
            rows = conn.execute(
                f"SELECT file_path FROM file_baselines WHERE agent_id = ? AND file_path IN ({placeholders})",
                (agent_id, *[f["file_path"] for f in cleaned_files]),
            ).fetchall()
            existing_paths = {row["file_path"] for row in rows}

        created = len(cleaned_files) - len(existing_paths)
        updated = len(existing_paths)
        baseline_repo.bulk_upsert(agent_id, cleaned_files)
    except Exception:
        current_app.logger.exception("Failed to synchronize file baselines")
        return _error("Internal server error", 500)

    return jsonify({
        "success": True,
        "agent_id": agent_id,
        "received_at": now,
        "processed": len(cleaned_files),
        "created": created,
        "updated": updated,
    }), 200


@api_bp.post("/events")
def ingest_security_event():
    """Ingest security event from Agent."""
    envelope, err = _validate_envelope(request)
    if err:
        return err

    db_path = current_app.config["DATABASE_PATH"]
    agent_id = envelope["agent_id"].strip()
    if not _check_agent_registered(agent_id, db_path):
        return _error(f"Agent '{agent_id}' is not registered", 404)

    payload = envelope["payload"]
    required_fields = ("event_type", "title")
    for field in required_fields:
        if field not in payload or not payload[field]:
            return _error(f"Missing or empty required field: {field}")

    event_type = payload["event_type"]
    if not isinstance(event_type, str) or not event_type.strip():
        return _error("event_type must be a non-empty string")

    source = payload.get("source", "agent")
    if source != "agent":
        return _error("Agent submitted event source must be 'agent'")

    severity = payload.get("severity", "info")
    if severity not in ("info", "low", "medium", "high", "critical"):
        return _error(f"Invalid severity '{severity}'. Must be one of info, low, medium, high, critical")

    occurred_at = payload.get("occurred_at") or envelope.get("collected_at")
    if not occurred_at or not is_valid_iso8601_utc(occurred_at):
        return _error("occurred_at must be a valid ISO 8601 UTC timestamp")

    title = payload["title"]
    if not isinstance(title, str) or not title.strip() or len(title.strip()) > 255:
        return _error("title must be a non-empty string of at most 255 characters")

    evidence = payload.get("evidence", {})
    if not isinstance(evidence, dict):
        return _error("evidence must be a JSON object")

    event_repo = EventRepository(db_path)
    message_id = envelope["message_id"].strip()

    # Idempotency check
    existing = event_repo.get_by_message_id(message_id)
    if existing:
        is_same = (
            existing["agent_id"] == agent_id
            and existing["event_type"] == event_type.strip()
            and existing["title"] == title.strip()
        )
        if is_same:
            return jsonify({
                "success": True,
                "message_id": message_id,
                "duplicate": True,
                "received_at": existing["received_at"],
            }), 200
        return _error("Conflict: message_id already exists with different payload", 409)

    received_at = utc_now()
    event_data = {
        "message_id": message_id,
        "schema_version": envelope["schema_version"],
        "agent_id": agent_id,
        "event_type": event_type.strip(),
        "severity": severity,
        "source": source,
        "title": title.strip(),
        "description": payload.get("description"),
        "evidence_json": evidence,
        "occurred_at": occurred_at,
        "received_at": received_at,
        "fingerprint": payload.get("fingerprint"),
    }

    try:
        saved = event_repo.record(event_data)
        try:
            from detection.engine import DetectionEngine
            det_engine = DetectionEngine(db_path)
            det_engine.evaluate_security_event(agent_id, saved)
        except Exception as det_exc:
            current_app.logger.warning("Detection engine event evaluation error: %s", det_exc)
    except Exception:
        current_app.logger.exception("Failed to record security event")
        return _error("Internal server error", 500)

    return jsonify({
        "success": True,
        "message_id": message_id,
        "duplicate": False,
        "received_at": saved["received_at"],
    }), 201


# -----------------------------------------------------------------------------
# Alert Query and Management Routes
# -----------------------------------------------------------------------------

@api_bp.get("/alerts")
def get_alerts():
    """List security alerts with optional filters and pagination."""
    db_path = current_app.config["DATABASE_PATH"]
    alert_repo = AlertRepository(db_path)

    status = request.args.get("status")
    if status and status not in ("new", "acknowledged", "resolved"):
        return _error(f"Invalid status filter '{status}'")

    severity = request.args.get("severity")
    if severity and severity not in ("info", "low", "medium", "high", "critical"):
        return _error(f"Invalid severity filter '{severity}'")

    agent_id = request.args.get("agent_id")

    limit_param = request.args.get("limit", "50")
    try:
        limit = int(limit_param)
        if limit < 1 or limit > 100:
            return _error("limit must be between 1 and 100")
    except ValueError:
        return _error("limit must be a valid integer")

    offset_param = request.args.get("offset", "0")
    try:
        offset = int(offset_param)
        if offset < 0:
            return _error("offset must be an integer >= 0")
    except ValueError:
        return _error("offset must be a valid integer")

    try:
        alerts = alert_repo.list_alerts(
            status=status,
            severity=severity,
            agent_id=agent_id,
            limit=limit,
            offset=offset,
        )
    except Exception:
        current_app.logger.exception("Failed to list alerts")
        return _error("Internal server error", 500)

    return jsonify({
        "success": True,
        "count": len(alerts),
        "limit": limit,
        "offset": offset,
        "alerts": alerts,
    }), 200


@api_bp.get("/alerts/<int:alert_id>")
def get_alert_detail(alert_id: int):
    """Get alert detail including linked security events."""
    db_path = current_app.config["DATABASE_PATH"]
    alert_repo = AlertRepository(db_path)

    try:
        alert = alert_repo.get_by_id(alert_id)
        if not alert:
            return _error(f"Alert {alert_id} not found", 404)
        linked_events = alert_repo.get_linked_events(alert_id)
        alert["events"] = linked_events
    except Exception:
        current_app.logger.exception("Failed to get alert detail")
        return _error("Internal server error", 500)

    return jsonify({
        "success": True,
        "alert": alert,
    }), 200


@api_bp.post("/alerts/<int:alert_id>/acknowledge")
def acknowledge_alert(alert_id: int):
    """Transition alert to acknowledged status."""
    db_path = current_app.config["DATABASE_PATH"]
    alert_repo = AlertRepository(db_path)

    try:
        alert = alert_repo.get_by_id(alert_id)
        if not alert:
            return _error(f"Alert {alert_id} not found", 404)

        if alert["status"] == "resolved":
            return _error("Resolved alert cannot be acknowledged", 400)

        if alert["status"] == "acknowledged":
            return jsonify({
                "success": True,
                "alert_id": alert_id,
                "status": "acknowledged",
                "acknowledged_at": alert["acknowledged_at"],
            }), 200

        updated = alert_repo.acknowledge(alert_id)
    except Exception:
        current_app.logger.exception("Failed to acknowledge alert")
        return _error("Internal server error", 500)

    return jsonify({
        "success": True,
        "alert_id": alert_id,
        "status": "acknowledged",
        "acknowledged_at": updated["acknowledged_at"],
    }), 200


@api_bp.post("/alerts/<int:alert_id>/resolve")
def resolve_alert(alert_id: int):
    """Transition alert to resolved status with optional resolution note."""
    db_path = current_app.config["DATABASE_PATH"]
    alert_repo = AlertRepository(db_path)

    resolution_note = None
    if request.is_json:
        data = request.get_json(silent=True)
        if isinstance(data, dict):
            note = data.get("resolution_note")
            if note is not None:
                if not isinstance(note, str) or len(note) > 2000:
                    return _error("resolution_note must be a string of at most 2000 characters or null")
                resolution_note = note

    try:
        alert = alert_repo.get_by_id(alert_id)
        if not alert:
            return _error(f"Alert {alert_id} not found", 404)

        if alert["status"] == "resolved":
            return jsonify({
                "success": True,
                "alert_id": alert_id,
                "status": "resolved",
                "resolved_at": alert["resolved_at"],
                "resolution_note": alert["resolution_note"],
            }), 200

        updated = alert_repo.resolve(alert_id, note=resolution_note)
    except Exception:
        current_app.logger.exception("Failed to resolve alert")
        return _error("Internal server error", 500)

    return jsonify({
        "success": True,
        "alert_id": alert_id,
        "status": "resolved",
        "resolved_at": updated["resolved_at"],
        "resolution_note": updated.get("resolution_note"),
    }), 200
