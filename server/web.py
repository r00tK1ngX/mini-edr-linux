"""Web Dashboard Blueprint for Mini EDR Linux.

Renders Cyberpunk-themed SOC console views:
- /: Redirects to /dashboard.
- /dashboard: SOC Command Center overview with KPIs, telemetry charts, and latest alerts.
- /endpoints: Monitored endpoints inventory, real-time resource meters, and inspection.
- /endpoints/<agent_id>/telemetry: Telemetry JSON for endpoint inspection modal.
- /alerts: Incident response console with filtering, evidence inspection, and triage.
- /alerts/<int:alert_id>/detail: Alert details and linked events JSON for modal inspection.
- /alerts/<int:alert_id>/acknowledge: Web action to acknowledge an alert.
- /alerts/<int:alert_id>/resolve: Web action to resolve an alert with notes.
- /alerts/<int:alert_id>/dismiss: Web action to dismiss an alert as false positive.
- /events: Security audit log and file integrity telemetry stream.
"""

from datetime import datetime, timezone
import hmac
import json
import secrets
from typing import Any, Dict, List, Optional

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from server.repositories.alert_repository import AlertRepository
from server.repositories.baseline_repository import BaselineRepository
from server.repositories.endpoint_repository import EndpointRepository
from server.repositories.event_repository import EventRepository
from server.repositories.metrics_repository import MetricsRepository
from server.repositories.process_repository import ProcessRepository

web_bp = Blueprint("web", __name__)


# -----------------------------------------------------------------------------
# Security & CSRF Helpers
# -----------------------------------------------------------------------------

def get_or_create_csrf_token() -> str:
    """Generate or retrieve per-session anti-CSRF token."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@web_bp.app_context_processor
def inject_security_context():
    """Inject CSRF token and operator authentication state into Jinja2 templates."""
    return {
        "csrf_token": get_or_create_csrf_token,
        "is_authenticated": session.get("operator_authenticated", False),
    }


def validate_csrf() -> bool:
    """Verify CSRF token for state-changing requests."""
    if current_app.config.get("TESTING") and not current_app.config.get("ENFORCE_CSRF_IN_TESTS", False):
        return True
    expected = session.get("csrf_token")
    if not expected:
        return False

    received = request.headers.get("X-CSRF-Token")
    if not received and request.is_json:
        received = (request.get_json(silent=True) or {}).get("csrf_token")
    if not received and request.form:
        received = request.form.get("csrf_token")

    return bool(received and hmac.compare_digest(str(received), str(expected)))


@web_bp.before_request
def require_operator_auth():
    """Enforce operator authentication for Web SOC views."""
    # Allow static assets and authentication endpoints
    if request.endpoint in ("web.login", "web.logout", "static"):
        return None

    # Allow testing bypass unless explicitly enforcing auth in tests
    if current_app.config.get("TESTING") and not current_app.config.get("ENFORCE_WEB_AUTH_IN_TESTS", False):
        return None

    # Check if operator session is authenticated
    if session.get("operator_authenticated"):
        return None

    # Allow Bearer token in header or ?token= query parameter for lab convenience
    auth_header = request.headers.get("Authorization", "")
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif request.args.get("token"):
        token = request.args.get("token").strip()

    expected_token = current_app.config.get("EDR_API_TOKEN")
    if token and expected_token and hmac.compare_digest(token, expected_token):
        session["operator_authenticated"] = True
        get_or_create_csrf_token()
        return None

    # Unauthorized request handling
    if request.is_json or request.path.endswith("/telemetry") or request.path.endswith("/detail"):
        return jsonify({"success": False, "error": "Unauthorized operator session"}), 401

    return redirect(url_for("web.login", next=request.path))


# -----------------------------------------------------------------------------
# Template Filters & Helpers
# -----------------------------------------------------------------------------

@web_bp.app_template_filter("pretty_json")
def pretty_json_filter(val: Any) -> str:
    """Format JSON string or dict into indented JSON for evidence inspection."""
    if not val:
        return "{}"
    if isinstance(val, (dict, list)):
        return json.dumps(val, indent=2, ensure_ascii=False)
    if isinstance(val, str):
        try:
            parsed = json.loads(val)
            return json.dumps(parsed, indent=2, ensure_ascii=False)
        except Exception:
            return val
    return str(val)


@web_bp.app_template_filter("format_dt")
def format_dt_filter(val: Optional[str]) -> str:
    """Format ISO 8601 UTC timestamp to readable UTC string."""
    if not val:
        return "N/A"
    try:
        clean = val.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(val)


@web_bp.app_template_filter("format_uptime")
def format_uptime_filter(seconds: Optional[float]) -> str:
    """Format uptime in seconds to human readable string."""
    if seconds is None:
        return "N/A"
    try:
        s = int(seconds)
        days, s = divmod(s, 86400)
        hours, s = divmod(s, 3600)
        minutes, s = divmod(s, 60)
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        if hours > 0:
            return f"{hours}h {minutes}m {s}s"
        return f"{minutes}m {s}s"
    except Exception:
        return f"{seconds}s"


# -----------------------------------------------------------------------------
# Web Authentication Routes
# -----------------------------------------------------------------------------

@web_bp.route("/login", methods=["GET", "POST"])
def login():
    """Operator login for Web SOC Console."""
    if session.get("operator_authenticated"):
        return redirect(url_for("web.dashboard"))

    error = None
    next_url = request.args.get("next") or url_for("web.dashboard")

    if request.method == "POST":
        token = request.form.get("token", "").strip()
        expected_token = current_app.config.get("EDR_API_TOKEN")

        if token and expected_token and hmac.compare_digest(token, expected_token):
            session["operator_authenticated"] = True
            get_or_create_csrf_token()
            flash("Operator session authenticated successfully.", "success")
            return redirect(next_url)
        else:
            error = "Invalid API Access Token. Authentication rejected."

    return render_template("login.html", error=error)


@web_bp.get("/logout")
def logout():
    """Terminate operator session."""
    session.clear()
    flash("Operator session terminated.", "info")
    return redirect(url_for("web.login"))


# -----------------------------------------------------------------------------
# Web Routes
# -----------------------------------------------------------------------------

@web_bp.get("/")
def index():
    """Redirect root path to SOC Dashboard overview."""
    return redirect(url_for("web.dashboard"))


@web_bp.get("/dashboard")
def dashboard():
    """Overview: SOC Command Center with real-time telemetry and metrics."""
    db_path = current_app.config["DATABASE_PATH"]
    offline_secs = current_app.config.get("OFFLINE_AFTER_SECONDS", 15)

    endpoint_repo = EndpointRepository(db_path)
    alert_repo = AlertRepository(db_path)
    event_repo = EventRepository(db_path)

    endpoints = endpoint_repo.list_all(offline_after_seconds=offline_secs)
    total_endpoints = len(endpoints)
    online_endpoints = sum(1 for e in endpoints if e["status"] == "online")
    offline_endpoints = total_endpoints - online_endpoints

    # Compute average resource metrics across online endpoints
    online_list = [e for e in endpoints if e["status"] == "online"]
    if online_list:
        cpu_vals = [e["cpu_percent"] for e in online_list if e.get("cpu_percent") is not None]
        mem_vals = [e["memory_percent"] for e in online_list if e.get("memory_percent") is not None]
        disk_vals = [e["disk_percent"] for e in online_list if e.get("disk_percent") is not None]
        avg_cpu = round(sum(cpu_vals) / len(cpu_vals), 1) if cpu_vals else 0.0
        avg_mem = round(sum(mem_vals) / len(mem_vals), 1) if mem_vals else 0.0
        avg_disk = round(sum(disk_vals) / len(disk_vals), 1) if disk_vals else 0.0
    else:
        avg_cpu = avg_mem = avg_disk = 0.0

    alert_summary = alert_repo.get_summary()
    total_events = event_repo.count()

    recent_alerts = alert_repo.list_alerts(limit=8)
    recent_events = event_repo.list_recent(limit=8)

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        total_endpoints=total_endpoints,
        online_endpoints=online_endpoints,
        offline_endpoints=offline_endpoints,
        avg_cpu=avg_cpu,
        avg_mem=avg_mem,
        avg_disk=avg_disk,
        alert_summary=alert_summary,
        total_events=total_events,
        recent_alerts=recent_alerts,
        recent_events=recent_events,
        endpoints=endpoints,
    )


@web_bp.get("/endpoints")
def endpoints():
    """Endpoints management view with filtering and search."""
    db_path = current_app.config["DATABASE_PATH"]
    offline_secs = current_app.config.get("OFFLINE_AFTER_SECONDS", 15)
    endpoint_repo = EndpointRepository(db_path)

    all_endpoints = endpoint_repo.list_all(offline_after_seconds=offline_secs)

    status_filter = request.args.get("status")
    search_query = request.args.get("q", "").strip().lower()

    filtered = all_endpoints
    if status_filter in ("online", "offline"):
        filtered = [e for e in filtered if e["status"] == status_filter]

    if search_query:
        filtered = [
            e for e in filtered
            if (
                search_query in (e.get("hostname") or "").lower()
                or search_query in (e.get("agent_id") or "").lower()
                or search_query in (e.get("ip_address") or "").lower()
                or search_query in (e.get("os") or "").lower()
            )
        ]

    total_count = len(all_endpoints)
    online_count = sum(1 for e in all_endpoints if e["status"] == "online")
    offline_count = total_count - online_count

    return render_template(
        "endpoints.html",
        active_page="endpoints",
        endpoints=filtered,
        status_filter=status_filter or "all",
        search_query=search_query,
        total_count=total_count,
        online_count=online_count,
        offline_count=offline_count,
    )


@web_bp.get("/endpoints/<agent_id>/telemetry")
def endpoint_telemetry(agent_id: str):
    """Retrieve detailed telemetry JSON for an endpoint modal inspection."""
    db_path = current_app.config["DATABASE_PATH"]
    endpoint_repo = EndpointRepository(db_path)
    proc_repo = ProcessRepository(db_path)
    baseline_repo = BaselineRepository(db_path)
    event_repo = EventRepository(db_path)
    metrics_repo = MetricsRepository(db_path)

    endpoint = endpoint_repo.get_by_id(agent_id)
    if not endpoint:
        return jsonify({"success": False, "error": f"Endpoint '{agent_id}' not found"}), 404

    latest_snapshot = proc_repo.get_latest_snapshot(agent_id)
    processes = []
    if latest_snapshot:
        processes = proc_repo.list_observations(latest_snapshot["id"])

    baselines = baseline_repo.list_by_agent(agent_id)
    metrics_history = metrics_repo.list_by_agent(agent_id, limit=15)
    recent_events = event_repo.list_by_agent(agent_id, limit=15)

    return jsonify({
        "success": True,
        "endpoint": endpoint,
        "snapshot": latest_snapshot,
        "processes": processes,
        "baselines_count": len(baselines),
        "baselines": baselines[:50],  # cap at 50 for performance
        "metrics_history": metrics_history,
        "recent_events": recent_events,
    }), 200


@web_bp.get("/alerts")
def alerts():
    """Incident & Alert management view with filtering, triage, and resolution."""
    db_path = current_app.config["DATABASE_PATH"]
    alert_repo = AlertRepository(db_path)
    endpoint_repo = EndpointRepository(db_path)

    status_filter = request.args.get("status")
    severity_filter = request.args.get("severity")
    agent_id_filter = request.args.get("agent_id")
    rule_id_filter = request.args.get("rule_id")

    # Clean filters if "all" was selected
    status = status_filter if status_filter and status_filter != "all" else None
    severity = severity_filter if severity_filter and severity_filter != "all" else None
    agent_id = agent_id_filter if agent_id_filter and agent_id_filter != "all" else None
    rule_id = rule_id_filter if rule_id_filter and rule_id_filter != "all" else None

    alerts_list = alert_repo.list_alerts(
        status=status,
        severity=severity,
        agent_id=agent_id,
        rule_id=rule_id,
        limit=100,
    )

    summary = alert_repo.get_summary()
    all_endpoints = endpoint_repo.list_all()

    return render_template(
        "alerts.html",
        active_page="alerts",
        alerts=alerts_list,
        summary=summary,
        status_filter=status_filter or "all",
        severity_filter=severity_filter or "all",
        agent_id_filter=agent_id_filter or "all",
        rule_id_filter=rule_id_filter or "all",
        endpoints=all_endpoints,
    )


@web_bp.get("/alerts/<int:alert_id>/detail")
def alert_detail_json(alert_id: int):
    """Return JSON details and linked security events for an alert."""
    db_path = current_app.config["DATABASE_PATH"]
    alert_repo = AlertRepository(db_path)

    alert = alert_repo.get_by_id(alert_id)
    if not alert:
        return jsonify({"success": False, "error": f"Alert {alert_id} not found"}), 404

    events = alert_repo.get_linked_events(alert_id)
    return jsonify({
        "success": True,
        "alert": alert,
        "events": events,
    }), 200


@web_bp.post("/alerts/<int:alert_id>/acknowledge")
def web_acknowledge_alert(alert_id: int):
    """Web action to acknowledge an alert (supports JSON fetch or Form POST)."""
    if not validate_csrf():
        if request.is_json:
            return jsonify({"success": False, "error": "CSRF verification failed"}), 403
        flash("CSRF verification failed. Action rejected.", "error")
        return redirect(request.referrer or url_for("web.alerts"))

    db_path = current_app.config["DATABASE_PATH"]
    alert_repo = AlertRepository(db_path)

    note = None
    if request.is_json:
        data = request.get_json(silent=True) or {}
        note = data.get("note") or data.get("resolution_note")
    else:
        note = request.form.get("note")

    alert = alert_repo.get_by_id(alert_id)
    if not alert:
        if request.is_json:
            return jsonify({"success": False, "error": "Alert not found"}), 404
        flash(f"Alert {alert_id} not found", "error")
        return redirect(request.referrer or url_for("web.alerts"))

    if alert["status"] == "resolved":
        if request.is_json:
            return jsonify({"success": False, "error": "Resolved alert cannot be acknowledged"}), 400
        flash("Resolved alert cannot be acknowledged", "error")
        return redirect(request.referrer or url_for("web.alerts"))

    updated = alert_repo.acknowledge(alert_id, note=note)
    if request.is_json:
        return jsonify({
            "success": True,
            "alert_id": alert_id,
            "status": "acknowledged",
            "acknowledged_at": updated["acknowledged_at"],
            "resolution_note": updated.get("resolution_note"),
        }), 200

    flash(f"Alert #{alert_id} acknowledged successfully.", "success")
    return redirect(request.referrer or url_for("web.alerts"))


@web_bp.post("/alerts/<int:alert_id>/resolve")
def web_resolve_alert(alert_id: int):
    """Web action to resolve an alert with notes (supports JSON fetch or Form POST)."""
    if not validate_csrf():
        if request.is_json:
            return jsonify({"success": False, "error": "CSRF verification failed"}), 403
        flash("CSRF verification failed. Action rejected.", "error")
        return redirect(request.referrer or url_for("web.alerts"))

    db_path = current_app.config["DATABASE_PATH"]
    alert_repo = AlertRepository(db_path)

    note = None
    if request.is_json:
        data = request.get_json(silent=True) or {}
        note = data.get("resolution_note") or data.get("note")
    else:
        note = request.form.get("resolution_note")

    alert = alert_repo.get_by_id(alert_id)
    if not alert:
        if request.is_json:
            return jsonify({"success": False, "error": "Alert not found"}), 404
        flash(f"Alert {alert_id} not found", "error")
        return redirect(request.referrer or url_for("web.alerts"))

    updated = alert_repo.resolve(alert_id, note=note)
    if request.is_json:
        return jsonify({
            "success": True,
            "alert_id": alert_id,
            "status": "resolved",
            "resolved_at": updated["resolved_at"],
            "resolution_note": updated.get("resolution_note"),
        }), 200

    flash(f"Alert #{alert_id} marked as resolved.", "success")
    return redirect(request.referrer or url_for("web.alerts"))


@web_bp.post("/alerts/<int:alert_id>/dismiss")
def web_dismiss_alert(alert_id: int):
    """Web action to dismiss an alert as false positive / ignored."""
    if not validate_csrf():
        if request.is_json:
            return jsonify({"success": False, "error": "CSRF verification failed"}), 403
        flash("CSRF verification failed. Action rejected.", "error")
        return redirect(request.referrer or url_for("web.alerts"))

    db_path = current_app.config["DATABASE_PATH"]
    alert_repo = AlertRepository(db_path)

    note = "Dismissed by operator (false positive / ignored)"
    if request.is_json:
        data = request.get_json(silent=True) or {}
        custom_note = data.get("resolution_note") or data.get("note")
        if custom_note:
            note = custom_note
    else:
        custom_note = request.form.get("resolution_note")
        if custom_note:
            note = custom_note

    alert = alert_repo.get_by_id(alert_id)
    if not alert:
        if request.is_json:
            return jsonify({"success": False, "error": "Alert not found"}), 404
        flash(f"Alert {alert_id} not found", "error")
        return redirect(request.referrer or url_for("web.alerts"))

    updated = alert_repo.dismiss(alert_id, note=note)
    if request.is_json:
        return jsonify({
            "success": True,
            "alert_id": alert_id,
            "status": "resolved",
            "resolved_at": updated["resolved_at"],
            "resolution_note": updated.get("resolution_note"),
            "dismissed": True,
        }), 200

    flash(f"Alert #{alert_id} dismissed (false positive).", "info")
    return redirect(request.referrer or url_for("web.alerts"))


@web_bp.get("/events")
def events():
    """Security Events and File Integrity audit log."""
    db_path = current_app.config["DATABASE_PATH"]
    event_repo = EventRepository(db_path)

    severity_filter = request.args.get("severity")
    event_type_filter = request.args.get("event_type")

    severity = severity_filter if severity_filter and severity_filter != "all" else None
    event_type = event_type_filter if event_type_filter and event_type_filter != "all" else None

    events_list = event_repo.list_recent(
        limit=100,
        severity=severity,
        event_type=event_type,
    )
    total_events = event_repo.count()

    return render_template(
        "events.html",
        active_page="events",
        events=events_list,
        total_events=total_events,
        severity_filter=severity_filter or "all",
        event_type_filter=event_type_filter or "all",
    )
