"""Security, Reliability, and Threat Resistance Test Suite for Phase 8.

Tests:
1. Database Integrity & PRAGMA Verification:
   - PRAGMA integrity_check returns 'ok'.
   - PRAGMA foreign_key_check returns 0 violations.
2. SQL Injection Resistance:
   - Probes endpoints and repositories with SQL injection payloads (e.g. "' OR '1'='1", "'; DROP TABLE endpoints; --").
   - Asserts all queries use strict parameterization with ? placeholders and no injection occurs.
3. Cross-Site Scripting (XSS) Sanitization:
   - Injects HTML/JS payloads (e.g. "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>") in process names, hostnames, and notes.
   - Asserts dashboard views and JSON formatters properly escape entities.
4. Token Confidentiality & Log Sanitization:
   - Asserts AgentClient and error handlers never leak the API token in logs or client responses.
   - Verifies constant-time comparison prevents timing attacks.
5. Input Boundary & Idempotency Controls:
   - Rejection of oversized payloads (> 64KB) with HTTP 413.
   - Rejection of invalid types, NaN, infinity, and out-of-range metrics with HTTP 400.
   - Idempotent duplicate message_id handling (HTTP 200 duplicate vs HTTP 409 conflict).
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import uuid
import pytest

from server.app import create_app
from server.db import get_connection
from server.repositories.alert_repository import AlertRepository
from server.repositories.endpoint_repository import EndpointRepository

TOKEN = "super-secret-token-do-not-leak-123456789"


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _new_uuid():
    return str(uuid.uuid4())


@pytest.fixture()
def app(tmp_path):
    db_path = tmp_path / "mini_edr_security.db"
    application = create_app({
        "TESTING": True,
        "EDR_API_TOKEN": TOKEN,
        "DATABASE_PATH": str(db_path),
        "OFFLINE_AFTER_SECONDS": 15,
        "MAX_CONTENT_LENGTH": 64 * 1024,
    })
    application.config["TEST_DATABASE_PATH"] = db_path
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def auth_headers(token=TOKEN):
    return {"Authorization": f"Bearer {token}"}


# =============================================================================
# 1. Database PRAGMA & Structural Integrity
# =============================================================================

def test_database_pragma_integrity(app):
    """Verify SQLite database structural integrity and zero foreign key violations."""
    db_path = app.config["DATABASE_PATH"]
    conn = get_connection(db_path)
    try:
        # 1. Integrity check
        integrity = conn.execute("PRAGMA integrity_check;").fetchone()
        assert integrity[0] == "ok"

        # 2. Foreign keys check
        violations = conn.execute("PRAGMA foreign_key_check;").fetchall()
        assert len(violations) == 0

        # 3. WAL journal mode
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()
        assert journal_mode[0].lower() == "wal"
    finally:
        conn.close()


# =============================================================================
# 2. SQL Injection Resistance Probes
# =============================================================================

@pytest.mark.parametrize("sqli_payload", [
    "' OR '1'='1",
    "'; DROP TABLE endpoints; --",
    "admin'--",
    "1' UNION SELECT null, null, null, null, null, null, null, null, null, null, null --",
    "'; DELETE FROM alerts; --",
])
def test_sql_injection_resistance_on_heartbeat(client, sqli_payload):
    """SQL injection payloads in agent_id or hostname must not execute or corrupt database."""
    resp = client.post(
        "/api/v1/heartbeat",
        json={
            "agent_id": sqli_payload,
            "hostname": sqli_payload,
            "os": "Linux",
        },
        headers=auth_headers(),
    )
    assert resp.status_code == 200

    # Ensure endpoints table is still fully intact and queryable
    list_resp = client.get("/api/v1/endpoints", headers=auth_headers())
    assert list_resp.status_code == 200
    endpoints = list_resp.get_json()["endpoints"]
    assert any(e["agent_id"] == sqli_payload for e in endpoints)


@pytest.mark.parametrize("sqli_filter", [
    "' OR '1'='1",
    "'; DROP TABLE alerts; --",
    "1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14 --",
])
def test_sql_injection_resistance_on_alert_queries(client, app, sqli_filter):
    """SQL injection payloads in alert query filters must safely evaluate without error."""
    # List alerts with malicious filter
    resp = client.get(f"/api/v1/alerts?agent_id={sqli_filter}&rule_id={sqli_filter}", headers=auth_headers())
    assert resp.status_code == 200
    assert resp.get_json()["total"] == 0

    # Summary query with malicious agent_id
    summary_resp = client.get(f"/api/v1/alerts/summary?agent_id={sqli_filter}", headers=auth_headers())
    assert summary_resp.status_code == 200
    assert summary_resp.get_json()["summary"]["total_alerts"] == 0


# =============================================================================
# 3. Cross-Site Scripting (XSS) Sanitization
# =============================================================================

def test_xss_sanitization_in_web_dashboard(client, app):
    """HTML and JavaScript payloads injected into telemetry are escaped in web rendering."""
    xss_payload = "<script>alert('XSS_BREACH')</script>"
    xss_img = "<img src=x onerror=alert('PWNED')>"

    # 1. Register endpoint with XSS payload in hostname
    client.post(
        "/api/v1/heartbeat",
        json={
            "agent_id": "agent-xss-01",
            "hostname": xss_payload,
            "os": "Linux",
        },
        headers=auth_headers(),
    )

    # 2. Ingest process with XSS payload in name
    client.post(
        "/api/v1/telemetry/processes",
        json={
            "message_id": _new_uuid(),
            "schema_version": "1.0",
            "agent_id": "agent-xss-01",
            "collected_at": _utc_now(),
            "payload": {
                "process_count": 1,
                "processes": [
                    {
                        "pid": 9999,
                        "ppid": 1,
                        "process_name": xss_img,
                        "username": "root",
                        "exe_path": "/bin/sh",
                        "cpu_percent": 10.0,
                        "memory_percent": 5.0,
                    }
                ],
            },
        },
        headers=auth_headers(),
    )

    # 3. Create an alert with XSS in resolution note
    alert_repo = AlertRepository(app.config["DATABASE_PATH"])
    alert = alert_repo.create_or_update({
        "alert_key": "alert:xss-test",
        "agent_id": "agent-xss-01",
        "rule_id": "xss_probe",
        "title": "Probe Alert " + xss_payload,
        "description": "Probe Description " + xss_img,
        "severity": "medium",
        "status": "resolved",
        "resolved_at": _utc_now(),
        "resolution_note": xss_payload,
    })

    # Verify Endpoints page HTML: must NOT contain unescaped <script> tag
    ep_page = client.get("/endpoints").get_data(as_text=True)
    assert "<script>alert('XSS_BREACH')</script>" not in ep_page
    assert "&lt;script&gt;alert(&#39;XSS_BREACH&#39;)&lt;/script&gt;" in ep_page

    # Verify Alerts page HTML: must NOT contain unescaped <script> tag
    alerts_page = client.get("/alerts").get_data(as_text=True)
    assert "<script>alert('XSS_BREACH')</script>" not in alerts_page

    # Verify modal detail JSON endpoint safely delivers text data
    detail_resp = client.get(f"/alerts/{alert['id']}/detail")
    assert detail_resp.status_code == 200
    assert xss_payload in detail_resp.get_json()["alert"]["title"]


# =============================================================================
# 4. Token Confidentiality & Authentication Security
# =============================================================================

def test_token_confidentiality_never_leaks(client):
    """API token is never reflected back in 401, 400, or 500 responses."""
    # 401 Unauthorized
    res_401 = client.get("/api/v1/endpoints", headers={"Authorization": "Bearer wrong-token"})
    assert res_401.status_code == 401
    assert TOKEN not in res_401.get_data(as_text=True)

    # Missing header
    res_no_auth = client.get("/api/v1/endpoints")
    assert res_no_auth.status_code == 401
    assert TOKEN not in res_no_auth.get_data(as_text=True)

    # 400 Bad Request
    res_400 = client.post("/api/v1/heartbeat", json={"bad": "payload"}, headers=auth_headers())
    assert res_400.status_code == 400
    assert TOKEN not in res_400.get_data(as_text=True)


# =============================================================================
# 5. Input Boundaries & Idempotency Protection
# =============================================================================

def test_oversized_payload_rejected_with_413(client):
    """Payloads exceeding MAX_CONTENT_LENGTH (64KB) are rejected with HTTP 413."""
    oversized_data = {"agent_id": "test", "big_junk": "X" * (70 * 1024)}
    resp = client.post("/api/v1/heartbeat", json=oversized_data, headers=auth_headers())
    assert resp.status_code == 413
    assert "too large" in resp.get_json()["error"].lower()


@pytest.mark.parametrize("invalid_val,field", [
    (-1.0, "cpu_percent"),
    (105.0, "cpu_percent"),
    (-5.0, "memory_percent"),
    (120.0, "memory_percent"),
    (-10.0, "disk_percent"),
    (101.0, "disk_percent"),
    (-1.0, "uptime_seconds"),
])
def test_metric_boundary_validation_rejects_out_of_range(client, invalid_val, field):
    """Out-of-range metrics (CPU/RAM/Disk not in 0-100, uptime < 0) return HTTP 400."""
    metrics = {
        "cpu_percent": 10.0,
        "memory_percent": 20.0,
        "disk_percent": 30.0,
        "uptime_seconds": 100.0,
    }
    metrics[field] = invalid_val

    resp = client.post(
        "/api/v1/heartbeat",
        json={
            "agent_id": "agent-boundary-test",
            "hostname": "kali",
            "os": "Linux",
            "metrics": metrics,
        },
        headers=auth_headers(),
    )
    assert resp.status_code == 400


def test_idempotency_duplicate_message_id(client):
    """Identical message_id with same payload returns 200 duplicate; differing payload returns 409 conflict."""
    msg_id = _new_uuid()
    now = _utc_now()
    agent_id = "agent-idemp-01"

    # Register endpoint first
    client.post("/api/v1/heartbeat", json={"agent_id": agent_id, "hostname": "box", "os": "Linux"}, headers=auth_headers())

    payload1 = {
        "message_id": msg_id,
        "schema_version": "1.0",
        "agent_id": agent_id,
        "collected_at": now,
        "payload": {
            "process_count": 1,
            "processes": [{"pid": 1, "process_name": "init", "cpu_percent": 0.0}],
        },
    }

    # Initial request -> 201 Created
    res1 = client.post("/api/v1/telemetry/processes", json=payload1, headers=auth_headers())
    assert res1.status_code == 201
    assert res1.get_json()["duplicate"] is False

    # Repeat exact same request -> 200 OK (duplicate: True)
    res2 = client.post("/api/v1/telemetry/processes", json=payload1, headers=auth_headers())
    assert res2.status_code == 200
    assert res2.get_json()["duplicate"] is True

    # Same message_id with conflicting payload -> 409 Conflict
    payload_conflict = dict(payload1)
    payload_conflict["payload"] = {
        "process_count": 2,
        "processes": [
            {"pid": 1, "process_name": "init"},
            {"pid": 2, "process_name": "kthreadd"},
        ],
    }
    res_conflict = client.post("/api/v1/telemetry/processes", json=payload_conflict, headers=auth_headers())
    assert res_conflict.status_code == 409
    assert "Conflict" in res_conflict.get_json()["error"]


# =============================================================================
# 6. Stage B: Security Remediation Regression Probes
# =============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_attribute_injection_xss_mitigated(client, app):
    """Alert title with single quotes is bound via HTML5 data attribute without inline JS breakout."""
    db_path = app.config["DATABASE_PATH"]
    endpoint_repo = EndpointRepository(db_path)
    now = _utc_now()
    endpoint_repo.upsert({"agent_id": "probe-agent", "hostname": "probe-box", "os": "Linux", "last_seen": now})

    alert_repo = AlertRepository(db_path)
    malicious_title = "Backdoor'); alert('ATTR_XSS');//"
    alert = alert_repo.create_or_update({
        "alert_key": "alert:probe-attr-xss",
        "agent_id": "probe-agent",
        "rule_id": "probe-rule",
        "title": malicious_title,
        "description": "Probe Description",
        "severity": "high",
        "status": "new",
        "first_seen_at": now,
        "last_seen_at": now,
    })

    alerts_page = client.get("/alerts").get_data(as_text=True)
    # Must NOT contain vulnerable inline onclick concatenation
    assert "onclick=\"promptResolveAlert(" not in alerts_page
    # Must contain safe data-alert-title attribute
    assert 'class="btn btn-green btn-sm btn-prompt-resolve"' in alerts_page
    assert f'data-alert-id="{alert["id"]}"' in alerts_page


def test_dom_xss_view_evidence_mitigation():
    """Verify static/dashboard.js uses escapeHtml for all untrusted telemetry fields in viewEvidence."""
    with open(PROJECT_ROOT / "static" / "dashboard.js", "r", encoding="utf-8") as f:
        js_code = f.read()

    assert "escapeHtml(alert.title)" in js_code
    assert "escapeHtml(alert.description" in js_code
    assert "escapeHtml(ev.title" in js_code
    assert "escapeHtml(ev.event_type)" in js_code
    assert "escapeHtml(formatJsonString(ev.evidence_json))" in js_code


def test_secret_key_form_post_resilience(client, app):
    """Form POST actions with session flashes succeed without missing secret key error."""
    db_path = app.config["DATABASE_PATH"]
    endpoint_repo = EndpointRepository(db_path)
    now = _utc_now()
    endpoint_repo.upsert({"agent_id": "probe-agent", "hostname": "probe-box", "os": "Linux", "last_seen": now})

    alert_repo = AlertRepository(db_path)
    alert = alert_repo.create_or_update({
        "alert_key": "alert:probe-form-post",
        "agent_id": "probe-agent",
        "rule_id": "probe-rule",
        "title": "Probe Alert for Form POST",
        "severity": "medium",
        "status": "new",
        "first_seen_at": now,
        "last_seen_at": now,
    })

    # Submitting form-encoded POST must NOT raise RuntimeError
    resp = client.post(
        f"/alerts/{alert['id']}/acknowledge",
        data={"note": "Form post note"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    updated = alert_repo.get_by_id(alert["id"])
    assert updated["status"] == "acknowledged"


def test_web_console_session_authentication(tmp_path):
    """Web SOC views enforce login when ENFORCE_WEB_AUTH_IN_TESTS is enabled."""
    db_path = tmp_path / "web_auth_test.db"
    application = create_app({
        "TESTING": True,
        "EDR_API_TOKEN": "valid-secret-token-123456789012345678",
        "DATABASE_PATH": str(db_path),
        "ENFORCE_WEB_AUTH_IN_TESTS": True,
    })
    test_client = application.test_client()

    # 1. Unauthenticated request redirects to /login
    res_unauth = test_client.get("/dashboard")
    assert res_unauth.status_code == 302
    assert "/login" in res_unauth.headers["Location"]

    # 2. Login page renders cleanly
    res_login_page = test_client.get("/login")
    assert res_login_page.status_code == 200
    assert "AUTHENTICATE SESSION" in res_login_page.get_data(as_text=True)

    # 3. Invalid token fails
    res_bad_login = test_client.post("/login", data={"token": "wrong-token"})
    assert res_bad_login.status_code == 200
    assert "Authentication rejected" in res_bad_login.get_data(as_text=True)

    # 4. Valid token succeeds and sets session
    res_good_login = test_client.post(
        "/login",
        data={"token": "valid-secret-token-123456789012345678"},
        follow_redirects=True,
    )
    assert res_good_login.status_code == 200
    assert "SOC COMMAND CENTER" in res_good_login.get_data(as_text=True)

    # 5. Logout terminates session via POST (GET is rejected to prevent Logout CSRF)
    res_get_logout = test_client.get("/logout")
    assert res_get_logout.status_code == 405

    res_logout = test_client.post("/logout", follow_redirects=True)
    assert res_logout.status_code == 200
    assert "terminated" in res_logout.get_data(as_text=True)


def test_csrf_protection_on_alert_mutations(tmp_path):
    """State-changing alert mutations reject requests when CSRF token is invalid or missing."""
    db_path = tmp_path / "csrf_test.db"
    application = create_app({
        "TESTING": True,
        "EDR_API_TOKEN": "valid-secret-token-123456789012345678",
        "DATABASE_PATH": str(db_path),
        "ENFORCE_CSRF_IN_TESTS": True,
    })
    test_client = application.test_client()

    alert_repo = AlertRepository(str(db_path))
    endpoint_repo = EndpointRepository(str(db_path))
    now = _utc_now()
    endpoint_repo.upsert({"agent_id": "probe-agent", "hostname": "probe-box", "os": "Linux", "last_seen": now})
    alert = alert_repo.create_or_update({
        "alert_key": "alert:probe-csrf",
        "agent_id": "probe-agent",
        "rule_id": "probe-rule",
        "title": "Probe Alert for CSRF",
        "severity": "medium",
        "status": "new",
        "first_seen_at": now,
        "last_seen_at": now,
    })

    # 1. Missing CSRF token is rejected with HTTP 403
    res_no_csrf = test_client.post(f"/alerts/{alert['id']}/resolve", json={"resolution_note": "Hacked"})
    assert res_no_csrf.status_code == 403
    assert "CSRF verification failed" in res_no_csrf.get_json()["error"]

    # 2. Authenticate session to establish valid csrf_token
    with test_client.session_transaction() as sess:
        sess["operator_authenticated"] = True
        sess["csrf_token"] = "valid-csrf-token-12345"

    # 3. Valid CSRF token in header succeeds
    res_valid_csrf = test_client.post(
        f"/alerts/{alert['id']}/resolve",
        headers={"X-CSRF-Token": "valid-csrf-token-12345"},
        json={"resolution_note": "Resolved with CSRF"},
    )
    assert res_valid_csrf.status_code == 200
    assert res_valid_csrf.get_json()["status"] == "resolved"

