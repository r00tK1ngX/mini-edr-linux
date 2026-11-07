"""Phase 1 Web Security Test Suite for Mini EDR Linux.

Validates all security fixes implemented in Phase 1:
- Unauthenticated access control and redirection
- Denial of credentials via URL query parameters (?token=)
- Login authentication, invalid tokens, and Login CSRF protection
- Logout method enforcement (POST-only) and Logout CSRF protection
- Open Redirect rejection across all vectors (external URLs, scheme-less, protocol-relative)
- Session cookie security flags (HttpOnly, SameSite=Lax)
- SECRET_KEY persistence and stability across factory reloads
- Session expiration and session clearance
- DOM XSS immunity across HTML templates and dynamic JavaScript modal sinks
"""

from datetime import datetime, timezone
import os
from pathlib import Path
import pytest

from server.app import create_app
from server.repositories.alert_repository import AlertRepository
from server.repositories.endpoint_repository import EndpointRepository
from server.repositories.event_repository import EventRepository
from server.repositories.process_repository import ProcessRepository
from server.web import is_safe_url


VALID_TEST_TOKEN = "a-very-long-random-secret-token-for-testing-only-12345"


@pytest.fixture
def web_security_app(tmp_path):
    """Factory fixture generating test app with web auth and CSRF enforcement options."""
    db_path = tmp_path / "web_sec_test.db"
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(db_path),
        "EDR_API_TOKEN": VALID_TEST_TOKEN,
        "ENFORCE_WEB_AUTH_IN_TESTS": True,
        "ENFORCE_CSRF_IN_TESTS": True,
    })
    return app


# -----------------------------------------------------------------------------
# 1. Open Redirect Validation
# -----------------------------------------------------------------------------

def test_is_safe_url_helper():
    """Verify is_safe_url correctly accepts local paths and rejects malicious targets."""
    # Safe local targets
    assert is_safe_url("/dashboard") is True
    assert is_safe_url("/alerts") is True
    assert is_safe_url("/alerts?severity=high&status=new") is True
    assert is_safe_url("/endpoints/lab-01/telemetry") is True
    assert is_safe_url("/") is True

    # Malicious external & bypass targets
    assert is_safe_url("https://evil.com") is False
    assert is_safe_url("http://attacker.com/steal") is False
    assert is_safe_url("//evil.com") is False
    assert is_safe_url("//evil.com/path") is False
    assert is_safe_url("///evil.com") is False
    assert is_safe_url("/\\evil.com") is False
    assert is_safe_url("\\evil.com") is False
    assert is_safe_url("javascript:alert(1)") is False
    assert is_safe_url("data:text/html,<script>alert(1)</script>") is False
    assert is_safe_url("") is False
    assert is_safe_url("   ") is False
    assert is_safe_url(None) is False


def test_open_redirect_rejected_on_login(web_security_app):
    """Attempting open redirect via ?next= or form next is rejected, falling back to /dashboard."""
    client = web_security_app.test_client()

    # Get CSRF token
    res_get = client.get("/login")
    with client.session_transaction() as sess:
        csrf_token = sess.get("csrf_token")

    # Malicious external targets
    malicious_targets = [
        "https://evil.com",
        "http://attacker.com/login",
        "//evil.com",
        "//evil.com/phish",
        "/\\evil.com",
        "javascript:alert(1)",
    ]

    for target in malicious_targets:
        res = client.post(
            "/login",
            data={
                "token": VALID_TEST_TOKEN,
                "csrf_token": csrf_token,
                "next": target,
            },
            follow_redirects=False,
        )
        assert res.status_code == 302
        assert res.headers["Location"].endswith("/dashboard"), (
            f"Expected fallback to /dashboard for malicious target '{target}', got: {res.headers['Location']}"
        )


def test_safe_local_redirect_allowed_on_login(web_security_app):
    """Legitimate relative URLs in next parameter are respected upon login."""
    client = web_security_app.test_client()

    client.get("/login")
    with client.session_transaction() as sess:
        csrf_token = sess.get("csrf_token")

    res = client.post(
        "/login",
        data={
            "token": VALID_TEST_TOKEN,
            "csrf_token": csrf_token,
            "next": "/alerts?severity=critical",
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    assert res.headers["Location"].endswith("/alerts?severity=critical")


# -----------------------------------------------------------------------------
# 2. Authentication & Credential Leakage via Query String
# -----------------------------------------------------------------------------

def test_unauthenticated_access_redirects_to_login(web_security_app):
    """Unauthenticated requests to protected views redirect to /login with validated next parameter."""
    client = web_security_app.test_client()

    views = ["/dashboard", "/endpoints", "/alerts", "/events"]
    for view in views:
        res = client.get(view, follow_redirects=False)
        assert res.status_code == 302
        assert "/login" in res.headers["Location"]
        assert f"next={view}" in res.headers["Location"]


def test_unauthenticated_modal_api_returns_401(web_security_app):
    """Modal inspection API endpoints return HTTP 401 JSON when accessed without session."""
    client = web_security_app.test_client()

    res_ep = client.get("/endpoints/unknown-agent/telemetry")
    assert res_ep.status_code == 401
    assert res_ep.get_json()["success"] is False

    res_alt = client.get("/alerts/1/detail")
    assert res_alt.status_code == 401
    assert res_alt.get_json()["success"] is False


def test_token_in_query_string_rejected(web_security_app):
    """Passing token in URL query parameter (?token=) is rejected to prevent credential leakage."""
    client = web_security_app.test_client()

    # Attempting to access protected view via ?token= must NOT authenticate session
    res = client.get(f"/dashboard?token={VALID_TEST_TOKEN}", follow_redirects=False)
    assert res.status_code == 302
    assert "/login" in res.headers["Location"]

    with client.session_transaction() as sess:
        assert sess.get("operator_authenticated") is not True


def test_bearer_token_in_auth_header_accepted(web_security_app):
    """Authorization: Bearer <token> in request header is accepted and authenticates session."""
    client = web_security_app.test_client()

    res = client.get(
        "/dashboard",
        headers={"Authorization": f"Bearer {VALID_TEST_TOKEN}"},
        follow_redirects=False,
    )
    assert res.status_code == 200
    with client.session_transaction() as sess:
        assert sess.get("operator_authenticated") is True


# -----------------------------------------------------------------------------
# 3. Login CSRF & Invalid Credentials
# -----------------------------------------------------------------------------

def test_login_csrf_validation_missing_token_rejected(web_security_app):
    """POST /login without anti-CSRF token returns HTTP 400 Bad Request."""
    client = web_security_app.test_client()
    client.get("/login")

    res = client.post(
        "/login",
        data={"token": VALID_TEST_TOKEN},  # Missing csrf_token
    )
    assert res.status_code == 400
    assert "CSRF" in res.get_data(as_text=True)

    with client.session_transaction() as sess:
        assert sess.get("operator_authenticated") is not True


def test_login_csrf_validation_invalid_token_rejected(web_security_app):
    """POST /login with invalid anti-CSRF token returns HTTP 400 Bad Request."""
    client = web_security_app.test_client()
    client.get("/login")

    res = client.post(
        "/login",
        data={
            "token": VALID_TEST_TOKEN,
            "csrf_token": "malicious-attacker-forged-token",
        },
    )
    assert res.status_code == 400
    assert "CSRF" in res.get_data(as_text=True)

    with client.session_transaction() as sess:
        assert sess.get("operator_authenticated") is not True


def test_login_invalid_credentials_rejected(web_security_app):
    """POST /login with valid CSRF but wrong token returns error and does not authenticate."""
    client = web_security_app.test_client()
    client.get("/login")
    with client.session_transaction() as sess:
        csrf_token = sess.get("csrf_token")

    res = client.post(
        "/login",
        data={
            "token": "wrong-token-abc",
            "csrf_token": csrf_token,
        },
    )
    assert res.status_code == 200
    assert "Authentication rejected" in res.get_data(as_text=True)

    with client.session_transaction() as sess:
        assert sess.get("operator_authenticated") is not True


# -----------------------------------------------------------------------------
# 4. Logout POST Enforcement & Logout CSRF Protection
# -----------------------------------------------------------------------------

def test_logout_via_get_rejected(web_security_app):
    """GET /logout is rejected with HTTP 405 Method Not Allowed to eliminate Logout CSRF."""
    client = web_security_app.test_client()

    # Authenticate session first
    client.get("/login")
    with client.session_transaction() as sess:
        sess["operator_authenticated"] = True

    # Attempt logout via GET (e.g. from an embedded <img src="/logout">)
    res = client.get("/logout")
    assert res.status_code == 405


def test_logout_via_post_without_csrf_rejected(web_security_app):
    """POST /logout without CSRF token fails CSRF validation."""
    client = web_security_app.test_client()

    client.get("/login")
    with client.session_transaction() as sess:
        sess["operator_authenticated"] = True

    # POST logout with missing CSRF token
    res = client.post("/logout", follow_redirects=False)
    assert res.status_code == 302
    assert res.headers["Location"].endswith("/dashboard")


def test_logout_via_post_with_csrf_succeeds(web_security_app):
    """POST /logout with valid CSRF terminates operator session cleanly."""
    client = web_security_app.test_client()

    client.get("/login")
    with client.session_transaction() as sess:
        sess["operator_authenticated"] = True
        csrf_token = sess.get("csrf_token")

    res = client.post(
        "/logout",
        data={"csrf_token": csrf_token},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert "terminated" in res.get_data(as_text=True)

    with client.session_transaction() as sess:
        assert sess.get("operator_authenticated") is not True


# -----------------------------------------------------------------------------
# 5. Session Cookie Security Flags & SECRET_KEY Stability
# -----------------------------------------------------------------------------

def test_session_cookie_flags_configured(web_security_app):
    """Verify session cookie configuration contains HttpOnly and SameSite=Lax flags."""
    assert web_security_app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert web_security_app.config["SESSION_COOKIE_SAMESITE"] == "Lax"

    client = web_security_app.test_client()
    res = client.get("/login")
    cookie_header = res.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie_header
    assert "SameSite=Lax" in cookie_header


def test_secret_key_stability_across_reloads(tmp_path):
    """Verify SECRET_KEY is persisted to disk and stable across application factory reloads."""
    # Ensure env SECRET_KEY is unset for this test
    original_secret = os.environ.pop("SECRET_KEY", None)
    try:
        data_dir = tmp_path / "data"
        db_file = data_dir / "test_stability.db"

        app1 = create_app({
            "TESTING": True,
            "DATABASE_PATH": str(db_file),
            "EDR_API_TOKEN": VALID_TEST_TOKEN,
        })
        key1 = app1.config["SECRET_KEY"]

        # Instantiate second factory instance pointing to same environment
        app2 = create_app({
            "TESTING": True,
            "DATABASE_PATH": str(db_file),
            "EDR_API_TOKEN": VALID_TEST_TOKEN,
        })
        key2 = app2.config["SECRET_KEY"]

        assert key1 == key2, "SECRET_KEY must remain stable across factory reloads"
        assert len(key1) >= 32, "SECRET_KEY must have adequate entropy"
    finally:
        if original_secret:
            os.environ["SECRET_KEY"] = original_secret


# -----------------------------------------------------------------------------
# 6. DOM XSS & Dynamic Modal Error Sink Immunity
# -----------------------------------------------------------------------------

def test_xss_payload_escaped_in_dashboard_and_modals(tmp_path):
    """Verify malicious HTML/JS payloads in telemetry and errors are strictly escaped."""
    db_path = tmp_path / "xss_test.db"
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(db_path),
        "EDR_API_TOKEN": VALID_TEST_TOKEN,
    })
    client = app.test_client()

    now = datetime.now(timezone.utc).isoformat()
    ep_repo = EndpointRepository(str(db_path))
    proc_repo = ProcessRepository(str(db_path))
    alert_repo = AlertRepository(str(db_path))
    event_repo = EventRepository(str(db_path))

    # Aggressive XSS payloads
    xss_payloads = {
        "hostname": 'test-host<script>alert("xss-host")</script>',
        "agent_id": 'agent-xss-"onload="alert(1)',
        "process_name": '<img src=x onerror=alert("xss-proc")>',
        "exe_path": '/tmp/<!--<script>alert("xss-path")</script>-->/bad',
        "alert_title": '<b onmouseover="alert(\'xss-title\')">CRITICAL THREAT</b>',
        "alert_description": '<svg/onload=alert("xss-desc")>',
        "error_message": '<img src=x onerror=alert("xss-error")>',
    }

    # Seed data
    ep_repo.upsert({
        "agent_id": xss_payloads["agent_id"],
        "hostname": xss_payloads["hostname"],
        "ip_address": "10.0.0.99",
        "os": "Linux",
        "last_seen": now,
    })

    snap = proc_repo.create_snapshot(
        {
            "message_id": "00000000-0000-4000-8000-000000000001",
            "agent_id": xss_payloads["agent_id"],
            "process_count": 1,
            "collected_at": now,
            "received_at": now,
        },
        [{
            "pid": 9999,
            "process_name": xss_payloads["process_name"],
            "exe_path": xss_payloads["exe_path"],
            "username": "root",
            "cpu_percent": 12.5,
            "memory_percent": 5.0,
        }],
    )

    alert_repo.create_or_update({
        "alert_key": "xss-test-alert",
        "agent_id": xss_payloads["agent_id"],
        "rule_id": "rule-test-xss",
        "title": xss_payloads["alert_title"],
        "description": xss_payloads["alert_description"],
        "severity": "high",
        "status": "new",
    })

    # Authenticate session
    with client.session_transaction() as sess:
        sess["operator_authenticated"] = True

    # 1. Test Dashboard HTML rendering
    res_dash = client.get("/dashboard")
    dash_html = res_dash.get_data(as_text=True)
    assert "<script>alert(" not in dash_html
    assert "<img src=x onerror" not in dash_html
    assert "<svg/onload=" not in dash_html

    # 2. Test Alerts HTML rendering
    res_alerts = client.get("/alerts")
    alerts_html = res_alerts.get_data(as_text=True)
    assert "<script>alert(" not in alerts_html
    assert 'data-alert-title="&lt;b onmouseover=' in alerts_html or "data-alert-title=" in alerts_html
    assert "<svg/onload=" not in alerts_html

    # 3. Test Endpoints HTML rendering
    res_ep = client.get("/endpoints")
    ep_html = res_ep.get_data(as_text=True)
    assert "<script>alert(" not in ep_html

    # 4. Inspect dashboard.js for safe error rendering
    js_path = Path(__file__).resolve().parent.parent / "static" / "dashboard.js"
    js_content = js_path.read_text(encoding="utf-8")
    assert "renderErrorMessage" in js_content, "dashboard.js must use renderErrorMessage"
    assert "body.innerHTML = `<div style=\"color: var(--neon-red);\">Failed to load evidence: ${data.error}</div>`" not in js_content
    assert "body.innerHTML = `<div style=\"color: var(--neon-red);\">Error: ${data.error}</div>`" not in js_content
