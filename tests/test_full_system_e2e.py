"""Full-cycle End-to-End (E2E) integration test for Phase 8.

Simulates the entire Mini EDR operational workflow across all 7 phases:
1. Agent registration & System Telemetry Heartbeat (Phase 1, 3, 4).
2. FIM Baseline Synchronization (Phase 2, 3, 4).
3. Malicious Process Snapshot Ingestion & Real-Time Detection (Phase 3, 4, 5).
4. Sensitive File Tampering & Multi-Factor Threat Correlation (Phase 4, 5).
5. Incident Generation, Evidence Linking, and Triage (Phase 5, 6).
6. Web SOC Dashboard Live Reflection & Telemetry Inspection (Phase 7).
7. Operator Incident Lifecycle: Acknowledge -> Resolve with Notes (Phase 6, 7).
8. Agent Heartbeat Expiration (Offline transition) and Online Re-activation (Phase 1, 4).
9. SQLite Database Integrity & Foreign Key Verification (Phase 2, 8).
"""

from datetime import datetime, timezone
import time
import uuid
import pytest

from server.app import create_app
from server.db import get_connection

TOKEN = "e2e-phase8-master-token"


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _new_msg_id():
    return str(uuid.uuid4())


@pytest.fixture()
def app(tmp_path):
    db_path = tmp_path / "mini_edr_e2e_phase8.db"
    application = create_app({
        "TESTING": True,
        "EDR_API_TOKEN": TOKEN,
        "DATABASE_PATH": str(db_path),
        "OFFLINE_AFTER_SECONDS": 2,  # short timeout for offline transition testing
    })
    application.config["TEST_DATABASE_PATH"] = db_path
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def auth_headers(token=TOKEN):
    return {"Authorization": f"Bearer {token}"}


def test_full_system_e2e_lifecycle(client, app):
    """Verify complete end-to-end integration across all subsystems."""
    agent_id = "agent-e2e-node-01"
    now = _utc_now()

    # =========================================================================
    # Step 1: Agent Registration via Heartbeat
    # =========================================================================
    heartbeat_payload = {
        "agent_id": agent_id,
        "hostname": "kali-target-box",
        "os": "Linux 6.8.0-kali",
        "ip_address": "192.168.10.50",
        "agent_version": "1.0.0",
        "metrics": {
            "cpu_percent": 24.5,
            "memory_percent": 55.0,
            "disk_percent": 42.0,
            "uptime_seconds": 15000.0,
        },
    }
    hb_resp = client.post(
        "/api/v1/heartbeat",
        json=heartbeat_payload,
        headers=auth_headers(),
    )
    assert hb_resp.status_code == 200
    assert hb_resp.get_json()["success"] is True
    assert hb_resp.get_json()["agent_id"] == agent_id

    # Verify endpoint inventory via REST API
    ep_list_resp = client.get("/api/v1/endpoints", headers=auth_headers())
    assert ep_list_resp.status_code == 200
    endpoints = ep_list_resp.get_json()["endpoints"]
    assert len(endpoints) == 1
    assert endpoints[0]["agent_id"] == agent_id
    assert endpoints[0]["status"] == "online"

    # =========================================================================
    # Step 2: FIM Baseline Synchronization
    # =========================================================================
    baseline_payload = {
        "message_id": _new_msg_id(),
        "schema_version": "1.0",
        "agent_id": agent_id,
        "collected_at": now,
        "payload": {
            "files": [
                {
                    "file_path": "/etc/passwd",
                    "sha256": "38c5efb0e00beae3f3a763ef8b2575fe7bc4878a9c2ecad1973b7a5449755b76",
                    "file_size_bytes": 2400,
                    "mtime_ns": 1700000000000000000,
                    "file_mode": 0o644,
                    "state": "present",
                },
                {
                    "file_path": "/etc/shadow",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "file_size_bytes": 1200,
                    "mtime_ns": 1700000000000000000,
                    "file_mode": 0o640,
                    "state": "present",
                },
            ]
        },
    }
    base_resp = client.post(
        "/api/v1/file-baselines",
        json=baseline_payload,
        headers=auth_headers(),
    )
    assert base_resp.status_code == 200
    assert base_resp.get_json()["success"] is True
    assert base_resp.get_json()["processed"] == 2

    # =========================================================================
    # Step 3: Process Snapshot Ingestion & Real-Time Threat Detection
    # =========================================================================
    # Malicious process running from /tmp consuming 92% CPU
    proc_payload = {
        "message_id": _new_msg_id(),
        "schema_version": "1.0",
        "agent_id": agent_id,
        "collected_at": now,
        "payload": {
            "process_count": 2,
            "processes": [
                {
                    "pid": 1337,
                    "ppid": 1,
                    "process_name": "nc",
                    "username": "root",
                    "exe_path": "/tmp/nc",
                    "cpu_percent": 92.5,
                    "memory_percent": 15.0,
                    "rss_bytes": 1048576,
                    "process_started_at": now,
                },
                {
                    "pid": 200,
                    "ppid": 1,
                    "process_name": "systemd",
                    "username": "root",
                    "exe_path": "/usr/lib/systemd/systemd",
                    "cpu_percent": 0.1,
                    "memory_percent": 2.0,
                    "rss_bytes": 4194304,
                    "process_started_at": now,
                },
            ]
        },
    }
    proc_resp = client.post(
        "/api/v1/telemetry/processes",
        json=proc_payload,
        headers=auth_headers(),
    )
    assert proc_resp.status_code == 201
    assert proc_resp.get_json()["success"] is True

    # DetectionEngine should have evaluated the process snapshot in real time:
    # 1. Suspicious path (/tmp/nc) -> high risk
    # 2. High CPU (92.5%) -> risk factor
    # Automatically created security events and correlated alert!
    alerts_resp = client.get(f"/api/v1/alerts?agent_id={agent_id}", headers=auth_headers())
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.get_json()["alerts"]
    assert len(alerts) >= 1
    proc_alert = alerts[0]
    assert proc_alert["status"] == "new"
    assert proc_alert["severity"] in ("high", "critical")
    alert_id = proc_alert["id"]

    # =========================================================================
    # Step 4: Sensitive File Tampering Detection (FIM)
    # =========================================================================
    fim_event_payload = {
        "message_id": _new_msg_id(),
        "schema_version": "1.0",
        "agent_id": agent_id,
        "collected_at": now,
        "payload": {
            "event_type": "fim_sensitive_file",
            "severity": "critical",
            "source": "agent",
            "title": "Critical Authentication File Modified: /etc/shadow",
            "description": "Cryptographic hash mismatch detected on /etc/shadow",
            "evidence": {
                "file_path": "/etc/shadow",
                "previous_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "current_sha256": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
            },
            "occurred_at": now,
        },
    }
    fim_resp = client.post(
        "/api/v1/events",
        json=fim_event_payload,
        headers=auth_headers(),
    )
    assert fim_resp.status_code == 201
    assert fim_resp.get_json()["success"] is True

    # =========================================================================
    # Step 5: Web Dashboard Verification (Phase 7)
    # =========================================================================
    # Overview page
    dash_resp = client.get("/dashboard")
    assert dash_resp.status_code == 200
    dash_html = dash_resp.get_data(as_text=True)
    assert "SOC COMMAND CENTER" in dash_html
    assert "MONITORED ENDPOINTS" in dash_html
    assert agent_id in dash_html

    # Endpoints matrix
    ep_page_resp = client.get("/endpoints")
    assert ep_page_resp.status_code == 200
    ep_html = ep_page_resp.get_data(as_text=True)
    assert "kali-target-box" in ep_html
    assert "ONLINE" in ep_html

    # Endpoint telemetry modal data
    telem_resp = client.get(f"/endpoints/{agent_id}/telemetry")
    assert telem_resp.status_code == 200
    telem_data = telem_resp.get_json()
    assert telem_data["success"] is True
    assert telem_data["baselines_count"] == 2
    procs = telem_data["processes"]
    assert any(p["process_name"] == "nc" for p in procs)

    # Incident Response view
    alerts_page_resp = client.get("/alerts")
    assert alerts_page_resp.status_code == 200
    alerts_html = alerts_page_resp.get_data(as_text=True)
    assert "INCIDENT RESPONSE" in alerts_html
    assert "NEW" in alerts_html

    # Alert detail modal API with evidence
    detail_resp = client.get(f"/alerts/{alert_id}/detail")
    assert detail_resp.status_code == 200
    detail_data = detail_resp.get_json()
    assert detail_data["success"] is True
    assert detail_data["alert"]["id"] == alert_id
    assert len(detail_data["events"]) >= 1

    # =========================================================================
    # Step 6: Incident Triage (Acknowledge -> Resolve)
    # =========================================================================
    # Operator acknowledges alert
    ack_resp = client.post(
        f"/alerts/{alert_id}/acknowledge",
        json={"note": "SOC Tier 1 actively containing threat"},
    )
    assert ack_resp.status_code == 200
    ack_data = ack_resp.get_json()
    assert ack_data["status"] == "acknowledged"
    assert ack_data["resolution_note"] == "SOC Tier 1 actively containing threat"

    # Operator resolves alert
    res_resp = client.post(
        f"/alerts/{alert_id}/resolve",
        json={"resolution_note": "Host isolated, /tmp/nc killed and deleted"},
    )
    assert res_resp.status_code == 200
    res_data = res_resp.get_json()
    assert res_data["status"] == "resolved"
    assert res_data["resolution_note"] == "Host isolated, /tmp/nc killed and deleted"

    # State transition guard: resolved alert cannot transition back to acknowledged
    guard_resp = client.post(
        f"/api/v1/alerts/{alert_id}/acknowledge",
        headers=auth_headers(),
    )
    assert guard_resp.status_code == 400
    assert "cannot be acknowledged" in guard_resp.get_json()["error"]

    # =========================================================================
    # Step 7: Offline Transition and Online Re-activation
    # =========================================================================
    # Sleep beyond OFFLINE_AFTER_SECONDS (2.0s)
    time.sleep(2.2)

    # Calling endpoints list recalculates status
    ep_recheck = client.get("/api/v1/endpoints", headers=auth_headers())
    assert ep_recheck.get_json()["endpoints"][0]["status"] == "offline"

    # Fresh heartbeat brings endpoint back online
    hb_revive = client.post(
        "/api/v1/heartbeat",
        json=heartbeat_payload,
        headers=auth_headers(),
    )
    assert hb_revive.status_code == 200
    assert hb_revive.get_json()["success"] is True

    # Recheck endpoint status is online
    ep_revive_check = client.get("/api/v1/endpoints", headers=auth_headers())
    assert ep_revive_check.get_json()["endpoints"][0]["status"] == "online"

    # =========================================================================
    # Step 8: Database Integrity & PRAGMA Verification
    # =========================================================================
    db_path = app.config["DATABASE_PATH"]
    conn = get_connection(db_path)
    try:
        # Integrity check
        integrity_row = conn.execute("PRAGMA integrity_check;").fetchone()
        assert integrity_row[0] == "ok"

        # Foreign key check: must be empty (0 violations)
        fk_violations = conn.execute("PRAGMA foreign_key_check;").fetchall()
        assert len(fk_violations) == 0

        # Quick check of table counts
        total_endpoints = conn.execute("SELECT COUNT(*) FROM endpoints;").fetchone()[0]
        assert total_endpoints == 1

        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts;").fetchone()[0]
        assert total_alerts >= 1

        total_events = conn.execute("SELECT COUNT(*) FROM security_events;").fetchone()[0]
        assert total_events >= 1
    finally:
        conn.close()
