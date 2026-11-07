"""Phase 5 Resource & Reliability Test Suite for Mini EDR Linux.

Verifies:
1. Snapshot process count boundary (limit: 1000) (FINDING-NEW-12, TEST-P5-01).
2. Baseline files array boundary (limit: 5000) (FINDING-NEW-12, TEST-P5-02).
3. Field length constraints across process, baseline, and event models (TEST-P5-03).
4. Telemetry TTL retention pruning and cascade cleanup (FINDING-PHASE02-03, TEST-P5-04).
5. Malformed UTF-8 request handling (TEST-P5-05).
6. Request payload body limits with HTTP 413 (TEST-P5-06).
7. Agent local event spool bounded capacity and FIFO drop policy (TEST-P5-07).
8. Agent process collector safe truncation on oversized process names (TEST-P5-08).
9. Administrative maintenance pruning endpoint (TEST-P5-09).
"""

from datetime import datetime, timedelta, timezone
import json
import sqlite3
import uuid
import pytest

from agent.process_collector import _clean_process_name
from agent.spool import EventSpool
from server.app import create_app
from server.db import get_connection
from server.maintenance import prune_telemetry
from server.repositories.metrics_repository import MetricsRepository
from server.repositories.process_repository import ProcessRepository

TOKEN = "token-p5-test-secret-123456789012345678901234"


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _new_uuid():
    return str(uuid.uuid4())


@pytest.fixture()
def app(tmp_path):
    db_path = tmp_path / "mini_edr_p5.db"
    application = create_app({
        "TESTING": True,
        "EDR_API_TOKEN": TOKEN,
        "DATABASE_PATH": str(db_path),
        "OFFLINE_AFTER_SECONDS": 15,
        "MAX_CONTENT_LENGTH": 1024 * 1024,  # 1 MiB for tests
    })
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def auth_headers(token=TOKEN):
    return {"Authorization": f"Bearer {token}"}


def register_endpoint(client, agent_id="agent-p5-01"):
    return client.post(
        "/api/v1/heartbeat",
        json={
            "agent_id": agent_id,
            "hostname": "kali-p5",
            "os": "Ubuntu 24.04 LTS",
            "metrics": {
                "cpu_percent": 12.0,
                "memory_percent": 34.0,
                "disk_percent": 56.0,
                "uptime_seconds": 12345.0,
            },
        },
        headers=auth_headers(),
    )


# =============================================================================
# 1. Snapshot Process Count Boundary (Limit: 1000)
# =============================================================================

def test_oversized_process_count_rejected(client):
    """Submitting process snapshot exceeding MAX_PROCESSES_PER_SNAPSHOT (1000) returns 400."""
    register_endpoint(client, "agent-p5-proc-limit")
    msg_id = _new_uuid()

    payload = {
        "message_id": msg_id,
        "schema_version": "1.0",
        "agent_id": "agent-p5-proc-limit",
        "collected_at": _utc_now(),
        "payload": {
            "process_count": 1001,
            "processes": [{"pid": i, "process_name": f"proc_{i}"} for i in range(1001)],
        },
    }

    res = client.post(
        "/api/v1/telemetry/processes",
        json=payload,
        headers=auth_headers(),
    )
    assert res.status_code == 400
    assert "exceeds maximum allowed limit" in res.get_json()["error"]


# =============================================================================
# 2. Baseline Files Array Boundary (Limit: 5000)
# =============================================================================

def test_oversized_baseline_files_rejected(client):
    """Submitting baseline batch exceeding MAX_FILES_PER_BASELINE (5000) returns 400."""
    register_endpoint(client, "agent-p5-base-limit")
    msg_id = _new_uuid()

    payload = {
        "message_id": msg_id,
        "schema_version": "1.0",
        "agent_id": "agent-p5-base-limit",
        "collected_at": _utc_now(),
        "payload": {
            "files": [
                {
                    "file_path": f"/usr/bin/tool_{i}",
                    "sha256": "0" * 64,
                    "file_size_bytes": 100,
                    "mtime_ns": 1000000,
                    "file_mode": 493,
                }
                for i in range(5001)
            ]
        },
    }

    res = client.post(
        "/api/v1/file-baselines",
        json=payload,
        headers=auth_headers(),
    )
    assert res.status_code == 400
    assert "exceeds maximum allowed limit" in res.get_json()["error"]


# =============================================================================
# 3. Field Length Constraints
# =============================================================================

def test_process_name_exceeding_255_chars_rejected(client):
    """Submitting process_name > 255 chars returns 400 Bad Request."""
    register_endpoint(client, "agent-p5-fields")
    msg_id = _new_uuid()

    payload = {
        "message_id": msg_id,
        "schema_version": "1.0",
        "agent_id": "agent-p5-fields",
        "collected_at": _utc_now(),
        "payload": {
            "process_count": 1,
            "processes": [
                {
                    "pid": 9999,
                    "process_name": "A" * 256,
                }
            ],
        },
    }

    res = client.post(
        "/api/v1/telemetry/processes",
        json=payload,
        headers=auth_headers(),
    )
    assert res.status_code == 400
    assert "process_name exceeds maximum length of 255 characters" in res.get_json()["error"]


def test_process_username_and_exe_path_limits(client):
    """Submitting username > 128 chars or exe_path > 4096 chars returns 400."""
    register_endpoint(client, "agent-p5-fields")

    # Username too long
    res_user = client.post(
        "/api/v1/telemetry/processes",
        json={
            "message_id": _new_uuid(),
            "schema_version": "1.0",
            "agent_id": "agent-p5-fields",
            "collected_at": _utc_now(),
            "payload": {
                "process_count": 1,
                "processes": [
                    {
                        "pid": 101,
                        "process_name": "worker",
                        "username": "U" * 129,
                    }
                ],
            },
        },
        headers=auth_headers(),
    )
    assert res_user.status_code == 400
    assert "username must be a string of at most 128 characters" in res_user.get_json()["error"]

    # Exe path too long
    res_exe = client.post(
        "/api/v1/telemetry/processes",
        json={
            "message_id": _new_uuid(),
            "schema_version": "1.0",
            "agent_id": "agent-p5-fields",
            "collected_at": _utc_now(),
            "payload": {
                "process_count": 1,
                "processes": [
                    {
                        "pid": 102,
                        "process_name": "worker",
                        "exe_path": "/bin/" + ("X" * 4095),
                    }
                ],
            },
        },
        headers=auth_headers(),
    )
    assert res_exe.status_code == 400
    assert "exe_path must be a string of at most 4096 characters" in res_exe.get_json()["error"]


def test_baseline_file_path_exceeding_4096_chars_rejected(client):
    """Submitting baseline with file_path > 4096 chars returns 400."""
    register_endpoint(client, "agent-p5-fields")

    res = client.post(
        "/api/v1/file-baselines",
        json={
            "message_id": _new_uuid(),
            "schema_version": "1.0",
            "agent_id": "agent-p5-fields",
            "collected_at": _utc_now(),
            "payload": {
                "files": [
                    {
                        "file_path": "/" + ("P" * 4097),
                        "sha256": "1" * 64,
                        "file_size_bytes": 10,
                        "mtime_ns": 1,
                        "file_mode": 420,
                    }
                ]
            },
        },
        headers=auth_headers(),
    )
    assert res.status_code == 400
    assert "file_path exceeds maximum length of 4096 characters" in res.get_json()["error"]


def test_security_event_field_and_evidence_limits(client):
    """Security event fields and serialized evidence exceeding bounds return 400."""
    register_endpoint(client, "agent-p5-fields")

    # event_type too long
    res_type = client.post(
        "/api/v1/events",
        json={
            "message_id": _new_uuid(),
            "schema_version": "1.0",
            "agent_id": "agent-p5-fields",
            "collected_at": _utc_now(),
            "payload": {
                "event_type": "E" * 65,
                "title": "Valid title",
            },
        },
        headers=auth_headers(),
    )
    assert res_type.status_code == 400
    assert "event_type exceeds maximum length" in res_type.get_json()["error"]

    # Description exceeds 4096 chars
    res_desc = client.post(
        "/api/v1/events",
        json={
            "message_id": _new_uuid(),
            "schema_version": "1.0",
            "agent_id": "agent-p5-fields",
            "collected_at": _utc_now(),
            "payload": {
                "event_type": "fim_anomaly",
                "title": "Valid title",
                "description": "D" * 4097,
            },
        },
        headers=auth_headers(),
    )
    assert res_desc.status_code == 400
    assert "description must be a string of at most 4096 characters" in res_desc.get_json()["error"]

    # Fingerprint exceeds 4096 chars
    res_fp = client.post(
        "/api/v1/events",
        json={
            "message_id": _new_uuid(),
            "schema_version": "1.0",
            "agent_id": "agent-p5-fields",
            "collected_at": _utc_now(),
            "payload": {
                "event_type": "fim_anomaly",
                "title": "Valid title",
                "fingerprint": "F" * 4097,
            },
        },
        headers=auth_headers(),
    )
    assert res_fp.status_code == 400
    assert "fingerprint must be a string of at most 4096 characters" in res_fp.get_json()["error"]

    # Evidence exceeds 64 KB
    huge_evidence = {"junk": "Z" * (70 * 1024)}
    res_ev = client.post(
        "/api/v1/events",
        json={
            "message_id": _new_uuid(),
            "schema_version": "1.0",
            "agent_id": "agent-p5-fields",
            "collected_at": _utc_now(),
            "payload": {
                "event_type": "fim_anomaly",
                "title": "Valid title",
                "evidence": huge_evidence,
            },
        },
        headers=auth_headers(),
    )
    assert res_ev.status_code == 400
    assert "evidence payload exceeds maximum allowed size" in res_ev.get_json()["error"]


# =============================================================================
# 4. Telemetry TTL Retention Pruning & Cascade Deletion (FINDING-PHASE02-03)
# =============================================================================

def test_telemetry_pruning_removes_old_and_preserves_recent(app):
    """prune_telemetry deletes records older than retention_days and cascades observations."""
    db_path = app.config["DATABASE_PATH"]
    conn = get_connection(db_path)

    # 1. Insert an agent
    conn.execute("""
        INSERT INTO endpoints (agent_id, hostname, ip_address, os, status, last_seen)
        VALUES ('agent-prune-test', 'prune-box', '10.0.0.1', 'Linux', 'online', datetime('now'))
        ON CONFLICT(agent_id) DO NOTHING
    """)

    old_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    recent_date = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()

    # 2. Insert metrics: one old (10 days ago), one recent (2 days ago)
    conn.execute("""
        INSERT INTO system_metrics (message_id, agent_id, cpu_percent, memory_percent, disk_percent, uptime_seconds, collected_at, received_at)
        VALUES ('msg-metric-old', 'agent-prune-test', 10.0, 20.0, 30.0, 100.0, ?, ?)
    """, (old_date, old_date))
    conn.execute("""
        INSERT INTO system_metrics (message_id, agent_id, cpu_percent, memory_percent, disk_percent, uptime_seconds, collected_at, received_at)
        VALUES ('msg-metric-recent', 'agent-prune-test', 15.0, 25.0, 35.0, 200.0, ?, ?)
    """, (recent_date, recent_date))

    # 3. Insert process snapshots with observations: one old, one recent
    conn.execute("""
        INSERT INTO process_snapshots (id, message_id, agent_id, process_count, collected_at, received_at)
        VALUES (8888, 'msg-snap-old', 'agent-prune-test', 2, ?, ?)
    """, (old_date, old_date))
    conn.execute("""
        INSERT INTO process_observations (snapshot_id, pid, process_name)
        VALUES (8888, 1, 'systemd'), (8888, 2, 'kthreadd')
    """)

    conn.execute("""
        INSERT INTO process_snapshots (id, message_id, agent_id, process_count, collected_at, received_at)
        VALUES (9999, 'msg-snap-recent', 'agent-prune-test', 1, ?, ?)
    """, (recent_date, recent_date))
    conn.execute("""
        INSERT INTO process_observations (snapshot_id, pid, process_name)
        VALUES (9999, 10, 'nginx')
    """)

    conn.commit()
    conn.close()

    # 4. Run prune_telemetry with 7 days retention
    prune_res = prune_telemetry(db_path, retention_days=7)
    assert prune_res["success"] is True
    assert prune_res["deleted_metrics"] == 1
    assert prune_res["deleted_snapshots"] == 1

    # 5. Verify database state
    verify_conn = get_connection(db_path)
    metrics = verify_conn.execute("SELECT message_id FROM system_metrics").fetchall()
    assert len(metrics) == 1
    assert metrics[0]["message_id"] == "msg-metric-recent"

    snapshots = verify_conn.execute("SELECT id FROM process_snapshots").fetchall()
    assert len(snapshots) == 1
    assert snapshots[0]["id"] == 9999

    # Verify CASCADE deleted observations of snapshot 8888
    obs_old = verify_conn.execute("SELECT pid FROM process_observations WHERE snapshot_id = 8888").fetchall()
    assert len(obs_old) == 0
    obs_recent = verify_conn.execute("SELECT pid FROM process_observations WHERE snapshot_id = 9999").fetchall()
    assert len(obs_recent) == 1
    verify_conn.close()


def test_maintenance_prune_api_endpoint(client):
    """POST /api/v1/maintenance/prune executes prune_telemetry over API."""
    res = client.post(
        "/api/v1/maintenance/prune",
        json={"retention_days": 14},
        headers=auth_headers(),
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["retention_days"] == 14
    assert "deleted_metrics" in data
    assert "deleted_snapshots" in data


# =============================================================================
# 5. Malformed UTF-8 Request Handling
# =============================================================================

def test_malformed_utf8_in_request_body_returns_400(client):
    """Sending invalid raw UTF-8 bytes returns 400 Bad Request, not unhandled 500."""
    res = client.post(
        "/api/v1/telemetry/processes",
        data=b"\x80\x81\x82\xff",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TOKEN}",
        },
    )
    assert res.status_code == 400
    assert res.get_json()["success"] is False


# =============================================================================
# 6. Request Payload Limit (HTTP 413)
# =============================================================================

def test_oversized_payload_stream_rejected_with_413(app):
    """Request exceeding app MAX_CONTENT_LENGTH returns HTTP 413."""
    small_app = create_app({
        "TESTING": True,
        "EDR_API_TOKEN": TOKEN,
        "MAX_CONTENT_LENGTH": 1024,  # 1 KB limit
    })
    c = small_app.test_client()

    oversized = {"junk": "X" * 2048}
    res = c.post(
        "/api/v1/heartbeat",
        json=oversized,
        headers=auth_headers(),
    )
    assert res.status_code == 413
    assert res.get_json()["error"] == "Request body is too large"


# =============================================================================
# 7. Agent Local Event Spool Queue Capacity & FIFO Drop Policy
# =============================================================================

def test_spool_queue_bounded_capacity_and_fifo_purge():
    """EventSpool purges acknowledged and oldest events when exceeding max_size."""
    spool = EventSpool(db_path=":memory:", max_size=5, agent_id="agent-spool-test")

    # Enqueue 5 events
    events = [
        {
            "message_id": f"msg-{i}",
            "schema_version": "1.0",
            "agent_id": "agent-spool-test",
            "payload": {"event_type": "fim", "index": i},
        }
        for i in range(5)
    ]
    enqueued = spool.enqueue_events(events)
    assert enqueued == 5
    assert spool.count_pending() == 5

    # Acknowledge the first 2 events
    spool.mark_acknowledged(["msg-0", "msg-1"])

    # Enqueue 2 more events; total would exceed 5, so acknowledged events msg-0, msg-1 are purged
    new_events = [
        {
            "message_id": "msg-5",
            "schema_version": "1.0",
            "agent_id": "agent-spool-test",
            "payload": {"event_type": "fim", "index": 5},
        },
        {
            "message_id": "msg-6",
            "schema_version": "1.0",
            "agent_id": "agent-spool-test",
            "payload": {"event_type": "fim", "index": 6},
        },
    ]
    spool.enqueue_events(new_events)

    # All 5 remaining should be pending (msg-2, msg-3, msg-4, msg-5, msg-6)
    pending = spool.get_pending_events(limit=10)
    pending_ids = [e["message_id"] for e in pending]
    assert len(pending_ids) == 5
    assert "msg-0" not in pending_ids
    assert "msg-1" not in pending_ids
    assert "msg-5" in pending_ids
    assert "msg-6" in pending_ids

    # Enqueue another event without acknowledging any: oldest pending (msg-2) should be purged
    spool.enqueue_events([
        {
            "message_id": "msg-7",
            "schema_version": "1.0",
            "agent_id": "agent-spool-test",
            "payload": {"event_type": "fim", "index": 7},
        }
    ])
    pending_after = spool.get_pending_events(limit=10)
    assert len(pending_after) == 5
    pending_after_ids = [e["message_id"] for e in pending_after]
    assert "msg-2" not in pending_after_ids
    assert "msg-7" in pending_after_ids


# =============================================================================
# 8. Agent Process Name Safe Truncation
# =============================================================================

def test_clean_process_name_safe_truncation():
    """_clean_process_name safely bounds process names to 255 chars."""
    huge_name = "malicious_process_" + ("A" * 500)
    cleaned = _clean_process_name(huge_name, None, 1234)
    assert len(cleaned) == 255
    assert cleaned.startswith("malicious_process_")

    huge_exe = "/usr/bin/" + ("B" * 500)
    cleaned_exe = _clean_process_name("", huge_exe, 5678)
    assert len(cleaned_exe) == 255
    assert cleaned_exe.startswith("BBBB")
