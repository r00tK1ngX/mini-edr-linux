"""Phase 4 Data Integrity Test Suite for Mini EDR Linux.

Validates all Phase 4 data integrity enhancements:
- Canonical JSON SHA-256 payload hashing for process snapshot deduplication (FINDING-NEW-09)
- Rejection of mismatched payloads reusing the same message_id (HTTP 409 Conflict)
- Security event canonical evidence idempotency verification
- Heartbeat partial-update semantics preserving existing endpoint metadata (FINDING-PHASE01-04)
- Chunked parameter queries for bulk baseline synchronization preventing SQLite variable overflow (FINDING-PHASE04-03)
- Foreign Key constraint enforcement and atomic transaction rollback on failure
"""

import json
import sqlite3
import uuid
import pytest

from server.app import create_app
from server.db import get_connection, init_db
from server.repositories.alert_repository import AlertRepository
from server.repositories.baseline_repository import BaselineRepository
from server.repositories.endpoint_repository import EndpointRepository
from server.repositories.event_repository import EventRepository
from server.repositories.process_repository import ProcessRepository

TOKEN = "test-phase4-token"


@pytest.fixture()
def app(tmp_path):
    database_path = tmp_path / "data_integrity_p4.db"
    application = create_app({
        "TESTING": True,
        "EDR_API_TOKEN": TOKEN,
        "DATABASE_PATH": str(database_path),
        "OFFLINE_AFTER_SECONDS": 15,
    })
    application.config["TEST_DATABASE_PATH"] = database_path
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def auth_headers():
    return {"Authorization": f"Bearer {TOKEN}"}


def register_endpoint(client, agent_id="agent-p4-01", hostname="kali-box", os="Kali Linux 2026"):
    resp = client.post(
        "/api/v1/heartbeat",
        json={
            "agent_id": agent_id,
            "hostname": hostname,
            "os": os,
            "agent_version": "1.0.0",
            "ip_address": "192.168.1.50",
            "metrics": {"cpu_percent": 10.0, "memory_percent": 20.0, "disk_percent": 30.0, "uptime_seconds": 1000.0},
        },
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    return agent_id


# -----------------------------------------------------------------------------
# 1. Process Snapshot Canonical Payload Hash Idempotency (FINDING-NEW-09)
# -----------------------------------------------------------------------------

def test_process_snapshot_idempotency_payload_hash(client, app):
    """Same message_id and identical payload is accepted as duplicate; same message_id with different payload returns 409 Conflict."""
    agent_id = register_endpoint(client, "agent-snap-idemp")
    msg_id = str(uuid.uuid4())

    payload_a = {
        "process_count": 2,
        "processes": [
            {"pid": 100, "ppid": 0, "process_name": "init", "exe_path": "/sbin/init", "cpu_percent": 0.1, "memory_percent": 0.1},
            {"pid": 101, "ppid": 100, "process_name": "sshd", "exe_path": "/usr/sbin/sshd", "cpu_percent": 0.5, "memory_percent": 1.0},
        ],
    }

    envelope_1 = {
        "schema_version": "1.0",
        "message_id": msg_id,
        "agent_id": agent_id,
        "collected_at": "2026-11-07T12:00:00Z",
        "payload": payload_a,
    }

    # 1. First submission succeeds (201 Created)
    resp1 = client.post("/api/v1/telemetry/processes", json=envelope_1, headers=auth_headers())
    assert resp1.status_code == 201
    assert resp1.get_json()["duplicate"] is False

    # 2. Retrying identical message_id with identical payload succeeds as duplicate (200 OK)
    resp2 = client.post("/api/v1/telemetry/processes", json=envelope_1, headers=auth_headers())
    assert resp2.status_code == 200
    assert resp2.get_json()["duplicate"] is True

    # 3. Reusing message_id with same process_count (2) but DIFFERENT processes must return 409 Conflict
    payload_b = {
        "process_count": 2,
        "processes": [
            {"pid": 200, "ppid": 0, "process_name": "malware1", "exe_path": "/tmp/malware1", "cpu_percent": 80.0, "memory_percent": 10.0},
            {"pid": 201, "ppid": 200, "process_name": "malware2", "exe_path": "/tmp/malware2", "cpu_percent": 75.0, "memory_percent": 15.0},
        ],
    }
    envelope_conflict = {
        "schema_version": "1.0",
        "message_id": msg_id,
        "agent_id": agent_id,
        "collected_at": "2026-11-07T12:00:00Z",
        "payload": payload_b,
    }

    resp3 = client.post("/api/v1/telemetry/processes", json=envelope_conflict, headers=auth_headers())
    assert resp3.status_code == 409
    body3 = resp3.get_json()
    assert "Conflict" in body3["error"]


# -----------------------------------------------------------------------------
# 2. Security Event Canonical Evidence Idempotency
# -----------------------------------------------------------------------------

def test_security_event_idempotency_payload_hash(client, app):
    """Same message_id and identical evidence is duplicate; same message_id with altered evidence returns 409 Conflict."""
    agent_id = register_endpoint(client, "agent-event-idemp")
    msg_id = str(uuid.uuid4())

    event_payload = {
        "event_type": "fim_file_modified",
        "severity": "high",
        "title": "Sensitive File Altered",
        "description": "File /etc/passwd was modified",
        "evidence": {"file_path": "/etc/passwd", "sha256": "a" * 64},
    }

    envelope = {
        "schema_version": "1.0",
        "message_id": msg_id,
        "agent_id": agent_id,
        "collected_at": "2026-11-07T12:00:00Z",
        "payload": event_payload,
    }

    # 1. First submission succeeds (201 Created)
    resp1 = client.post("/api/v1/events", json=envelope, headers=auth_headers())
    assert resp1.status_code == 201
    assert resp1.get_json()["duplicate"] is False

    # 2. Exact retry succeeds as duplicate (200 OK)
    resp2 = client.post("/api/v1/events", json=envelope, headers=auth_headers())
    assert resp2.status_code == 200
    assert resp2.get_json()["duplicate"] is True

    # 3. Same message_id and title, but DIFFERENT evidence payload returns 409 Conflict
    conflicting_envelope = dict(envelope)
    conflicting_envelope["payload"] = dict(event_payload)
    conflicting_envelope["payload"]["evidence"] = {"file_path": "/etc/shadow", "sha256": "b" * 64}

    resp3 = client.post("/api/v1/events", json=conflicting_envelope, headers=auth_headers())
    assert resp3.status_code == 409
    assert "Conflict" in resp3.get_json()["error"]


# -----------------------------------------------------------------------------
# 3. Heartbeat Partial-Update Semantics (FINDING-PHASE01-04)
# -----------------------------------------------------------------------------

def test_heartbeat_partial_update_preserves_metadata(app):
    """Partial updates to endpoint metrics preserve existing metadata without overwriting with nulls."""
    db_path = str(app.config["TEST_DATABASE_PATH"])
    repo = EndpointRepository(db_path)

    # 1. Initial registration with full metadata
    initial = repo.upsert({
        "agent_id": "endpoint-preserve-test",
        "hostname": "bastion-host-01",
        "ip_address": "10.0.0.1",
        "os": "Ubuntu 24.04 LTS",
        "agent_version": "1.2.3",
        "cpu_percent": 5.0,
        "memory_percent": 10.0,
        "disk_percent": 15.0,
        "uptime_seconds": 3600.0,
        "last_seen": "2026-11-07T10:00:00Z",
    })
    assert initial["hostname"] == "bastion-host-01"
    assert initial["os"] == "Ubuntu 24.04 LTS"

    # 2. Subsequent partial update omitting hostname and os
    updated = repo.upsert({
        "agent_id": "endpoint-preserve-test",
        "cpu_percent": 45.0,
        "memory_percent": 55.0,
        "last_seen": "2026-11-07T11:00:00Z",
    })

    # Metadata must be preserved from initial registration
    assert updated["hostname"] == "bastion-host-01"
    assert updated["ip_address"] == "10.0.0.1"
    assert updated["os"] == "Ubuntu 24.04 LTS"
    assert updated["agent_version"] == "1.2.3"
    # Metrics and timestamp must be updated
    assert updated["cpu_percent"] == 45.0
    assert updated["memory_percent"] == 55.0
    assert updated["last_seen"] == "2026-11-07T11:00:00Z"


# -----------------------------------------------------------------------------
# 4. Bulk FIM Baseline Sync Parameter Chunking (FINDING-PHASE04-03)
# -----------------------------------------------------------------------------

def test_baseline_bulk_sync_parameter_chunking(client, app):
    """Synchronizing over 1000 baseline files does not exceed SQLite variable limits."""
    agent_id = register_endpoint(client, "agent-chunk-test")

    # Generate 1200 files (exceeds traditional SQLite limit of 999 parameters)
    file_count = 1200
    files = [
        {
            "file_path": f"/usr/local/bin/file_{i}.bin",
            "sha256": f"{i:064x}",
            "file_size_bytes": 1024 + i,
            "mtime_ns": 1700000000000000000 + i,
            "file_mode": 493,  # 0o755
            "state": "present",
        }
        for i in range(file_count)
    ]

    msg_id = str(uuid.uuid4())
    envelope = {
        "schema_version": "1.0",
        "message_id": msg_id,
        "agent_id": agent_id,
        "collected_at": "2026-11-07T12:00:00Z",
        "payload": {"files": files},
    }

    # Must complete cleanly with 200 OK
    resp = client.post("/api/v1/fim/baselines", json=envelope, headers=auth_headers())
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["created"] == file_count
    assert data["updated"] == 0

    # Verify rows in database
    db_path = str(app.config["TEST_DATABASE_PATH"])
    repo = BaselineRepository(db_path)
    stored = repo.list_by_agent(agent_id)
    assert len(stored) == file_count


# -----------------------------------------------------------------------------
# 5. Foreign Key Constraint Enforcement
# -----------------------------------------------------------------------------

def test_foreign_key_constraint_enforcement(app):
    """Foreign key constraint blocks inserting snapshots for un-registered agents."""
    db_path = str(app.config["TEST_DATABASE_PATH"])
    proc_repo = ProcessRepository(db_path)

    # Attempting to insert a snapshot for a non-existent agent_id must fail Foreign Key check
    with pytest.raises(sqlite3.IntegrityError):
        proc_repo.create_snapshot(
            snapshot={
                "message_id": str(uuid.uuid4()),
                "schema_version": "1.0",
                "agent_id": "ghost-agent-nonexistent",
                "process_count": 0,
                "collected_at": "2026-11-07T12:00:00Z",
                "received_at": "2026-11-07T12:00:01Z",
            },
            observations=[],
        )


# -----------------------------------------------------------------------------
# 6. Transaction Rollback Atomicity on Observation Error
# -----------------------------------------------------------------------------

def test_process_snapshot_transaction_rollback(app):
    """If an observation fails during insertion, the parent snapshot is completely rolled back."""
    db_path = str(app.config["TEST_DATABASE_PATH"])
    ep_repo = EndpointRepository(db_path)
    ep_repo.upsert({"agent_id": "agent-rollback-test", "hostname": "host", "os": "Linux"})

    proc_repo = ProcessRepository(db_path)
    msg_id = str(uuid.uuid4())

    # Snapshot containing duplicate PIDs in observation list, which violates composite primary key (snapshot_id, pid)
    invalid_observations = [
        {"pid": 999, "ppid": 1, "process_name": "proc_a"},
        {"pid": 999, "ppid": 1, "process_name": "proc_a_dup"},  # Duplicate (snapshot_id, pid=999)
    ]

    with pytest.raises(sqlite3.IntegrityError):
        proc_repo.create_snapshot(
            snapshot={
                "message_id": msg_id,
                "schema_version": "1.0",
                "agent_id": "agent-rollback-test",
                "process_count": 2,
                "collected_at": "2026-11-07T12:00:00Z",
                "received_at": "2026-11-07T12:00:01Z",
            },
            observations=invalid_observations,
        )

    # CRUCIAL ASSERTION: Snapshot row must NOT exist due to atomic rollback
    snapshot_row = proc_repo.get_snapshot_by_message_id(msg_id)
    assert snapshot_row is None, "Snapshot record must be rolled back atomically when observations fail"
