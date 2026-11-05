import sqlite3
import pytest

from server.db import init_db
from server.repositories import (
    AlertRepository,
    BaselineRepository,
    EndpointRepository,
    EventRepository,
    MetricsRepository,
    ProcessRepository,
)


@pytest.fixture()
def db_path(tmp_path):
    path = tmp_path / "test_dal.db"
    init_db(path)
    return str(path)


@pytest.fixture()
def sample_endpoint(db_path):
    repo = EndpointRepository(db_path)
    return repo.upsert({
        "agent_id": "lab-host-01",
        "hostname": "kali-box",
        "ip_address": "192.168.1.50",
        "os": "Kali Linux 2026.1",
        "agent_version": "1.0.0",
        "cpu_percent": 12.5,
        "memory_percent": 45.0,
        "disk_percent": 30.0,
        "uptime_seconds": 3600.0,
        "last_seen": "2026-11-05T08:00:00Z",
    })


# -----------------------------------------------------------------------------
# 1. EndpointRepository Tests
# -----------------------------------------------------------------------------

def test_endpoint_repository_upsert_and_get(db_path):
    repo = EndpointRepository(db_path)
    endpoint = repo.upsert({
        "agent_id": "agent-100",
        "hostname": "srv-web",
        "ip_address": "10.0.0.10",
        "os": "Debian 12",
        "agent_version": "0.2.0",
        "last_seen": "2026-11-05T08:30:00Z",
    })
    assert endpoint["agent_id"] == "agent-100"
    assert endpoint["status"] == "online"

    fetched = repo.get_by_id("agent-100")
    assert fetched is not None
    assert fetched["hostname"] == "srv-web"

    # Non-existent ID returns None
    assert repo.get_by_id("non-existent") is None


def test_endpoint_repository_list_and_status(db_path, sample_endpoint):
    repo = EndpointRepository(db_path)
    all_endpoints = repo.list_all(offline_after_seconds=3600)
    assert len(all_endpoints) >= 1
    assert any(e["agent_id"] == sample_endpoint["agent_id"] for e in all_endpoints)

    updated = repo.update_status("lab-host-01", "offline")
    assert updated is True
    assert repo.get_by_id("lab-host-01")["status"] == "offline"
    assert repo.count() == 1


# -----------------------------------------------------------------------------
# 2. MetricsRepository Tests
# -----------------------------------------------------------------------------

def test_metrics_repository_record_and_query(db_path, sample_endpoint):
    repo = MetricsRepository(db_path)
    metric = repo.record({
        "message_id": "metric-msg-001",
        "schema_version": "1.0",
        "agent_id": sample_endpoint["agent_id"],
        "cpu_percent": 35.5,
        "memory_percent": 60.0,
        "disk_percent": 42.1,
        "uptime_seconds": 7200.0,
        "collected_at": "2026-11-05T08:10:00Z",
        "received_at": "2026-11-05T08:10:01Z",
    })

    assert metric["id"] is not None
    assert metric["agent_id"] == sample_endpoint["agent_id"]

    by_id = repo.get_by_id(metric["id"])
    assert by_id["message_id"] == "metric-msg-001"

    by_msg = repo.get_by_message_id("metric-msg-001")
    assert by_msg["id"] == metric["id"]

    latest = repo.get_latest(sample_endpoint["agent_id"])
    assert latest["cpu_percent"] == 35.5

    metrics_list = repo.list_by_agent(sample_endpoint["agent_id"])
    assert len(metrics_list) == 1
    assert repo.count_by_agent(sample_endpoint["agent_id"]) == 1


def test_metrics_repository_rejects_missing_endpoint_or_duplicate(db_path, sample_endpoint):
    repo = MetricsRepository(db_path)

    # Missing endpoint FK violation
    with pytest.raises(sqlite3.IntegrityError):
        repo.record({
            "message_id": "metric-bad-endpoint",
            "agent_id": "ghost-agent",
            "cpu_percent": 10.0,
            "memory_percent": 20.0,
            "disk_percent": 30.0,
            "uptime_seconds": 100.0,
            "collected_at": "2026-11-05T08:00:00Z",
            "received_at": "2026-11-05T08:00:01Z",
        })

    # Duplicate message_id
    repo.record({
        "message_id": "msg-unique-metric",
        "agent_id": sample_endpoint["agent_id"],
        "cpu_percent": 10.0,
        "memory_percent": 20.0,
        "disk_percent": 30.0,
        "uptime_seconds": 100.0,
        "collected_at": "2026-11-05T08:00:00Z",
        "received_at": "2026-11-05T08:00:01Z",
    })
    with pytest.raises(sqlite3.IntegrityError):
        repo.record({
            "message_id": "msg-unique-metric",
            "agent_id": sample_endpoint["agent_id"],
            "cpu_percent": 10.0,
            "memory_percent": 20.0,
            "disk_percent": 30.0,
            "uptime_seconds": 100.0,
            "collected_at": "2026-11-05T08:05:00Z",
            "received_at": "2026-11-05T08:05:01Z",
        })


# -----------------------------------------------------------------------------
# 3. ProcessRepository Tests
# -----------------------------------------------------------------------------

def test_process_repository_create_snapshot_and_observations(db_path, sample_endpoint):
    repo = ProcessRepository(db_path)
    snapshot_data = {
        "message_id": "snap-msg-001",
        "agent_id": sample_endpoint["agent_id"],
        "collected_at": "2026-11-05T08:15:00Z",
        "received_at": "2026-11-05T08:15:02Z",
    }
    observations = [
        {
            "pid": 1,
            "ppid": 0,
            "process_name": "systemd",
            "username": "root",
            "exe_path": "/usr/lib/systemd/systemd",
            "cpu_percent": 0.1,
            "memory_percent": 0.5,
            "rss_bytes": 12000000,
            "process_started_at": "2026-11-05T07:00:00Z",
        },
        {
            "pid": 1234,
            "ppid": 1,
            "process_name": "python3",
            "username": "kali",
            "exe_path": "/usr/bin/python3",
            "cpu_percent": 5.2,
            "memory_percent": 2.1,
            "rss_bytes": 45000000,
            "process_started_at": "2026-11-05T08:00:00Z",
        },
    ]

    snapshot = repo.create_snapshot(snapshot_data, observations)
    assert snapshot["id"] is not None
    assert snapshot["process_count"] == 2

    # Query observations
    obs_list = repo.list_observations(snapshot["id"])
    assert len(obs_list) == 2
    assert obs_list[0]["process_name"] == "systemd"
    assert obs_list[1]["process_name"] == "python3"

    # Query latest snapshot
    latest = repo.get_latest_snapshot(sample_endpoint["agent_id"])
    assert latest["id"] == snapshot["id"]

    # Search by process name
    matches = repo.find_observations_by_name("python3", agent_id=sample_endpoint["agent_id"])
    assert len(matches) == 1
    assert matches[0]["pid"] == 1234


def test_process_repository_atomic_rollback_on_observation_error(db_path, sample_endpoint):
    repo = ProcessRepository(db_path)
    snapshot_data = {
        "message_id": "snap-fail-001",
        "agent_id": sample_endpoint["agent_id"],
        "collected_at": "2026-11-05T08:15:00Z",
        "received_at": "2026-11-05T08:15:02Z",
    }
    invalid_observations = [
        {
            "pid": 100,
            "process_name": "valid_proc",
        },
        {
            "pid": -5,  # CHECK (pid >= 0) violation
            "process_name": "invalid_pid",
        },
    ]

    with pytest.raises(sqlite3.IntegrityError):
        repo.create_snapshot(snapshot_data, invalid_observations)

    # Verify that the entire snapshot was rolled back
    assert repo.get_snapshot_by_message_id("snap-fail-001") is None


# -----------------------------------------------------------------------------
# 4. BaselineRepository Tests
# -----------------------------------------------------------------------------

def test_baseline_repository_upsert_and_lifecycle(db_path, sample_endpoint):
    repo = BaselineRepository(db_path)
    baseline_entry = {
        "agent_id": sample_endpoint["agent_id"],
        "file_path": "/etc/passwd",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "file_size_bytes": 1024,
        "mtime_ns": 1730800000000000000,
        "file_mode": 420,  # 0o644
        "state": "present",
        "first_seen_at": "2026-11-05T08:00:00Z",
        "last_seen_at": "2026-11-05T08:00:00Z",
        "last_checked_at": "2026-11-05T08:00:00Z",
    }

    saved = repo.upsert(baseline_entry)
    assert saved["file_path"] == "/etc/passwd"
    assert saved["state"] == "present"

    # Fetch by path
    found = repo.get_by_path(sample_endpoint["agent_id"], "/etc/passwd")
    assert found is not None
    assert found["file_size_bytes"] == 1024

    # Mark missing
    marked = repo.mark_missing(sample_endpoint["agent_id"], "/etc/passwd", "2026-11-05T08:30:00Z")
    assert marked is True

    updated = repo.get_by_path(sample_endpoint["agent_id"], "/etc/passwd")
    assert updated["state"] == "missing"
    assert updated["sha256"] == baseline_entry["sha256"]  # Hash preserved

    # Test bulk upsert
    batch = [
        {
            "file_path": "/bin/bash",
            "sha256": "a" * 64,
            "file_size_bytes": 500000,
            "mtime_ns": 1000,
            "file_mode": 493,
            "first_seen_at": "2026-11-05T08:00:00Z",
            "last_seen_at": "2026-11-05T08:00:00Z",
            "last_checked_at": "2026-11-05T08:00:00Z",
        },
        {
            "file_path": "/bin/ls",
            "sha256": "b" * 64,
            "file_size_bytes": 200000,
            "mtime_ns": 2000,
            "file_mode": 493,
            "first_seen_at": "2026-11-05T08:00:00Z",
            "last_seen_at": "2026-11-05T08:00:00Z",
            "last_checked_at": "2026-11-05T08:00:00Z",
        },
    ]
    count = repo.bulk_upsert(sample_endpoint["agent_id"], batch)
    assert count == 2
    assert repo.count_by_agent(sample_endpoint["agent_id"]) == 3


def test_baseline_repository_rejects_invalid_hash(db_path, sample_endpoint):
    repo = BaselineRepository(db_path)
    with pytest.raises(sqlite3.IntegrityError):
        repo.upsert({
            "agent_id": sample_endpoint["agent_id"],
            "file_path": "/etc/shadow",
            "sha256": "NOT-A-VALID-HEX-64",
            "file_size_bytes": 500,
            "mtime_ns": 1000,
            "file_mode": 384,
            "first_seen_at": "2026-11-05T08:00:00Z",
            "last_seen_at": "2026-11-05T08:00:00Z",
            "last_checked_at": "2026-11-05T08:00:00Z",
        })


# -----------------------------------------------------------------------------
# 5. EventRepository Tests
# -----------------------------------------------------------------------------

def test_event_repository_record_and_query(db_path, sample_endpoint):
    repo = EventRepository(db_path)
    event_data = {
        "message_id": "evt-msg-001",
        "agent_id": sample_endpoint["agent_id"],
        "event_type": "suspicious_process_spawn",
        "severity": "high",
        "source": "detection",
        "title": "Suspicious execution from /tmp",
        "description": "Process nc executed inside /tmp directory",
        "evidence_json": {"pid": 666, "exe": "/tmp/nc", "args": ["-lvnp", "4444"]},
        "occurred_at": "2026-11-05T08:20:00Z",
        "received_at": "2026-11-05T08:20:01Z",
        "fingerprint": "tmp-nc-4444",
    }

    event = repo.record(event_data)
    assert event["id"] is not None
    assert event["severity"] == "high"

    # Query by ID and message_id
    by_id = repo.get_by_id(event["id"])
    assert by_id["fingerprint"] == "tmp-nc-4444"

    by_msg = repo.get_by_message_id("evt-msg-001")
    assert by_msg["id"] == event["id"]

    # Filter by agent and severity
    events = repo.list_by_agent(sample_endpoint["agent_id"], severity="high")
    assert len(events) == 1

    # Fingerprint lookup
    fps = repo.find_by_fingerprint("tmp-nc-4444")
    assert len(fps) == 1
    assert fps[0]["id"] == event["id"]
    assert repo.count(agent_id=sample_endpoint["agent_id"]) == 1


# -----------------------------------------------------------------------------
# 6. AlertRepository Tests
# -----------------------------------------------------------------------------

def test_alert_repository_lifecycle_and_linking(db_path, sample_endpoint):
    evt_repo = EventRepository(db_path)
    event = evt_repo.record({
        "message_id": "evt-link-001",
        "agent_id": sample_endpoint["agent_id"],
        "event_type": "privilege_escalation",
        "severity": "critical",
        "source": "detection",
        "title": "Privilege escalation attempt",
        "occurred_at": "2026-11-05T08:25:00Z",
        "received_at": "2026-11-05T08:25:01Z",
    })

    alert_repo = AlertRepository(db_path)
    alert = alert_repo.create_or_update(
        {
            "alert_key": "rule-privesc-lab-host-01",
            "agent_id": sample_endpoint["agent_id"],
            "rule_id": "RULE_005_PRIVESC",
            "title": "Privilege escalation detected on lab-host-01",
            "description": "Root access attempt from unprivileged process",
            "severity": "critical",
        },
        event_ids=[event["id"]],
    )

    assert alert["id"] is not None
    assert alert["status"] == "new"

    # Verify linked event
    linked_events = alert_repo.get_linked_events(alert["id"])
    assert len(linked_events) == 1
    assert linked_events[0]["id"] == event["id"]

    # Acknowledge alert
    ack = alert_repo.acknowledge(alert["id"], note="Investigating incident")
    assert ack is not None
    assert ack["status"] == "acknowledged"
    assert ack["acknowledged_at"] is not None
    assert ack["resolution_note"] == "Investigating incident"

    # Resolve alert
    res = alert_repo.resolve(alert["id"], note="False positive verified")
    assert res is not None
    assert res["status"] == "resolved"
    assert res["resolved_at"] is not None
    assert res["resolution_note"] == "False positive verified"

    # Test correlation: upserting same alert_key updates last_seen without duplicate row
    updated_alert = alert_repo.create_or_update({
        "alert_key": "rule-privesc-lab-host-01",
        "agent_id": sample_endpoint["agent_id"],
        "rule_id": "RULE_005_PRIVESC",
        "title": "Privilege escalation detected on lab-host-01",
        "severity": "critical",
    })
    assert updated_alert["id"] == alert["id"]
    assert alert_repo.count() == 1
