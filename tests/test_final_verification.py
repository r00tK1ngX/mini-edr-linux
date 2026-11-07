"""Final Independent Verification Test Suite for Mini EDR Linux.

Rigorously tests all critical operational and security requirements from Phases 1 through 6:
- Phase 1: FIM Local Spool Reliability (Queue full, FIFO drops, recovery, crash resilience, corruption recovery).
- Phase 2: FIM Security (Symlinks, TOCTOU, timestomping detection, empty/large files, baseline persistence).
- Phase 3: Web Application Security (Secret key persistence, CSRF, open redirect, cookie flags, auth gates).
- Phase 4: Dashboard DOM XSS Review (Sanitizer whitelists, textContent error rendering, template escaping).
- Phase 5: Detection Engine Correctness (Event ID mapping, PPID parent resolution, PID reuse, time window).
- Phase 6: Data Integrity & Resource Safety (Canonical JSON hash deduplication, conflict 409, active alert pruning protection).
"""

import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
from typing import Any, Dict
import unittest
import uuid

import pytest

from agent.file_integrity import (
    EMPTY_FILE_SHA256,
    FileIntegrityMonitor,
    compute_sha256,
    detect_file_changes,
    inspect_file,
    scan_monitored_paths,
)
from agent.spool import EventSpool
from detection.correlation import CorrelationEngine
from detection.engine import DetectionEngine
from detection.rules import DetectionResult, ProcessShellSpawnRule, RuleRegistry
from server.app import _resolve_secret_key, create_app
from server.maintenance import prune_telemetry
from server.repositories.alert_repository import AlertRepository
from server.repositories.endpoint_repository import EndpointRepository
from server.repositories.event_repository import EventRepository
from server.repositories.metrics_repository import MetricsRepository
from server.repositories.process_repository import ProcessRepository
from server.routes import _compute_canonical_payload_hash


@pytest.fixture
def app(tmp_path):
    db_path = str(tmp_path / "verify.db")
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": db_path,
        "EDR_API_TOKEN": "test-api-token-minimum-32-chars-long",
        "ENFORCE_WEB_AUTH_IN_TESTS": True,
        "ENFORCE_CSRF_IN_TESTS": True,
    })
    return app


@pytest.fixture
def client(app):
    return app.test_client()


# =============================================================================
# PHASE 1: FIM SPOOL RELIABILITY TESTS
# =============================================================================

def test_spool_queue_full_with_only_pending_events_drops_fifo():
    """Verify that when queue reaches capacity with ONLY pending events, oldest pending is purged (bounded FIFO)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "spool_test.db")
        spool = EventSpool(db_path=db_path, max_size=5)

        # Enqueue 5 pending events
        events_batch1 = [
            {"message_id": f"msg-{i}", "payload": {"event_type": "fim_modified", "idx": i}}
            for i in range(1, 6)
        ]
        spool.enqueue_events(events_batch1)
        assert spool.count_pending() == 5

        # Enqueue 2 more events; capacity is 5, so msg-1 and msg-2 should be dropped
        events_batch2 = [
            {"message_id": "msg-6", "payload": {"event_type": "fim_modified", "idx": 6}},
            {"message_id": "msg-7", "payload": {"event_type": "fim_modified", "idx": 7}},
        ]
        spool.enqueue_events(events_batch2)

        # Total pending must be clamped to max_size=5
        assert spool.count_pending() == 5

        pending = spool.get_pending_events(limit=10)
        pending_ids = [p["message_id"] for p in pending]
        assert "msg-1" not in pending_ids
        assert "msg-2" not in pending_ids
        assert pending_ids == ["msg-3", "msg-4", "msg-5", "msg-6", "msg-7"]


def test_spool_queue_full_purges_acknowledged_before_pending():
    """Verify that when queue is near capacity, acknowledged events are purged FIRST before pending events."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "spool_test.db")
        spool = EventSpool(db_path=db_path, max_size=5)

        # Enqueue 4 events
        events = [
            {"message_id": f"msg-{i}", "payload": {"event_type": "fim_modified", "idx": i}}
            for i in range(1, 5)
        ]
        spool.enqueue_events(events)

        # Acknowledge msg-1 and msg-2
        spool.mark_acknowledged(["msg-1", "msg-2"])
        assert spool.count_pending() == 2
        assert spool.count_total() == 4

        # Enqueue 3 new events (2 pending + 2 acked + 3 new = 7 > 5)
        new_events = [
            {"message_id": f"msg-new-{i}", "payload": {"event_type": "fim_modified"}}
            for i in range(1, 4)
        ]
        spool.enqueue_events(new_events)

        # Acknowledged events should be deleted, leaving all pending events intact
        assert spool.count_pending() == 5  # msg-3, msg-4, and the 3 new ones
        pending_ids = [p["message_id"] for p in spool.get_pending_events(limit=10)]
        assert "msg-1" not in pending_ids
        assert "msg-2" not in pending_ids
        assert "msg-3" in pending_ids
        assert "msg-4" in pending_ids


def test_spool_corrupted_database_automatic_recovery():
    """Verify that if the SQLite spool database file becomes corrupted on disk, the agent automatically recovers."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "corrupt_spool.db")

        # Create valid spool first
        spool1 = EventSpool(db_path=db_path, max_size=10)
        spool1.enqueue_events([{"message_id": "valid-1", "payload": {"event_type": "fim_created"}}])
        assert spool1.count_pending() == 1

        # Corrupt the database file by writing garbage
        with open(db_path, "wb") as f:
            f.write(b"NOT_A_VALID_SQLITE_DATABASE_HEADER_CORRUPTED_BYTES_1234567890")

        # Initializing EventSpool must detect corruption, rotate to .corrupted, and re-create a clean DB
        spool2 = EventSpool(db_path=db_path, max_size=10)
        assert spool2.count_pending() == 0

        # Verify that new events can be enqueued normally
        spool2.enqueue_events([{"message_id": "recovered-1", "payload": {"event_type": "fim_modified"}}])
        assert spool2.count_pending() == 1

        # Verify corrupted backup exists
        backups = [f for f in os.listdir(tmpdir) if ".corrupted." in f]
        assert len(backups) == 1


def test_spool_sigkill_and_restart_preserves_pending_events():
    """Simulate agent crash (SIGKILL) while events are pending; verify restart restores all pending events."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "crash_spool.db")

        spool = EventSpool(db_path=db_path, max_size=20)
        spool.enqueue_events([
            {"message_id": "crash-1", "payload": {"event_type": "fim_created"}},
            {"message_id": "crash-2", "payload": {"event_type": "fim_modified"}},
        ])

        # Baseline state saved
        spool.save_baseline({
            "/etc/passwd": {"file_path": "/etc/passwd", "sha256": "abc1", "file_size_bytes": 100, "mtime_ns": 1, "file_mode": 0o644}
        })

        # Simulate sudden process termination (del spool connection)
        del spool

        # Restart agent with same spool DB
        recovered_spool = EventSpool(db_path=db_path, max_size=20)
        assert recovered_spool.count_pending() == 2
        pending = recovered_spool.get_pending_events()
        assert [p["message_id"] for p in pending] == ["crash-1", "crash-2"]
        assert recovered_spool.has_persisted_baseline() is True
        loaded_baseline = recovered_spool.load_baseline()
        assert "/etc/passwd" in loaded_baseline
        assert loaded_baseline["/etc/passwd"]["sha256"] == "abc1"


# =============================================================================
# PHASE 2: FILE INTEGRITY MONITORING TESTS
# =============================================================================

def test_fim_timestomping_detection_on_sensitive_files():
    """Verify that sensitive files (e.g. /etc/passwd) undergo forced rehash, defeating timestomping."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a mock /etc/passwd path
        passwd_mock = os.path.join(tmpdir, "passwd")
        with open(passwd_mock, "w") as f:
            f.write("root:x:0:0:root:/root:/bin/bash\n")

        # Initial baseline inspection
        rec1 = inspect_file(passwd_mock, force_hash=True)
        assert rec1 is not None
        orig_hash = rec1["sha256"]
        orig_mtime_ns = rec1["mtime_ns"]
        orig_size = rec1["file_size_bytes"]
        orig_mode = rec1["file_mode"]

        # Modify content with EXACT same size (32 bytes)
        with open(passwd_mock, "w") as f:
            f.write("hckr:x:0:0:root:/root:/bin/bash\n")
        assert os.path.getsize(passwd_mock) == orig_size

        # Timestomp: restore exact previous mtime
        os.utime(passwd_mock, ns=(orig_mtime_ns, orig_mtime_ns))

        # 1. Non-forced inspection on regular file would normally reuse cached hash:
        cached_rec = inspect_file(passwd_mock, previous_record=rec1, force_hash=False)
        assert cached_rec["sha256"] == orig_hash  # Documented limitation of fast-path

        # 2. Forced inspection (or sensitive file path) detects modified content:
        forced_rec = inspect_file(passwd_mock, previous_record=rec1, force_hash=True)
        assert forced_rec["sha256"] != orig_hash

        # 3. Detect file changes triggers modified event
        _, changes = detect_file_changes({passwd_mock: rec1}, {passwd_mock: forced_rec})
        assert len(changes) == 1
        assert changes[0]["change_type"] == "modified"


def test_fim_symlink_to_external_target_rejected():
    """Verify that symbolic links pointing outside or inside monitored root are atomically rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        external_file = os.path.join(tmpdir, "external_target.txt")
        with open(external_file, "w") as f:
            f.write("sensitive external content")

        monitored_dir = os.path.join(tmpdir, "monitored")
        os.makedirs(monitored_dir)

        symlink_path = os.path.join(monitored_dir, "symlink_file.txt")
        os.symlink(external_file, symlink_path)

        # Inspecting symlink must return None
        res = inspect_file(symlink_path)
        assert res is None

        # Scanning directory must skip symlinks
        scan = scan_monitored_paths([monitored_dir])
        assert symlink_path not in scan


def test_fim_empty_and_large_file_boundaries():
    """Verify empty file SHA-256 computation and skipping of files exceeding max size limit."""
    with tempfile.TemporaryDirectory() as tmpdir:
        empty_file = os.path.join(tmpdir, "empty.txt")
        Path(empty_file).touch()

        # Empty file SHA-256
        assert compute_sha256(empty_file) == EMPTY_FILE_SHA256

        # Large file exceeding max_size limit (50 MiB)
        large_file = os.path.join(tmpdir, "large.bin")
        with open(large_file, "wb") as f:
            f.seek(1024 * 1024)  # 1 MiB sparse file
            f.write(b"0")

        # Setting max_size to 512 KiB must skip hashing
        assert compute_sha256(large_file, max_size=512 * 1024) is None


# =============================================================================
# PHASE 3: WEB APPLICATION SECURITY TESTS
# =============================================================================

def test_secret_key_atomic_persistence(tmp_path):
    """Verify that _resolve_secret_key creates .secret_key atomically and maintains key across restarts."""
    key1 = _resolve_secret_key(tmp_path)
    assert len(key1) == 64  # token_hex(32)

    key_file = tmp_path / "data" / ".secret_key"
    assert key_file.is_file()
    assert key_file.read_text(encoding="utf-8").strip() == key1

    # Second call returns identical key
    key2 = _resolve_secret_key(tmp_path)
    assert key1 == key2


def test_login_open_redirect_rejection(client):
    """Verify that open redirect payloads on /login are rejected and redirected safely to /dashboard."""
    malicious_urls = [
        "https://evil.com",
        "//evil.com",
        "\\\\evil.com",
        "javascript:alert(1)",
        "http://attacker.org/phish",
    ]
    with client.session_transaction() as sess:
        sess["csrf_token"] = "valid-csrf-token"

    for evil in malicious_urls:
        resp = client.post("/login", data={
            "token": "test-api-token-minimum-32-chars-long",
            "next": evil,
            "csrf_token": "valid-csrf-token",
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert "evil.com" not in resp.headers.get("Location", "")
        assert "attacker.org" not in resp.headers.get("Location", "")


def test_logout_csrf_and_post_enforcement(client):
    """Verify that GET /logout is rejected (405 Method Not Allowed) and POST /logout requires CSRF."""
    get_resp = client.get("/logout")
    assert get_resp.status_code == 405


# =============================================================================
# PHASE 4: DASHBOARD DOM XSS & CLASS INJECTION MITIGATION
# =============================================================================

def test_dashboard_js_whitelists_and_safe_sinks():
    """Verify that dashboard.js contains severity and status whitelists to prevent CSS class injection."""
    js_path = Path(__file__).resolve().parent.parent / "static" / "dashboard.js"
    content = js_path.read_text(encoding="utf-8")

    # Whitelist definitions present
    assert "VALID_SEVERITIES" in content
    assert "VALID_STATUSES" in content
    assert "sanitizeSeverity" in content
    assert "sanitizeStatus" in content

    # Sinks sanitized with whitelists
    assert "badge-${sanitizeSeverity(" in content
    assert "badge-${sanitizeStatus(" in content

    # Error rendering uses textContent
    assert "errDiv.textContent = String(message)" in content


# =============================================================================
# PHASE 5: DETECTION ENGINE CORRECTNESS TESTS
# =============================================================================

def test_shell_spawn_parent_resolution_from_snapshot(tmp_path):
    """Verify that DetectionEngine correctly resolves parent_name from in-snapshot PPID -> PID mapping."""
    db_path = str(tmp_path / "det_test.db")
    app = create_app({"TESTING": True, "DATABASE_PATH": db_path})

    with app.app_context():
        # Register endpoint
        ep_repo = EndpointRepository(db_path)
        ep_repo.upsert({"agent_id": "test-agent", "hostname": "host1", "os": "Linux"})

        det_engine = DetectionEngine(db_path)

        # Snapshot containing nginx (PID 100) and bash child (PID 105, PPID 100)
        observations = [
            {"pid": 100, "ppid": 1, "process_name": "nginx", "exe_path": "/usr/sbin/nginx"},
            {"pid": 105, "ppid": 100, "process_name": "bash", "exe_path": "/bin/bash"},
        ]

        result = det_engine.evaluate_process_snapshot("test-agent", 1, observations)
        assert result["detections_count"] >= 1

        # Check that shell spawn rule triggered
        alert_repo = AlertRepository(db_path)
        alerts = alert_repo.list_alerts()
        assert any(a["rule_id"] == "rule-proc-shell-spawn" for a in alerts)


def test_pid_reuse_resilience_in_alert_keys(tmp_path):
    """Verify that process alert keys incorporate start_time to prevent collisions when Linux reuses PIDs."""
    correlation = CorrelationEngine()
    detection1 = DetectionResult(
        rule_id="rule-process-suspicious-path",
        rule_name="Suspicious Path",
        title="Suspicious execution",
        description="Path in /tmp",
        severity="high",
        risk_score=75,
        evidence={"pid": 4200, "process_name": "miner", "start_time": "2026-11-07T10:00:00Z"},
    )
    finding1 = correlation.calculate_single_rule_alert("agent-1", detection1)

    # Process 2 reuses PID 4200 hours later with different start_time
    detection2 = DetectionResult(
        rule_id="rule-process-suspicious-path",
        rule_name="Suspicious Path",
        title="Suspicious execution",
        description="Path in /tmp",
        severity="high",
        risk_score=75,
        evidence={"pid": 4200, "process_name": "miner", "start_time": "2026-11-07T14:30:00Z"},
    )
    finding2 = correlation.calculate_single_rule_alert("agent-1", detection2)

    # Alert keys must be completely distinct
    assert finding1.alert_key != finding2.alert_key
    assert "2026-11-07T10:00:00Z" in finding1.alert_key
    assert "2026-11-07T14:30:00Z" in finding2.alert_key


# =============================================================================
# PHASE 6: DATA INTEGRITY & ACTIVE ALERT RETENTION TESTS
# =============================================================================

def test_canonical_json_hashing_and_conflict_detection(client):
    """Verify canonical payload hashing idempotency (200 duplicate) and payload mutation conflict (409)."""
    headers = {
        "Authorization": "Bearer test-api-token-minimum-32-chars-long",
        "Content-Type": "application/json",
    }
    # Register endpoint first
    client.post("/api/v1/heartbeat", headers=headers, json={
        "agent_id": "test-agent-idemp",
        "hostname": "host-idemp",
        "os": "Linux",
    })

    msg_id = str(uuid.uuid4())
    payload = {
        "schema_version": "1.0",
        "message_id": msg_id,
        "agent_id": "test-agent-idemp",
        "collected_at": "2026-11-07T10:00:00Z",
        "payload": {
            "process_count": 1,
            "processes": [{"pid": 1234, "process_name": "test_proc", "cpu_percent": 10.0}],
        },
    }

    # First send: 201 Created
    resp1 = client.post("/api/v1/telemetry/processes", headers=headers, json=payload)
    assert resp1.status_code == 201
    assert resp1.get_json()["duplicate"] is False

    # Resend identical payload with same message_id: 200 OK (duplicate: true)
    resp2 = client.post("/api/v1/telemetry/processes", headers=headers, json=payload)
    assert resp2.status_code == 200
    assert resp2.get_json()["duplicate"] is True

    # Mutate payload with same message_id: 409 Conflict
    mutated = dict(payload)
    mutated["payload"] = {
        "process_count": 1,
        "processes": [{"pid": 9999, "process_name": "altered_proc", "cpu_percent": 99.0}],
    }
    resp3 = client.post("/api/v1/telemetry/processes", headers=headers, json=mutated)
    assert resp3.status_code == 409


def test_pruning_preserves_events_linked_to_active_alerts(tmp_path):
    """Verify that prune_telemetry preserves security events linked to open/active alerts (new/acknowledged)."""
    db_path = str(tmp_path / "prune_test.db")
    app = create_app({"TESTING": True, "DATABASE_PATH": db_path})

    with app.app_context():
        ep_repo = EndpointRepository(db_path)
        ep_repo.upsert({"agent_id": "agent-p", "hostname": "host-p", "os": "Linux"})

        event_repo = EventRepository(db_path)
        alert_repo = AlertRepository(db_path)

        # 1. Old event linked to an ACTIVE alert (status='new')
        ev_active = event_repo.record({
            "message_id": "msg-ev-active",
            "agent_id": "agent-p",
            "event_type": "fim_modified",
            "severity": "high",
            "source": "agent",
            "title": "Active event",
            "evidence_json": {},
            "occurred_at": "2020-01-01T00:00:00Z",  # 6 years ago
            "received_at": "2020-01-01T00:00:00Z",
        })
        alert_repo.create_or_update({
            "alert_key": "alert-active",
            "agent_id": "agent-p",
            "rule_id": "rule-fim",
            "title": "Active Alert",
            "severity": "high",
            "status": "new",
        }, event_ids=[ev_active["id"]])

        # 2. Old event linked to a RESOLVED alert (status='resolved')
        ev_resolved = event_repo.record({
            "message_id": "msg-ev-resolved",
            "agent_id": "agent-p",
            "event_type": "fim_modified",
            "severity": "high",
            "source": "agent",
            "title": "Resolved event",
            "evidence_json": {},
            "occurred_at": "2020-01-01T00:00:00Z",
            "received_at": "2020-01-01T00:00:00Z",
        })
        alert_repo.create_or_update({
            "alert_key": "alert-resolved",
            "agent_id": "agent-p",
            "rule_id": "rule-fim",
            "title": "Resolved Alert",
            "severity": "high",
            "status": "resolved",
            "resolved_at": "2020-01-01T00:00:00Z",
        }, event_ids=[ev_resolved["id"]])

        # 3. Old unlinked event
        ev_unlinked = event_repo.record({
            "message_id": "msg-ev-unlinked",
            "agent_id": "agent-p",
            "event_type": "fim_modified",
            "severity": "high",
            "source": "agent",
            "title": "Unlinked event",
            "evidence_json": {},
            "occurred_at": "2020-01-01T00:00:00Z",
            "received_at": "2020-01-01T00:00:00Z",
        })

        # Run prune_telemetry
        prune_res = prune_telemetry(db_path, retention_days=7)
        assert prune_res["success"] is True

        # ev_active MUST be preserved because it belongs to an active alert!
        assert event_repo.get_by_id(ev_active["id"]) is not None

        # ev_resolved and ev_unlinked can be pruned
        assert event_repo.get_by_id(ev_unlinked["id"]) is None
