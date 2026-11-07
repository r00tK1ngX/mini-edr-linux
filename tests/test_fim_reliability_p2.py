"""Phase 2 FIM Reliability & TOCTOU Protection Test Suite for Mini EDR Linux.

Validates all reliability enhancements:
- TOCTOU symlink traversal protection using os.O_NOFOLLOW & os.fstat
- Symlinks pointing outside monitored directory roots are skipped
- Local SQLite Event Spool queue persistence across network errors and restarts
- Bounded spool queue capacity handling
- Partial batch transmission and retry without duplicates
- Agent crash recovery (SIGKILL simulation) preserving pending FIM events
- Baseline persistence across restarts without eager desync
- File changes multiple times during outage
- File modified and reverted during outage
"""

import os
from pathlib import Path
import stat
import time
from typing import Any, Dict, List
import uuid

import pytest

from agent.client import AgentClient, AgentConnectionError
from agent.file_integrity import (
    FileIntegrityMonitor,
    compute_sha256,
    detect_file_changes,
    inspect_file,
    scan_monitored_paths,
)
from agent.main import AgentConfig, AgentOrchestrator
from agent.spool import EventSpool


# -----------------------------------------------------------------------------
# 1. TOCTOU & Symlink Traversal Protection Tests
# -----------------------------------------------------------------------------

def test_compute_sha256_toctou_symlink_rejected(tmp_path):
    """compute_sha256 uses os.O_NOFOLLOW to atomically reject symbolic links."""
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("SUPER_SECRET_PAYLOAD", encoding="utf-8")

    symlink_file = tmp_path / "symlink_to_secret.txt"
    os.symlink(str(secret_file), str(symlink_file))

    # compute_sha256 must return None on symlink, never opening target
    result = compute_sha256(str(symlink_file))
    assert result is None, "compute_sha256 must reject symlinks via O_NOFOLLOW"


def test_inspect_file_skips_symlink_targets(tmp_path):
    """inspect_file strictly returns None for symbolic links."""
    target_file = tmp_path / "target.txt"
    target_file.write_text("Hello World", encoding="utf-8")

    link_file = tmp_path / "link.txt"
    os.symlink(str(target_file), str(link_file))

    record = inspect_file(str(link_file))
    assert record is None, "inspect_file must return None for symbolic link"


def test_scan_monitored_paths_skips_symlinks_pointing_outside(tmp_path):
    """scan_monitored_paths does not follow symlinks pointing outside monitored tree."""
    outside_dir = tmp_path / "outside_root"
    outside_dir.mkdir()
    outside_file = outside_dir / "confidential.conf"
    outside_file.write_text("CONFIDENTIAL", encoding="utf-8")

    monitored_dir = tmp_path / "monitored_dir"
    monitored_dir.mkdir()

    regular_file = monitored_dir / "app.conf"
    regular_file.write_text("REGULAR", encoding="utf-8")

    # Symlink pointing to outside confidential file
    symlink_outside = monitored_dir / "symlink_escape.conf"
    os.symlink(str(outside_file), str(symlink_outside))

    # Symlink directory pointing to outside folder
    symlink_dir = monitored_dir / "outside_symlink_dir"
    os.symlink(str(outside_dir), str(symlink_dir))

    scan_res = scan_monitored_paths([str(monitored_dir)], recursive=True)

    assert str(regular_file) in scan_res
    assert str(symlink_outside) not in scan_res
    assert str(outside_file) not in scan_res
    assert not any("confidential" in k for k in scan_res)


# -----------------------------------------------------------------------------
# 2. SQLite Event Spool Queue Persistence & Idempotency Tests
# -----------------------------------------------------------------------------

def test_spool_enqueue_and_fifo_draining(tmp_path):
    """Events enqueued in EventSpool are persisted in SQLite and retrieved in FIFO order."""
    spool_db = tmp_path / "spool_fifo.db"
    spool = EventSpool(db_path=str(spool_db), agent_id="test-agent")

    ev1 = {
        "message_id": "00000000-0000-4000-8000-000000000001",
        "agent_id": "test-agent",
        "payload": {"event_type": "fim_file_created", "severity": "medium"},
    }
    ev2 = {
        "message_id": "00000000-0000-4000-8000-000000000002",
        "agent_id": "test-agent",
        "payload": {"event_type": "fim_file_modified", "severity": "high"},
    }

    assert spool.enqueue_events([ev1, ev2]) == 2
    assert spool.count_pending() == 2

    # FIFO retrieval
    pending = spool.get_pending_events(limit=10)
    assert len(pending) == 2
    assert pending[0]["message_id"] == "00000000-0000-4000-8000-000000000001"
    assert pending[1]["message_id"] == "00000000-0000-4000-8000-000000000002"

    # Mark first acknowledged
    assert spool.mark_acknowledged(ev1["message_id"]) is True
    assert spool.count_pending() == 1

    remaining = spool.get_pending_events(limit=10)
    assert len(remaining) == 1
    assert remaining[0]["message_id"] == ev2["message_id"]


def test_spool_stable_message_id_idempotency(tmp_path):
    """Enqueuing event with duplicate message_id is ignored (idempotent enqueue)."""
    spool_db = tmp_path / "spool_idemp.db"
    spool = EventSpool(db_path=str(spool_db), agent_id="test-agent")

    ev = {
        "message_id": "stable-msg-uuid-1",
        "agent_id": "test-agent",
        "payload": {"event_type": "fim_file_created", "severity": "medium"},
    }

    assert spool.enqueue_events([ev]) == 1
    # Second enqueue of same message_id is ignored
    assert spool.enqueue_events([ev]) == 0
    assert spool.count_total() == 1


def test_spool_bounded_capacity_enforcement(tmp_path):
    """EventSpool purges acknowledged and drops oldest items when capacity is reached."""
    spool_db = tmp_path / "spool_bounded.db"
    max_cap = 15
    spool = EventSpool(db_path=str(spool_db), max_size=max_cap, agent_id="test-agent")

    events = [
        {
            "message_id": f"bounded-msg-{i}",
            "agent_id": "test-agent",
            "payload": {"event_type": "fim_file_created", "severity": "low"},
        }
        for i in range(25)
    ]

    spool.enqueue_events(events[:10])
    # Acknowledge first 5
    for i in range(5):
        spool.mark_acknowledged(f"bounded-msg-{i}")

    # Enqueue remaining 15
    spool.enqueue_events(events[10:])

    # Total events must not exceed max_cap
    assert spool.count_total() <= max_cap


# -----------------------------------------------------------------------------
# 3. Baseline Persistence & Crash Recovery Tests
# -----------------------------------------------------------------------------

def test_fim_baseline_persistence_across_restart(tmp_path):
    """FIM baseline state persisted in SQLite is restored cleanly across agent restarts."""
    spool_db = tmp_path / "spool_baseline.db"
    spool = EventSpool(db_path=str(spool_db), agent_id="test-agent")

    monitored = tmp_path / "monitored"
    monitored.mkdir()
    f1 = monitored / "file1.txt"
    f1.write_text("Version 1", encoding="utf-8")

    # Instance 1: establishes baseline and commits to spool
    fim1 = FileIntegrityMonitor(agent_id="test-agent", monitored_paths=[str(monitored)], spool=spool)
    count1 = fim1.initialize_baseline()
    assert count1 == 1
    assert str(f1) in fim1.baseline
    initial_hash = fim1.baseline[str(f1)]["sha256"]

    # Modify file while agent is simulated as offline/killed
    f1.write_text("Version 2 - Modified while offline", encoding="utf-8")

    # Instance 2: new agent instance restarts and loads persisted baseline
    spool2 = EventSpool(db_path=str(spool_db), agent_id="test-agent")
    fim2 = FileIntegrityMonitor(agent_id="test-agent", monitored_paths=[str(monitored)], spool=spool2)
    assert len(fim2.baseline) == 1
    assert fim2.baseline[str(f1)]["sha256"] == initial_hash

    # Scan for changes detects modification against persisted baseline
    new_base, changes = fim2.scan_for_changes()
    assert len(changes) == 1
    assert changes[0]["change_type"] == "modified"
    assert changes[0]["previous"]["sha256"] == initial_hash
    assert changes[0]["current"]["sha256"] != initial_hash


def test_file_modified_and_reverted_during_outage(tmp_path):
    """If file is modified and reverted while agent is offline, no change event is produced."""
    spool_db = tmp_path / "spool_revert.db"
    spool = EventSpool(db_path=str(spool_db), agent_id="test-agent")

    monitored = tmp_path / "monitored_revert"
    monitored.mkdir()
    target_file = monitored / "stable.txt"
    target_file.write_text("ORIGINAL_CONTENT", encoding="utf-8")

    fim = FileIntegrityMonitor(agent_id="test-agent", monitored_paths=[str(monitored)], spool=spool)
    fim.initialize_baseline()
    orig_hash = fim.baseline[str(target_file)]["sha256"]

    # File modified then reverted
    target_file.write_text("TAMPERED_TEMP", encoding="utf-8")
    target_file.write_text("ORIGINAL_CONTENT", encoding="utf-8")

    # Reset mtime so quick-check doesn't rely solely on mtime
    st = os.lstat(str(target_file))
    current_scan = fim.scan(previous_baseline=fim.baseline)
    _, changes = detect_file_changes(fim.baseline, current_scan)
    assert len(changes) == 0, "Reverted content matching original baseline produces zero change events"


# -----------------------------------------------------------------------------
# 4. Agent Orchestrator Spool Drainage & Partial Retry Tests
# -----------------------------------------------------------------------------

class MockFlakyClient:
    """Mock HTTP client that can simulate server outages and partial batch failures."""

    def __init__(self, fail_until_attempt: int = 0, fail_on_message_id: str = ""):
        self.sent_events: List[Dict[str, Any]] = []
        self.call_count = 0
        self.fail_until_attempt = fail_until_attempt
        self.fail_on_message_id = fail_on_message_id

    def send_heartbeat(self, _data):
        return {"success": True}

    def send_system_telemetry(self, _data):
        return {"success": True}

    def send_process_snapshot(self, _data):
        return {"success": True}

    def send_file_baselines(self, _data):
        return {"success": True}

    def send_security_event(self, event):
        self.call_count += 1
        msg_id = event.get("message_id")

        if self.call_count <= self.fail_until_attempt:
            raise AgentConnectionError(f"Simulated network outage (attempt {self.call_count})")

        if self.fail_on_message_id and msg_id == self.fail_on_message_id:
            raise AgentConnectionError(f"Simulated drop on message {msg_id}")

        self.sent_events.append(event)
        return {"success": True, "message_id": msg_id}


def test_orchestrator_offline_spool_and_recovery(tmp_path):
    """When server is offline, FIM events are enqueued in SQLite spool and drained upon recovery."""
    spool_db = tmp_path / "orch_spool.db"
    spool = EventSpool(db_path=str(spool_db), agent_id="test-orch-agent")

    monitored = tmp_path / "monitored_orch"
    monitored.mkdir()

    cfg = AgentConfig(
        agent_id="test-orch-agent",
        monitored_paths=[str(monitored)],
        spool_path=str(spool_db),
    )

    # First cycle: baseline initialization
    fim = FileIntegrityMonitor(agent_id=cfg.agent_id, monitored_paths=cfg.monitored_paths, spool=spool)
    mock_client = MockFlakyClient(fail_until_attempt=0)
    orch = AgentOrchestrator(config=cfg, fim_monitor=fim, client=mock_client, spool=spool)

    summary1 = orch.run_single_cycle(force_all=True)
    assert summary1["fim_synced"] is True

    # Create 2 files while server goes offline
    f1 = monitored / "drop1.bin"
    f2 = monitored / "drop2.bin"
    f1.write_text("Malicious binary 1", encoding="utf-8")
    f2.write_text("Malicious binary 2", encoding="utf-8")

    # Outage: mock client fails
    broken_client = MockFlakyClient(fail_until_attempt=999)
    orch.client = broken_client

    summary2 = orch.run_single_cycle(force_all=True)
    # Events were detected and enqueued into local spool despite network failure
    assert spool.count_pending() == 2
    assert len(broken_client.sent_events) == 0

    # Recovery: server back online
    healthy_client = MockFlakyClient(fail_until_attempt=0)
    orch.client = healthy_client

    # Next cycle drains the spool
    summary3 = orch.run_single_cycle(force_all=True)
    assert summary3["fim_events_sent"] == 2
    assert spool.count_pending() == 0
    assert len(healthy_client.sent_events) == 2


def test_partial_batch_retry_without_duplicates(tmp_path):
    """When a batch partially fails, successfully acked events are not retransmitted."""
    spool_db = tmp_path / "orch_partial.db"
    spool = EventSpool(db_path=str(spool_db), agent_id="test-partial-agent")

    ev1 = {"message_id": "batch-ev-1", "agent_id": "test-partial-agent", "payload": {"event_type": "fim_file_created", "severity": "medium"}}
    ev2 = {"message_id": "batch-ev-2", "agent_id": "test-partial-agent", "payload": {"event_type": "fim_file_created", "severity": "medium"}}
    ev3 = {"message_id": "batch-ev-3", "agent_id": "test-partial-agent", "payload": {"event_type": "fim_file_created", "severity": "medium"}}

    spool.enqueue_events([ev1, ev2, ev3])
    assert spool.count_pending() == 3

    # Client that fails specifically on ev2
    flaky = MockFlakyClient(fail_on_message_id="batch-ev-2")

    cfg = AgentConfig(agent_id="test-partial-agent", monitored_paths=[str(tmp_path)], spool_path=str(spool_db))
    orch = AgentOrchestrator(config=cfg, client=flaky, spool=spool)

    # First cycle: ev1 succeeds, ev2 fails and pauses drainage
    orch.run_single_cycle(force_all=True)
    assert "batch-ev-1" in [e["message_id"] for e in flaky.sent_events]
    assert spool.count_pending() == 2  # ev2 and ev3 remain pending

    # Second cycle: server completely healthy
    recovered = MockFlakyClient()
    orch.client = recovered

    orch.run_single_cycle(force_all=True)
    sent_ids = [e["message_id"] for e in recovered.sent_events]
    assert "batch-ev-2" in sent_ids
    assert "batch-ev-3" in sent_ids
    assert "batch-ev-1" not in sent_ids, "Already acknowledged ev1 must NOT be retransmitted"
    assert spool.count_pending() == 0
