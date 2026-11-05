import hashlib
import os
from pathlib import Path
import pytest

from agent.file_integrity import (
    EMPTY_FILE_SHA256,
    FileIntegrityMonitor,
    compute_sha256,
    detect_file_changes,
    format_baseline_sync_payload,
    format_fim_security_event,
    inspect_file,
    scan_monitored_paths,
)
from server.db import init_db
from server.repositories import BaselineRepository, EndpointRepository, EventRepository


def test_compute_sha256(tmp_path):
    # Empty file
    empty_file = tmp_path / "empty.txt"
    empty_file.write_bytes(b"")
    assert compute_sha256(str(empty_file)) == EMPTY_FILE_SHA256

    # Known content: "hello world"
    hello_file = tmp_path / "hello.txt"
    content = b"hello world\n"
    hello_file.write_bytes(content)
    expected_hash = hashlib.sha256(content).hexdigest()
    assert compute_sha256(str(hello_file)) == expected_hash

    # Non-existent file
    assert compute_sha256(str(tmp_path / "ghost.txt")) is None

    # Exceeding max_size
    large_file = tmp_path / "large.bin"
    large_file.write_bytes(b"A" * 1000)
    assert compute_sha256(str(large_file), max_size=500) is None


def test_inspect_file(tmp_path):
    test_file = tmp_path / "config.ini"
    test_file.write_text("setting=active\n", encoding="utf-8")

    record = inspect_file(str(test_file))
    assert record is not None
    assert record["file_path"] == str(test_file.resolve())
    assert len(record["sha256"]) == 64
    assert record["file_size_bytes"] == len("setting=active\n")
    assert record["mtime_ns"] > 0
    assert 0 <= record["file_mode"] <= 4095
    assert record["state"] == "present"

    # Directory returns None
    assert inspect_file(str(tmp_path)) is None


def test_scan_monitored_paths(tmp_path):
    dir_a = tmp_path / "dir_a"
    dir_a.mkdir()
    (dir_a / "f1.txt").write_text("file 1")
    (dir_a / "f2.txt").write_text("file 2")

    sub_dir = dir_a / "sub"
    sub_dir.mkdir()
    (sub_dir / "f3.txt").write_text("file 3")

    # Recursive scan
    scan_rec = scan_monitored_paths([str(dir_a)], recursive=True)
    assert len(scan_rec) == 3

    # Non-recursive scan
    scan_non_rec = scan_monitored_paths([str(dir_a)], recursive=False)
    assert len(scan_non_rec) == 2

    # Non-existent path skipped safely
    scan_empty = scan_monitored_paths([str(tmp_path / "not_exist")])
    assert len(scan_empty) == 0


def test_detect_file_changes_lifecycle(tmp_path):
    mon_dir = tmp_path / "watch"
    mon_dir.mkdir()
    target_file = mon_dir / "app.conf"
    target_file.write_text("v1.0")

    # Initial scan (no previous baseline) -> detected as created
    scan1 = scan_monitored_paths([str(mon_dir)])
    baseline1, events1 = detect_file_changes({}, scan1)
    assert len(events1) == 1
    assert events1[0]["change_type"] == "created"
    assert events1[0]["file_path"] == str(target_file.resolve())

    # Second scan (no change) -> 0 change events
    scan2 = scan_monitored_paths([str(mon_dir)])
    baseline2, events2 = detect_file_changes(baseline1, scan2)
    assert len(events2) == 0

    # Modify file -> detected as modified
    target_file.write_text("v2.0-modified")
    scan3 = scan_monitored_paths([str(mon_dir)])
    baseline3, events3 = detect_file_changes(baseline2, scan3)
    assert len(events3) == 1
    assert events3[0]["change_type"] == "modified"
    assert events3[0]["current"]["sha256"] != events3[0]["previous"]["sha256"]

    # Delete file -> detected as deleted, marked missing in baseline
    target_file.unlink()
    scan4 = scan_monitored_paths([str(mon_dir)])
    baseline4, events4 = detect_file_changes(baseline3, scan4)
    assert len(events4) == 1
    assert events4[0]["change_type"] == "deleted"
    deleted_path = str(target_file.resolve())
    assert baseline4[deleted_path]["state"] == "missing"
    assert len(baseline4[deleted_path]["sha256"]) == 64  # Hash preserved

    # Recreate file -> detected as created, state back to present
    target_file.write_text("v3.0-reborn")
    scan5 = scan_monitored_paths([str(mon_dir)])
    baseline5, events5 = detect_file_changes(baseline4, scan5)
    assert len(events5) == 1
    assert events5[0]["change_type"] == "created"
    assert baseline5[deleted_path]["state"] == "present"


def test_format_baseline_sync_payload_and_persistence(tmp_path):
    watch_dir = tmp_path / "sync_watch"
    watch_dir.mkdir()
    (watch_dir / "file_a.txt").write_text("content A")
    (watch_dir / "file_b.txt").write_text("content B")

    scan = scan_monitored_paths([str(watch_dir)])
    baseline, _ = detect_file_changes({}, scan)

    payload_envelope = format_baseline_sync_payload(
        agent_id="agent-sync-01",
        baseline=baseline,
        message_id="msg-sync-001",
    )

    assert payload_envelope["schema_version"] == "1.0"
    assert payload_envelope["message_id"] == "msg-sync-001"
    assert payload_envelope["agent_id"] == "agent-sync-01"
    assert len(payload_envelope["payload"]["files"]) == 2

    # Integration: Persist into BaselineRepository
    db_path = str(tmp_path / "fim_test.db")
    init_db(db_path)

    endpoint_repo = EndpointRepository(db_path)
    endpoint_repo.upsert({
        "agent_id": "agent-sync-01",
        "hostname": "kali-box",
        "os": "Kali Linux",
        "last_seen": "2026-11-05T08:00:00Z",
    })

    baseline_repo = BaselineRepository(db_path)
    synced_count = baseline_repo.bulk_upsert("agent-sync-01", payload_envelope["payload"]["files"])
    assert synced_count == 2
    assert baseline_repo.count_by_agent("agent-sync-01") == 2


def test_format_fim_security_event_and_persistence(tmp_path):
    change_event = {
        "change_type": "modified",
        "file_path": "/etc/shadow",
        "detected_at": "2026-11-05T08:30:00Z",
        "current": {
            "sha256": "1" * 64,
            "file_size_bytes": 1200,
            "file_mode": 384,
        },
        "previous": {
            "sha256": "0" * 64,
            "file_size_bytes": 1100,
            "file_mode": 384,
        },
    }

    sec_event = format_fim_security_event(
        agent_id="agent-fim-01",
        change_event=change_event,
        message_id="msg-sec-fim-001",
    )

    assert sec_event["schema_version"] == "1.0"
    assert sec_event["agent_id"] == "agent-fim-01"
    assert sec_event["payload"]["event_type"] == "fim_file_modified"
    assert sec_event["payload"]["severity"] == "high"
    assert sec_event["payload"]["source"] == "agent"

    # Integration: Persist into EventRepository
    db_path = str(tmp_path / "fim_event_test.db")
    init_db(db_path)

    endpoint_repo = EndpointRepository(db_path)
    endpoint_repo.upsert({
        "agent_id": "agent-fim-01",
        "hostname": "kali-box",
        "os": "Kali Linux",
        "last_seen": "2026-11-05T08:00:00Z",
    })

    event_repo = EventRepository(db_path)
    saved_event = event_repo.record({
        "message_id": sec_event["message_id"],
        "schema_version": sec_event["schema_version"],
        "agent_id": sec_event["agent_id"],
        "event_type": sec_event["payload"]["event_type"],
        "severity": sec_event["payload"]["severity"],
        "source": sec_event["payload"]["source"],
        "title": sec_event["payload"]["title"],
        "description": sec_event["payload"]["description"],
        "evidence_json": sec_event["payload"]["evidence"],
        "occurred_at": sec_event["collected_at"],
        "received_at": "2026-11-05T08:30:01Z",
        "fingerprint": sec_event["payload"]["fingerprint"],
    })

    assert saved_event["id"] is not None
    assert saved_event["event_type"] == "fim_file_modified"


def test_file_integrity_monitor_class(tmp_path):
    fim_dir = tmp_path / "fim_class"
    fim_dir.mkdir()
    target = fim_dir / "system.cfg"
    target.write_text("initial=true")

    monitor = FileIntegrityMonitor(agent_id="test-agent", monitored_paths=[str(fim_dir)])
    initial_count = monitor.initialize_baseline()
    assert initial_count == 1
    assert len(monitor.baseline) == 1

    # Modify file and check for changes
    target.write_text("initial=false;modified=true")
    changes = monitor.check_for_changes()
    assert len(changes) == 1
    assert changes[0]["change_type"] == "modified"

    # Transform into security events
    sec_events = monitor.get_security_events(changes)
    assert len(sec_events) == 1
    assert sec_events[0]["payload"]["event_type"] == "fim_file_modified"

    # Get sync payload
    sync_payload = monitor.get_baseline_sync_payload()
    assert len(sync_payload["payload"]["files"]) == 1
