from collections import namedtuple
import os
from unittest.mock import MagicMock, patch
import psutil
import pytest

from agent.process_collector import (
    ProcessCollector,
    _clean_process_name,
    _format_start_time,
    _sanitize_numeric,
    collect_process_snapshot,
    collect_processes,
    collect_single_process,
    get_process_by_pid,
)
from server.db import init_db
from server.repositories import EndpointRepository, ProcessRepository


def test_collect_processes_real():
    processes = collect_processes(sort_by="pid")
    assert isinstance(processes, list)
    assert len(processes) > 0

    required_keys = {
        "pid",
        "ppid",
        "process_name",
        "username",
        "exe_path",
        "cpu_percent",
        "memory_percent",
        "rss_bytes",
        "process_started_at",
    }
    for proc in processes:
        assert required_keys.issubset(proc.keys())
        assert isinstance(proc["pid"], int)
        assert proc["pid"] >= 0
        assert isinstance(proc["process_name"], str)
        assert len(proc["process_name"].strip()) > 0
        if proc["ppid"] is not None:
            assert proc["ppid"] >= 0
        if proc["cpu_percent"] is not None:
            assert proc["cpu_percent"] >= 0.0
        if proc["memory_percent"] is not None:
            assert 0.0 <= proc["memory_percent"] <= 100.0
        if proc["rss_bytes"] is not None:
            assert proc["rss_bytes"] >= 0


def test_collect_processes_sorting():
    by_pid = collect_processes(sort_by="pid")
    pids = [p["pid"] for p in by_pid]
    assert pids == sorted(pids)

    by_cpu = collect_processes(sort_by="cpu_percent")
    assert len(by_cpu) == len(by_pid)


def test_collect_single_process_mocked():
    MemInfo = namedtuple("pmem", ["rss"])
    mock_proc = MagicMock()
    mock_proc.info = {
        "pid": 4321,
        "ppid": 100,
        "name": "edr-agent",
        "username": "root",
        "exe": "/opt/edr/edr-agent",
        "cpu_percent": 15.5,
        "memory_percent": 2.3,
        "memory_info": MemInfo(rss=10485760),
        "create_time": 1730800000.0,
    }

    result = collect_single_process(mock_proc)
    assert result is not None
    assert result["pid"] == 4321
    assert result["ppid"] == 100
    assert result["process_name"] == "edr-agent"
    assert result["username"] == "root"
    assert result["exe_path"] == "/opt/edr/edr-agent"
    assert result["cpu_percent"] == 15.5
    assert result["memory_percent"] == 2.3
    assert result["rss_bytes"] == 10485760
    assert result["process_started_at"] is not None


def test_collect_single_process_no_such_process():
    mock_proc = MagicMock()
    mock_proc.info = None
    mock_proc.as_dict.side_effect = psutil.NoSuchProcess(pid=999)

    assert collect_single_process(mock_proc) is None


def test_collect_single_process_zombie():
    mock_proc = MagicMock()
    mock_proc.info = None
    mock_proc.as_dict.side_effect = psutil.ZombieProcess(pid=999)

    assert collect_single_process(mock_proc) is None


def test_collect_single_process_access_denied():
    mock_proc = MagicMock()
    mock_proc.info = None
    mock_proc.pid = 777
    mock_proc.as_dict.side_effect = psutil.AccessDenied(pid=777)

    result = collect_single_process(mock_proc)
    assert result is not None
    assert result["pid"] == 777
    assert result["process_name"] == "proc-777"
    assert result["username"] is None
    assert result["exe_path"] is None


def test_clean_process_name_fallback():
    assert _clean_process_name("systemd", "/usr/lib/systemd/systemd", 1) == "systemd"
    assert _clean_process_name("   ", "/usr/bin/python3", 100) == "python3"
    assert _clean_process_name(None, None, 200) == "proc-200"
    assert _clean_process_name("", "", 300) == "proc-300"


def test_sanitize_numeric():
    assert _sanitize_numeric(12.3456) == 12.35
    assert _sanitize_numeric(-5.0, min_val=0.0) == 0.0
    assert _sanitize_numeric(150.0, max_val=100.0) == 100.0
    assert _sanitize_numeric(True) is None
    assert _sanitize_numeric(False) is None
    assert _sanitize_numeric("invalid") is None
    assert _sanitize_numeric(None) is None


def test_format_start_time():
    assert _format_start_time(None) is None
    assert _format_start_time(0.0) is None
    assert _format_start_time(-100.0) is None
    formatted = _format_start_time(1730800000.0)
    assert formatted is not None
    assert "2024-" in formatted or "202" in formatted
    assert "T" in formatted


def test_get_process_by_pid_current_process():
    current_pid = os.getpid()
    proc = get_process_by_pid(current_pid)
    assert proc is not None
    assert proc["pid"] == current_pid
    assert len(proc["process_name"]) > 0


def test_get_process_by_pid_not_found():
    assert get_process_by_pid(99999999) is None


def test_collect_process_snapshot_envelope_and_persistence(tmp_path):
    # Test Data Contract envelope format
    snapshot_msg = collect_process_snapshot(
        agent_id="lab-linux-01",
        message_id="msg-snap-test-001",
        schema_version="1.0",
    )
    assert snapshot_msg["schema_version"] == "1.0"
    assert snapshot_msg["message_id"] == "msg-snap-test-001"
    assert snapshot_msg["agent_id"] == "lab-linux-01"
    assert "collected_at" in snapshot_msg
    assert "payload" in snapshot_msg

    payload = snapshot_msg["payload"]
    assert "process_count" in payload
    assert "processes" in payload
    assert payload["process_count"] == len(payload["processes"])

    # Test integration: verify ProcessRepository can persist this collected snapshot directly!
    db_path = str(tmp_path / "integration_snap.db")
    init_db(db_path)

    # Register endpoint first (FK constraint)
    endpoint_repo = EndpointRepository(db_path)
    endpoint_repo.upsert({
        "agent_id": "lab-linux-01",
        "hostname": "kali-box",
        "os": "Kali Linux",
        "last_seen": "2026-11-05T08:00:00Z",
    })

    proc_repo = ProcessRepository(db_path)
    persisted_snap = proc_repo.create_snapshot(
        {
            "message_id": snapshot_msg["message_id"],
            "schema_version": snapshot_msg["schema_version"],
            "agent_id": snapshot_msg["agent_id"],
            "process_count": payload["process_count"],
            "collected_at": snapshot_msg["collected_at"],
            "received_at": "2026-11-05T08:10:01Z",
        },
        payload["processes"],
    )

    assert persisted_snap["id"] is not None
    assert persisted_snap["process_count"] == payload["process_count"]

    saved_observations = proc_repo.list_observations(persisted_snap["id"])
    assert len(saved_observations) == payload["process_count"]


def test_process_collector_class():
    collector = ProcessCollector(agent_id="collector-agent-01")
    processes = collector.collect_processes()
    assert isinstance(processes, list)
    assert len(processes) > 0

    current_pid = os.getpid()
    proc = collector.get_process(current_pid)
    assert proc is not None
    assert proc["pid"] == current_pid

    snapshot = collector.collect_snapshot(message_id="class-msg-001")
    assert snapshot["agent_id"] == "collector-agent-01"
    assert snapshot["message_id"] == "class-msg-001"
    assert snapshot["payload"]["process_count"] == len(snapshot["payload"]["processes"])
