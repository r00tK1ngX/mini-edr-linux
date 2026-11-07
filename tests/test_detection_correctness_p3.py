"""Phase 3 Detection Correctness Test Suite for Mini EDR Linux.

Validates all Phase 3 detection and correlation enhancements:
- Detection-to-event ID direct mapping without unsafe index() lookups
- Correlated alerts link only relevant contributing event IDs (not fleet/snapshot-wide)
- Parent process resolution via in-snapshot PID->PPID mapping
- ProcessCollector enriches parent_name metadata
- Correlation time window enforcement (configurable time_window_seconds)
- PID reuse resilience via start_time and process identity separation
- Rule registry metadata catalog: purpose, input fields, expected false positives
- Resilience against database persistence failures during detection evaluation
"""

from datetime import datetime, timezone
import json
from unittest.mock import MagicMock
import pytest

from agent.process_collector import collect_processes
from detection.correlation import CorrelatedFinding, CorrelationEngine
from detection.engine import DetectionEngine
from detection.rules import (
    BaseRule,
    DetectionResult,
    FimDroppedBinaryRule,
    FimSensitiveFileRule,
    ProcessHiddenBinaryRule,
    ProcessHighCpuRule,
    ProcessHighMemoryRule,
    ProcessShellSpawnRule,
    ProcessSuspiciousPathRule,
    RuleRegistry,
)
from server.db import init_db
from server.repositories.alert_repository import AlertRepository
from server.repositories.endpoint_repository import EndpointRepository
from server.repositories.event_repository import EventRepository


@pytest.fixture()
def db_path(tmp_path):
    database_file = tmp_path / "det_p3.db"
    init_db(str(database_file))
    return str(database_file)


@pytest.fixture()
def endpoint(db_path):
    repo = EndpointRepository(db_path)
    return repo.upsert({
        "agent_id": "agent-p3-test",
        "hostname": "kali-p3",
        "os": "Kali Linux 2026",
        "last_seen": "2026-11-07T12:00:00Z",
    })


# -----------------------------------------------------------------------------
# 1. Detection-to-Event ID Mapping & Index Integrity Tests
# -----------------------------------------------------------------------------

def test_detection_to_event_id_direct_mapping(db_path, endpoint):
    """Detection results map directly to their persisted event_id without index() lookups."""
    engine = DetectionEngine(database_path=db_path)
    agent_id = endpoint["agent_id"]

    observations = [
        {
            "pid": 2001,
            "ppid": 1,
            "process_name": "miner_app",
            "exe_path": "/tmp/miner_app",
            "cpu_percent": 10.0,
            "memory_percent": 10.0,
        }
    ]

    result = engine.evaluate_process_snapshot(agent_id, snapshot_id=1, observations=observations)
    assert result["alerts_created"] == 1
    alert = result["alerts"][0]

    alert_repo = AlertRepository(db_path)
    linked_events = alert_repo.get_linked_events(alert["id"])
    assert len(linked_events) == 1

    event_repo = EventRepository(db_path)
    event_row = event_repo.get_by_id(linked_events[0]["id"])
    assert event_row is not None
    assert event_row["agent_id"] == agent_id
    assert "miner_app" in event_row["title"]


def test_correlated_alert_links_only_relevant_event_ids(db_path, endpoint):
    """Correlated alerts link only events belonging to the correlated process, not other processes."""
    engine = DetectionEngine(database_path=db_path)
    agent_id = endpoint["agent_id"]

    observations = [
        # Process A: Multi-factor anomaly (High CPU + Suspicious Path) -> Correlated Alert
        {
            "pid": 3001,
            "ppid": 1,
            "process_name": "attack_proc",
            "exe_path": "/tmp/attack_proc",
            "cpu_percent": 90.0,
            "memory_percent": 10.0,
        },
        # Process B: Single rule trigger (Hidden binary only) -> Single Alert
        {
            "pid": 3002,
            "ppid": 1,
            "process_name": ".hidden_app",
            "exe_path": "/usr/bin/.hidden_app",
            "cpu_percent": 5.0,
            "memory_percent": 5.0,
        },
    ]

    result = engine.evaluate_process_snapshot(agent_id, snapshot_id=2, observations=observations)
    assert result["alerts_created"] == 2

    alert_repo = AlertRepository(db_path)
    correlated_alert = next((a for a in result["alerts"] if a["rule_id"] == "rule-correlated-multistage"), None)
    single_alert = next((a for a in result["alerts"] if a["rule_id"] == "rule-process-hidden-binary"), None)

    assert correlated_alert is not None
    assert single_alert is not None

    corr_events = alert_repo.get_linked_events(correlated_alert["id"])
    single_events = alert_repo.get_linked_events(single_alert["id"])

    # Correlated alert should have 2 events: high-cpu and suspicious-path for PID 3001
    assert len(corr_events) == 2
    for ev in corr_events:
        evidence = json.loads(ev["evidence_json"])
        assert evidence.get("pid") == 3001, "Correlated alert must only link events for PID 3001"

    # Single alert should have 1 event for PID 3002
    assert len(single_events) == 1
    evidence_single = json.loads(single_events[0]["evidence_json"])
    assert evidence_single.get("pid") == 3002, "Single alert must only link events for PID 3002"


def test_detection_event_mapping_resilience_on_partial_persistence_failure(db_path, endpoint, monkeypatch):
    """If saving an event to the repository fails, subsequent detections are safely evaluated without IndexError."""
    engine = DetectionEngine(database_path=db_path)
    agent_id = endpoint["agent_id"]

    orig_record = engine.event_repo.record
    call_count = 0

    def flaky_record(event_record, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("Simulated transient database lock on first event")
        return orig_record(event_record, **kwargs)

    monkeypatch.setattr(engine.event_repo, "record", flaky_record)

    observations = [
        # Process 1: triggers suspicious path (event record fails)
        {
            "pid": 4001,
            "ppid": 1,
            "process_name": "proc_fail",
            "exe_path": "/tmp/proc_fail",
            "cpu_percent": 1.0,
            "memory_percent": 1.0,
        },
        # Process 2: triggers suspicious path (event record succeeds)
        {
            "pid": 4002,
            "ppid": 1,
            "process_name": "proc_success",
            "exe_path": "/tmp/proc_success",
            "cpu_percent": 1.0,
            "memory_percent": 1.0,
        },
    ]

    # Must complete cleanly without raising IndexError
    result = engine.evaluate_process_snapshot(agent_id, snapshot_id=3, observations=observations)
    assert result["detections_count"] == 2
    assert result["events_created"] == 1
    assert result["alerts_created"] >= 1


# -----------------------------------------------------------------------------
# 2. Parent Process Resolution Tests
# -----------------------------------------------------------------------------

def test_shell_spawn_parent_process_resolution(db_path, endpoint):
    """DetectionEngine resolves parent_name from in-snapshot PID->PPID hierarchy and triggers shell spawn rule."""
    engine = DetectionEngine(database_path=db_path)
    agent_id = endpoint["agent_id"]

    observations = [
        # Parent web server
        {
            "pid": 500,
            "ppid": 1,
            "process_name": "nginx",
            "exe_path": "/usr/sbin/nginx",
            "cpu_percent": 1.0,
            "memory_percent": 2.0,
            "username": "www-data",
        },
        # Child shell spawned by nginx (parent_name is initially absent)
        {
            "pid": 501,
            "ppid": 500,
            "process_name": "sh",
            "exe_path": "/bin/sh",
            "cpu_percent": 2.0,
            "memory_percent": 1.0,
            "username": "www-data",
            "parent_name": None,  # Engine must resolve this to 'nginx'
        },
    ]

    result = engine.evaluate_process_snapshot(agent_id, snapshot_id=4, observations=observations)
    assert result["alerts_created"] >= 1

    shell_alert = next((a for a in result["alerts"] if a["rule_id"] == "rule-proc-shell-spawn"), None)
    assert shell_alert is not None
    assert "sh" in shell_alert["title"]

    alert_repo = AlertRepository(db_path)
    events = alert_repo.get_linked_events(shell_alert["id"])
    assert len(events) >= 1
    ev_data = json.loads(events[0]["evidence_json"])
    assert ev_data.get("parent_name") == "nginx", "parent_name must be successfully resolved from PPID 500"


def test_process_collector_enriches_parent_name():
    """Agent ProcessCollector automatically enriches processes with parent_name from in-snapshot PIDs."""
    procs = collect_processes(sort_by="pid")
    assert len(procs) > 0

    # Every process dictionary must contain the parent_name key
    for p in procs:
        assert "parent_name" in p


# -----------------------------------------------------------------------------
# 3. Correlation Time Window Tests
# -----------------------------------------------------------------------------

def test_correlation_time_window_recent_event_matches():
    """FIM drop event occurring within configured time window correlates with process execution."""
    # 5-minute window (300 seconds)
    engine = CorrelationEngine(min_correlation_score=75, time_window_seconds=300)

    fim_det = DetectionResult(
        rule_id="rule-fim-dropped-binary",
        rule_name="FIM Drop",
        title="File dropped in /tmp",
        description="Drop",
        severity="medium",
        risk_score=40,
        evidence={
            "file_path": "/tmp/tool.elf",
            "occurred_at": "2026-11-07T10:00:00Z",
        },
    )

    proc_path_det = DetectionResult(
        rule_id="rule-process-suspicious-path",
        rule_name="Suspicious Path",
        title="Executed from /tmp",
        description="Path",
        severity="high",
        risk_score=50,
        evidence={
            "pid": 6001,
            "process_name": "tool.elf",
            "exe_path": "/tmp/tool.elf",
            "start_time": "2026-11-07T10:02:30Z",  # 2.5 minutes later (within 5-min window)
        },
    )

    proc_cpu_det = DetectionResult(
        rule_id="rule-process-high-cpu",
        rule_name="High CPU",
        title="High CPU",
        description="CPU",
        severity="medium",
        risk_score=30,
        evidence={
            "pid": 6001,
            "process_name": "tool.elf",
            "exe_path": "/tmp/tool.elf",
            "start_time": "2026-11-07T10:02:30Z",
            "cpu_percent": 90.0,
        },
    )

    findings = engine.correlate_process_and_fim(
        agent_id="test-agent",
        process_detections=[proc_path_det, proc_cpu_det],
        fim_detections=[fim_det],
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "critical"
    factor_names = [f["factor"] for f in finding.factors]
    assert "fim_dropped_and_executed" in factor_names


def test_correlation_time_window_stale_event_rejected():
    """FIM drop event occurring outside configured time window is rejected from correlation."""
    # 5-minute window (300 seconds)
    engine = CorrelationEngine(min_correlation_score=75, time_window_seconds=300)

    fim_stale_det = DetectionResult(
        rule_id="rule-fim-dropped-binary",
        rule_name="FIM Drop",
        title="File dropped in /tmp",
        description="Drop",
        severity="medium",
        risk_score=40,
        evidence={
            "file_path": "/tmp/tool.elf",
            "occurred_at": "2026-11-07T08:00:00Z",  # 2 hours earlier (outside 5-min window)
        },
    )

    proc_path_det = DetectionResult(
        rule_id="rule-process-suspicious-path",
        rule_name="Suspicious Path",
        title="Executed from /tmp",
        description="Path",
        severity="high",
        risk_score=50,
        evidence={
            "pid": 6002,
            "process_name": "tool.elf",
            "exe_path": "/tmp/tool.elf",
            "start_time": "2026-11-07T10:00:00Z",
        },
    )

    proc_cpu_det = DetectionResult(
        rule_id="rule-process-high-cpu",
        rule_name="High CPU",
        title="High CPU",
        description="CPU",
        severity="medium",
        risk_score=30,
        evidence={
            "pid": 6002,
            "process_name": "tool.elf",
            "exe_path": "/tmp/tool.elf",
            "start_time": "2026-11-07T10:00:00Z",
            "cpu_percent": 90.0,
        },
    )

    findings = engine.correlate_process_and_fim(
        agent_id="test-agent",
        process_detections=[proc_path_det, proc_cpu_det],
        fim_detections=[fim_stale_det],
    )

    assert len(findings) == 1
    finding = findings[0]
    # Score without FIM dropped factor: 50 + 30 = 80 (< 85, so severity is 'high' instead of 'critical')
    assert finding.severity == "high"
    factor_names = [f["factor"] for f in finding.factors]
    assert "fim_dropped_and_executed" not in factor_names, "Stale FIM event must not correlate"


# -----------------------------------------------------------------------------
# 4. PID Reuse & Process Identity Tests
# -----------------------------------------------------------------------------

def test_pid_reuse_distinct_process_identity():
    """Processes with identical PID but different start times generate distinct alert keys."""
    engine = CorrelationEngine()

    pid = 7777
    proc_name = "reused_app"
    exe = "/tmp/reused_app"

    # Instance 1: Started at 09:00:00
    det1 = [
        DetectionResult(
            rule_id="rule-process-suspicious-path",
            rule_name="Path",
            title="Path",
            description="Path",
            severity="high",
            risk_score=50,
            evidence={"pid": pid, "process_name": proc_name, "exe_path": exe, "start_time": "2026-11-07T09:00:00Z"},
        ),
        DetectionResult(
            rule_id="rule-process-high-cpu",
            rule_name="CPU",
            title="CPU",
            description="CPU",
            severity="medium",
            risk_score=30,
            evidence={"pid": pid, "process_name": proc_name, "exe_path": exe, "cpu_percent": 90.0, "start_time": "2026-11-07T09:00:00Z"},
        ),
    ]

    # Instance 2: New process with recycled PID 7777 started at 15:00:00
    det2 = [
        DetectionResult(
            rule_id="rule-process-suspicious-path",
            rule_name="Path",
            title="Path",
            description="Path",
            severity="high",
            risk_score=50,
            evidence={"pid": pid, "process_name": proc_name, "exe_path": exe, "start_time": "2026-11-07T15:00:00Z"},
        ),
        DetectionResult(
            rule_id="rule-process-high-cpu",
            rule_name="CPU",
            title="CPU",
            description="CPU",
            severity="medium",
            risk_score=30,
            evidence={"pid": pid, "process_name": proc_name, "exe_path": exe, "cpu_percent": 90.0, "start_time": "2026-11-07T15:00:00Z"},
        ),
    ]

    findings1 = engine.correlate_process_and_fim("agent-01", det1, [])
    findings2 = engine.correlate_process_and_fim("agent-01", det2, [])

    assert len(findings1) == 1
    assert len(findings2) == 1

    key1 = findings1[0].alert_key
    key2 = findings2[0].alert_key

    assert key1 != key2, "PID reuse must produce distinct alert_keys based on start_time process identity"
    assert "2026-11-07T09:00:00Z" in key1
    assert "2026-11-07T15:00:00Z" in key2


# -----------------------------------------------------------------------------
# 5. Rule Registry Catalog & Documentation Integrity Tests
# -----------------------------------------------------------------------------

def test_rule_registry_catalog_completeness():
    """All rules in registry provide complete academic documentation metadata."""
    registry = RuleRegistry()
    catalog = registry.get_rule_catalog()

    assert len(catalog) >= 7

    for entry in catalog:
        assert entry["rule_id"], "Rule must have a valid rule_id"
        assert entry["name"], "Rule must have a descriptive name"
        assert entry["purpose"], f"Rule '{entry['rule_id']}' must define an explicit purpose"
        assert isinstance(entry["input_fields"], list) and len(entry["input_fields"]) > 0, (
            f"Rule '{entry['rule_id']}' must declare input fields"
        )
        assert isinstance(entry["expected_false_positives"], list) and len(entry["expected_false_positives"]) > 0, (
            f"Rule '{entry['rule_id']}' must document expected false-positive scenarios"
        )
        assert entry["severity"] in ("info", "low", "medium", "high", "critical")
        assert 0 <= entry["base_score"] <= 100
        assert entry["mitre_attack"], f"Rule '{entry['rule_id']}' must map to MITRE ATT&CK"


def test_rule_registry_get_rule_by_id():
    """RuleRegistry retrieves rule instances by ID."""
    registry = RuleRegistry()
    rule = registry.get_rule_by_id("rule-proc-shell-spawn")
    assert rule is not None
    assert isinstance(rule, ProcessShellSpawnRule)

    none_rule = registry.get_rule_by_id("non-existent-rule-id")
    assert none_rule is None


def test_heuristic_boundary_transparency():
    """Rules document transparent detection boundaries without claims of 100% catch rate."""
    registry = RuleRegistry()
    catalog = registry.get_rule_catalog()

    for r in catalog:
        # Academic boundary verification: Heuristics must avoid grandiose claims
        full_text = f"{r['name']} {r['description']} {r['purpose']}".lower()
        assert "catches all" not in full_text
        assert "undetectable" not in full_text
        assert "guarantees" not in full_text
