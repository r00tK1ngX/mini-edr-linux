"""Tests for Mini EDR Linux Detection Engine and Correlation Module.

Verifies:
- Config loading and RuleRegistry initialization
- Process rules: High CPU, High Memory, Suspicious Path, Hidden Binary
- FIM rules: Sensitive configuration file tampering and deletion
- Correlation Engine: Multi-factor correlation and explainable risk scoring (0-100)
- Guard against false conclusions (High CPU alone does NOT trigger a malware alert)
- DetectionEngine end-to-end integration with database persistence and real-time API triggers
"""

from contextlib import closing
import json
from pathlib import Path
import pytest

from detection.correlation import CorrelatedFinding, CorrelationEngine
from detection.engine import DetectionEngine
from detection.rules import (
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
from server.app import create_app
from server.db import get_connection, init_db
from server.repositories.alert_repository import AlertRepository
from server.repositories.endpoint_repository import EndpointRepository
from server.repositories.event_repository import EventRepository

TOKEN = "test-detection-token"


@pytest.fixture()
def db_path(tmp_path):
    database_file = tmp_path / "detection_test.db"
    init_db(str(database_file))
    return str(database_file)


@pytest.fixture()
def sample_endpoint(db_path):
    repo = EndpointRepository(db_path)
    return repo.upsert({
        "agent_id": "lab-linux-det-01",
        "hostname": "kali-detection",
        "os": "Kali Linux 2026",
        "last_seen": "2026-11-05T08:00:00Z",
    })


@pytest.fixture()
def app(tmp_path):
    database_path = tmp_path / "mini_edr_api_det.db"
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


# -----------------------------------------------------------------------------
# 1. RuleRegistry and Configuration Tests
# -----------------------------------------------------------------------------

def test_rule_registry_default_loading():
    registry = RuleRegistry()
    assert len(registry.rules) >= 7

    rule_ids = [r.rule_id for r in registry.rules]
    assert "rule-process-high-cpu" in rule_ids
    assert "rule-process-high-memory" in rule_ids
    assert "rule-process-suspicious-path" in rule_ids
    assert "rule-process-hidden-binary" in rule_ids
    assert "rule-proc-shell-spawn" in rule_ids
    assert "rule-fim-sensitive-tampered" in rule_ids
    assert "rule-fim-dropped-binary" in rule_ids


def test_rule_registry_custom_json_config(tmp_path):
    cfg_file = tmp_path / "custom_rules.json"
    cfg_file.write_text(json.dumps({
        "thresholds": {"cpu_percent": 95.0, "memory_percent": 90.0},
        "suspicious_paths": ["/opt/untrusted"],
        "rules": {
            "rule-process-high-cpu": {"enabled": False},
            "rule-process-suspicious-path": {"severity": "critical", "base_score": 70},
        }
    }))

    registry = RuleRegistry(config_path=str(cfg_file))
    cpu_rule = next(r for r in registry.rules if r.rule_id == "rule-process-high-cpu")
    assert cpu_rule.enabled is False

    path_rule = next(r for r in registry.rules if r.rule_id == "rule-process-suspicious-path")
    assert path_rule.severity == "critical"
    assert path_rule.base_score == 70
    assert "/opt/untrusted" in path_rule.suspicious_paths


# -----------------------------------------------------------------------------
# 2. Individual Rule Unit Tests
# -----------------------------------------------------------------------------

def test_process_high_cpu_rule():
    rule = ProcessHighCpuRule(threshold_percent=80.0)

    # Below threshold -> None
    res_low = rule.evaluate({"agent_id": "agent-01", "pid": 101, "process_name": "worker", "cpu_percent": 45.0})
    assert res_low is None

    # Over threshold -> DetectionResult
    res_high = rule.evaluate({
        "agent_id": "agent-01",
        "pid": 102,
        "process_name": "cryptominer",
        "exe_path": "/usr/local/bin/miner",
        "cpu_percent": 98.5,
    })
    assert res_high is not None
    assert res_high.rule_id == "rule-process-high-cpu"
    assert res_high.severity == "medium"
    assert res_high.risk_score == 30
    assert res_high.evidence["cpu_percent"] == 98.5
    assert "cryptominer" in res_high.title


def test_process_high_memory_rule():
    rule = ProcessHighMemoryRule(threshold_percent=75.0)

    # Below threshold -> None
    res_normal = rule.evaluate({"pid": 200, "process_name": "daemon", "memory_percent": 20.0})
    assert res_normal is None

    # Over threshold -> DetectionResult
    res_high = rule.evaluate({
        "agent_id": "agent-01",
        "pid": 201,
        "process_name": "mem_hog",
        "memory_percent": 88.0,
        "rss_bytes": 1024 * 1024 * 500,
    })
    assert res_high is not None
    assert res_high.rule_id == "rule-process-high-memory"
    assert res_high.risk_score == 30
    assert res_high.evidence["memory_percent"] == 88.0


@pytest.mark.parametrize(
    "path,expected_match",
    [
        ("/usr/bin/python3", False),
        ("/bin/bash", False),
        ("/tmp/payload", True),
        ("/tmp/subdir/malware.elf", True),
        ("/var/tmp/crypto", True),
        ("/dev/shm/.run", True),
    ],
)
def test_process_suspicious_path_rule(path, expected_match):
    rule = ProcessSuspiciousPathRule(suspicious_paths=["/tmp", "/var/tmp", "/dev/shm"])
    res = rule.evaluate({
        "agent_id": "agent-01",
        "pid": 300,
        "process_name": "proc",
        "exe_path": path,
    })
    if expected_match:
        assert res is not None
        assert res.rule_id == "rule-process-suspicious-path"
        assert res.severity == "high"
        assert res.risk_score == 50
    else:
        assert res is None


@pytest.mark.parametrize(
    "name,exe_path,expected_hidden",
    [
        ("systemd", "/usr/lib/systemd/systemd", False),
        ("sshd", "/usr/sbin/sshd", False),
        (".hidden_miner", "/tmp/.hidden_miner", True),
        ("stealth", "/var/tmp/.drop/stealth", True),
        (".backdoor", None, True),
    ],
)
def test_process_hidden_binary_rule(name, exe_path, expected_hidden):
    rule = ProcessHiddenBinaryRule()
    res = rule.evaluate({
        "agent_id": "agent-01",
        "pid": 400,
        "process_name": name,
        "exe_path": exe_path,
    })
    if expected_hidden:
        assert res is not None
        assert res.rule_id == "rule-process-hidden-binary"
        assert res.severity == "high"
    else:
        assert res is None


def test_fim_sensitive_file_tampering_rule():
    rule = FimSensitiveFileRule()

    # Regular file modified -> None
    res_regular = rule.evaluate({
        "event_type": "fim_file_modified",
        "evidence": {"file_path": "/home/kali/notes.txt"},
    })
    assert res_regular is None

    # Sensitive file modified -> High/Critical DetectionResult
    res_passwd = rule.evaluate({
        "agent_id": "agent-01",
        "event_type": "fim_file_modified",
        "evidence": {"file_path": "/etc/passwd", "old_sha256": "1" * 64, "new_sha256": "2" * 64},
    })
    assert res_passwd is not None
    assert res_passwd.rule_id == "rule-fim-sensitive-tampered"
    assert res_passwd.severity == "high"
    assert res_passwd.risk_score == 60

    # Critical /etc/shadow deletion -> Critical
    res_shadow_del = rule.evaluate({
        "agent_id": "agent-01",
        "event_type": "fim_file_deleted",
        "evidence": {"file_path": "/etc/shadow"},
    })
    assert res_shadow_del is not None
    assert res_shadow_del.severity == "critical"
    assert res_shadow_del.risk_score >= 80


def test_process_shell_spawn_rule():
    """Verify ProcessShellSpawnRule detects reverse shells spawned by daemons/web users."""
    rule = ProcessShellSpawnRule()

    # 1. Normal user shell -> None
    res_normal = rule.evaluate({
        "agent_id": "agent-01",
        "pid": 501,
        "process_name": "bash",
        "exe_path": "/bin/bash",
        "username": "kali",
        "parent_name": "login",
    })
    assert res_normal is None

    # 2. Web server user (www-data) spawning bash -> High alert
    res_web_shell = rule.evaluate({
        "agent_id": "agent-01",
        "pid": 502,
        "process_name": "sh",
        "exe_path": "/bin/sh",
        "username": "www-data",
        "parent_name": "apache2",
    })
    assert res_web_shell is not None
    assert res_web_shell.rule_id == "rule-proc-shell-spawn"
    assert res_web_shell.severity == "high"
    assert res_web_shell.risk_score == 60
    assert "T1059.004" in res_web_shell.mitre_attack

    # 3. Python parent spawning /bin/bash -> High alert
    res_py_spawn = rule.evaluate({
        "agent_id": "agent-01",
        "pid": 503,
        "process_name": "bash",
        "exe_path": "/usr/bin/bash",
        "username": "nobody",
        "parent_name": "python3",
    })
    assert res_py_spawn is not None
    assert res_py_spawn.rule_id == "rule-proc-shell-spawn"


def test_fim_dropped_binary_rule():
    """Verify FimDroppedBinaryRule detects files created in suspicious/temp directories."""
    rule = FimDroppedBinaryRule()

    # 1. Regular file in /home/kali -> None
    res_home = rule.evaluate({
        "event_type": "fim_file_created",
        "evidence": {"file_path": "/home/kali/script.py"},
    })
    assert res_home is None

    # 2. File modification in /tmp -> None (only file creation triggers dropped binary)
    res_mod = rule.evaluate({
        "event_type": "fim_file_modified",
        "evidence": {"file_path": "/tmp/existing.log"},
    })
    assert res_mod is None

    # 3. New binary created in /tmp -> DetectionResult
    res_drop = rule.evaluate({
        "agent_id": "agent-01",
        "event_type": "fim_file_created",
        "evidence": {"file_path": "/tmp/dropper.elf"},
    })
    assert res_drop is not None
    assert res_drop.rule_id == "rule-fim-dropped-binary"
    assert res_drop.severity == "medium"
    assert res_drop.risk_score == 40
    assert "T1105" in res_drop.mitre_attack
    assert res_drop.evidence["file_path"] == "/tmp/dropper.elf"



# -----------------------------------------------------------------------------
# 3. Correlation Engine & Risk Scoring Tests
# -----------------------------------------------------------------------------

def test_correlation_single_high_cpu_does_not_conclude_malware():
    """Verify requirement: Do not conclude malware merely from a single high CPU threshold."""
    engine = CorrelationEngine()

    cpu_detection = DetectionResult(
        rule_id="rule-process-high-cpu",
        rule_name="High CPU",
        title="High CPU consumption",
        description="Process used 99% CPU",
        severity="medium",
        risk_score=30,
        evidence={"pid": 1234, "process_name": "ffmpeg", "cpu_percent": 99.0},
    )

    correlated = engine.correlate_process_and_fim(
        agent_id="agent-01",
        process_detections=[cpu_detection],
        fim_detections=[],
    )

    # Must NOT produce a multi-stage correlated alert
    assert len(correlated) == 0

    # Single-rule alert remains isolated with medium severity and low score (30)
    single_alert = engine.calculate_single_rule_alert("agent-01", cpu_detection)
    assert single_alert.severity == "medium"
    assert single_alert.total_risk_score == 30
    assert "High CPU" in single_alert.title


def test_correlation_multi_stage_suspicious_path_and_high_cpu():
    """Correlates a suspicious path with high CPU into an escalated High severity alert."""
    engine = CorrelationEngine()

    pid = 9999
    path_det = DetectionResult(
        rule_id="rule-process-suspicious-path",
        rule_name="Suspicious Path",
        title="Process in /tmp",
        description="Binary in /tmp",
        severity="high",
        risk_score=50,
        evidence={"pid": pid, "process_name": "xmrig", "exe_path": "/tmp/xmrig"},
    )
    cpu_det = DetectionResult(
        rule_id="rule-process-high-cpu",
        rule_name="High CPU",
        title="High CPU",
        description="95% CPU",
        severity="medium",
        risk_score=30,
        evidence={"pid": pid, "process_name": "xmrig", "exe_path": "/tmp/xmrig", "cpu_percent": 95.0},
    )

    correlated = engine.correlate_process_and_fim(
        agent_id="agent-01",
        process_detections=[path_det, cpu_det],
        fim_detections=[],
    )

    assert len(correlated) == 1
    finding = correlated[0]
    assert finding.severity in ("high", "critical")
    assert finding.total_risk_score >= 80
    assert len(finding.factors) == 2
    factor_names = [f["factor"] for f in finding.factors]
    assert "suspicious_execution_path" in factor_names
    assert "high_cpu_utilization" in factor_names


def test_correlation_complete_attack_chain_with_fim():
    """Correlates FIM dropped file + execution from /tmp + high CPU into Critical alert."""
    engine = CorrelationEngine()

    pid = 7777
    exe = "/tmp/dropper.elf"

    path_det = DetectionResult(
        rule_id="rule-process-suspicious-path",
        rule_name="Suspicious Path",
        title="Process in /tmp",
        description="In /tmp",
        severity="high",
        risk_score=50,
        evidence={"pid": pid, "process_name": "dropper.elf", "exe_path": exe},
    )
    cpu_det = DetectionResult(
        rule_id="rule-process-high-cpu",
        rule_name="High CPU",
        title="High CPU",
        description="90% CPU",
        severity="medium",
        risk_score=30,
        evidence={"pid": pid, "process_name": "dropper.elf", "exe_path": exe, "cpu_percent": 90.0},
    )
    fim_det = DetectionResult(
        rule_id="rule-fim-dropped-binary",
        rule_name="FIM Dropped Binary",
        title="New file in /tmp",
        description="File dropped in /tmp",
        severity="medium",
        risk_score=40,
        evidence={"file_path": exe},
    )

    correlated = engine.correlate_process_and_fim(
        agent_id="agent-01",
        process_detections=[path_det, cpu_det],
        fim_detections=[fim_det],
    )

    assert len(correlated) == 1
    finding = correlated[0]
    assert finding.severity == "critical"
    assert finding.total_risk_score >= 90
    factor_names = [f["factor"] for f in finding.factors]
    assert "fim_dropped_and_executed" in factor_names


# -----------------------------------------------------------------------------
# 4. DetectionEngine Integration with Database
# -----------------------------------------------------------------------------

def test_detection_engine_evaluates_processes_and_persists_alerts(db_path, sample_endpoint):
    engine = DetectionEngine(database_path=db_path)
    agent_id = sample_endpoint["agent_id"]

    observations = [
        {
            "pid": 1,
            "ppid": 0,
            "process_name": "systemd",
            "exe_path": "/usr/lib/systemd/systemd",
            "cpu_percent": 0.5,
            "memory_percent": 0.5,
        },
        {
            "pid": 8888,
            "ppid": 1,
            "process_name": "untrusted_miner",
            "exe_path": "/tmp/untrusted_miner",
            "cpu_percent": 92.0,
            "memory_percent": 40.0,
        },
    ]

    result = engine.evaluate_process_snapshot(agent_id, snapshot_id=1, observations=observations)

    assert result["observations_evaluated"] == 2
    assert result["detections_count"] >= 2  # high CPU + suspicious path
    assert result["alerts_created"] >= 1

    # Verify alerts table in SQLite
    alert_repo = AlertRepository(db_path)
    alerts = alert_repo.list_alerts(agent_id=agent_id)
    assert len(alerts) >= 1
    top_alert = alerts[0]
    assert top_alert["status"] == "new"
    assert top_alert["severity"] in ("high", "critical")

    # Verify security_events table in SQLite has detection source events
    event_repo = EventRepository(db_path)
    events = event_repo.list_by_agent(agent_id)
    assert len(events) >= 2
    assert all(e["source"] == "detection" for e in events)


def test_detection_engine_evaluates_fim_event_and_generates_alert(db_path, sample_endpoint):
    engine = DetectionEngine(database_path=db_path)
    agent_id = sample_endpoint["agent_id"]

    event_repo = EventRepository(db_path)
    saved_event = event_repo.record({
        "message_id": "fim-event-uuid-001",
        "agent_id": agent_id,
        "event_type": "fim_file_modified",
        "severity": "high",
        "source": "agent",
        "title": "Monitored file modified: /etc/sudoers",
        "occurred_at": "2026-11-05T08:00:00Z",
        "received_at": "2026-11-05T08:00:01Z",
        "evidence_json": {"file_path": "/etc/sudoers", "old_sha256": "0" * 64, "new_sha256": "1" * 64},
    })

    result = engine.evaluate_security_event(agent_id, saved_event)
    assert result["matches_count"] == 1
    assert result["alerts_created"] == 1

    alert_repo = AlertRepository(db_path)
    alerts = alert_repo.list_alerts(agent_id=agent_id)
    assert len(alerts) == 1
    assert "/etc/sudoers" in alerts[0]["title"]
    linked_events = alert_repo.get_linked_events(alerts[0]["id"])
    assert len(linked_events) == 1
    assert linked_events[0]["id"] == saved_event["id"]


# -----------------------------------------------------------------------------
# 5. Real-Time API Ingestion Triggering Detection
# -----------------------------------------------------------------------------

def test_api_process_ingestion_triggers_detection_and_creates_alert(client, app):
    """Verify that posting process telemetry to API automatically invokes DetectionEngine and creates alerts."""
    import uuid

    # 1. Register endpoint with heartbeat
    client.post(
        "/api/v1/heartbeat",
        json={"agent_id": "auto-det-agent", "hostname": "auto-det-host", "os": "Linux"},
        headers=auth_headers(),
    )

    # 2. Ingest suspicious process snapshot
    msg_id = str(uuid.uuid4())
    snapshot_payload = {
        "schema_version": "1.0",
        "message_id": msg_id,
        "agent_id": "auto-det-agent",
        "collected_at": "2026-11-05T08:00:00.000Z",
        "payload": {
            "process_count": 2,
            "processes": [
                {
                    "pid": 1,
                    "ppid": 0,
                    "process_name": "systemd",
                    "exe_path": "/usr/lib/systemd/systemd",
                    "cpu_percent": 0.1,
                    "memory_percent": 0.2,
                },
                {
                    "pid": 5555,
                    "ppid": 1,
                    "process_name": "crypto_miner",
                    "exe_path": "/tmp/crypto_miner",
                    "cpu_percent": 96.0,
                    "memory_percent": 30.0,
                },
            ],
        },
    }

    resp = client.post("/api/v1/telemetry/processes", json=snapshot_payload, headers=auth_headers())
    assert resp.status_code == 201

    # 3. Query GET /api/v1/alerts: DetectionEngine must have created an alert in real time!
    alert_resp = client.get("/api/v1/alerts?agent_id=auto-det-agent", headers=auth_headers())
    assert alert_resp.status_code == 200
    alert_body = alert_resp.get_json()
    assert alert_body["count"] >= 1

    alert = alert_body["alerts"][0]
    assert alert["agent_id"] == "auto-det-agent"
    assert alert["severity"] in ("high", "critical")
    assert alert["status"] == "new"

    # 4. Check alert details and linked events
    detail_resp = client.get(f"/api/v1/alerts/{alert['id']}", headers=auth_headers())
    assert detail_resp.status_code == 200
    detail = detail_resp.get_json()["alert"]
    assert len(detail["events"]) >= 1


def test_correlation_min_score_threshold_enforced():
    """Verify min_correlation_score parameter blocks correlation if combined score is below threshold."""
    # min_correlation_score set to 90
    strict_engine = CorrelationEngine(min_correlation_score=90)

    pid = 1111
    # Score 50 + 30 = 80 (< 90 threshold)
    path_det = DetectionResult(
        rule_id="rule-process-suspicious-path",
        rule_name="Suspicious Path",
        title="Path",
        description="Path",
        severity="high",
        risk_score=50,
        evidence={"pid": pid, "process_name": "app", "exe_path": "/tmp/app"},
    )
    cpu_det = DetectionResult(
        rule_id="rule-process-high-cpu",
        rule_name="High CPU",
        title="High CPU",
        description="CPU",
        severity="medium",
        risk_score=30,
        evidence={"pid": pid, "process_name": "app", "exe_path": "/tmp/app", "cpu_percent": 90.0},
    )

    correlated_strict = strict_engine.correlate_process_and_fim(
        agent_id="agent-01",
        process_detections=[path_det, cpu_det],
        fim_detections=[],
    )
    assert len(correlated_strict) == 0  # Blocked by min_correlation_score=90

    # With standard threshold 75:
    normal_engine = CorrelationEngine(min_correlation_score=75)
    correlated_normal = normal_engine.correlate_process_and_fim(
        agent_id="agent-01",
        process_detections=[path_det, cpu_det],
        fim_detections=[],
    )
    assert len(correlated_normal) == 1  # 80 >= 75: Passes


def test_fim_dropped_binary_and_process_exec_correlation_e2e(db_path, sample_endpoint):
    """E2E Detection Engine: FIM dropped binary event in /tmp followed by process execution triggers Critical alert."""
    engine = DetectionEngine(database_path=db_path)
    agent_id = sample_endpoint["agent_id"]

    # 1. Ingest FIM event of newly dropped binary into database
    fim_event = engine.event_repo.record({
        "message_id": "msg-fim-drop-001",
        "schema_version": "1.0",
        "agent_id": agent_id,
        "event_type": "fim_file_created",
        "severity": "medium",
        "source": "agent",
        "title": "New file in /tmp",
        "description": "File created in /tmp/backdoor.elf",
        "evidence_json": {"file_path": "/tmp/backdoor.elf"},
        "occurred_at": "2026-11-05T08:00:00Z",
        "received_at": "2026-11-05T08:00:01Z",
        "fingerprint": "fim:dropped:test",
    })

    # Evaluate FIM event directly -> FimDroppedBinaryRule triggers alert
    fim_eval = engine.evaluate_security_event(agent_id, fim_event)
    assert fim_eval["matches_count"] == 1
    assert fim_eval["alerts_created"] == 1
    assert fim_eval["alerts"][0]["rule_id"] == "rule-fim-dropped-binary"

    # 2. Process snapshot arrives executing /tmp/backdoor.elf with high CPU
    observations = [
        {
            "pid": 6666,
            "ppid": 1,
            "process_name": "backdoor.elf",
            "exe_path": "/tmp/backdoor.elf",
            "cpu_percent": 90.0,
            "memory_percent": 10.0,
        }
    ]

    proc_eval = engine.evaluate_process_snapshot(agent_id, snapshot_id=2, observations=observations)
    assert proc_eval["alerts_created"] >= 1

    # Correlated alert generated combining dropped binary + execution + CPU
    correlated_alert = next((a for a in proc_eval["alerts"] if a["rule_id"] == "rule-correlated-multistage"), None)
    assert correlated_alert is not None
    assert correlated_alert["severity"] == "critical"
    assert "backdoor.elf" in correlated_alert["title"]

