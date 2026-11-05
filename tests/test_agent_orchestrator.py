from unittest.mock import MagicMock, patch
import pytest

from agent.main import AgentConfig, AgentOrchestrator


def test_agent_config_from_env(monkeypatch):
    monkeypatch.setenv("EDR_AGENT_ID", "custom-agent-99")
    monkeypatch.setenv("EDR_SERVER_URL", "http://192.168.1.100:8000")
    monkeypatch.setenv("EDR_API_TOKEN", "super-secret-token")
    monkeypatch.setenv("EDR_HEARTBEAT_INTERVAL", "3.5")
    monkeypatch.setenv("EDR_PROCESS_SCAN_INTERVAL", "7.0")
    monkeypatch.setenv("EDR_FIM_SCAN_INTERVAL", "15.0")
    monkeypatch.setenv("EDR_MONITORED_PATHS", "/etc,/var/log")

    cfg = AgentConfig.from_env()
    assert cfg.agent_id == "custom-agent-99"
    assert cfg.server_url == "http://192.168.1.100:8000"
    assert cfg.api_token == "super-secret-token"
    assert cfg.heartbeat_interval == 3.5
    assert cfg.process_interval == 7.0
    assert cfg.fim_interval == 15.0
    assert cfg.monitored_paths == ["/etc", "/var/log"]


def test_orchestrator_initialization():
    cfg = AgentConfig(agent_id="test-orch-01", server_url="http://127.0.0.1:5000")
    orch = AgentOrchestrator(config=cfg)

    assert orch.config.agent_id == "test-orch-01"
    assert orch.system_collector.agent_id == "test-orch-01"
    assert orch.process_collector.agent_id == "test-orch-01"
    assert orch.fim_monitor.agent_id == "test-orch-01"
    assert orch.client.server_url == "http://127.0.0.1:5000"
    assert orch.running is False
    assert orch.fim_initialized is False


def test_orchestrator_single_cycle_force_all():
    mock_sys = MagicMock()
    mock_sys.collect_system_info.return_value = {"agent_id": "test", "metrics": {}}

    mock_proc = MagicMock()
    mock_proc.collect_snapshot.return_value = {"schema_version": "1.0", "payload": {"process_count": 5}}

    mock_fim = MagicMock()
    mock_fim.initialize_baseline.return_value = 10
    mock_fim.get_baseline_sync_payload.return_value = {"payload": {"files": []}}

    mock_client = MagicMock()

    cfg = AgentConfig(agent_id="test-agent")
    orch = AgentOrchestrator(
        config=cfg,
        system_collector=mock_sys,
        process_collector=mock_proc,
        fim_monitor=mock_fim,
        client=mock_client,
    )

    summary = orch.run_single_cycle(force_all=True)

    assert summary["heartbeat_sent"] is True
    assert summary["process_snapshot_sent"] is True
    assert summary["fim_synced"] is True
    assert summary["fim_events_sent"] == 0
    assert len(summary["errors"]) == 0

    mock_client.send_heartbeat.assert_called_once()
    mock_client.send_process_snapshot.assert_called_once()
    mock_client.send_file_baselines.assert_called_once()
    assert orch.fim_initialized is True


def test_orchestrator_subsequent_fim_change_detection():
    mock_sys = MagicMock()
    mock_proc = MagicMock()
    mock_fim = MagicMock()
    mock_client = MagicMock()

    cfg = AgentConfig(agent_id="test-agent")
    orch = AgentOrchestrator(
        config=cfg,
        system_collector=mock_sys,
        process_collector=mock_proc,
        fim_monitor=mock_fim,
        client=mock_client,
    )
    orch.fim_initialized = True  # Baseline already synced

    mock_fim.check_for_changes.return_value = [
        {"change_type": "modified", "file_path": "/etc/passwd"},
    ]
    mock_fim.get_security_events.return_value = [
        {"schema_version": "1.0", "payload": {"event_type": "fim_file_modified"}},
    ]

    summary = orch.run_single_cycle(force_all=True)

    assert summary["fim_synced"] is False
    assert summary["fim_events_sent"] == 1
    mock_client.send_security_event.assert_called_once()


def test_orchestrator_collector_error_resilience():
    mock_sys = MagicMock()
    mock_sys.collect_system_info.side_effect = RuntimeError("Kernel procfs locked")

    mock_proc = MagicMock()
    mock_proc.collect_snapshot.return_value = {"payload": {"process_count": 1}}

    mock_fim = MagicMock()
    mock_fim.initialize_baseline.return_value = 0
    mock_fim.get_baseline_sync_payload.return_value = {"payload": {"files": []}}

    mock_client = MagicMock()

    cfg = AgentConfig(agent_id="test-agent")
    orch = AgentOrchestrator(
        config=cfg,
        system_collector=mock_sys,
        process_collector=mock_proc,
        fim_monitor=mock_fim,
        client=mock_client,
    )

    # Must not raise exception
    summary = orch.run_single_cycle(force_all=True)

    assert summary["heartbeat_sent"] is False
    assert len(summary["errors"]) == 1
    assert "Heartbeat error: Kernel procfs locked" in summary["errors"][0]

    # Process and FIM tasks should still have succeeded!
    assert summary["process_snapshot_sent"] is True
    assert summary["fim_synced"] is True


def test_orchestrator_stop_cleanly():
    orch = AgentOrchestrator()
    orch.running = True
    orch.stop()
    assert orch.running is False
