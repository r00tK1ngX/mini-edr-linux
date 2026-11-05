"""Phase 4 End-to-End (E2E) Integration Tests.

Verifies end-to-end communication between multiple Linux Agents and the Flask Server:
- Real loopback TCP HTTP network requests via AgentClient
- Multiple endpoints registration without duplicate records
- System metrics telemetry, process snapshots, and FIM baseline synchronization persisted in SQLite
- File tampering change detection generating security events
- Stale endpoint offline transition (> 15s) and automatic online reactivation upon new heartbeat
- Authentication failure handling and credential protection
"""

from contextlib import closing
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Generator
import urllib.request

import pytest
from werkzeug.serving import make_server

from agent.client import AgentAuthenticationError, AgentClient
from agent.main import AgentConfig, AgentOrchestrator
from server.app import create_app
from server.db import get_connection

TOKEN = "phase4-e2e-secret-token"


@pytest.fixture()
def live_server(tmp_path) -> Generator[dict, None, None]:
    """Start a real Flask HTTP server on an ephemeral loopback port."""
    database_path = tmp_path / "phase4_e2e.db"
    application = create_app({
        "TESTING": True,
        "EDR_API_TOKEN": TOKEN,
        "DATABASE_PATH": str(database_path),
        "OFFLINE_AFTER_SECONDS": 15,
    })

    server = make_server("127.0.0.1", 0, application)
    port = server.port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    server_url = f"http://127.0.0.1:{port}"

    yield {
        "url": server_url,
        "database_path": str(database_path),
        "port": port,
        "app": application,
    }

    server.shutdown()
    thread.join()


def test_e2e_multiple_agents_registration_and_persistence(live_server, tmp_path):
    """Verify multiple endpoints connect, register without duplicates, and persist telemetry."""
    server_url = live_server["url"]
    db_path = live_server["database_path"]

    # Setup isolated monitored directories for two agents
    agent1_dir = tmp_path / "agent1_monitored"
    agent1_dir.mkdir()
    (agent1_dir / "app.conf").write_text("setting=alpha\n")

    agent2_dir = tmp_path / "agent2_monitored"
    agent2_dir.mkdir()
    (agent2_dir / "service.conf").write_text("setting=beta\n")

    # Initialize Agent 1 Orchestrator
    cfg1 = AgentConfig(
        agent_id="lab-linux-01",
        server_url=server_url,
        api_token=TOKEN,
        monitored_paths=[str(agent1_dir)],
    )
    orch1 = AgentOrchestrator(config=cfg1)

    # Initialize Agent 2 Orchestrator
    cfg2 = AgentConfig(
        agent_id="lab-linux-02",
        server_url=server_url,
        api_token=TOKEN,
        monitored_paths=[str(agent2_dir)],
    )
    orch2 = AgentOrchestrator(config=cfg2)

    # 1. Run single cycle for Agent 1
    summary1 = orch1.run_single_cycle(force_all=True)
    assert summary1["heartbeat_sent"] is True
    assert summary1["process_snapshot_sent"] is True
    assert summary1["fim_synced"] is True
    assert len(summary1["errors"]) == 0

    # 2. Run single cycle for Agent 2
    summary2 = orch2.run_single_cycle(force_all=True)
    assert summary2["heartbeat_sent"] is True
    assert summary2["process_snapshot_sent"] is True
    assert summary2["fim_synced"] is True
    assert len(summary2["errors"]) == 0

    # 3. Run Agent 1 a second time to ensure upsert idempotency (no duplicate endpoints)
    summary1_second = orch1.run_single_cycle(force_all=True)
    assert summary1_second["heartbeat_sent"] is True

    # 4. Verify endpoints inventory via Server API
    client = AgentClient(server_url=server_url, api_token=TOKEN)
    resp = client._execute_request("GET", "/api/v1/endpoints", require_auth=True)

    assert resp["success"] is True
    assert resp["count"] == 2
    endpoints = {ep["agent_id"]: ep for ep in resp["endpoints"]}
    assert "lab-linux-01" in endpoints
    assert "lab-linux-02" in endpoints
    assert endpoints["lab-linux-01"]["status"] == "online"
    assert endpoints["lab-linux-02"]["status"] == "online"

    # 5. Direct verification in SQLite database
    with closing(get_connection(db_path)) as conn:
        # Check endpoints table has exactly 2 records
        ep_rows = conn.execute("SELECT agent_id, hostname, status FROM endpoints ORDER BY agent_id ASC").fetchall()
        assert len(ep_rows) == 2
        assert ep_rows[0]["agent_id"] == "lab-linux-01"
        assert ep_rows[1]["agent_id"] == "lab-linux-02"

        # Check system_metrics table has records for both agents
        metrics_rows = conn.execute("SELECT DISTINCT agent_id FROM system_metrics ORDER BY agent_id ASC").fetchall()
        agents_in_metrics = [r["agent_id"] for r in metrics_rows]
        assert "lab-linux-01" in agents_in_metrics
        assert "lab-linux-02" in agents_in_metrics

        # Check process_snapshots table has records for both agents
        snap_rows = conn.execute("SELECT agent_id, process_count FROM process_snapshots ORDER BY agent_id ASC").fetchall()
        assert len(snap_rows) >= 2
        agents_in_snaps = {r["agent_id"] for r in snap_rows}
        assert "lab-linux-01" in agents_in_snaps
        assert "lab-linux-02" in agents_in_snaps

        # Check process_observations table has observed processes
        obs_count = conn.execute("SELECT COUNT(*) FROM process_observations").fetchone()[0]
        assert obs_count > 0

        # Check file_baselines table has records for both agents
        base_rows = conn.execute("SELECT agent_id, file_path, sha256 FROM file_baselines ORDER BY agent_id ASC").fetchall()
        assert len(base_rows) == 2
        base_by_agent = {r["agent_id"]: r["file_path"] for r in base_rows}
        assert str(agent1_dir / "app.conf") == base_by_agent["lab-linux-01"]
        assert str(agent2_dir / "service.conf") == base_by_agent["lab-linux-02"]


def test_e2e_fim_file_tampering_detects_and_creates_security_event(live_server, tmp_path):
    """Verify that tampering with a monitored file triggers an E2E security event."""
    server_url = live_server["url"]
    db_path = live_server["database_path"]

    monitored_dir = tmp_path / "fim_target"
    monitored_dir.mkdir()
    target_file = monitored_dir / "critical_file.txt"
    target_file.write_text("initial secure content\n")

    cfg = AgentConfig(
        agent_id="lab-linux-tamper",
        server_url=server_url,
        api_token=TOKEN,
        monitored_paths=[str(monitored_dir)],
    )
    orch = AgentOrchestrator(config=cfg)

    # Initial cycle: establishes and syncs baseline
    cycle1 = orch.run_single_cycle(force_all=True)
    assert cycle1["fim_synced"] is True
    assert cycle1["fim_events_sent"] == 0

    # Tamper with file
    time.sleep(0.05)
    target_file.write_text("MALICIOUS MODIFICATION\n")

    # Second cycle: change detection should trigger security event transmission
    cycle2 = orch.run_single_cycle(force_all=True)
    assert cycle2["fim_events_sent"] == 1
    assert len(cycle2["errors"]) == 0

    # Verify event stored in security_events table in SQLite
    with closing(get_connection(db_path)) as conn:
        events = conn.execute(
            "SELECT * FROM security_events WHERE agent_id = ?",
            ("lab-linux-tamper",),
        ).fetchall()
        assert len(events) == 1
        event = events[0]
        assert event["event_type"] == "fim_file_modified"
        assert event["severity"] == "high"
        assert event["source"] == "agent"
        assert str(target_file) in event["title"]
        assert str(target_file) in event["evidence_json"]


def test_e2e_offline_transition_and_online_reactivation(live_server, tmp_path):
    """Verify stale endpoints transition to Offline and reactivate upon new heartbeat."""
    server_url = live_server["url"]
    db_path = live_server["database_path"]

    dir1 = tmp_path / "life1"
    dir1.mkdir()
    (dir1 / "test.txt").write_text("ok\n")

    cfg1 = AgentConfig(
        agent_id="agent-lifecycle-01",
        server_url=server_url,
        api_token=TOKEN,
        monitored_paths=[str(dir1)],
    )
    cfg2 = AgentConfig(
        agent_id="agent-lifecycle-02",
        server_url=server_url,
        api_token=TOKEN,
        monitored_paths=[str(dir1)],
    )
    orch1 = AgentOrchestrator(config=cfg1)
    orch2 = AgentOrchestrator(config=cfg2)

    # Register both agents
    orch1.run_single_cycle(force_all=True)
    orch2.run_single_cycle(force_all=True)

    client = AgentClient(server_url=server_url, api_token=TOKEN)

    # Both online initially
    res1 = client._execute_request("GET", "/api/v1/endpoints", require_auth=True)
    assert res1["count"] == 2
    for ep in res1["endpoints"]:
        assert ep["status"] == "online"

    # Simulate Agent 1 heartbeat going stale (> 15 seconds ago)
    with closing(get_connection(db_path)) as conn:
        with conn:
            conn.execute(
                "UPDATE endpoints SET last_seen = ? WHERE agent_id = ?",
                ("2000-01-01T00:00:00+00:00", "agent-lifecycle-01"),
            )

    # Query inventory again: Agent 1 should be offline, Agent 2 still online
    res2 = client._execute_request("GET", "/api/v1/endpoints", require_auth=True)
    ep_map = {ep["agent_id"]: ep["status"] for ep in res2["endpoints"]}
    assert ep_map["agent-lifecycle-01"] == "offline"
    assert ep_map["agent-lifecycle-02"] == "online"

    # Agent 1 sends a new heartbeat
    sys_info = orch1.system_collector.collect_system_info()
    client.send_heartbeat(sys_info)

    # Query inventory again: Agent 1 should now be back online!
    res3 = client._execute_request("GET", "/api/v1/endpoints", require_auth=True)
    ep_map_after = {ep["agent_id"]: ep["status"] for ep in res3["endpoints"]}
    assert ep_map_after["agent-lifecycle-01"] == "online"
    assert ep_map_after["agent-lifecycle-02"] == "online"


def test_e2e_agent_authentication_failure(live_server):
    """Verify that an agent with an invalid token fails authentication without leaking credentials."""
    server_url = live_server["url"]

    bad_client = AgentClient(server_url=server_url, api_token="invalid-token-123")

    with pytest.raises(AgentAuthenticationError) as exc_info:
        bad_client.send_heartbeat({"agent_id": "test-agent", "hostname": "host", "os": "Linux"})

    assert "invalid or missing Bearer token" in str(exc_info.value)
    # Ensure raw secret is not in exception representation
    assert "invalid-token-123" not in str(exc_info.value)
