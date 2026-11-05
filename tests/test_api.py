from contextlib import closing

import pytest

from server.app import create_app
from server.db import get_connection

TOKEN = "test-mini-edr-token"


@pytest.fixture()
def app(tmp_path):
    database_path = tmp_path / "mini_edr_test.db"
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


def auth_headers(token=TOKEN):
    return {"Authorization": f"Bearer {token}"}


def sample_heartbeat(**overrides):
    payload = {
        "agent_id": "lab-linux-01",
        "hostname": "ubuntu-lab-01",
        "os": "Ubuntu 24.04",
        "ip_address": "192.0.2.10",
        "agent_version": "0.1.0",
        "metrics": {
            "cpu_percent": 25.5,
            "memory_percent": 52.4,
            "disk_percent": 60.0,
            "uptime_seconds": 7200,
        },
    }
    payload.update(overrides)
    return payload


def post_heartbeat(client, payload=None, headers=None):
    request_headers = auth_headers() if headers is None else headers
    return client.post(
        "/api/v1/heartbeat",
        json=payload if payload is not None else sample_heartbeat(),
        headers=request_headers,
    )


def test_health_check_is_public(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"
    assert response.get_json()["service"] == "mini-edr-server"


@pytest.mark.parametrize(
    "headers",
    [{}, auth_headers("wrong-token"), {"Authorization": "Basic abc"}],
)
def test_heartbeat_rejects_missing_or_invalid_token(client, headers):
    response = post_heartbeat(client, headers=headers)

    assert response.status_code == 401
    assert response.get_json()["error"] == "unauthorized"
    assert response.headers["WWW-Authenticate"].startswith("Bearer")


def test_heartbeat_rejects_request_without_authorization_header(client):
    response = client.post("/api/v1/heartbeat", json=sample_heartbeat())

    assert response.status_code == 401
    assert response.get_json()["error"] == "unauthorized"


def test_heartbeat_accepts_valid_payload_and_persists_endpoint(client, app):
    response = post_heartbeat(client)

    assert response.status_code == 200
    body = response.get_json()
    assert body["success"] is True
    assert body["agent_id"] == "lab-linux-01"
    assert body["server_time"]

    with closing(get_connection(app.config["TEST_DATABASE_PATH"])) as connection:
        row = connection.execute(
            "SELECT * FROM endpoints WHERE agent_id = ?",
            ("lab-linux-01",),
        ).fetchone()

    assert row is not None
    assert row["hostname"] == "ubuntu-lab-01"
    assert row["cpu_percent"] == 25.5
    assert row["status"] == "online"


def test_heartbeat_upserts_existing_agent_instead_of_duplicating(client, app):
    first = post_heartbeat(client)
    updated_payload = sample_heartbeat(hostname="ubuntu-lab-renamed")
    second = post_heartbeat(client, updated_payload)

    assert first.status_code == 200
    assert second.status_code == 200

    with closing(get_connection(app.config["TEST_DATABASE_PATH"])) as connection:
        count = connection.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0]
        row = connection.execute(
            "SELECT hostname FROM endpoints WHERE agent_id = ?",
            ("lab-linux-01",),
        ).fetchone()

    assert count == 1
    assert row["hostname"] == "ubuntu-lab-renamed"


def test_heartbeat_requires_json_content_type(client):
    response = client.post(
        "/api/v1/heartbeat",
        data='{"agent_id":"lab-linux-01"}',
        headers={**auth_headers(), "Content-Type": "text/plain"},
    )

    assert response.status_code == 400
    assert "application/json" in response.get_json()["error"]


def test_heartbeat_rejects_malformed_json(client):
    response = client.post(
        "/api/v1/heartbeat",
        data="{invalid-json",
        headers={**auth_headers(), "Content-Type": "application/json"},
    )

    assert response.status_code == 400
    assert response.get_json()["success"] is False


@pytest.mark.parametrize("field", ["agent_id", "hostname", "os"])
def test_heartbeat_requires_non_empty_identity_fields(client, field):
    payload = sample_heartbeat()
    payload[field] = "   "

    response = post_heartbeat(client, payload)

    assert response.status_code == 400
    assert field in response.get_json()["error"]


def test_heartbeat_rejects_non_object_metrics(client):
    response = post_heartbeat(client, sample_heartbeat(metrics=[]))

    assert response.status_code == 400
    assert response.get_json()["error"] == "metrics must be a JSON object"


@pytest.mark.parametrize(
    "bad_value",
    ["high", True, -1, 101, float("nan"), float("inf")],
)
def test_heartbeat_rejects_invalid_cpu_metric_values(client, bad_value):
    payload = sample_heartbeat()
    payload["metrics"]["cpu_percent"] = bad_value

    response = post_heartbeat(client, payload)

    assert response.status_code == 400


@pytest.mark.parametrize(
    "field",
    ["cpu_percent", "memory_percent", "disk_percent"],
)
def test_heartbeat_rejects_percentages_above_100(client, field):
    payload = sample_heartbeat()
    payload["metrics"][field] = 100.01

    response = post_heartbeat(client, payload)

    assert response.status_code == 400
    assert "between 0 and 100" in response.get_json()["error"]


def test_heartbeat_rejects_invalid_ip_address(client):
    response = post_heartbeat(client, sample_heartbeat(ip_address="not-an-ip"))

    assert response.status_code == 400
    assert "ip_address" in response.get_json()["error"]


def test_endpoints_requires_authentication(client):
    response = client.get("/api/v1/endpoints")

    assert response.status_code == 401


def test_endpoints_returns_saved_endpoint(client):
    post_heartbeat(client)

    response = client.get("/api/v1/endpoints", headers=auth_headers())

    assert response.status_code == 200
    body = response.get_json()
    assert body["success"] is True
    assert body["count"] == 1
    assert body["endpoints"][0]["agent_id"] == "lab-linux-01"
    assert body["endpoints"][0]["status"] == "online"


def test_endpoints_marks_stale_heartbeat_as_offline(client, app):
    post_heartbeat(client)
    with closing(get_connection(app.config["TEST_DATABASE_PATH"])) as connection:
        with connection:
            connection.execute(
                "UPDATE endpoints SET last_seen = ? WHERE agent_id = ?",
                ("2000-01-01T00:00:00+00:00", "lab-linux-01"),
            )

    response = client.get("/api/v1/endpoints", headers=auth_headers())

    assert response.status_code == 200
    assert response.get_json()["endpoints"][0]["status"] == "offline"


def test_heartbeat_rejects_request_larger_than_configured_limit(client):
    response = client.post(
        "/api/v1/heartbeat",
        data="x" * (64 * 1024 + 1),
        headers={**auth_headers(), "Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert response.get_json()["error"] == "Request body is too large"


def test_database_uses_wal_mode(app):
    with closing(get_connection(app.config["TEST_DATABASE_PATH"])) as connection:
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]

    assert journal_mode.lower() == "wal"


def test_heartbeat_reactivates_endpoint_after_offline_state(client, app):
    post_heartbeat(client)
    with closing(get_connection(app.config["TEST_DATABASE_PATH"])) as connection:
        with connection:
            connection.execute(
                "UPDATE endpoints SET last_seen = ? WHERE agent_id = ?",
                ("2000-01-01T00:00:00+00:00", "lab-linux-01"),
            )

    offline_response = client.get(
        "/api/v1/endpoints", headers=auth_headers()
    )
    assert offline_response.get_json()["endpoints"][0]["status"] == "offline"

    heartbeat_response = post_heartbeat(client)
    assert heartbeat_response.status_code == 200

    online_response = client.get(
        "/api/v1/endpoints", headers=auth_headers()
    )
    assert online_response.get_json()["endpoints"][0]["status"] == "online"


# -----------------------------------------------------------------------------
# Phase 2 Ingestion & Management Endpoint Tests
# -----------------------------------------------------------------------------

def sample_envelope(agent_id="lab-linux-01", **overrides):
    import uuid
    data = {
        "schema_version": "1.0",
        "message_id": str(uuid.uuid4()),
        "agent_id": agent_id,
        "collected_at": "2026-11-05T08:00:00.000Z",
        "payload": {},
    }
    data.update(overrides)
    return data


def test_system_telemetry_requires_authentication(client):
    env = sample_envelope(payload={"cpu_percent": 10.0, "memory_percent": 20.0, "disk_percent": 30.0, "uptime_seconds": 100})
    res = client.post("/api/v1/telemetry/system", json=env)
    assert res.status_code == 401


def test_system_telemetry_rejects_unregistered_agent(client):
    env = sample_envelope(agent_id="unregistered-agent", payload={
        "cpu_percent": 10.0, "memory_percent": 20.0, "disk_percent": 30.0, "uptime_seconds": 100
    })
    res = client.post("/api/v1/telemetry/system", json=env, headers=auth_headers())
    assert res.status_code == 404
    assert "not registered" in res.get_json()["error"]


def test_system_telemetry_validates_envelope(client):
    post_heartbeat(client)

    # Invalid schema version
    env = sample_envelope(schema_version="2.0")
    res = client.post("/api/v1/telemetry/system", json=env, headers=auth_headers())
    assert res.status_code == 400
    assert "schema_version" in res.get_json()["error"]

    # Invalid message_id
    env = sample_envelope(message_id="not-a-uuid")
    res = client.post("/api/v1/telemetry/system", json=env, headers=auth_headers())
    assert res.status_code == 400
    assert "UUID" in res.get_json()["error"]

    # Invalid timestamp
    env = sample_envelope(collected_at="invalid-date")
    res = client.post("/api/v1/telemetry/system", json=env, headers=auth_headers())
    assert res.status_code == 400
    assert "ISO 8601" in res.get_json()["error"]


def test_system_telemetry_validates_metrics(client):
    post_heartbeat(client)

    # Missing metric
    env = sample_envelope(payload={"cpu_percent": 10.0, "memory_percent": 20.0})
    res = client.post("/api/v1/telemetry/system", json=env, headers=auth_headers())
    assert res.status_code == 400

    # Negative metric
    env = sample_envelope(payload={"cpu_percent": -5.0, "memory_percent": 20.0, "disk_percent": 30.0, "uptime_seconds": 100})
    res = client.post("/api/v1/telemetry/system", json=env, headers=auth_headers())
    assert res.status_code == 400

    # Metric > 100%
    env = sample_envelope(payload={"cpu_percent": 105.0, "memory_percent": 20.0, "disk_percent": 30.0, "uptime_seconds": 100})
    res = client.post("/api/v1/telemetry/system", json=env, headers=auth_headers())
    assert res.status_code == 400


def test_system_telemetry_ingestion_and_idempotency(client, app):
    post_heartbeat(client)

    env = sample_envelope(payload={
        "cpu_percent": 42.0, "memory_percent": 55.5, "disk_percent": 68.2, "uptime_seconds": 3600
    })

    # First insert -> 201
    res1 = client.post("/api/v1/telemetry/system", json=env, headers=auth_headers())
    assert res1.status_code == 201
    b1 = res1.get_json()
    assert b1["success"] is True
    assert b1["duplicate"] is False
    assert b1["message_id"] == env["message_id"]

    # Verify database persistence
    with closing(get_connection(app.config["TEST_DATABASE_PATH"])) as conn:
        row = conn.execute("SELECT * FROM system_metrics WHERE message_id = ?", (env["message_id"],)).fetchone()
        assert row is not None
        assert row["cpu_percent"] == 42.0
        assert row["agent_id"] == "lab-linux-01"

    # Identical retry -> 200 duplicate
    res2 = client.post("/api/v1/telemetry/system", json=env, headers=auth_headers())
    assert res2.status_code == 200
    b2 = res2.get_json()
    assert b2["success"] is True
    assert b2["duplicate"] is True

    # Conflicting retry with different metrics -> 409
    conflicting_env = dict(env)
    conflicting_env["payload"] = {
        "cpu_percent": 99.0, "memory_percent": 55.5, "disk_percent": 68.2, "uptime_seconds": 3600
    }
    res3 = client.post("/api/v1/telemetry/system", json=conflicting_env, headers=auth_headers())
    assert res3.status_code == 409


def test_process_telemetry_validation_and_idempotency(client, app):
    post_heartbeat(client)

    # Count mismatch
    bad_env = sample_envelope(payload={"process_count": 2, "processes": [{"pid": 1, "process_name": "init"}]})
    res_bad = client.post("/api/v1/telemetry/processes", json=bad_env, headers=auth_headers())
    assert res_bad.status_code == 400

    # Duplicate pid
    dup_pid_env = sample_envelope(payload={
        "process_count": 2,
        "processes": [
            {"pid": 100, "process_name": "proc1"},
            {"pid": 100, "process_name": "proc2"},
        ]
    })
    res_dup = client.post("/api/v1/telemetry/processes", json=dup_pid_env, headers=auth_headers())
    assert res_dup.status_code == 400
    assert "Duplicate pid" in res_dup.get_json()["error"]

    # Valid process snapshot
    valid_env = sample_envelope(payload={
        "process_count": 2,
        "processes": [
            {
                "pid": 1,
                "ppid": 0,
                "process_name": "systemd",
                "username": "root",
                "exe_path": "/usr/lib/systemd/systemd",
                "cpu_percent": 0.1,
                "memory_percent": 0.5,
                "rss_bytes": 10485760,
                "process_started_at": "2026-11-05T07:00:00.000Z",
            },
            {
                "pid": 500,
                "ppid": 1,
                "process_name": "sshd",
                "username": "root",
                "exe_path": "/usr/sbin/sshd",
                "cpu_percent": 0.0,
                "memory_percent": 0.2,
                "rss_bytes": 4194304,
                "process_started_at": "2026-11-05T07:05:00.000Z",
            }
        ]
    })

    # First insert -> 201
    res1 = client.post("/api/v1/telemetry/processes", json=valid_env, headers=auth_headers())
    assert res1.status_code == 201
    b1 = res1.get_json()
    assert b1["success"] is True
    assert b1["duplicate"] is False

    # Check database rows
    with closing(get_connection(app.config["TEST_DATABASE_PATH"])) as conn:
        snap = conn.execute("SELECT * FROM process_snapshots WHERE message_id = ?", (valid_env["message_id"],)).fetchone()
        assert snap is not None
        obs = conn.execute("SELECT * FROM process_observations WHERE snapshot_id = ? ORDER BY pid ASC", (snap["id"],)).fetchall()
        assert len(obs) == 2
        assert obs[0]["process_name"] == "systemd"
        assert obs[1]["process_name"] == "sshd"

    # Retry -> 200 duplicate
    res2 = client.post("/api/v1/telemetry/processes", json=valid_env, headers=auth_headers())
    assert res2.status_code == 200
    assert res2.get_json()["duplicate"] is True


def test_file_baselines_synchronization(client, app):
    post_heartbeat(client)

    # Empty files array
    bad_env = sample_envelope(payload={"files": []})
    res_bad = client.post("/api/v1/file-baselines", json=bad_env, headers=auth_headers())
    assert res_bad.status_code == 400

    # Invalid sha256
    invalid_hash_env = sample_envelope(payload={
        "files": [{
            "file_path": "/etc/shadow",
            "sha256": "bad-hash",
            "file_size_bytes": 100,
            "mtime_ns": 1000,
            "file_mode": 384,
            "state": "present",
        }]
    })
    res_inv = client.post("/api/v1/file-baselines", json=invalid_hash_env, headers=auth_headers())
    assert res_inv.status_code == 400

    # Valid baseline sync
    h1 = "a" * 64
    h2 = "b" * 64
    valid_env = sample_envelope(payload={
        "files": [
            {
                "file_path": "/etc/passwd",
                "sha256": h1,
                "file_size_bytes": 2048,
                "mtime_ns": 1730790000000000000,
                "file_mode": 420,
                "state": "present",
            },
            {
                "file_path": "/etc/shadow",
                "sha256": h2,
                "file_size_bytes": 1024,
                "mtime_ns": 1730790000000000000,
                "file_mode": 384,
                "state": "present",
            }
        ]
    })

    # Initial sync: 2 created, 0 updated
    res1 = client.post("/api/v1/file-baselines", json=valid_env, headers=auth_headers())
    assert res1.status_code == 200
    b1 = res1.get_json()
    assert b1["processed"] == 2
    assert b1["created"] == 2
    assert b1["updated"] == 0

    # Second sync with modification: 0 created, 2 updated
    h1_new = "c" * 64
    sync2_env = sample_envelope(payload={
        "files": [
            {
                "file_path": "/etc/passwd",
                "sha256": h1_new,
                "file_size_bytes": 2100,
                "mtime_ns": 1730795000000000000,
                "file_mode": 420,
                "state": "present",
            },
            {
                "file_path": "/etc/shadow",
                "sha256": h2,
                "file_size_bytes": 1024,
                "mtime_ns": 1730790000000000000,
                "file_mode": 384,
                "state": "present",
            }
        ]
    })
    res2 = client.post("/api/v1/file-baselines", json=sync2_env, headers=auth_headers())
    assert res2.status_code == 200
    b2 = res2.get_json()
    assert b2["processed"] == 2
    assert b2["created"] == 0
    assert b2["updated"] == 2

    # Verify database has updated sha256
    with closing(get_connection(app.config["TEST_DATABASE_PATH"])) as conn:
        row = conn.execute("SELECT sha256, file_size_bytes FROM file_baselines WHERE file_path = ?", ("/etc/passwd",)).fetchone()
        assert row["sha256"] == h1_new
        assert row["file_size_bytes"] == 2100


def test_security_events_ingestion_and_idempotency(client, app):
    post_heartbeat(client)

    # Invalid source (agent cannot claim detection)
    bad_source_env = sample_envelope(payload={
        "event_type": "file.modified",
        "severity": "high",
        "source": "detection",
        "title": "Title",
        "occurred_at": "2026-11-05T08:00:00.000Z",
    })
    res_src = client.post("/api/v1/events", json=bad_source_env, headers=auth_headers())
    assert res_src.status_code == 400
    assert "source" in res_src.get_json()["error"]

    # Valid security event
    valid_env = sample_envelope(payload={
        "event_type": "fim_file_modified",
        "severity": "high",
        "source": "agent",
        "title": "Monitored file modified: /etc/pam.d/common-auth",
        "description": "File hash changed unexpectedly",
        "occurred_at": "2026-11-05T08:02:00.000Z",
        "fingerprint": "sha256:testfingerprint",
        "evidence": {
            "file_path": "/etc/pam.d/common-auth",
            "old_hash": "a" * 64,
            "new_hash": "b" * 64,
        }
    })

    # First insert -> 201
    res1 = client.post("/api/v1/events", json=valid_env, headers=auth_headers())
    assert res1.status_code == 201
    assert res1.get_json()["duplicate"] is False

    # Check database
    with closing(get_connection(app.config["TEST_DATABASE_PATH"])) as conn:
        ev = conn.execute("SELECT * FROM security_events WHERE message_id = ?", (valid_env["message_id"],)).fetchone()
        assert ev is not None
        assert ev["event_type"] == "fim_file_modified"
        assert ev["severity"] == "high"

    # Retry -> 200 duplicate
    res2 = client.post("/api/v1/events", json=valid_env, headers=auth_headers())
    assert res2.status_code == 200
    assert res2.get_json()["duplicate"] is True

    # Conflicting retry -> 409
    conflicting = dict(valid_env)
    conflicting["payload"] = dict(valid_env["payload"])
    conflicting["payload"]["title"] = "Different Title"
    res3 = client.post("/api/v1/events", json=conflicting, headers=auth_headers())
    assert res3.status_code == 409


def test_alerts_query_and_lifecycle(client, app):
    from server.repositories.alert_repository import AlertRepository
    from server.repositories.event_repository import EventRepository

    post_heartbeat(client)
    db_path = app.config["TEST_DATABASE_PATH"]
    alert_repo = AlertRepository(db_path)
    event_repo = EventRepository(db_path)

    # Insert a security event first
    ev = event_repo.record({
        "message_id": "00000000-0000-0000-0000-000000000001",
        "agent_id": "lab-linux-01",
        "event_type": "fim_file_modified",
        "severity": "high",
        "source": "agent",
        "title": "File changed",
        "evidence_json": {"path": "/etc/shadow"},
        "occurred_at": "2026-11-05T08:00:00.000Z",
        "received_at": "2026-11-05T08:00:01.000Z",
    })

    # Create an alert linked to the event
    alert = alert_repo.create_or_update({
        "alert_key": "rule-shadow-change-01",
        "agent_id": "lab-linux-01",
        "rule_id": "rule-file-integrity",
        "title": "Critical system file modified",
        "description": "Sensitive /etc/shadow file was modified",
        "severity": "high",
        "status": "new",
    }, event_ids=[ev["id"]])
    alert_id = alert["id"]

    # 1. GET /api/v1/alerts
    res_list = client.get("/api/v1/alerts", headers=auth_headers())
    assert res_list.status_code == 200
    body = res_list.get_json()
    assert body["count"] == 1
    assert body["alerts"][0]["id"] == alert_id

    # Filter with query params
    res_filtered = client.get("/api/v1/alerts?status=new&severity=high", headers=auth_headers())
    assert res_filtered.status_code == 200
    assert res_filtered.get_json()["count"] == 1

    res_empty = client.get("/api/v1/alerts?status=resolved", headers=auth_headers())
    assert res_empty.status_code == 200
    assert res_empty.get_json()["count"] == 0

    # 2. GET /api/v1/alerts/<id>
    res_detail = client.get(f"/api/v1/alerts/{alert_id}", headers=auth_headers())
    assert res_detail.status_code == 200
    detail_body = res_detail.get_json()["alert"]
    assert detail_body["id"] == alert_id
    assert len(detail_body["events"]) == 1
    assert detail_body["events"][0]["event_type"] == "fim_file_modified"

    # Detail 404
    res_404 = client.get("/api/v1/alerts/99999", headers=auth_headers())
    assert res_404.status_code == 404

    # 3. POST /api/v1/alerts/<id>/acknowledge
    res_ack = client.post(f"/api/v1/alerts/{alert_id}/acknowledge", headers=auth_headers())
    assert res_ack.status_code == 200
    ack_body = res_ack.get_json()
    assert ack_body["status"] == "acknowledged"
    assert ack_body["acknowledged_at"] is not None

    # Acknowledge idempotent
    res_ack2 = client.post(f"/api/v1/alerts/{alert_id}/acknowledge", headers=auth_headers())
    assert res_ack2.status_code == 200
    assert res_ack2.get_json()["acknowledged_at"] == ack_body["acknowledged_at"]

    # 4. POST /api/v1/alerts/<id>/resolve
    res_res = client.post(
        f"/api/v1/alerts/{alert_id}/resolve",
        json={"resolution_note": "Legitimate admin maintenance"},
        headers=auth_headers(),
    )
    assert res_res.status_code == 200
    res_body = res_res.get_json()
    assert res_body["status"] == "resolved"
    assert res_body["resolution_note"] == "Legitimate admin maintenance"

    # Cannot acknowledge resolved alert
    res_ack_after_res = client.post(f"/api/v1/alerts/{alert_id}/acknowledge", headers=auth_headers())
    assert res_ack_after_res.status_code == 400
    assert "cannot be acknowledged" in res_ack_after_res.get_json()["error"]

