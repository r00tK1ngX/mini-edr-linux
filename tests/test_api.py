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
