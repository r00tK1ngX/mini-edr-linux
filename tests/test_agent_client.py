from io import BytesIO
import json
from unittest.mock import MagicMock, patch
import urllib.error
import pytest

from agent.client import (
    AgentAuthenticationError,
    AgentClient,
    AgentConnectionError,
    AgentRequestError,
)


def _mock_http_response(status_code: int = 200, json_data: dict = None):
    """Helper creating a mock urllib response context manager."""
    data = json.dumps(json_data or {"success": True}).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.status = status_code
    mock_resp.read.return_value = data
    mock_resp.__enter__.return_value = mock_resp
    return mock_resp


def _mock_http_error(status_code: int, error_data: dict = None):
    """Helper creating a mock urllib.error.HTTPError."""
    data = json.dumps(error_data or {"error": "request failed"}).encode("utf-8")
    fp = BytesIO(data)
    return urllib.error.HTTPError(
        url="http://127.0.0.1:5000/api",
        code=status_code,
        msg="Error",
        hdrs={},
        fp=fp,
    )


def test_client_initialization():
    client = AgentClient(
        server_url="http://127.0.0.1:5000///",
        api_token="test-secret-token",
        timeout=3.0,
        max_retries=2,
        backoff_factor=0.1,
    )
    assert client.server_url == "http://127.0.0.1:5000"
    assert client.api_token == "test-secret-token"
    assert client.timeout == 3.0
    assert client.max_retries == 2
    assert client.backoff_factor == 0.1


def test_client_build_headers():
    client = AgentClient(server_url="http://localhost:5000", api_token="abc-123")
    auth_headers = client._build_headers(require_auth=True)
    assert auth_headers["Authorization"] == "Bearer abc-123"
    assert auth_headers["Content-Type"] == "application/json"

    no_auth_headers = client._build_headers(require_auth=False)
    assert "Authorization" not in no_auth_headers


def test_check_health_success():
    client = AgentClient()
    mock_resp = _mock_http_response(200, {"status": "ok", "service": "mini-edr-server"})
    with patch("urllib.request.urlopen", return_value=mock_resp):
        assert client.check_health() is True


def test_check_health_failure():
    client = AgentClient()
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        assert client.check_health() is False


def test_send_heartbeat_success():
    client = AgentClient(api_token="my-token")
    mock_resp = _mock_http_response(200, {"success": True, "agent_id": "lab-01"})
    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        resp = client.send_heartbeat({"agent_id": "lab-01", "hostname": "box"})
        assert resp["success"] is True
        assert resp["agent_id"] == "lab-01"

        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "http://127.0.0.1:5000/api/v1/heartbeat"
        assert req.get_header("Authorization") == "Bearer my-token"
        assert req.get_method() == "POST"


def test_authentication_error_401_no_retry():
    client = AgentClient(api_token="bad-token", max_retries=3, backoff_factor=0.01)
    err = _mock_http_error(401, {"error": "unauthorized"})

    with patch("urllib.request.urlopen", side_effect=err) as mock_urlopen:
        with pytest.raises(AgentAuthenticationError) as exc_info:
            client.send_heartbeat({"agent_id": "test"})

        assert "Authentication failed" in str(exc_info.value)
        # Verify it did not retry on 401
        assert mock_urlopen.call_count == 1


def test_client_error_400_no_retry():
    client = AgentClient(api_token="token", max_retries=3, backoff_factor=0.01)
    err = _mock_http_error(400, {"error": "Missing or invalid field: agent_id"})

    with patch("urllib.request.urlopen", side_effect=err) as mock_urlopen:
        with pytest.raises(AgentRequestError) as exc_info:
            client.send_heartbeat({})

        assert exc_info.value.status_code == 400
        assert "Missing or invalid field" in str(exc_info.value)
        assert mock_urlopen.call_count == 1


def test_retry_on_server_error_500_then_success():
    client = AgentClient(api_token="token", max_retries=2, backoff_factor=0.01)
    err500 = _mock_http_error(500, {"error": "Internal server error"})
    resp200 = _mock_http_response(200, {"success": True})

    with patch("urllib.request.urlopen", side_effect=[err500, resp200]) as mock_urlopen:
        res = client.send_heartbeat({"agent_id": "test"})
        assert res["success"] is True
        assert mock_urlopen.call_count == 2


def test_retry_exhausted_connection_error():
    client = AgentClient(max_retries=2, backoff_factor=0.01)
    conn_err = urllib.error.URLError("Connection refused")

    with patch("urllib.request.urlopen", side_effect=conn_err) as mock_urlopen:
        with pytest.raises(AgentConnectionError) as exc_info:
            client.send_heartbeat({"agent_id": "test"})

        assert "Failed to connect to server" in str(exc_info.value)
        assert mock_urlopen.call_count == 3  # 1 initial + 2 retries


def test_all_envelope_endpoints():
    client = AgentClient(api_token="test-token")
    mock_resp = _mock_http_response(200, {"success": True})

    endpoints_called = []

    def fake_urlopen(req, timeout):
        endpoints_called.append((req.get_method(), req.full_url))
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        client.send_system_telemetry({"schema_version": "1.0", "payload": {}})
        client.send_process_snapshot({"schema_version": "1.0", "payload": {}})
        client.send_file_baselines({"schema_version": "1.0", "payload": {}})
        client.send_security_event({"schema_version": "1.0", "payload": {}})

    expected = [
        ("POST", "http://127.0.0.1:5000/api/v1/telemetry/system"),
        ("POST", "http://127.0.0.1:5000/api/v1/telemetry/processes"),
        ("POST", "http://127.0.0.1:5000/api/v1/file-baselines"),
        ("POST", "http://127.0.0.1:5000/api/v1/events"),
    ]
    assert endpoints_called == expected
