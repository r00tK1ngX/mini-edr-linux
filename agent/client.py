"""HTTP Client module for Mini EDR Linux Agent.

Transmits heartbeat, telemetry metrics, process snapshots, file baselines,
and security events to the Flask Server. Implements Bearer token authentication,
configurable timeouts, limited retry with exponential backoff, and strict credential
sanitization to prevent token leakage in logs.
"""

from datetime import datetime, timezone
import json
import logging
import socket
import time
from typing import Any, Dict, Optional
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)


class AgentClientError(Exception):
    """Base exception for Mini EDR Agent HTTP client errors."""


class AgentConnectionError(AgentClientError):
    """Raised when the server is unreachable or timed out after all retries."""


class AgentAuthenticationError(AgentClientError):
    """Raised when the server rejects API token authentication (HTTP 401)."""


class AgentRequestError(AgentClientError):
    """Raised when the server rejects a request with a 4xx client error."""

    def __init__(self, message: str, status_code: int, response_data: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data or {}


class AgentClient:
    """Robust HTTP client for communicating with the Mini EDR Flask Server."""

    def __init__(
        self,
        server_url: str = "http://127.0.0.1:5000",
        api_token: Optional[str] = None,
        timeout: float = 5.0,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
    ):
        self.server_url = server_url.rstrip("/")
        self.api_token = api_token or ""
        self.timeout = max(0.5, float(timeout))
        self.max_retries = max(0, int(max_retries))
        self.backoff_factor = max(0.0, float(backoff_factor))

    def _build_headers(self, require_auth: bool = True) -> Dict[str, str]:
        """Construct request headers without logging the API token."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "MiniEDR-Agent/1.0 (Linux)",
        }
        if require_auth and self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        return headers

    def _execute_request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        require_auth: bool = True,
    ) -> Dict[str, Any]:
        """Execute an HTTP request with retry, backoff, and error translation."""
        url = f"{self.server_url}/{path.lstrip('/')}"
        headers = self._build_headers(require_auth=require_auth)
        data_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None

        last_exception: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                sleep_duration = self.backoff_factor * (2 ** (attempt - 1))
                logger.debug("Retrying %s %s in %.2fs (attempt %d/%d)", method, path, sleep_duration, attempt, self.max_retries)
                time.sleep(sleep_duration)

            req = urllib.request.Request(
                url=url,
                data=data_bytes,
                headers=headers,
                method=method.upper(),
            )

            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    raw_body = response.read()
                    status = response.status
                    if raw_body:
                        try:
                            return json.loads(raw_body.decode("utf-8"))
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            return {"success": True, "raw": raw_body.decode("utf-8", errors="replace")}
                    return {"success": True, "status": status}

            except urllib.error.HTTPError as exc:
                status_code = exc.code
                error_body: Dict[str, Any] = {}
                try:
                    raw_err = exc.read().decode("utf-8", errors="replace")
                    error_body = json.loads(raw_err)
                except Exception:
                    error_body = {"error": str(exc)}

                # 401 Unauthorized: Do not retry, raise immediately
                if status_code == 401:
                    logger.error("Authentication failed: Server rejected API token (HTTP 401)")
                    raise AgentAuthenticationError("Authentication failed: invalid or missing Bearer token") from exc

                # 4xx Client Errors: Do not retry (bad request, payload too large, not found, etc.)
                if 400 <= status_code < 500:
                    err_msg = error_body.get("error", f"Client request error HTTP {status_code}")
                    logger.warning("Request rejected by server (%d): %s", status_code, err_msg)
                    raise AgentRequestError(err_msg, status_code=status_code, response_data=error_body) from exc

                # 5xx Server Errors: Candidate for retry
                logger.warning("Server error %d on %s %s (attempt %d/%d)", status_code, method, path, attempt + 1, self.max_retries + 1)
                last_exception = exc

            except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
                # Connection refused, DNS failure, or network timeout: Candidate for retry
                logger.debug("Network error connecting to %s: %s (attempt %d/%d)", self.server_url, exc, attempt + 1, self.max_retries + 1)
                last_exception = exc

        # All retries exhausted
        raise AgentConnectionError(f"Failed to connect to server at {self.server_url} after {self.max_retries + 1} attempts: {last_exception}") from last_exception

    # -------------------------------------------------------------------------
    # Public API Communication Methods
    # -------------------------------------------------------------------------

    def check_health(self) -> bool:
        """Check if the server is alive and responding (GET /health)."""
        try:
            resp = self._execute_request("GET", "/health", require_auth=False)
            return resp.get("status") == "ok"
        except Exception as exc:
            logger.debug("Server health check failed: %s", exc)
            return False

    def send_heartbeat(self, system_info: Dict[str, Any]) -> Dict[str, Any]:
        """Send endpoint heartbeat and current performance metrics (POST /api/v1/heartbeat)."""
        return self._execute_request(
            method="POST",
            path="/api/v1/heartbeat",
            payload=system_info,
            require_auth=True,
        )

    def send_system_telemetry(self, metrics_envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Send periodic historical system metrics (POST /api/v1/telemetry/system)."""
        return self._execute_request(
            method="POST",
            path="/api/v1/telemetry/system",
            payload=metrics_envelope,
            require_auth=True,
        )

    def send_process_snapshot(self, snapshot_envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Send complete process observation snapshot (POST /api/v1/telemetry/processes)."""
        return self._execute_request(
            method="POST",
            path="/api/v1/telemetry/processes",
            payload=snapshot_envelope,
            require_auth=True,
        )

    def send_file_baselines(self, baseline_envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Synchronize file integrity baselines (POST /api/v1/file-baselines)."""
        return self._execute_request(
            method="POST",
            path="/api/v1/file-baselines",
            payload=baseline_envelope,
            require_auth=True,
        )

    def send_security_event(self, event_envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Send security incident or detection event (POST /api/v1/events)."""
        return self._execute_request(
            method="POST",
            path="/api/v1/events",
            payload=event_envelope,
            require_auth=True,
        )
