# Mini EDR for Linux

An educational Mini Endpoint Detection and Response (EDR) system for monitoring Linux endpoints, detecting suspicious activity through explainable rules, and displaying security alerts in a centralized web dashboard.

> **Project status:** Phase 1 backend foundation is implemented. Linux Agent collection, detection rules, alert management, and dashboard pages are planned for subsequent phases.

## Objectives

- Collect basic Linux endpoint telemetry.
- Monitor running processes and system resource usage.
- Detect file changes in designated protected directories using SHA-256 hashes.
- Receive and validate Agent heartbeat data through a centralized Flask API.
- Store endpoint inventory and liveness state in SQLite.
- Add explainable detection rules and a web dashboard in later phases.

## Architecture

1. **Linux Agent:** Collects endpoint telemetry and reports it to the server.
2. **Flask API Server:** Authenticates Agents, receives and validates their data.
3. **Detection Engine:** Evaluates telemetry against configurable detection rules.
4. **SQLite Database and Web Dashboard:** Stores records and presents endpoints, events, and alerts.

## Technology Stack

- Python
- Flask
- SQLite (WAL mode)
- psutil
- HTML, CSS, and JavaScript
- pytest

## Setup

Use Python 3.10 or newer. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

Generate a token:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Put the generated value in `.env` as `EDR_API_TOKEN`. Never commit `.env` or share the token. `.env.example` is a template only; the server rejects authenticated API requests when no real token is configured.

The SQLite database is created automatically at `data/mini_edr.db`. Override it with `EDR_DATABASE_PATH` in `.env`. Relative database paths are resolved from the repository root.

## Run the server

```bash
python -m server.app
```

By default, Flask listens on `127.0.0.1:5000`, suitable when Agent and Server run on the same machine. To connect from another VM in an isolated lab, set `EDR_HOST=0.0.0.0`, restrict access with the VM network/firewall, and do not expose the development server directly to the Internet.

Health check (does not require an API token):

```bash
curl -i http://127.0.0.1:5000/health
```

## Phase 1 API

All `/api/v1/*` routes require this header:

```http
Authorization: Bearer <EDR_API_TOKEN>
```

### Submit an endpoint heartbeat

`POST /api/v1/heartbeat`

Content-Type: `application/json`

Example body:

```json
{
  "agent_id": "lab-linux-01",
  "hostname": "ubuntu-lab-01",
  "os": "Ubuntu 24.04",
  "ip_address": "192.0.2.10",
  "agent_version": "0.1.0",
  "metrics": {
    "cpu_percent": 25.5,
    "memory_percent": 52.4,
    "disk_percent": 60.0,
    "uptime_seconds": 7200
  }
}
```

The `agent_id`, `hostname`, and `os` fields are required. `ip_address` and `agent_version` are optional. CPU, memory, and disk percentages must be between 0 and 100. Uptime must be non-negative. Non-finite numbers (NaN and Infinity) are rejected. The server sets `last_seen` using its own UTC clock.

Example with curl (load variables from `.env` first using `set -a; source .env; set +a`):

```bash
curl -i -X POST http://127.0.0.1:5000/api/v1/heartbeat \
  -H "Authorization: Bearer $EDR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "lab-linux-01",
    "hostname": "ubuntu-lab-01",
    "os": "Ubuntu 24.04",
    "ip_address": "192.0.2.10",
    "agent_version": "0.1.0",
    "metrics": {
      "cpu_percent": 25.5,
      "memory_percent": 52.4,
      "disk_percent": 60.0,
      "uptime_seconds": 7200
    }
  }'
```

### List endpoints

`GET /api/v1/endpoints`

Returns endpoint inventory. The server marks an endpoint `offline` when its most recent heartbeat is older than `EDR_OFFLINE_AFTER_SECONDS` (default: 15 seconds). A new heartbeat changes it back to `online`.

### HTTP status codes

- `200`: Request accepted or health check succeeded.
- `400`: Invalid content type, JSON, required field, IP address, or metric.
- `401`: Missing or invalid Bearer token.
- `413`: Request body exceeds the 64 KiB limit.
- `500`: Unexpected database or server error; details are written to the server log, not returned to the client.

## Database behavior

Phase 1 creates the `endpoints` table and an index on `last_seen`. SQLite uses a 5-second connection timeout, a 5-second busy timeout, foreign-key enforcement, and WAL journal mode. Existing endpoint records are updated by `agent_id` rather than duplicated.

## Testing

Run the Phase 1 API test suite:

```bash
python -m pytest -q
```

Tests use a temporary SQLite database and a test-only API token. They do not require the developer's `.env` file or the production/local database.

## Scope and Limitations

This is an educational security project, not a production-grade EDR product.

- Detection is based on explicit rules, not machine learning.
- A file hash change is an indicator for investigation, not proof of malware.
- Initial development targets Linux endpoints.
- The current API token is a shared lab credential, not per-Agent identity or a full enrollment system.
- HTTPS, token rotation, role-based administrator authentication, process response, malware sandboxing, and production deployment are outside the Phase 1 scope.

## Security

- Never commit real credentials, API tokens, private keys, or sensitive telemetry.
- Use isolated lab environments for security testing.
- Keep the server bound to localhost unless cross-VM access is required.
- Do not expose Flask's built-in development server directly to the public Internet.

## License

License not yet selected.
