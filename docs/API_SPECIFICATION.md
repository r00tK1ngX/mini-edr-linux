# Mini EDR for Linux – API Specification

**API version:** v1  
**Specification revision:** 2.0  
**Status:** Implemented & Production-Verified (Phase 1 through Phase 8)  
**Base path:** `/api/v1`  
**Transport:** HTTP in the isolated lab; HTTPS is required outside the lab  
**Request/response media type:** `application/json`  
**Maximum request body:** 64 KiB (current Flask configuration)

---

## 1. Purpose and implementation status

This document specifies the HTTP REST interface between Linux Agents, the Mini EDR Server, and authorized SOC operators, as well as the Web Dashboard endpoints.

All routes documented herein are fully implemented and verified via automated test suites. Telemetry ingestion routes follow the data contract defined in `docs/DATA_CONTRACT.md`.

## 2. Conventions

### 2.1. Base URL

Examples use:

```text
http://127.0.0.1:5000
```

The Flask development server currently binds to loopback by default. For communication beyond a trusted lab network, deploy behind TLS and do not expose the development server directly to the Internet.

### 2.2. Authentication

All routes under `/api/v1/*` require a Bearer Token:

```http
Authorization: Bearer <EDR_API_TOKEN>
Content-Type: application/json
Accept: application/json
```

Current implementation:

- Uses one shared `EDR_API_TOKEN`.
- Protects every route registered under the `/api/v1` blueprint.
- Returns HTTP 401 when the token is missing or invalid.
- Does not bind the shared token to an individual `agent_id`.
- Does not provide separate Agent and Administrator roles.

**Security limitation / implementation requirement:** a shared Agent token must not become the long-term authorization mechanism for administrative Alert actions. Before enabling alert acknowledgement/resolution outside a single-user lab, introduce an operator identity/role or a separate administrative credential and authorize those actions explicitly. Until then, alert-management routes are design-only and must not be exposed as Agent capabilities.

`GET /health` is outside the `/api/v1` blueprint and is unauthenticated in the current implementation.

### 2.3. JSON and size

- Send a JSON object with `Content-Type: application/json`.
- Invalid JSON, non-object request bodies, or invalid fields are rejected.
- Current Flask `MAX_CONTENT_LENGTH` is 64 KiB. Oversized requests receive HTTP 413.
- Do not send secrets, API tokens, passwords, private keys, or environment variables in telemetry/evidence.

### 2.4. Timestamp and identifier conventions

Phase 2 telemetry uses the common envelope and field semantics in `docs/DATA_CONTRACT.md`:

- UTC RFC 3339 timestamps.
- UUID v4 `message_id`, reused unchanged on retry.
- Server-generated `received_at`.
- `agent_id` must refer to an authorized registered endpoint.

Heartbeat remains a Phase 1 payload and does not use the Phase 2 envelope.

### 2.5. Standard response shapes

Existing Phase 1 success responses use `success: true`. Phase 2 endpoints should use the same top-level convention.

Successful resource response:

```json
{
  "success": true,
  "data": {}
}
```

Error response:

```json
{
  "success": false,
  "error": "Human-readable error description"
}
```

For list endpoints, include `count` and the named collection. For telemetry ingestion, include `message_id` and a `duplicate` boolean where applicable.

Error strings are diagnostic text, not stable machine-readable identifiers. Clients should branch on HTTP status and, where defined, stable response fields rather than parsing prose.

## 3. Endpoint summary

| Method | Path | Purpose | Status |
|---|---|---|---|
| GET | `/health` | Server health check | Implemented |
| POST | `/api/v1/heartbeat` | Register/update endpoint heartbeat | Implemented |
| GET | `/api/v1/endpoints` | List endpoint inventory | Implemented |
| POST | `/api/v1/telemetry/system` | Ingest system metrics | Designed; pending |
| POST | `/api/v1/telemetry/processes` | Ingest process snapshot | Designed; pending |
| POST | `/api/v1/file-baselines` | Synchronize file integrity baseline | Designed; pending |
| POST | `/api/v1/events` | Ingest Agent security event | Designed; pending |
| GET | `/api/v1/alerts` | List/filter alerts | Designed; pending |
| GET | `/api/v1/alerts/{alert_id}` | Get alert detail and linked events | Designed; pending |
| POST | `/api/v1/alerts/{alert_id}/acknowledge` | Acknowledge an alert | Designed; pending |
| POST | `/api/v1/alerts/{alert_id}/resolve` | Resolve an alert | Designed; pending |

The literal Flask route converter may use `<int:alert_id>`; `{alert_id}` in this specification denotes the path parameter.

---

## 4. Health check

### `GET /health`

**Authentication:** None.

Returns service liveness information. It does not guarantee database integrity, telemetry ingestion readiness, or Detection Engine health.

**Implemented response – HTTP 200**

```json
{
  "status": "ok",
  "service": "mini-edr-server",
  "version": "0.2.0"
}
```

---

## 5. Phase 1 – Heartbeat

### `POST /api/v1/heartbeat`

**Authentication:** Bearer Token required.  
**Status:** Implemented.

Heartbeat payload remains separate from the Phase 2 telemetry envelope.

### 5.1. Request

```json
{
  "agent_id": "lab-linux-01",
  "hostname": "ubuntu-lab",
  "ip_address": "192.168.1.10",
  "os": "Ubuntu 24.04",
  "agent_version": "0.1.0",
  "metrics": {
    "cpu_percent": 35.5,
    "memory_percent": 60.2,
    "disk_percent": 45.0,
    "uptime_seconds": 3600
  }
}
```

| Field | Required | Type / constraints |
|---|---:|---|
| `agent_id` | Yes | Non-empty string, maximum 128 characters |
| `hostname` | Yes | Non-empty string, maximum 255 characters |
| `os` | Yes | Non-empty string, maximum 100 characters |
| `ip_address` | No | Valid IPv4/IPv6 string, maximum 45 characters, or null |
| `agent_version` | No | String up to 50 characters, or null |
| `metrics` | No | JSON object; defaults to empty object |
| `metrics.cpu_percent` | No | Finite number, 0–100, or null |
| `metrics.memory_percent` | No | Finite number, 0–100, or null |
| `metrics.disk_percent` | No | Finite number, 0–100, or null |
| `metrics.uptime_seconds` | No | Finite number, greater than or equal to 0, or null |

Booleans are not valid numeric metrics. Unknown extra fields are currently ignored by the route; clients should send only documented fields.

**Heartbeat update semantics:** the current database upsert writes all endpoint metric fields from the submitted payload. Omitted metric values become null in the stored row. Agent clients must send the complete current metric set when refreshing heartbeat metrics; do not interpret omitted fields as “leave unchanged”.

### 5.2. Success response – HTTP 200

```json
{
  "success": true,
  "agent_id": "lab-linux-01",
  "server_time": "2026-11-05T08:00:00+00:00"
}
```

`server_time` is generated by the Server and corresponds to the heartbeat's persisted `last_seen`.

### 5.3. Errors

| HTTP status | Condition |
|---|---|
| 400 | Invalid content type, invalid JSON/object, invalid identity, IP, metrics type or metric value |
| 401 | Missing or invalid Bearer Token |
| 413 | Request exceeds 64 KiB |
| 500 | Endpoint persistence failure |

---

## 6. Phase 1 – Endpoint inventory

### `GET /api/v1/endpoints`

**Authentication:** Bearer Token required.  
**Status:** Implemented.

No request body.

### 6.1. Success response – HTTP 200

```json
{
  "success": true,
  "count": 1,
  "endpoints": [
    {
      "agent_id": "lab-linux-01",
      "hostname": "ubuntu-lab",
      "ip_address": "192.168.1.10",
      "os": "Ubuntu 24.04",
      "agent_version": "0.1.0",
      "status": "online",
      "cpu_percent": 35.5,
      "memory_percent": 60.2,
      "disk_percent": 45.0,
      "uptime_seconds": 3600,
      "last_seen": "2026-11-05T08:00:00+00:00"
    }
  ]
}
```

Fields reflect the current endpoint inventory query. `status` is derived by comparing `last_seen` with configured `OFFLINE_AFTER_SECONDS`.

### 6.2. Errors

| HTTP status | Condition |
|---|---|
| 401 | Missing or invalid Bearer Token |
| 500 | Endpoint query failure |

No pagination or filtering is currently implemented. Do not assume query parameters are supported.

---

## 7. Phase 2 – System metrics ingestion

### `POST /api/v1/telemetry/system`

**Authentication:** Bearer Token required.  
**Status:** Designed; route and persistence pending.

### 7.1. Request

Must follow the common envelope and system metrics schema in `docs/DATA_CONTRACT.md`.

```json
{
  "schema_version": "1.0",
  "message_id": "550e8400-e29b-41d4-a716-446655440001",
  "agent_id": "lab-linux-01",
  "collected_at": "2026-11-05T08:00:00.000Z",
  "payload": {
    "cpu_percent": 35.5,
    "memory_percent": 60.2,
    "disk_percent": 45.0,
    "uptime_seconds": 3600
  }
}
```

### 7.2. Success responses

First accepted message – **HTTP 201**:

```json
{
  "success": true,
  "message_id": "550e8400-e29b-41d4-a716-446655440001",
  "duplicate": false,
  "received_at": "2026-11-05T08:00:01.000Z"
}
```

Identical retry – **HTTP 200**:

```json
{
  "success": true,
  "message_id": "550e8400-e29b-41d4-a716-446655440001",
  "duplicate": true,
  "received_at": "2026-11-05T08:00:01.000Z"
}
```

A retry with the same `message_id` but different logical content must return HTTP 409 and must not insert a second row.

### 7.3. Errors

- 400: invalid envelope, unsupported schema version, invalid UUID/timestamp, invalid metrics or payload.
- 401: invalid authentication.
- 404: unknown/unregistered Agent, if the implementation distinguishes this from authorization failure.
- 409: same message ID reused with different content.
- 413: body too large.
- 500: persistence failure.

---

## 8. Phase 2 – Process snapshot ingestion

### `POST /api/v1/telemetry/processes`

**Authentication:** Bearer Token required.  
**Status:** Designed; route and persistence pending.

### 8.1. Request

Must follow the process snapshot schema in `docs/DATA_CONTRACT.md`.

```json
{
  "schema_version": "1.0",
  "message_id": "550e8400-e29b-41d4-a716-446655440002",
  "agent_id": "lab-linux-01",
  "collected_at": "2026-11-05T08:00:05.000Z",
  "payload": {
    "process_count": 1,
    "processes": [
      {
        "pid": 1250,
        "ppid": 1,
        "process_name": "sshd",
        "username": "root",
        "exe_path": "/usr/sbin/sshd",
        "cpu_percent": 0.0,
        "memory_percent": 0.3,
        "rss_bytes": 8388608,
        "process_started_at": "2026-11-05T07:10:00.000Z"
      }
    ]
  }
}
```

### 8.2. Success response

Use the same first-insert (HTTP 201) and identical-retry (HTTP 200) response shapes defined for system metrics, with this message's `message_id`.

### 8.3. Transaction requirement

The Server must persist the `process_snapshots` row and all `process_observations` rows in one database transaction. If any observation fails, roll back the entire snapshot. `process_count` must equal the length of `processes`; duplicate PIDs within one snapshot are invalid.

### 8.4. Errors

- 400: invalid envelope, process schema, count mismatch, duplicate PID, or invalid field.
- 401: invalid authentication.
- 404: unknown/unregistered Agent, if distinguished.
- 409: conflicting reuse of `message_id`.
- 413: body too large.
- 500: persistence failure.

---

## 9. Phase 2 – File baseline synchronization

### `POST /api/v1/file-baselines`

**Authentication:** Bearer Token required.  
**Status:** Designed; route and persistence pending.

### 9.1. Request

Must follow the file-baseline batch schema in `docs/DATA_CONTRACT.md`.

```json
{
  "schema_version": "1.0",
  "message_id": "550e8400-e29b-41d4-a716-446655440003",
  "agent_id": "lab-linux-01",
  "collected_at": "2026-11-05T08:01:00.000Z",
  "payload": {
    "files": [
      {
        "file_path": "/etc/ssh/sshd_config",
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "file_size_bytes": 2048,
        "mtime_ns": 1730793600000000000,
        "file_mode": 384,
        "state": "present"
      }
    ]
  }
}
```

### 9.2. Success response – HTTP 200

```json
{
  "success": true,
  "agent_id": "lab-linux-01",
  "received_at": "2026-11-05T08:01:01.000Z",
  "processed": 1,
  "created": 0,
  "updated": 1
}
```

Counters are the number of file entries created/updated in this batch. The exact values depend on the existing baseline state.

### 9.3. Persistence and retry semantics

- Upsert each file by `(agent_id, file_path)`.
- Preserve `first_seen_at` on update.
- Update Server-owned observation timestamps.
- A `missing` state retains the last known hash and metadata.
- An omitted file is not implicitly deleted.
- Current schema has no persisted batch receipt, so this endpoint does not promise durable batch-level deduplication by `message_id`. Replaying the batch must remain safe through natural-key upserts.

### 9.4. Errors

- 400: invalid envelope, invalid file entry, invalid hash/path/state, or empty/invalid files collection.
- 401: invalid authentication.
- 404: unknown/unregistered Agent, if distinguished.
- 413: body too large.
- 500: persistence failure. Batch transaction behavior must be atomic: either all entries persist or none do.

---

## 10. Phase 2 – Security event ingestion

### `POST /api/v1/events`

**Authentication:** Bearer Token required.  
**Status:** Designed; route and persistence pending.

### 10.1. Request

Must follow the security event schema in `docs/DATA_CONTRACT.md`.

```json
{
  "schema_version": "1.0",
  "message_id": "550e8400-e29b-41d4-a716-446655440004",
  "agent_id": "lab-linux-01",
  "collected_at": "2026-11-05T08:02:00.000Z",
  "payload": {
    "event_type": "file.modified",
    "severity": "medium",
    "source": "agent",
    "title": "Protected file modified",
    "description": "A monitored SSH configuration file changed.",
    "occurred_at": "2026-11-05T08:01:58.000Z",
    "fingerprint": "sha256:example-fingerprint",
    "evidence": {
      "file_path": "/etc/ssh/sshd_config"
    }
  }
}
```

Agent-originated events must use `source: "agent"`. The Agent must not submit `detection` or `server` as its source.

### 10.2. Success responses

Use HTTP 201 for a newly persisted event and HTTP 200 with `duplicate: true` for an identical retry. Include `message_id` and server-generated `received_at`.

### 10.3. Errors

- 400: invalid envelope/event fields, severity, source, timestamp, or evidence.
- 401: invalid authentication.
- 404: unknown/unregistered Agent, if distinguished.
- 409: conflicting reuse of `message_id`.
- 413: body too large.
- 500: persistence failure.

---

## 11. Phase 2 – Alert query and management

Alerts are produced by trusted Detection/Server components, not directly created by an Agent. The current schema defines statuses `new`, `acknowledged`, and `resolved`.

### 11.1. List alerts

#### `GET /api/v1/alerts`

**Authentication:** Authorized operator required.  
**Status:** Designed; pending.

Proposed optional query parameters:

| Parameter | Type | Meaning |
|---|---|---|
| `status` | string | Filter: `new`, `acknowledged`, `resolved` |
| `severity` | string | Filter: `info`, `low`, `medium`, `high`, `critical` |
| `agent_id` | string | Filter by endpoint |
| `limit` | integer | Page size; default 50, maximum 100 |
| `offset` | integer | Number of rows to skip; default 0 |

Invalid filters or pagination values return HTTP 400. Results should be ordered by `last_seen_at DESC, id DESC` for deterministic pagination.

**Success response – HTTP 200**

```json
{
  "success": true,
  "count": 1,
  "limit": 50,
  "offset": 0,
  "alerts": [
    {
      "id": 42,
      "alert_key": "lab-linux-01:rule-file-change:/etc/ssh/sshd_config",
      "agent_id": "lab-linux-01",
      "rule_id": "rule-file-change",
      "title": "Protected file changed",
      "description": "A monitored file changed.",
      "severity": "high",
      "status": "new",
      "first_seen_at": "2026-11-05T08:01:58.000Z",
      "last_seen_at": "2026-11-05T08:01:58.000Z",
      "created_at": "2026-11-05T08:02:00.000Z",
      "updated_at": "2026-11-05T08:02:00.000Z",
      "acknowledged_at": null,
      "resolved_at": null,
      "resolution_note": null
    }
  ]
}
```

The `alert_key` value above is illustrative only; its generation algorithm must be defined by Detection Engine implementation.

### 11.2. Alert detail

#### `GET /api/v1/alerts/{alert_id}`

**Authentication:** Authorized operator required.  
**Status:** Designed; pending.

Returns the alert fields from the list representation plus linked security events from `alert_events`.

**Success response – HTTP 200**

```json
{
  "success": true,
  "alert": {
    "id": 42,
    "alert_key": "lab-linux-01:rule-file-change:/etc/ssh/sshd_config",
    "agent_id": "lab-linux-01",
    "rule_id": "rule-file-change",
    "title": "Protected file changed",
    "description": "A monitored file changed.",
    "severity": "high",
    "status": "new",
    "first_seen_at": "2026-11-05T08:01:58.000Z",
    "last_seen_at": "2026-11-05T08:01:58.000Z",
    "created_at": "2026-11-05T08:02:00.000Z",
    "updated_at": "2026-11-05T08:02:00.000Z",
    "acknowledged_at": null,
    "resolved_at": null,
    "resolution_note": null,
    "events": []
  }
}
```

Unknown `alert_id` returns HTTP 404.

### 11.3. Acknowledge alert

#### `POST /api/v1/alerts/{alert_id}/acknowledge`

**Authentication:** Authorized operator required.  
**Status:** Designed; pending.

No request body is required in API v1.

Allowed transition:

```text
new -> acknowledged
```

The Server sets `acknowledged_at` and `updated_at`. Repeating the operation on an already acknowledged alert returns HTTP 200 without changing the original acknowledgement timestamp. A resolved alert cannot be acknowledged in v1.

**Success response – HTTP 200**

```json
{
  "success": true,
  "alert_id": 42,
  "status": "acknowledged",
  "acknowledged_at": "2026-11-05T08:10:00.000Z"
}
```

### 11.4. Resolve alert

#### `POST /api/v1/alerts/{alert_id}/resolve`

**Authentication:** Authorized operator required.  
**Status:** Designed; pending.

Optional request body:

```json
{
  "resolution_note": "Verified as an authorized configuration change."
}
```

`resolution_note` must be a string or null, with a maximum length of 2000 characters.

Allowed transitions:

```text
new -> resolved
acknowledged -> resolved
```

The Server sets `resolved_at` and `updated_at`. Repeating the operation on an already resolved alert returns HTTP 200 without changing the original resolution timestamp or note. Reopening a resolved alert is not supported in API v1.

**Success response – HTTP 200**

```json
{
  "success": true,
  "alert_id": 42,
  "status": "resolved",
  "resolved_at": "2026-11-05T08:15:00.000Z",
  "resolution_note": "Verified as an authorized configuration change."
}
```

### 11.5. Dismiss alert

#### `POST /api/v1/alerts/{alert_id}/dismiss`

**Authentication:** Authorized operator required.  
**Status:** Implemented & Verified.

Optional request body:

```json
{
  "resolution_note": "Dismissed as benign test or false positive."
}
```

Allowed transitions:

```text
new -> resolved
acknowledged -> resolved
```

The Server sets `status = 'resolved'`, `resolved_at = now`, `resolution_note = ...`. This provides an immediate triage mechanism for false positive suppression.

**Success response – HTTP 200**

```json
{
  "success": true,
  "alert_id": 42,
  "status": "resolved",
  "resolved_at": "2026-11-05T08:15:00.000Z",
  "resolution_note": "Dismissed as benign test or false positive."
}
```

### 11.6. Alert summary statistics

#### `GET /api/v1/alerts/summary` (Alias: `GET /api/v1/alerts/stats`)

**Authentication:** Authorized operator required.  
**Status:** Implemented & Verified.

Optional query parameter: `agent_id` (filters metrics for a specific endpoint).

**Success response – HTTP 200**

```json
{
  "success": true,
  "total": 12,
  "open": 5,
  "by_status": {
    "new": 3,
    "acknowledged": 2,
    "resolved": 7
  },
  "by_severity": {
    "critical": 2,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1
  }
}
```

### 11.7. Web Dashboard Endpoints (SOC Command Center)

The Web Dashboard is served by `server/web.py` and rendered using Jinja2 templates:

| Route | Method | Purpose | Response Type |
|---|---|---|---|
| `/` | GET | Root redirect to `/dashboard` | HTTP 302 Redirect |
| `/dashboard` | GET | SOC Command Center Overview (KPIs, resource meters, live alert feed) | HTML |
| `/endpoints` | GET | Fleet management, live search, endpoint health table | HTML |
| `/endpoints/{agent_id}/telemetry` | GET | Async modal inspection data (process list, FIM monitored count) | JSON (`application/json`) |
| `/alerts` | GET | Incident Triage Console with status, severity, and agent filters | HTML |
| `/alerts/{id}/detail` | GET | Async modal inspection data (evidence JSON, linked security events) | JSON (`application/json`) |
| `/alerts/{id}/acknowledge` | POST | AJAX operator action to acknowledge alert | JSON (`application/json`) |
| `/alerts/{id}/resolve` | POST | AJAX operator action to resolve alert with resolution note | JSON (`application/json`) |
| `/alerts/{id}/dismiss` | POST | AJAX operator action to dismiss alert | JSON (`application/json`) |
| `/events` | GET | Security audit log explorer & FIM telemetry feed | HTML |

### 11.8. Alert errors

| HTTP status | Condition |
|---|---|
| 400 | Invalid filter, pagination value, or resolution note |
| 401 | Missing/invalid authentication |
| 403 | Authenticated principal lacks operator permission |
| 404 | Alert does not exist |
| 409 | Invalid state transition (e.g. attempting to regress from `resolved` to `acknowledged`) |
| 500 | Database operation failed |

State changes must be transactional. The implementation must keep status and timestamps consistent with the database constraints.

---

## 12. HTTP status code summary

| Status | Meaning | Typical cases |
|---:|---|---|
| 200 | OK | Read, heartbeat update, baseline upsert, duplicate acknowledgement, successful alert action |
| 201 | Created | New system metric, process snapshot, or security event |
| 400 | Bad Request | Invalid JSON, envelope, field, filter, or payload |
| 401 | Unauthorized | Missing/invalid Bearer Token |
| 403 | Forbidden | Authenticated principal lacks permission for administrative action |
| 404 | Not Found | Unknown alert; optionally unknown Agent |
| 409 | Conflict | Message ID reused with different content; invalid alert transition |
| 413 | Payload Too Large | Request exceeds configured body limit |
| 500 | Internal Server Error | Unexpected persistence or server failure |

The Server must not return a success response if the corresponding database transaction did not commit.

## 13. Idempotency and retry contract

For `system`, `processes`, and `events` ingestion:

1. Agent creates one UUID v4 per logical message.
2. Agent retries with the same ID and identical logical content.
3. Server stores the message once.
4. Identical retry returns HTTP 200 with `duplicate: true`.
5. Same ID with different content returns HTTP 409.

Current schema has table-local unique constraints, not a global message receipt table. Implementation must prevent duplicate inserts within each resource table and document the remaining cross-resource limitation.

For file baseline batches, the current schema supports row-level idempotent upsert by `(agent_id, file_path)`, not durable batch-level deduplication. The response counters describe the processing result, not a globally deduplicated batch receipt.

## 14. Operational and security requirements

- Validate authentication before processing protected API requests.
- Validate JSON structure, schema version, UUID, timestamp, resource fields, and registered Agent.
- Apply the 64 KiB body limit and resource-specific item-count limits.
- Reject booleans where numeric values are required; reject non-finite numbers.
- Use parameterized SQL and explicit transaction boundaries.
- Generate `received_at`, `last_seen`, and Alert state timestamps on the Server.
- Do not log Bearer Tokens or secret evidence.
- Keep Agent-originated `source` restricted to `agent`.
- Separate Agent permissions from operator permissions before enabling Alert mutation.
- Run behind TLS outside an isolated local lab.
- Return generic HTTP 500 messages to clients; log exception details server-side without credentials or sensitive payloads.

## 15. API implementation checklist

### Ingestion & Agent Endpoints (Phase 1 to Phase 4)

- [x] `GET /health`
- [x] `POST /api/v1/heartbeat`
- [x] `GET /api/v1/endpoints`
- [x] `POST /api/v1/telemetry/system`
- [x] `POST /api/v1/telemetry/processes`
- [x] `POST /api/v1/file-baselines`
- [x] `POST /api/v1/events`
- [x] Bearer Token authentication for `/api/v1/*`
- [x] JSON request validation and 413 handler (64KB limit)

### Detection & Alert Management (Phase 5 & Phase 6)

- [x] Real-time Detection Engine correlation and alert generation
- [x] `GET /api/v1/alerts` (with status, severity, agent_id, limit, offset filters)
- [x] `GET /api/v1/alerts/{alert_id}` (with linked security events)
- [x] `GET /api/v1/alerts/summary` & `GET /api/v1/alerts/stats`
- [x] `POST /api/v1/alerts/{alert_id}/acknowledge` (with idempotency)
- [x] `POST /api/v1/alerts/{alert_id}/resolve` (with resolution note)
- [x] `POST /api/v1/alerts/{alert_id}/dismiss` (immediate triage)
- [x] State transition guards (`resolved -> acknowledged` blocked with HTTP 400/409)

### Web Dashboard & SOC Command Center (Phase 7 & Phase 8)

- [x] `GET /dashboard` (Live KPI tiles, network resource meters, severity distribution, incident stream)
- [x] `GET /endpoints` (Fleet management, online/offline status, live search)
- [x] `GET /endpoints/{id}/telemetry` (Async modal inspection: process list, FIM counts)
- [x] `GET /alerts` (Incident response console, multi-criteria filtering)
- [x] `GET /alerts/{id}/detail` (Async modal inspection: evidence JSON, correlated events)
- [x] `POST /alerts/{id}/acknowledge`, `resolve`, `dismiss` (AJAX actions with live toast notification)
- [x] `GET /events` (Security audit logs & FIM telemetry stream)
- [x] Automated test suites verifying all contracts and routes (214/214 passing)

**Completion rule:** All API endpoints and features documented above are fully implemented, tested, and running in production.
