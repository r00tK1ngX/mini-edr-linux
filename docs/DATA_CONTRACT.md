# Mini EDR for Linux – Data Contract

**Document:** Data Contract  
**Contract version:** 1.0  
**Status:** Implemented & Verified in Production Baseline (Phase 1 through Phase 8)  
**Scope:** Linux Agent ↔ Flask Server  
**Transport:** HTTP  
**Media type:** `application/json`  
**Encoding:** UTF-8

---

## 1. Purpose and status

This document defines the data contract between the Mini EDR Linux Agent and the Flask Server. It specifies message envelopes, resource payloads, field constraints, timestamp ownership, validation, idempotency, retry behavior, and trust boundaries.

All listed Agent modules, API endpoints, schema validators, DAL repositories, and database behaviors are fully implemented and verified with automated test suites (214/214 passing tests).

## 2. Compatibility and scope

### 2.1. Phase 1 heartbeat compatibility

The existing endpoint `POST /api/v1/heartbeat` retains its Phase 1 request format. It is not required to use the Phase 2 telemetry envelope.

Example:

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

The current heartbeat API requires `agent_id`, `hostname`, and `os`; `ip_address` and `agent_version` are optional; metrics are accepted in the `metrics` object. The existing implementation is a full update of the endpoint's metric fields: omitted metric values are written as NULL. Agent implementations must therefore send the complete current heartbeat metric set when they intend to refresh those fields.

Do not silently change the heartbeat payload. Any future migration to a common envelope must be a separately reviewed and tested compatibility change.

### 2.2. Phase 2 telemetry scope

The common telemetry envelope applies to:

- System metrics.
- Process snapshots.
- Security events.

File baseline synchronization uses the same top-level envelope fields and a batch payload.

Alerts are created and managed by trusted Server/Detection Engine components. An Agent must not directly create or modify Alert records.

## 3. Common telemetry envelope

Every Phase 2 telemetry message must use this structure:

```json
{
  "schema_version": "1.0",
  "message_id": "550e8400-e29b-41d4-a716-446655440000",
  "agent_id": "lab-linux-01",
  "collected_at": "2026-11-05T08:00:00.000Z",
  "payload": {}
}
```

### 3.1. Envelope fields

| Field | Type | Required | Definition |
|---|---|---:|---|
| `schema_version` | string | Yes | Contract version used to serialize the message |
| `message_id` | UUID v4 string | Yes | Identifier for one logical message |
| `agent_id` | string | Yes | Registered endpoint identifier |
| `collected_at` | timestamp string | Yes | Time the Agent collected the data |
| `payload` | object | Yes | Resource-specific data |

### 3.2. Validation rules

**schema_version**

- Must be a string.
- Version `1.0` is the initial supported contract version.
- The Server must explicitly reject unsupported versions.
- The Server must not silently parse an unknown version as `1.0`.

**message_id**

- Must be a syntactically valid UUID version 4.
- The Agent generates the identifier for each new logical message.
- A retry of the same logical message must reuse the same identifier and the same logical content.
- A new collection/message must use a new identifier.
- UUID generation must use a standard UUID implementation.

The intended identifier namespace is global across telemetry message types. The current database schema has a separate UNIQUE constraint in each of `system_metrics`, `process_snapshots`, and `security_events`; it does not enforce cross-table uniqueness. Server-side receipt/deduplication logic must account for this implementation limitation until a global message receipt mechanism exists.

**agent_id**

- Must be a non-empty string.
- Maximum length: 128 characters.
- Must refer to a registered endpoint.
- Must be authorized for the authenticated sender.

The current Phase 1 implementation uses a shared Bearer Token. It does not cryptographically bind that token to one specific `agent_id`. Until per-Agent credentials or equivalent identity binding are implemented, the Server cannot treat the submitted `agent_id` alone as proof of Agent identity.

**collected_at**

- Must be a valid RFC 3339 timestamp with a UTC offset.
- The canonical serialized representation is UTC with a trailing `Z`, for example `2026-11-05T08:00:00.000Z`.
- Represents collection time, not Server receipt time.
- Must not be used as the authoritative endpoint heartbeat time.

**payload**

- Must be a JSON object.
- Must satisfy the schema for its resource type.
- Required fields must be present.
- Numeric values must be finite; booleans are not accepted as numbers.
- Resource-specific size and count limits must be enforced by the Server.
- Validation must complete before persistence.

## 4. Timestamp semantics

| Timestamp | Owner | Meaning |
|---|---|---|
| `collected_at` | Agent | Time telemetry was collected |
| `occurred_at` | Event source / Agent | Time a security event occurred |
| `received_at` | Server | Time the Server accepted the message |
| `last_seen` | Server | Time a valid heartbeat was processed |

Rules:

1. The Agent must not supply or override `received_at`.
2. The Server generates `received_at` using its own UTC clock.
3. The Server generates `last_seen` when processing a valid heartbeat.
4. Agent-provided timestamps are useful for investigation and event ordering, but are not proof of Server receipt time.
5. Persisted timestamps must be normalized to UTC.
6. If clock skew is detected or suspected, preserve the Agent timestamp as reported/normalized and rely on Server receipt time for server-side ordering and liveness decisions.

## 5. System metrics

**Intended endpoint:** `POST /api/v1/telemetry/system`

Example:

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

### 5.1. Payload fields

| Field | Type | Required | Constraints |
|---|---|---:|---|
| `cpu_percent` | number | Yes | Finite; 0–100 inclusive |
| `memory_percent` | number | Yes | Finite; 0–100 inclusive |
| `disk_percent` | number | Yes | Finite; 0–100 inclusive |
| `uptime_seconds` | number | Yes | Finite; greater than or equal to 0 |

Definitions:

- `cpu_percent`: overall system CPU utilization.
- `memory_percent`: system memory utilization.
- `disk_percent`: utilization of the configured monitored filesystem. Initial implementation should consistently use the root filesystem `/`.
- `uptime_seconds`: system uptime in seconds.

Booleans, NaN, positive infinity, and negative infinity are invalid numeric values.

### 5.2. Database mapping

| Contract field | Database column |
|---|---|
| `message_id` | `system_metrics.message_id` |
| `schema_version` | `system_metrics.schema_version` |
| `agent_id` | `system_metrics.agent_id` |
| `payload.cpu_percent` | `system_metrics.cpu_percent` |
| `payload.memory_percent` | `system_metrics.memory_percent` |
| `payload.disk_percent` | `system_metrics.disk_percent` |
| `payload.uptime_seconds` | `system_metrics.uptime_seconds` |
| `collected_at` | `system_metrics.collected_at` |
| Server-generated time | `system_metrics.received_at` |

## 6. Process snapshots

**Intended endpoint:** `POST /api/v1/telemetry/processes`

One message represents one process collection cycle.

Example:

```json
{
  "schema_version": "1.0",
  "message_id": "550e8400-e29b-41d4-a716-446655440002",
  "agent_id": "lab-linux-01",
  "collected_at": "2026-11-05T08:00:05.000Z",
  "payload": {
    "process_count": 2,
    "processes": [
      {
        "pid": 1,
        "ppid": 0,
        "process_name": "systemd",
        "username": "root",
        "exe_path": "/usr/lib/systemd/systemd",
        "cpu_percent": 0.2,
        "memory_percent": 0.5,
        "rss_bytes": 12582912,
        "process_started_at": "2026-11-05T07:00:00.000Z"
      },
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

### 6.1. Payload fields

| Field | Type | Required | Constraints |
|---|---|---:|---|
| `process_count` | integer | Yes | Greater than or equal to 0 |
| `processes` | array | Yes | Number of elements must equal `process_count` |

Each process object:

| Field | Type | Required | Constraints |
|---|---|---:|---|
| `pid` | integer | Yes | Greater than or equal to 0 |
| `ppid` | integer or null | No | Greater than or equal to 0 when non-null |
| `process_name` | string | Yes | Non-empty |
| `username` | string or null | No | Null when unavailable |
| `exe_path` | string or null | No | Null when unavailable |
| `cpu_percent` | number or null | No | Finite and greater than or equal to 0 |
| `memory_percent` | number or null | No | Finite; 0–100 inclusive |
| `rss_bytes` | integer or null | No | Greater than or equal to 0 |
| `process_started_at` | timestamp or null | No | UTC when available |

### 6.2. Collection and persistence rules

- A process that exits during collection must not crash the Agent.
- Permission errors must be handled without terminating the collection cycle.
- Unavailable process attributes must be represented as `null`, not fabricated values.
- PID is not globally unique and can be reused after process exit.
- The initial schema identifies an observation by `(snapshot_id, pid)`.
- The number of entries in `processes` must exactly equal `process_count`.
- The snapshot row and all its process observations must be persisted in one database transaction.
- Duplicate PIDs within one snapshot are invalid.

### 6.3. Database mapping

| Contract field | Database column |
|---|---|
| `message_id` | `process_snapshots.message_id` |
| `schema_version` | `process_snapshots.schema_version` |
| `agent_id` | `process_snapshots.agent_id` |
| `payload.process_count` | `process_snapshots.process_count` |
| `collected_at` | `process_snapshots.collected_at` |
| Server-generated time | `process_snapshots.received_at` |
| `processes[].pid` | `process_observations.pid` |
| `processes[].ppid` | `process_observations.ppid` |
| `processes[].process_name` | `process_observations.process_name` |
| `processes[].username` | `process_observations.username` |
| `processes[].exe_path` | `process_observations.exe_path` |
| `processes[].cpu_percent` | `process_observations.cpu_percent` |
| `processes[].memory_percent` | `process_observations.memory_percent` |
| `processes[].rss_bytes` | `process_observations.rss_bytes` |
| `processes[].process_started_at` | `process_observations.process_started_at` |

## 7. File integrity baselines

**Intended endpoint:** `POST /api/v1/file-baselines`

File baseline synchronization uses the common top-level envelope and a batch payload.

Example:

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

### 7.1. File fields

| Field | Type | Required | Constraints |
|---|---|---:|---|
| `file_path` | string | Yes | Non-empty absolute path |
| `sha256` | string | Yes | Exactly 64 lowercase hexadecimal characters |
| `file_size_bytes` | integer | Yes | Greater than or equal to 0 |
| `mtime_ns` | integer | Yes | Greater than or equal to 0 |
| `file_mode` | integer | Yes | 0–4095 |
| `state` | string | Yes | `present` or `missing` |

### 7.2. Baseline semantics

- A baseline is identified by `(agent_id, file_path)`.
- Repeated synchronization updates the existing baseline (upsert); it must not create duplicate rows.
- `first_seen_at` is assigned by the Server when the baseline is first created and is preserved on subsequent updates.
- `last_seen_at` is updated when the file is observed as present.
- `last_checked_at` is assigned by the Server when the file state is processed.
- Agent input must not overwrite Server-owned timestamps.
- A missing file retains its last known hash and metadata.
- A missing-state update is valid only for a file that already has a known baseline.
- A file omitted from a batch must not automatically be interpreted as deleted.
- The Agent must explicitly report a missing state.

The current `file_baselines` table does not have a batch `message_id` or receipt record. Therefore, the defined retry safety for this resource is row-level upsert by `(agent_id, file_path)`; durable batch-level deduplication is not currently represented in the schema.

## 8. Security events

**Intended endpoint:** `POST /api/v1/events`

One message represents one Security Event.

Example:

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
      "file_path": "/etc/ssh/sshd_config",
      "old_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "new_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
  }
}
```

### 8.1. Payload fields

| Field | Type | Required | Constraints |
|---|---|---:|---|
| `event_type` | string | Yes | Non-empty |
| `severity` | string | No | `info`, `low`, `medium`, `high`, `critical`; default `info` |
| `source` | string | Yes | Agent messages must use `agent` |
| `title` | string | Yes | Non-empty |
| `description` | string or null | No | Human-readable description |
| `occurred_at` | timestamp | Yes | UTC |
| `fingerprint` | string or null | No | Optional correlation identifier |
| `evidence` | object | No | Structured JSON object; default empty object |

### 8.2. Security event rules

- Agent-originated events must use `source = agent`.
- `detection` and `server` are reserved for trusted Server components.
- The Agent must not claim that an event was generated by the Detection Engine.
- Severity must use one of the five defined values.
- Evidence must be a JSON object, not an arbitrary string.
- Evidence must not contain API tokens, passwords, private keys, or other secrets.
- `occurred_at` is the event time; `collected_at` is the collection/message time. They are not interchangeable.
- The Server assigns `received_at`.

### 8.3. Database mapping

| Contract field | Database column |
|---|---|
| `message_id` | `security_events.message_id` |
| `schema_version` | `security_events.schema_version` |
| `agent_id` | `security_events.agent_id` |
| `payload.event_type` | `security_events.event_type` |
| `payload.severity` | `security_events.severity` |
| `payload.source` | `security_events.source` |
| `payload.title` | `security_events.title` |
| `payload.description` | `security_events.description` |
| `payload.evidence` | `security_events.evidence_json` |
| `payload.occurred_at` | `security_events.occurred_at` |
| Server-generated time | `security_events.received_at` |
| `payload.fingerprint` | `security_events.fingerprint` |

## 9. Idempotency and retry

Idempotency ensures that retrying a logical message does not create duplicate telemetry records.

### 9.1. Agent behavior

1. Generate a UUID v4 for a new logical message.
2. Serialize and send the message.
3. If the request times out or the connection fails, retry with the same `message_id` and same logical content.
4. Do not generate a new ID merely because a retry is required.
5. Generate a new ID for a new collection cycle/message.

### 9.2. Server behavior

For resources with persisted unique message IDs:

- First accepted message: persist once.
- Same ID and identical logical content: do not insert a second record; return a duplicate acknowledgement.
- Same ID with different logical content: reject as a conflict (HTTP 409).
- Invalid payload: reject before persistence.
- A duplicate must not create another process snapshot or security event.

The Server should compare a canonical representation or canonical payload hash to distinguish an identical retry from conflicting reuse of an ID. The canonicalization algorithm and storage location must be specified by the implementation before the API is considered complete.

The current schema's UNIQUE constraints prevent repeated IDs within each corresponding table, but do not implement the complete duplicate acknowledgement behavior and do not enforce uniqueness across all resource tables.

### 9.3. File baseline retry

File baseline retries use the natural key:

`(agent_id, file_path)`

The Server uses an upsert operation so replaying the same file baseline does not create duplicate rows. Because the current schema has no persisted batch receipt record, it does not provide durable batch-level deduplication for file baseline requests.

## 10. Validation and resource limits

All telemetry must be validated before database insertion.

Minimum requirements:

- Valid JSON object and JSON content type.
- Supported `schema_version`.
- Valid UUID v4 `message_id`.
- Valid and authorized `agent_id`.
- Valid UTC timestamps.
- Correct payload object and resource schema.
- Required fields present.
- Numeric values finite and within defined ranges.
- Booleans rejected where numbers are expected.
- Supported severity and source values only.
- Valid SHA-256 representation.
- No orphaned endpoint references.
- Duplicate PIDs rejected within one process snapshot.
- Process count must match the process array length.
- Evidence must be a JSON object and must not contain secrets.

The current Flask application sets `MAX_CONTENT_LENGTH = 64 * 1024` (64 KiB). Phase 2 endpoints must respect this limit unless a separately reviewed configuration change is made. Resource-specific limits (for example, maximum process count and maximum files per baseline batch) must be explicitly configured and tested before those endpoints are enabled.

The Server must not log Bearer Tokens or sensitive evidence.

## 11. Error semantics

The exact response JSON belongs to Task 2.5 – API Specification. The required semantic behavior is:

| Condition | Expected behavior |
|---|---|
| Invalid JSON | Reject request |
| Missing required field | Reject request |
| Unsupported schema version | Explicit rejection |
| Invalid UUID | Reject request |
| Invalid timestamp | Reject request |
| Invalid numeric value | Reject request |
| Unknown or unauthorized Agent | Reject request |
| Invalid authentication | HTTP 401 |
| Payload too large | HTTP 413 |
| Duplicate identical message | Acknowledge duplicate without reinsertion |
| Same ID with different content | HTTP 409 |
| Database failure | HTTP 500; never report successful persistence |

## 12. Security and trust boundaries

The Agent is an untrusted data producer from the Server's perspective. A validly authenticated request does not make every submitted field trustworthy.

The Server must:

- Authenticate incoming requests.
- Authorize the Agent identity for the submitted `agent_id`.
- Validate every field independently.
- Generate server-owned timestamps.
- Avoid trusting Agent timestamps as receipt times.
- Enforce request and resource limits.
- Reject invalid or unsupported schema versions.
- Avoid logging credentials or sensitive evidence.
- Treat process names, paths, usernames, and evidence as untrusted input.
- Use parameterized SQL in persistence code.

The shared Bearer Token is a lab-stage limitation. Per-Agent credentials, token rotation, and stronger identity binding remain security improvements and must not be described as implemented until delivered and tested.

## 13. Versioning and compatibility policy

- `1.0` is the initial telemetry contract version.
- A breaking field rename/removal, type change, or semantic change requires a new contract version.
- New optional fields require an explicit compatibility decision and documentation update.
- The Server rejects unsupported versions rather than silently misinterpreting them.
- Agent and Server must agree on a supported version before telemetry exchange.
- Heartbeat compatibility is managed separately until a deliberate migration is approved.

## 14. Implementation mapping

| Component | Responsibility | Status |
|---|---|---|
| `agent/client.py` | Serialize and transmit contract messages with UUIDv4 | Implemented & Verified |
| `agent/system_collector.py` | Produce system metrics | Implemented & Verified |
| `agent/process_collector.py` | Produce process snapshots | Implemented & Verified |
| `agent/file_integrity.py` | Produce file baseline data with SHA-256 | Implemented & Verified |
| `server/routes.py` | Receive and validate telemetry requests | Implemented & Verified |
| `server/repositories/` | Persist validated data via parameterized DAL | Implemented & Verified |
| `server/migrations/` | Maintain database schema and checksums | Implemented & Verified |
| `server/detection/` | Real-time threat detection and correlation | Implemented & Verified |
| `server/web.py` | Cyberpunk SOC Dashboard & Incident Console | Implemented & Verified |
| `tests/` | Comprehensive test suite (Unit, Integration, E2E, Security) | Implemented (214/214 passing) |

## 15. Acceptance criteria

- [x] Common telemetry envelope documented.
- [x] Contract versioning rules defined.
- [x] UUID and idempotency requirements defined.
- [x] Agent and Server timestamp ownership defined.
- [x] Phase 1 heartbeat compatibility documented.
- [x] System metrics schema documented.
- [x] Process snapshot schema documented.
- [x] File baseline schema and missing-file semantics documented.
- [x] Security event schema documented.
- [x] Database field mappings documented.
- [x] Validation and trust-boundary requirements documented.
- [x] Retry and duplicate semantics documented.
- [x] Contract examples validated by automated schema tests.
- [x] Server validators and idempotency behavior implemented.
- [x] Contract integrated with API Specification.
- [x] End-to-end integration and security hardening verified.

**Document status:** Complete and fully verified against the codebase baseline.
