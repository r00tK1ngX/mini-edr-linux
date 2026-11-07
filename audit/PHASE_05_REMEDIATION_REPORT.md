# PHASE 5 REMEDIATION REPORT — RESOURCE & RELIABILITY
**Mini EDR for Linux — Academic Acceptance & Verified Remediation**

- **Project:** Mini EDR Linux (`r00tK1ngX/mini-edr-linux`)
- **Phase:** Phase 5 — Resource Controls, Input Boundaries & Database Pruning
- **Date:** 2026-11-07
- **Branch:** `remediation/academic-acceptance`
- **Base Commit:** `cecc440`
- **Status:** **COMPLETED & VERIFIED (285 / 285 TESTS PASSED)**

---

## 1. OBJECTIVES & SCOPE

Phase 5 targeted system reliability, DoS/resource exhaustion defenses, input validation boundaries, and long-term storage sustainability:
1. Enforce strict boundaries on batch telemetry sizes: `MAX_PROCESSES_PER_SNAPSHOT` (1,000) and `MAX_FILES_PER_BASELINE` (5,000) (`FINDING-NEW-12`).
2. Implement comprehensive per-field length constraints across process telemetry, baseline paths, and security event payloads.
3. Validate and enforce safe process name bounding and truncation (`[:255]`) in the agent collector to prevent malformed or adversarial process metadata from disrupting telemetry.
4. Bound incoming request payload sizes at both the HTTP server configuration level (`MAX_CONTENT_LENGTH`) and envelope validation layer, returning HTTP 413 for oversized requests.
5. Provide resilient handling of malformed UTF-8 byte sequences across HTTP endpoints, returning HTTP 400 Bad Request instead of unhandled 500 crashes.
6. Enforce bounded queue capacity in the local SQLite event spool (`DEFAULT_MAX_SPOOL_EVENTS = 1000`) with automatic FIFO purging of acknowledged events and oldest records under disk pressure.
7. Implement automated TTL database retention pruning (`prune_telemetry`) to prevent unbounded SQLite disk growth (`FINDING-PHASE02-03`).

### Target Findings Addressed

1. **`FINDING-NEW-12` (🟡 Medium / CWE-400):** Unbounded batch sizes for process snapshots and baseline files enabled memory exhaustion and SQLite query overload.
2. **`FINDING-PHASE02-03` (🟡 Medium / CWE-770):** Unbounded telemetry growth without TTL pruning caused continuous SQLite database file expansion.
3. **`FINDING-PHASE04-01` (🔴 High / CWE-400):** Request body size boundaries and Content-Length enforcement verified with HTTP 413.
4. **Input Boundaries & Safe Truncation:** Per-field bounds preventing buffer bloat or DB index degradation.

---

## 2. DETAILED TECHNICAL REMEDIATIONS

### 2.1 Batch Size & Resource Boundaries (`server/routes.py`)
- Configured upper bounds on incoming telemetry collections:
  - `MAX_PROCESSES_PER_SNAPSHOT = 1000`: In `ingest_process_telemetry`, requests with `process_count > 1000` or array length > 1,000 are rejected immediately with HTTP 400 (`"process_count (...) exceeds maximum allowed limit of 1000"`).
  - `MAX_FILES_PER_BASELINE = 5000`: In `sync_file_baselines`, baseline batches exceeding 5,000 files are rejected with HTTP 400.
  - `MAX_EVIDENCE_BYTES = 65536` (64 KB): In `ingest_security_event`, evidence payloads exceeding 64 KB of serialized JSON are rejected with HTTP 400.

### 2.2 Per-Field Length Constraints (`server/routes.py`)
- Standardized strict length limits on all data fields:
  - `process_name`: Max 255 characters.
  - `username`: Max 128 characters.
  - `exe_path`: Max 4,096 characters (Linux `PATH_MAX`).
  - `file_path`: Max 4,096 characters.
  - `event_type`: Max 64 characters.
  - `title`: Max 255 characters.
  - `description`: Max 4,096 characters.
  - `fingerprint`: Max 4,096 characters (allowing path-based event fingerprints).
  - `schema_version`: Max 16 characters.
  - `agent_id`: Max 128 characters.
  - `collected_at`: Max 64 characters.

### 2.3 Agent Safe Process Name Truncation (`agent/process_collector.py`)
- In `_clean_process_name(name, exe_path, pid)`:
  - If a process name or binary name exceeds 255 characters, it is safely truncated to 255 characters (`[:255]`) before dispatch, ensuring normal telemetry flow even under adversarial process naming.

### 2.4 Telemetry Retention & Database Pruning (`server/maintenance.py`, `server/repositories/`)
- Added `prune_older_than(days: int)` methods across repository layers:
  - `MetricsRepository.prune_older_than`: Deletes `system_metrics` where `datetime(collected_at) < datetime('now', '-' || ? || ' days')`.
  - `ProcessRepository.prune_older_than`: Deletes `process_snapshots` older than N days. Because `process_observations` references snapshots with `ON DELETE CASCADE`, all associated observations are automatically and atomically purged.
  - `EventRepository.prune_older_than`: Deletes aged `security_events` older than compliance window.
- Unified Maintenance Routine (`server/maintenance.py`):
  - Created `prune_telemetry(database_path, retention_days=7)` returning detailed counts of pruned metrics and snapshots.
  - Exposed administrative endpoint `POST /api/v1/maintenance/prune` for scheduled or on-demand execution.

### 2.5 Malformed UTF-8 & Body Size Hardening (`server/app.py`, `server/routes.py`)
- Registered `@app.errorhandler(UnicodeDecodeError)` returning HTTP 400 Bad Request with JSON error message rather than unhandled 500 server errors.
- Handled `MAX_CONTENT_LENGTH` (16 MiB default) with HTTP 413 error handler and explicit Content-Length pre-flight check in `_validate_envelope`.

### 2.6 Agent Spool Queue Bound & Batch Acknowledging (`agent/spool.py`)
- In `EventSpool`:
  - Enforced bounded queue capacity (`self.max_size = max(1, int(max_size))`).
  - Automatically purges acknowledged events when capacity is approached, followed by FIFO dropping of the oldest pending events under disk backpressure.
  - Enhanced `mark_acknowledged` to support both single message IDs and batch collections (`Union[str, Iterable[str]]`).

---

## 3. VERIFICATION & TEST RESULTS

### 3.1 Dedicated Test Suite (`tests/test_resource_reliability_p5.py`)
A test suite of 12 comprehensive unit and integration tests was implemented:
- `test_oversized_process_count_rejected`: Submitting 1,001 processes returns HTTP 400 (`TEST-P5-01`).
- `test_oversized_baseline_files_rejected`: Submitting 5,001 baseline files returns HTTP 400 (`TEST-P5-02`).
- `test_process_name_exceeding_255_chars_rejected`: Process name > 255 chars returns HTTP 400 (`TEST-P5-03`).
- `test_process_username_and_exe_path_limits`: Rejection of usernames > 128 chars and exe paths > 4096 chars (`TEST-P5-03`).
- `test_baseline_file_path_exceeding_4096_chars_rejected`: File path > 4096 chars returns HTTP 400 (`TEST-P5-03`).
- `test_security_event_field_and_evidence_limits`: Rejection of oversized event_type, description, fingerprint, and evidence > 64 KB (`TEST-P5-03`).
- `test_telemetry_pruning_removes_old_and_preserves_recent`: Confirms records older than 7 days are pruned and recent records remain; verifies cascade deletion of process observations (`TEST-P5-04`).
- `test_maintenance_prune_api_endpoint`: Validates `POST /api/v1/maintenance/prune` (`TEST-P5-09`).
- `test_malformed_utf8_in_request_body_returns_400`: Raw invalid UTF-8 bytes return HTTP 400 (`TEST-P5-05`).
- `test_oversized_payload_stream_rejected_with_413`: Payloads exceeding `MAX_CONTENT_LENGTH` return HTTP 413 (`TEST-P5-06`).
- `test_spool_queue_bounded_capacity_and_fifo_purge`: Validates spool capacity limit and FIFO drop policy under backpressure (`TEST-P5-07`).
- `test_clean_process_name_safe_truncation`: Validates agent-side safe truncation to 255 chars (`TEST-P5-08`).

### 3.2 Full Regression Suite
- **Executed:** `pytest -v` across the entire project repository.
- **Result:** **285 passed** (0 failed, 0 errors, 0 skipped).
- All previous Phase 1, Phase 2, Phase 3, Phase 4, and E2E suites pass with 100% compliance.

---

## 4. ACCEPTANCE CRITERIA COMPLIANCE

| Acceptance Criterion | Target Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| **AC-P5-01: Snapshot Count Limit** | Reject snapshots with > 1,000 processes | **MET** | `server/routes.py:ingest_process_telemetry` |
| **AC-P5-02: Baseline Count Limit** | Reject baseline batches with > 5,000 files | **MET** | `server/routes.py:sync_file_baselines` |
| **AC-P5-03: Per-Field Length Limits** | Enforce max lengths on all string fields | **MET** | `MAX_FIELD_LENGTH_*` in `server/routes.py` |
| **AC-P5-04: Malformed UTF-8** | Invalid UTF-8 returns HTTP 400 Bad Request | **MET** | `@app.errorhandler(UnicodeDecodeError)` in `server/app.py` |
| **AC-P5-05: Payload Size Limit** | Oversized payloads return HTTP 413 | **MET** | `MAX_CONTENT_LENGTH` handler in `server/app.py` |
| **AC-P5-06: Database TTL Pruning** | `prune_telemetry` cleans expired metrics & snapshots | **MET** | `server/maintenance.py`, `tests/test_resource_reliability_p5.py` |
| **AC-P5-07: Spool Queue Bounds** | Bounded local spool with FIFO drop under disk pressure | **MET** | `agent/spool.py:enqueue_events` |
| **AC-P5-08: Safe Truncation** | Process names truncated to 255 chars in collector | **MET** | `agent/process_collector.py:_clean_process_name` |

---

## 5. SUMMARY OF CHANGED FILES

- `server/routes.py`: Added `MAX_PROCESSES_PER_SNAPSHOT`, `MAX_FILES_PER_BASELINE`, field length checks, payload limits, and `POST /maintenance/prune`.
- `server/app.py`: Added error handler for `UnicodeDecodeError` returning 400.
- `server/maintenance.py`: Implemented unified `prune_telemetry` retention maintenance utility.
- `server/repositories/metrics_repository.py`: Added `prune_older_than(days)` method.
- `server/repositories/process_repository.py`: Added `prune_older_than(days)` method with cascade observation deletion.
- `server/repositories/event_repository.py`: Added `prune_older_than(days)` method and wrapped in `with conn:`.
- `agent/process_collector.py`: Added safe truncation (`[:255]`) in `_clean_process_name`.
- `agent/spool.py`: Allowed configurable queue bounds down to 1 item and batch acknowledging.
- `tests/test_resource_reliability_p5.py`: Created 12 automated unit/integration tests verifying Phase 5 controls.
