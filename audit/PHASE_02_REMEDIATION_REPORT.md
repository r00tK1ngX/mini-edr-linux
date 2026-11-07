# PHASE 2 REMEDIATION REPORT — FIM RELIABILITY & TOCTOU PROTECTION
**Mini EDR for Linux — Academic Acceptance & Verified Remediation**

- **Project:** Mini EDR Linux (`r00tK1ngX/mini-edr-linux`)
- **Phase:** Phase 2 — FIM Reliability Remediation
- **Date:** 2026-11-07
- **Branch:** `remediation/academic-acceptance`
- **Base Commit:** `3aed1a9`
- **Status:** **COMPLETED & VERIFIED (256 / 256 TESTS PASSED)**

---

## 1. OBJECTIVES & SCOPE

Phase 2 addressed critical File Integrity Monitoring (FIM) reliability and operating system security vulnerabilities identified during the Phase 0 audit:
1. Mitigate race conditions and symlink directory traversals (TOCTOU) when computing file integrity hashes.
2. Prevent event loss during transient network partitions, server outages, or unexpected Agent crashes.
3. Guarantee that FIM change events carry stable identifiers (`message_id`) for server-side idempotent deduplication.
4. Persist baseline state in durable local storage to maintain synchronization across Agent restarts without eager desynchronization.
5. Strictly adhere to academic scope constraints: implement durable local queuing using Python's standard library and embedded SQLite without introducing enterprise dependencies (no Redis, Kafka, or Celery).

### Target Findings Addressed

1. **`FINDING-PHASE02-01` (🔴 High / CWE-59 / CWE-367):** TOCTOU Symlink Traversal vulnerability during FIM file opening and hash computation.
2. **`FINDING-NEW-07` (🔴 High / CWE-703):** Transient network drop causes lost FIM security events without local durable queue.
3. **`FINDING-NEW-08` (🟡 Medium / CWE-662):** Agent crash (SIGKILL) or restart drops pending FIM events and causes baseline divergence.
4. **`FINDING-PHASE04-01` (🟡 Medium / CWE-703):** Missing stable message identifier for retry idempotency on FIM events.
5. **`FINDING-PHASE02-02` (🟡 Medium / CWE-400):** Unbounded queue growth mitigated by FIFO pruning and bounded spool capacity.

---

## 2. DETAILED TECHNICAL REMEDIATIONS

### 2.1 TOCTOU & Symlink Traversal Defense (`agent/file_integrity.py`)
- **Atomic File Descriptors via `os.open`:**
  - Replaced standard Python `open(path, "rb")` with atomic descriptor opening:
    ```python
    fd = os.open(file_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    ```
  - If a monitored path is replaced with a symbolic link before or during opening, the Linux kernel halts resolution immediately and returns `errno.ELOOP` (or `errno.EMLINK`), rejecting traversal before any target can be accessed.
  - Followed by atomic descriptor inspection via `os.fstat(fd)` to verify file type (`stat.S_ISREG`), preventing named pipes (FIFOs), block devices, and sockets from blocking worker threads.
- **Strict Symlink Inspection:**
  - Updated `inspect_file(path)` and `scan_monitored_paths(paths)` to use `os.lstat(path)`.
  - Any path where `stat.S_ISLNK(st.st_mode)` is true is skipped immediately without inspecting or opening the target file.
  - Normalized all evaluated file paths using `os.path.normpath` while strictly preserving absolute identity.

### 2.2 Durable SQLite Event Spool Queue (`agent/spool.py`)
- Created `EventSpool` class managing a local SQLite database (`data/spool_{agent_id}.db` in production, or `:memory:`/temp in testing).
- Configured SQLite with `PRAGMA journal_mode = WAL;`, `PRAGMA foreign_keys = ON;`, and `PRAGMA busy_timeout = 10000;` for ACID durability across unexpected agent terminates (`SIGKILL`).
- Maintained table schema `fim_spool`:
  - `message_id TEXT UNIQUE NOT NULL`
  - `agent_id TEXT NOT NULL`
  - `event_type TEXT NOT NULL`
  - `severity TEXT NOT NULL`
  - `envelope_json TEXT NOT NULL`
  - `created_at TEXT NOT NULL`
  - `status TEXT NOT NULL DEFAULT 'pending'` ('pending' or 'acknowledged')
  - `attempts INTEGER NOT NULL DEFAULT 0`
  - `last_attempt_at TEXT`
- **Bounded Spool Capacity (`max_spool_size`):**
  - When spool capacity is approached, acknowledged events are purged first.
  - If pending events still exceed capacity, the oldest pending events are purged in FIFO order with warning logs, preventing local filesystem exhaustion.

### 2.3 Atomic Baseline State Persistence (`agent/spool.py`, `agent/file_integrity.py`)
- Maintained table schema `fim_baseline_state`:
  - Stores `file_path PRIMARY KEY`, `sha256`, `size_bytes`, `mtime_ns`, `file_mode`, `state`, timestamps.
- Added `save_baseline_state(baseline)` and `load_baseline_state()` in `EventSpool`.
- Updated `FileIntegrityMonitor`:
  - On startup, attempts to load baseline from SQLite spool first (`load_persisted_baseline()`).
  - Added atomic baseline advance via `commit_baseline(new_baseline)`.
  - Crucial guarantee: If network delivery fails during a cycle, `commit_baseline()` is **NOT** invoked, keeping the baseline locked to the last acknowledged state until network recovery.

### 2.4 Orchestrator Coordination & Idempotent Drain (`agent/main.py`)
- Integrated `EventSpool` into `AgentOrchestrator` lifecycle:
  - **Step 3a (Drain Spool):** At the beginning of the FIM evaluation cycle, queries pending events from `EventSpool` in FIFO order (`LIMIT 50`) and transmits them to the server. On `HTTP 200/201`, marks them acknowledged (`mark_acknowledged`). On transmission exception, stops drain and backs off.
  - **Deduplication Coexistence:** Tracks `drained_paths` in Step 3a.
  - **Step 3b (Delta Change Scan):** Detects changes via `scan_for_changes()`.
    - Every change event is assigned a stable UUID v4 `message_id`.
    - Newly detected events are immediately inserted into `EventSpool` before attempting transmission.
    - If a path's change was already transmitted in Step 3a, it is not re-transmitted in Step 3b, preventing duplicate telemetry.
    - If transmission fails, appends error to `summary["errors"]`, retains event in spool for next cycle retry, and leaves baseline unadvanced.

---

## 3. VERIFICATION & TEST RESULTS

### 3.1 Dedicated Phase 2 Test Suite (`tests/test_fim_reliability_p2.py`)

A comprehensive 10-test suite was engineered covering all failure modes:

| Test Name | Verification Focus | Result |
| :--- | :--- | :---: |
| `test_compute_sha256_toctou_symlink_rejected` | `os.O_NOFOLLOW` rejects symlink target without opening | ✅ PASSED |
| `test_inspect_file_skips_symlink_targets` | `inspect_file` returns None for symlinks | ✅ PASSED |
| `test_scan_monitored_paths_skips_symlinks` | Symlinks pointing outside monitored root are skipped | ✅ PASSED |
| `test_spool_enqueue_and_drain_fifo` | SQLite spool stores events and drains in FIFO order | ✅ PASSED |
| `test_spool_bounded_capacity_purges_oldest` | Bounded capacity drops oldest pending events without crash | ✅ PASSED |
| `test_fim_baseline_persistence_across_restart` | Baseline is saved to SQLite and restored across restarts | ✅ PASSED |
| `test_file_modified_and_reverted_during_outage` | Temporary modifications reverted during outage produce zero events | ✅ PASSED |
| `test_orchestrator_offline_spool_and_recovery` | Outage queues events; recovery drains without loss | ✅ PASSED |
| `test_partial_batch_retry_without_duplicates` | Partial batch error retries only unacknowledged items | ✅ PASSED |
| `test_agent_crash_recovery_preserves_spool` | Agent restart preserves pending spool items | ✅ PASSED |

### 3.2 Full Regression Test Suite Execution

```
============================= test session starts ==============================
platform linux -- Python 3.14.8, pytest-9.1.1, pluggy-1.7.0
rootdir: /home/kali/Projects/mini-edr-linux
configfile: pytest.ini
collected 256 items

tests/test_agent_client.py ..........                                    [  3%]
tests/test_agent_orchestrator.py .......                                 [  6%]
tests/test_alert_management.py ....................................      [ 20%]
tests/test_api.py ........................................               [ 36%]
tests/test_dashboard.py ...........                                      [ 40%]
tests/test_database.py .............                                     [ 45%]
tests/test_detection.py ..........................                       [ 55%]
tests/test_file_integrity.py .........                                   [ 59%]
tests/test_fim_reliability_p2.py ..........                              [ 63%]
tests/test_full_system_e2e.py .                                          [ 63%]
tests/test_migrations.py .......                                         [ 66%]
tests/test_phase4_e2e.py ....                                            [ 67%]
tests/test_process_collector.py .............                            [ 73%]
tests/test_repositories.py ............                                  [ 77%]
tests/test_security_reliability.py .........................             [ 87%]
tests/test_system_collector.py ................                          [ 93%]
tests/test_web_security_p1.py ................                           [100%]

============================= 256 passed in 12.60s =============================
```

- **Pass Rate:** 100% (256/256 passed).
- **Regressions:** Zero.

---

## 4. PHASE 2 ACCEPTANCE CHECKLIST

- [x] Durable local pending-event queue implemented via embedded SQLite (`EventSpool`).
- [x] Stable UUID v4 `message_id` on all security event envelopes.
- [x] Idempotent retry and acknowledgement tracking (`status = 'acknowledged'`).
- [x] Crash recovery and offline survival tested and verified.
- [x] Bounded spool queue capacity (`max_spool_size`) with FIFO eviction.
- [x] Atomic baseline persistence (`commit_baseline` and `fim_baseline_state`).
- [x] Symlink-safe traversal and TOCTOU protection (`os.O_NOFOLLOW | os.O_CLOEXEC` & `os.fstat`).
- [x] Zero enterprise bloat (strictly SQLite + standard library, no Redis/Celery/Kafka).
- [x] All 256 tests passing.

Phase 2 is completed. Ready for review and authorization to proceed to Phase 3 (Detection Correctness).
