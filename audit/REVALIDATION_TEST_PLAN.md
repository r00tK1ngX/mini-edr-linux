# REVALIDATION TEST PLAN & EXECUTION REPORT (PHASE 0)
**Mini EDR for Linux — Academic Acceptance & Verified Remediation**

- **Target Repository:** `r00tK1ngX/mini-edr-linux`
- **Working Branch:** `remediation/academic-acceptance`
- **Baseline Commit SHA:** `47b8fcd81b9df107ac66ef0992f233b1e1c82d3d`
- **Audit Date:** 2026-11-07
- **Test Environment:** Linux Kali x86_64, Python 3.14.8, Pytest 9.1.1
- **Status:** **PHASE 0 AUDIT BASELINE RECORDED**

---

## 1. BASELINE TEST EXECUTION METRICS (EXECUTED TESTS)

The entire automated test suite was executed against the clean working tree at commit `47b8fcd81b9df107ac66ef0992f233b1e1c82d3d` using `.venv/bin/pytest`.

### 1.1 Execution Environment & Parameters

- **Operating System:** Linux 6.18.9-amd64 (Kali Linux)
- **Python Version:** `Python 3.14.8`
- **Key Dependencies:**
  - `Flask == 3.1.3`
  - `Werkzeug == 3.1.9`
  - `Jinja2 == 3.1.6`
  - `psutil == 7.2.2`
  - `pytest == 9.1.1`
  - `python-dotenv == 1.2.4`
- **Execution Command:**
  ```bash
  .venv/bin/pytest
  ```
- **Execution Timestamp:** 2026-11-07 05:06:27 UTC
- **Test Duration:** 11.79 seconds

### 1.2 Quantitative Baseline Results

| Test Suite Category | Test File Path | Tests Executed | Passed | Failed | Skipped | Error |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| Agent Client Tests | `tests/test_agent_client.py` | 10 | 10 | 0 | 0 | 0 |
| Agent Orchestrator Tests | `tests/test_agent_orchestrator.py` | 7 | 7 | 0 | 0 | 0 |
| Alert Management Tests | `tests/test_alert_management.py` | 36 | 36 | 0 | 0 | 0 |
| REST API Telemetry Tests | `tests/test_api.py` | 40 | 40 | 0 | 0 | 0 |
| Web Dashboard View Tests | `tests/test_dashboard.py` | 11 | 11 | 0 | 0 | 0 |
| SQLite Database Core Tests | `tests/test_database.py` | 13 | 13 | 0 | 0 | 0 |
| Detection & Correlation Tests | `tests/test_detection.py` | 26 | 26 | 0 | 0 | 0 |
| File Integrity Tests | `tests/test_file_integrity.py` | 9 | 9 | 0 | 0 | 0 |
| Full System E2E Pipeline | `tests/test_full_system_e2e.py` | 1 | 1 | 0 | 0 | 0 |
| Database Migration Tests | `tests/test_migrations.py` | 7 | 7 | 0 | 0 | 0 |
| Ingestion & Correlation E2E | `tests/test_phase4_e2e.py` | 4 | 4 | 0 | 0 | 0 |
| Process Collector Tests | `tests/test_process_collector.py` | 13 | 13 | 0 | 0 | 0 |
| Repositories Data Layer | `tests/test_repositories.py` | 12 | 12 | 0 | 0 | 0 |
| Security & Reliability Tests | `tests/test_security_reliability.py` | 25 | 25 | 0 | 0 | 0 |
| System Collector Tests | `tests/test_system_collector.py` | 16 | 16 | 0 | 0 | 0 |
| **TOTAL BASELINE** | **15 Test Files** | **230 / 230** | **230** | **0** | **0** | **0** |

> [!NOTE]
> All 230 existing tests pass cleanly at the baseline commit. However, as demonstrated in `audit/REVALIDATION_REPORT.md`, these tests lack coverage for critical edge cases: Open Redirects, Logout CSRF, Login CSRF, DOM XSS in error sinks, TOCTOU symlink races, Agent crash recovery, Snapshot payload hashing, and SQL variable batch overflows.

---

## 2. PROPOSED REMEDIATION TEST SUITE (PHASES 1 TO 6)

The following tests are **PROPOSED** to rigorously validate each subsequent remediation phase. No code has been modified in Phase 0; these test specifications define the acceptance criteria for Phases 1 through 6.

### Phase 1: Web Security Test Suite (`tests/test_web_security_p1.py`)

| Test Case ID | Test Target | Description & Expected Outcome | Target Finding |
| :--- | :--- | :--- | :--- |
| `TEST-P1-01` | `POST /login` | Submit login without CSRF token; must return `400 Bad Request` or reject authentication. | `FINDING-NEW-03` |
| `TEST-P1-02` | `POST /login` | Submit login with valid token and valid CSRF; must authenticate session. | `FINDING-PHASE01-02` |
| `TEST-P1-03` | `GET /logout` | Issue `GET /logout`; must return `405 Method Not Allowed` or redirect without logging out. | `FINDING-NEW-02` |
| `TEST-P1-04` | `POST /logout` | Issue `POST /logout` with valid CSRF; must clear session and redirect to `/login`. | `FINDING-NEW-02` |
| `TEST-P1-05` | `GET /login?next=https://evil.com` | Authenticate; must reject external `next` URL and redirect strictly to `/dashboard`. | `FINDING-NEW-01` |
| `TEST-P1-06` | `GET /login?next=//evil.com` | Authenticate; must reject protocol-relative `//` redirect. | `FINDING-NEW-01` |
| `TEST-P1-07` | `GET /dashboard?token=...` | Request protected view with `?token=`; must reject query parameter token and redirect to `/login`. | `FINDING-NEW-04` |
| `TEST-P1-08` | Session Cookies | Inspect `Set-Cookie` header; verify `HttpOnly` and `SameSite=Lax` flags are present. | `FINDING-NEW-06` |
| `TEST-P1-09` | DOM XSS Error Sinks | Mock API error response containing `<img src=x onerror=alert(1)>`; verify modal escapes content. | `FINDING-NEW-05` |

---

### Phase 2: FIM Reliability Test Suite (`tests/test_fim_reliability_p2.py`)

| Test Case ID | Test Target | Description & Expected Outcome | Target Finding |
| :--- | :--- | :--- | :--- |
| `TEST-P2-01` | TOCTOU Hashing | Replace monitored file with symlink pointing to `/etc/shadow` during scan; verify `compute_sha256` fails safely without following symlink (`O_NOFOLLOW`). | `FINDING-NEW-07` |
| `TEST-P2-02` | Offline Ingestion Spool | Simulate server unreachable; agent enqueues FIM events in local spool (`.fim_spool.db`). | `FINDING-NEW-08` |
| `TEST-P2-03` | Agent Crash Recovery | Enqueue pending FIM events, simulate `SIGKILL` on agent process, restart agent; verify pending events are retransmitted without loss. | `FINDING-NEW-08` |
| `TEST-P2-04` | Partial Batch Retry | Transmit batch of 5 events where server fails on event #4; verify already-acked events are not duplicated and failed events retry with stable IDs. | `FINDING-PHASE03-01` |
| `TEST-P2-05` | Symlink Outside Root | Monitored directory contains symlink pointing to `/etc`; verify scanner skips traversal. | `FINDING-PHASE03-04` |
| `TEST-P2-06` | File Modified & Reverted | File modified then reverted to initial state while agent is offline; verify both changes are captured. | `FINDING-PHASE03-01` |

---

### Phase 3: Detection Correctness Test Suite (`tests/test_detection_correctness_p3.py`)

| Test Case ID | Test Target | Description & Expected Outcome | Target Finding |
| :--- | :--- | :--- | :--- |
| `TEST-P3-01` | Parent Process Resolution | Process snapshot has `python3` (PPID 100) spawning `sh` (PID 101); verify `ProcessShellSpawnRule` resolves `parent_name="python3"` and triggers. | `FINDING-NEW-11` |
| `TEST-P3-02` | Detection-to-Event Mapping | Process snapshot generates 3 detections where event insert #2 throws exception; verify remaining detections map to correct event IDs without `IndexError`. | `FINDING-NEW-10` |
| `TEST-P3-03` | Correlation Event Isolation | Two distinct processes in snapshot generate alerts; verify `alert_events` only links events specific to each respective process. | `FINDING-NEW-10` |
| `TEST-P3-04` | Correlation Time Window | FIM drop event occurred 10 minutes ago ($> 300$s); subsequent execution does not correlate with expired drop. | `FINDING-NEW-10` |
| `TEST-P3-05` | Rule Registry Integrity | Evaluate all 7 detection rules against positive and negative fixtures; verify zero false triggers on benign binaries (`/bin/ls`, `/usr/bin/python3`). | `FINDING-PHASE05-01` |

---

### Phase 4: Data Integrity Test Suite (`tests/test_data_integrity_p4.py`)

| Test Case ID | Test Target | Description & Expected Outcome | Target Finding |
| :--- | :--- | :--- | :--- |
| `TEST-P4-01` | Snapshot Payload Hash | Send duplicate `message_id` with different process observations (same count); verify server returns `409 Conflict`. | `FINDING-NEW-09` |
| `TEST-P4-02` | Snapshot True Duplicate | Resend exact identical process snapshot with same `message_id`; verify server returns `200 OK` with `duplicate: true`. | `FINDING-NEW-09` |
| `TEST-P4-03` | SQL Variable Limit (2500 files) | Synchronize baseline batch of 2,500 files; verify query executes in chunks without `sqlite3.OperationalError`. | `FINDING-PHASE04-03` |
| `TEST-P4-04` | Heartbeat Metadata Preservation | Send partial heartbeat lacking optional fields; verify existing values are retained via `COALESCE`. | `FINDING-PHASE01-04` |
| `TEST-P4-05` | Alert Non-Downgrade & Reopen | Recurrent alert with lower severity does not downgrade status; resolved alert reopens to `new`. | `FINDING-PHASE02-01` |

---

### Phase 5: Resource & Reliability Test Suite (`tests/test_resource_reliability_p5.py`)

| Test Case ID | Test Target | Description & Expected Outcome | Target Finding |
| :--- | :--- | :--- | :--- |
| `TEST-P5-01` | Oversized Snapshot Count | Submit snapshot claiming `process_count: 50000`; verify server returns `400 Bad Request` (limit: 1000). | `FINDING-NEW-12` |
| `TEST-P5-02` | Oversized Baseline Array | Submit baseline with 10,000 files in single request; verify server returns `400 Bad Request` (limit: 5000). | `FINDING-NEW-12` |
| `TEST-P5-03` | Oversized Field Length | Submit process snapshot with `process_name` exceeding 255 chars; verify rejection with clear error. | `FINDING-NEW-12` |
| `TEST-P5-04` | Database Pruning Routine | Run `prune_telemetry(retention_days=7)`; verify records older than 7 days are deleted while recent records remain intact. | `FINDING-PHASE02-03` |

---

### Phase 6: Full Regression & E2E Verification (`tests/test_full_regression_p6.py`)

| Test Case ID | Scope | Verification Flow | Acceptance Criteria |
| :--- | :--- | :--- | :--- |
| `TEST-P6-01` | Full System E2E | Live Agent → Collectors → HTTP Ingestion → SQLite WAL → Detection Engine → Alert Triaging → Web SOC Console. | Complete pipeline executes with zero errors. |
| `TEST-P6-02` | Attack Simulator | Execute `scripts/simulate_attack_scenario.py --auto`; verify all 5 attack phases generate expected alerts. | Alerts generated: Critical & High; UI reflects triage. |
| `TEST-P6-03` | Full Pytest Suite | Run all unit, integration, security, and regression tests. | 100% passing tests with 0 failures, 0 errors. |

---

## 3. SUMMARY: EXECUTED VS. PROPOSED TEST METRICS

- **Tests Currently Executed & Verified (Phase 0 Baseline):** **230 / 230 PASSED (100%)**
- **New Tests Proposed for Remediation (Phases 1 to 6):** **30 Proposed Tests**
- **Projected Total Test Count Upon Project Completion:** **$\ge 260$ Tests**
