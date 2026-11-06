# PHASE 9 — DOCUMENTATION & ARCHITECTURE CONSISTENCY AUDIT REPORT
**Mini EDR for Linux — Comprehensive Security & Quality Audit**

- **Target Repository:** `r00tK1ngX/mini-edr-linux`
- **Component Audited:** Technical Documentation, Specifications, and Source Code Alignment
- **Audit Date:** 2026-11-06
- **Auditor:** Senior Cybersecurity Engineer & Security Auditor (Independent Review)
- **Status:** COMPLETED — AUDIT-ONLY (No code modified, zero data altered)

---

## 1. EXECUTIVE SUMMARY

Phase 9 performed an exhaustive, line-by-line cross-examination between the project's technical documentation (`README.md`, `docs/ARCHITECTURE.md`, `docs/DATA_CONTRACT.md`, `docs/API_SPECIFICATION.md`, `docs/TEST_PLAN.md`, `docs/DEMO_SCENARIO.md`, `docs/PRESENTATION_SLIDES_OUTLINE.md`) and the actual implementation in Python source code, database schemas, and unit test suites.

While the documentation is exceptionally comprehensive, well-structured, and professionally formatted, the audit revealed several **critical divergences between documentation claims and the physical codebase**. In particular:
1. **Broken Quickstart Execution:** `README.md` instructs users to run `python3 -m agent.orchestrator`, which crashes with `No module named agent.orchestrator` because the implementation file is `agent/main.py`.
2. **Missing Process Attribute `cmdline`:** `ARCHITECTURE.md`, `README.md`, and presentation slides advertise collection of 10 process attributes including `cmdline`, whereas `agent/process_collector.py` and SQLite schemas completely omit `cmdline`.
3. **Ghost Detection Rules:** `ARCHITECTURE.md` and `README.md` document `RULE_SHELL_SPAWN` and `RULE_SUSPICIOUS_PROCESS` as core rules, but neither exists in `detection/rules.py`.
4. **Internal Specification Contradiction:** `docs/API_SPECIFICATION.md` marks major telemetry and alert APIs as "Designed; pending" in its summary table despite them being fully implemented in `server/routes.py`.
5. **Path Mismatches in Project Tree:** `README.md` lists `server/detection/` (actually `detection/` at root) and `system_metrics_repository.py` (actually `metrics_repository.py`).

---

## 2. AUDIT SCOPE & DOCUMENTS REVIEWED

| Document | Stated Version / Status | File Size / Lines | Key Sections Audited |
| :--- | :--- | :--- | :--- |
| `README.md` | v1.0 / Production | 391 lines | Architecture, Folder Tree, Quickstart, Detection Table |
| `docs/ARCHITECTURE.md` | Revision 2.0 / Implemented | 609 lines | C4 Architecture, Collectors, Engine Rules, DAL, ERD |
| `docs/DATA_CONTRACT.md` | Version 1.0 / Implemented | 562 lines | Envelope 1.0, Schemas, Process Snapshot Mapping |
| `docs/API_SPECIFICATION.md` | Revision 2.0 / Implemented | 820 lines | REST endpoints, Authentication, Table of Status |
| `docs/TEST_PLAN.md` | Revision 2.0 / Implemented | 450 lines | 214 Test Matrix, Coverage mapping |
| `docs/DEMO_SCENARIO.md` | 5-7 min Thesis Demo | 210 lines | Simulation steps, expected alert triggers |
| `docs/PRESENTATION_SLIDES_OUTLINE.md` | 18 Slides Outline | 620 lines | System architecture, collector attributes |

---

## 3. DOCUMENTATION VS CODE DISCREPANCY REGISTER

### `DISCREPANCY-DOC-01` (Critical) — Non-Existent `agent.orchestrator` Entry Point in README
- **Severity:** High (Broken User Experience / Crash)
- **Documented Location:**
  - `README.md` (Section 4, Line 102 & Section 5.5, Line 232)
  - `docs/ARCHITECTURE.md` (Section 4, Line 111)
- **Documented Claim:**
  Users are instructed to start the Linux agent via:
  ```bash
  python3 -m agent.orchestrator
  ```
- **Code Reality:**
  There is no `agent/orchestrator.py` module in the repository. Executing the command produces:
  ```text
  /home/kali/Projects/mini-edr-linux/.venv/bin/python: No module named agent.orchestrator
  ```
  The agent orchestrator class `AgentOrchestrator` and CLI entry point are located in `agent/main.py`. The actual working command is `python3 -m agent.main`.
- **Remediation:** Update `README.md` and `docs/ARCHITECTURE.md` to reference `python3 -m agent.main`, or create an `agent/orchestrator.py` compatibility wrapper that imports and invokes `agent/main.py`.

---

### `DISCREPANCY-DOC-02` (Critical) — Claimed Process `cmdline` Attribute is Missing from Collector and Schema
- **Severity:** High (Functional Gap)
- **Documented Location:**
  - `README.md` (Line 40: *"PID, PPID, User, Path, Cmdline, RSS"*)
  - `docs/ARCHITECTURE.md` (Section 3.2, Line 100: *"pid, ppid, name, username, exe_path, cmdline, cpu_percent, memory_percent, rss_bytes, process_started_at"*)
  - `docs/DEMO_SCENARIO.md` (Line 92: *"Modal Cyberpunk hiển thị... dòng lệnh cmdline"*)
  - `docs/PRESENTATION_SLIDES_OUTLINE.md` (Slide 7, Line 120: *"Trích xuất 10 trường thông tin... cmdline"*)
- **Code Reality:**
  In `agent/process_collector.py`:
  ```python
  PROCESS_ATTRS = ["pid", "name", "exe", "username", "status", "create_time", "cpu_percent", "memory_percent", "ppid"]
  ```
  `cmdline` is completely omitted from the collector. Furthermore, the `process_observations` SQLite schema (`server/migrations/sql/001_initial_schema.sql`) contains NO `cmdline` column. `cmdline` exists only in `scripts/simulate_attack_scenario.py` as an unpersisted dummy payload field.
- **Remediation:** Either implement `cmdline` extraction (`p.info.get("cmdline")`) and add a migration for `process_observations.cmdline`, or remove claims of `cmdline` collection from all documentation.

---

### `DISCREPANCY-DOC-03` (High) — Documented Core Rules `RULE_SHELL_SPAWN` and `RULE_SUSPICIOUS_PROCESS` Do Not Exist
- **Severity:** High (Functional & Architectural Inconsistency)
- **Documented Location:**
  - `README.md` (Section 7, Lines 287–293)
  - `docs/ARCHITECTURE.md` (Section 4.3, Lines 183–186)
- **Documented Claim:**
  The documentation describes 4 primary detection rules:
  1. `RULE_SUSPICIOUS_PROCESS` (Critical)
  2. `RULE_SHELL_SPAWN` (High)
  3. `RULE_HIGH_CPU_PROCESS` (Medium)
  4. `RULE_FIM_SENSITIVE_FILE` (High)
- **Code Reality:**
  In `detection/rules.py`, the actual rule registry instantiates:
  1. `rule-proc-high-cpu` (`ProcessHighCpuRule`)
  2. `rule-proc-high-mem` (`ProcessHighMemoryRule`) — *Undocumented in README/Architecture*
  3. `rule-proc-suspicious-path` (`ProcessSuspiciousPathRule`)
  4. `rule-proc-hidden-binary` (`ProcessHiddenBinaryRule`) — *Undocumented in README/Architecture*
  5. `rule-fim-sensitive-file` (`FimSensitiveFileRule`)
  
  `RULE_SHELL_SPAWN` is completely absent from the codebase. `RULE_SUSPICIOUS_PROCESS` was renamed and partitioned into `rule-proc-suspicious-path` and `rule-proc-reverse-shell-name` in unit tests, but the documentation was never updated.
- **Remediation:** Update `README.md` and `docs/ARCHITECTURE.md` to reflect the actual rule IDs and implementations present in `detection/rules.py`.

---

### `DISCREPANCY-DOC-04` (Medium) — Directory Tree & Repository Naming Mismatches in `README.md`
- **Severity:** Medium (Cosmetic / Developer Confusion)
- **Documented Location:** `README.md` (Section 4: Project Structure)
- **Discrepancies:**
  1. `server/detection/`: `README.md` places the detection engine inside `server/detection/`. In reality, it resides at the project root `detection/`.
  2. `system_metrics_repository.py`: `README.md` lists `server/repositories/system_metrics_repository.py`. The actual file is `server/repositories/metrics_repository.py`.
  3. `agent/orchestrator.py`: Listed as an individual file; actual file is `agent/main.py`.
- **Remediation:** Align `README.md` Section 4 with the true filesystem directory layout.

---

### `DISCREPANCY-DOC-05` (Medium) — Internal Contradiction in `docs/API_SPECIFICATION.md`
- **Severity:** Medium (Documentation Out of Sync)
- **Documented Location:** `docs/API_SPECIFICATION.md` (Section 3, Lines 104–111)
- **Documented Claim:**
  The summary table states:
  - `POST /api/v1/telemetry/system`: "Designed; pending"
  - `POST /api/v1/telemetry/processes`: "Designed; pending"
  - `POST /api/v1/file-baselines`: "Designed; pending"
  - `POST /api/v1/events`: "Designed; pending"
  - `GET /api/v1/alerts`: "Designed; pending"
  - `GET /api/v1/alerts/{alert_id}`: "Designed; pending"
  - `POST /api/v1/alerts/{alert_id}/acknowledge`: "Designed; pending"
  - `POST /api/v1/alerts/{alert_id}/resolve`: "Designed; pending"
- **Code Reality:**
  Every single one of these endpoints has been implemented, tested, and actively used by the agent and frontend since Phase 4 & Phase 6. The summary table in Section 3 was left in its initial design draft state.
- **Remediation:** Update status column from "Designed; pending" to "Implemented" across all rows in Section 3.

---

### `DISCREPANCY-DOC-06` (Low) — Phantom FIM Dropped Binary Detection in Attack Simulation
- **Severity:** Low
- **Documented Location:** `docs/DEMO_SCENARIO.md`, `docs/PRESENTATION_SLIDES_OUTLINE.md`
- **Discrepancy:**
  The demo scenario states that dropping a binary into `/tmp` triggers a FIM alert, which correlates with process execution to yield the +50 `fim_dropped_and_executed` factor.
  However, in `detection/rules.py`, `FimSensitiveFileRule` only checks files under `/etc`. Files dropped into `/tmp` generate no FIM security events, so this correlation factor cannot trigger through normal agent operations.

---

## 4. ACCURACY MATRIX ACROSS DOCUMENTATION

| Audit Criteria | README.md | ARCHITECTURE.md | DATA_CONTRACT.md | API_SPECIFICATION.md | TEST_PLAN.md |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Component Hierarchy & File Paths** | ❌ (3 mismatches) | ⚠️ (orchestrator path) | ✅ Accurate | ✅ Accurate | ✅ Accurate |
| **API Endpoints & HTTP Methods** | ✅ Accurate | ✅ Accurate | ✅ Accurate | ⚠️ (Table says pending) | ✅ Accurate |
| **Data Contract & Schema Mapping** | ❌ (Claims cmdline) | ❌ (Claims cmdline) | ✅ Accurate (No cmdline) | ✅ Accurate | ✅ Accurate |
| **Detection Rule Names & IDs** | ❌ (Old RULE_ names)| ❌ (Old RULE_ names)| N/A | N/A | ✅ Accurate |
| **Quickstart Execution Instructions** | ❌ (orchestrator err)| N/A | N/A | N/A | N/A |
| **Test Count Alignment (214 tests)** | ✅ (214 passed) | ✅ (214 passed) | ✅ (214 passed) | ✅ (214 passed) | ✅ (214 passed) |

---

## 5. PHASE 9 CONCLUSION & AUDIT VERDICT

The documentation for Mini EDR Linux is remarkably thorough, featuring rigorous architectural diagrams, complete schema contracts, and clear presentation materials. However, documentation drifted from the codebase during rapid iterations between Phase 3 and Phase 6.

### Summary of Discrepancies:
- **`DISCREPANCY-DOC-01` (Critical):** `python3 -m agent.orchestrator` in `README.md` fails; actual entry point is `agent.main`.
- **`DISCREPANCY-DOC-02` (Critical):** `cmdline` is documented across multiple files but absent from `ProcessCollector` and database.
- **`DISCREPANCY-DOC-03` (High):** Documented rules `RULE_SHELL_SPAWN` and `RULE_SUSPICIOUS_PROCESS` missing in `detection/rules.py`.
- **`DISCREPANCY-DOC-04` (Medium):** Tree mismatches in `README.md` (`server/detection/`, `system_metrics_repository.py`).
- **`DISCREPANCY-DOC-05` (Medium):** `docs/API_SPECIFICATION.md` table lists production endpoints as "Designed; pending".
- **`DISCREPANCY-DOC-06` (Low):** FIM dropped binary detection discrepancy in demo scenario.

Phase 9 is officially **COMPLETED**.
The audit now transitions to **PHASE 10 — FINAL ACCEPTANCE, SLIDE DECK & RELEASE READINESS**.
