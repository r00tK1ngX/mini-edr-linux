# MASTER AUDIT FINDINGS REGISTER — MINI EDR FOR LINUX
**Comprehensive Technical & Security Vulnerability Register**

- **Target Repository:** `r00tK1ngX/mini-edr-linux`
- **Audit Scope:** Phases 1 to 10 (Full System Audit)
- **Auditor:** Senior Cybersecurity Engineer & Security Auditor (Independent Review)
- **Date:** 2026-11-06
- **Status:** COMPLETED — AUDIT-ONLY (No code modified, zero data altered)

---

## 1. FINDINGS SUMMARY & SEVERITY DISTRIBUTION

The Full System Audit identified a total of **36 distinct findings** (including security vulnerabilities, architectural flaws, reliability bottlenecks, and documentation discrepancies) across the 10 project phases.

| Severity Level | Count | Definition | Action Required |
| :--- | :---: | :--- | :--- |
| 🔴 **CRITICAL / HIGH** | **14** | Direct security compromise (XSS, Auth bypass, Denial of Service, Event loss, Broken execution) | Must remediate before production release (P0 / P1) |
| 🟡 **MEDIUM** | **14** | Architecture degradation, performance bottleneck, evasion risk, data integrity edge cases | Remediate in next minor version update (P2) |
| 🔵 **LOW** | **6** | Minor usability flaws, cosmetic naming issues, documentation desynchronization | Address during routine maintenance (P3) |
| 🟢 **INFORMATIONAL** | **2** | Verified architectural strengths & positive compliance findings (Immunity to SQLi/RCE, Air-gapped pass) | Preserve existing implementation |
| **TOTAL** | **36** | | |

---

## 2. CONSOLIDATED FINDINGS REGISTER

| Finding ID | Phase | Severity | CVSS v3.1 | CWE | Title & Summary | Affected File & Lines |
| :--- | :---: | :---: | :---: | :---: | :--- | :--- |
| **`FINDING-PHASE01-01`** | P1 | 🔴 High | 7.5 | CWE-755 | Missing `SECRET_KEY` causes unhandled HTTP 500 runtime crash on HTML Form POST actions | `server/app.py:27-56`, `server/web.py:291-402` |
| **`FINDING-PHASE01-02`** | P1 | 🔴 High | 7.5 | CWE-306 | Unauthenticated Web SOC Console (`web_bp`) allows anyone to inspect telemetry and manipulate alerts | `server/web.py:38-430`, `server/app.py:53-56` |
| **`FINDING-PHASE01-03`** | P1 | 🟡 Medium | 6.5 | CWE-287 | Shared static Bearer token lacks endpoint binding, exposing fleet to lateral impersonation | `server/routes.py:101-125`, `agent/client.py:45` |
| **`FINDING-PHASE01-04`** | P1 | 🟡 Medium | 5.3 | CWE-476 | Heartbeat upsert overwrites optional metadata (`ip_address`, `agent_version`) with NULL on partial update | `server/repositories/endpoint_repository.py:43-55` |
| **`FINDING-PHASE01-05`** | P1 | 🔵 Low | 3.7 | CWE-521 | Token strength validation ($\ge 32$ chars) bypassed when launched under WSGI or `create_app()` | `server/app.py:73-83` |
| **`FINDING-PHASE02-01`** | P2 | 🔴 High | 7.1 | CWE-670 | Resolved alerts are never reopened upon threat recurrence (`ON CONFLICT` does not update `status`) | `server/repositories/alert_repository.py:43-65` |
| **`FINDING-PHASE02-02`** | P2 | 🟡 Medium | 5.3 | CWE-697 | Table-level message ID uniqueness without cross-table deduplication envelope | `server/migrations/sql/001_initial_schema.sql` |
| **`FINDING-PHASE02-03`** | P2 | 🟡 Medium | 5.3 | CWE-770 | Unbounded high-frequency telemetry growth due to lack of TTL / automatic pruning mechanism | `server/repositories/metrics_repository.py` |
| **`FINDING-PHASE02-04`** | P2 | 🔵 Low | 3.1 | CWE-613 | Status calculation depends on SQLite `julianday('now')` and host clock synchronization | `server/repositories/endpoint_repository.py:82-95` |
| **`FINDING-PHASE03-01`** | P3 | 🔴 High | 7.5 | CWE-754 | Permanent FIM event loss during network failure due to eager in-memory baseline advancement | `agent/main.py:215-245`, `agent/file_integrity.py` |
| **`FINDING-PHASE03-02`** | P3 | 🔴 High | 6.8 | CWE-1059 | Architecture discrepancy: `cmdline` is NEVER collected by `ProcessCollector` despite documentation claims | `agent/process_collector.py:10-18` |
| **`FINDING-PHASE03-03`** | P3 | 🟡 Medium | 5.3 | CWE-400 | Unconditional byte-level re-hashing on every FIM cycle without `stat`/`mtime` fast-path | `agent/file_integrity.py:85-115` |
| **`FINDING-PHASE03-04`** | P3 | 🟡 Medium | 5.5 | CWE-59 | Early symlink resolution (`Path.resolve()`) collapses symlink identity and misidentifies symlink attacks | `agent/file_integrity.py:92` |
| **`FINDING-PHASE03-05`** | P3 | 🟡 Medium | 5.3 | CWE-362 | Complete blind spot for short-lived processes ($< 10$s) due to lack of kernel event stream (eBPF/Netlink) | `agent/main.py:180-210` |
| **`FINDING-PHASE03-06`** | P3 | 🔵 Low | 3.3 | CWE-799 | Hostname-based agent identity without persistent local machine UUID causing collisions on cloned VMs | `agent/main.py:45-75` |
| **`FINDING-PHASE04-01`** | P4 | 🔴 High | 7.5 | CWE-400 | Server `MAX_CONTENT_LENGTH = 64 KB` rejects realistic baseline syncs and heavy process snapshots | `server/app.py:34`, `server/routes.py:38` |
| **`FINDING-PHASE04-02`** | P4 | 🟡 Medium | 5.3 | CWE-400 | Synchronous in-line threat detection in HTTP ingestion pipeline creates severe scalability bottlenecks | `server/routes.py:330-360` |
| **`FINDING-PHASE04-03`** | P4 | 🟡 Medium | 5.3 | CWE-770 | Dynamic `IN ({placeholders})` in baseline sync risks `sqlite3.OperationalError: too many SQL variables` | `server/repositories/baseline_repository.py:112` |
| **`FINDING-PHASE04-04`** | P4 | 🔵 Low | 3.1 | CWE-1025 | Online/offline state flip-flops without hysteresis or warning state | `server/repositories/endpoint_repository.py:85` |
| **`FINDING-PHASE05-01`** | P5 | 🔴 High | 7.2 | CWE-1059 | Documented core rules `RULE_SHELL_SPAWN` and `RULE_SUSPICIOUS_PROCESS` missing in `detection/rules.py` | `detection/rules.py:70-390` |
| **`FINDING-PHASE05-02`** | P5 | 🔴 High | 7.1 | CWE-670 | Phantom FIM rule bug: `rule-fim-dropped-binary` mocked in tests but absent; `/tmp` drops never trigger alert | `detection/rules.py:317-380` |
| **`FINDING-PHASE05-03`** | P5 | 🔴 High | 7.5 | CWE-693 | Trivial detection evasion: renamed netcat (`/usr/bin/nc`), python reverse shells, CPU $<85\%$ ignored | `detection/rules.py:73-220` |
| **`FINDING-PHASE05-04`** | P5 | 🟡 Medium | 4.3 | CWE-1164 | `min_correlation_score` is a dead parameter in `CorrelationEngine` (never evaluated) | `detection/engine.py:42-70` |
| **`FINDING-PHASE05-05`** | P5 | 🔵 Low | 3.1 | CWE-1059 | Absence of MITRE ATT&CK tagging in detection data structures and schemas | `detection/rules.py:30-40` |
| **`FINDING-PHASE06-01`** | P6 | 🔴 High | 7.5 | CWE-306 | Unauthenticated triage actions and lack of CSRF protection allow any network actor to close incidents | `server/web.py:291-402`, `server/routes.py:530` |
| **`FINDING-PHASE06-02`** | P6 | 🔴 High | 7.1 | CWE-670 | Permanent incident lock-in: resolved alerts cannot be reopened (no API, blocked by state guard) | `server/repositories/alert_repository.py:110` |
| **`FINDING-PHASE06-03`** | P6 | 🟡 Medium | 5.3 | CWE-697 | Involuntary alert severity downgrade from Critical to Medium when a lower-severity recurrent finding arrives | `server/repositories/alert_repository.py:58-62` |
| **`FINDING-PHASE06-04`** | P6 | 🔵 Low | 3.1 | CWE-770 | Web Console hardcodes `limit=100` without UI pagination controls | `server/web.py:254`, `server/web.py:417` |
| **`FINDING-PHASE07-01`** | P7 | 🔴 High | 7.2 | CWE-79 | DOM-based Cross-Site Scripting (DOM XSS) in `viewEvidence()` modal via raw `innerHTML` | `static/dashboard.js:189-221` |
| **`FINDING-PHASE07-02`** | P7 | 🟡 Medium | 6.1 | CWE-79 | Inline event handler attribute breakout XSS in `alerts.html:170` and `dashboard.html:238` | `templates/alerts.html:170`, `dashboard.html:238` |
| **`FINDING-PHASE07-03`** | P7 | 🟡 Medium | 5.3 | CWE-306 | Unauthenticated Web Console exposing fleet process tree, baselines, and events | `server/web.py:38-430` |
| **`FINDING-PHASE07-04`** | P7 | 🔵 Low | 4.3 | CWE-352 | Missing anti-CSRF protection on web state mutation POST actions | `server/web.py:291-402` |
| **`FINDING-PHASE07-05`** | P7 | 🟢 Info | N/A | N/A | 100% Air-Gapped compliance verified (0 external CDNs, 0 fonts, 0 remote scripts) | `templates/base.html`, `static/style.css` |
| **`FINDING-PHASE08-01`** | P8 | 🔴 High | 7.5 | CWE-306 | STRIDE boundary failure: complete lack of access control on Web SOC Console | `server/web.py:1-430` |
| **`FINDING-PHASE08-02`** | P8 | 🔴 High | 7.2 | CWE-1025| False assurance in security test suite regarding XSS resistance (only tests HTML table escaping) | `tests/test_security_reliability.py:143-213` |
| **`FINDING-PHASE08-03`** | P8 | 🟡 Medium | 5.3 | CWE-770 | Uncontrolled telemetry ingestion rate & SQLite lock starvation risk (Denial of Service) | `server/routes.py`, `server/db.py` |
| **`FINDING-PHASE08-04`** | P8 | 🟡 Medium | 5.5 | CWE-59 | Insecure symlink traversal (TOCTOU) in File Integrity Monitoring | `agent/file_integrity.py:92` |
| **`FINDING-PHASE08-05`** | P8 | 🔵 Low | 3.8 | CWE-522 | Shared static PSK exposes entire fleet to lateral impersonation | `server/routes.py`, `agent/client.py` |
| **`FINDING-PHASE08-06`** | P8 | 🟢 Info | N/A | N/A | Architectural immunity to SQLi (100% param SQL), Command Injection (0 subprocess), and SSTI | Project-wide |
| **`DISCREPANCY-DOC-01`** | P9 | 🔴 High | 7.0 | CWE-1059| `python3 -m agent.orchestrator` in README fails with ModuleNotFoundError; actual file is `agent/main.py` | `README.md:102,232`, `ARCHITECTURE.md:111` |
| **`DISCREPANCY-DOC-02`** | P9 | 🔴 High | 6.8 | CWE-1059| Process `cmdline` attribute documented across multiple files but absent from code and database | `README.md:40`, `ARCHITECTURE.md:100` |
| **`DISCREPANCY-DOC-03`** | P9 | 🔴 High | 7.1 | CWE-1059| Documented core rules `RULE_SHELL_SPAWN` and `RULE_SUSPICIOUS_PROCESS` missing in `detection/rules.py` | `README.md:287-293`, `ARCHITECTURE.md:183` |
| **`DISCREPANCY-DOC-04`** | P9 | 🟡 Medium | 4.0 | CWE-1059| Directory tree mismatches in `README.md` (`server/detection/`, `system_metrics_repository.py`) | `README.md:109-122` |
| **`DISCREPANCY-DOC-05`** | P9 | 🟡 Medium | 4.0 | CWE-1059| `docs/API_SPECIFICATION.md` table lists implemented production endpoints as "Designed; pending" | `docs/API_SPECIFICATION.md:104-111` |
| **`DISCREPANCY-DOC-06`** | P9 | 🔵 Low | 3.0 | CWE-1059| Phantom FIM dropped binary detection discrepancy in demo scenario | `docs/DEMO_SCENARIO.md` |

---

## 3. AUDIT FINDINGS CLASSIFICATION & ROOT CAUSE TAXONOMY

### 3.1 Security & Access Control (10 Findings)
- Unauthenticated Web Console (`FINDING-PHASE01-02`, `FINDING-PHASE07-03`, `FINDING-PHASE08-01`, `FINDING-PHASE06-01`).
- Cross-Site Scripting (DOM XSS in `FINDING-PHASE07-01`, Attribute Injection in `FINDING-PHASE07-02`).
- Cross-Site Request Forgery (`FINDING-PHASE07-04`).
- Shared PSK Impersonation (`FINDING-PHASE01-03`, `FINDING-PHASE08-05`).
- Symlink TOCTOU Traversal (`FINDING-PHASE03-04`, `FINDING-PHASE08-04`).

### 3.2 Robustness & Reliability (9 Findings)
- `MAX_CONTENT_LENGTH = 64KB` Payload Drop (`FINDING-PHASE04-01`).
- Missing `SECRET_KEY` Application Crash (`FINDING-PHASE01-01`).
- Eager In-Memory Baseline Advancement & Permanent Event Loss (`FINDING-PHASE03-01`).
- SQLite Lock Contention & Starvation (`FINDING-PHASE08-03`).
- Dynamic SQL Variable Overflow (`FINDING-PHASE04-03`).
- Unbounded High-Frequency Telemetry Growth (`FINDING-PHASE02-03`).
- Synchronous In-line Detection Bottleneck (`FINDING-PHASE04-02`).
- Hardcoded Unpaginated Limit 100 (`FINDING-PHASE06-04`).
- Heartbeat NULL Overwrites (`FINDING-PHASE01-04`).

### 3.3 Detection & SOC Workflow (7 Findings)
- Resolved Alert Permanent Lock-in (`FINDING-PHASE02-01`, `FINDING-PHASE06-02`).
- Trivial Heuristic Rule Evasion (`FINDING-PHASE05-03`).
- Phantom FIM Dropped Binary Rule Bug (`FINDING-PHASE05-02`, `DISCREPANCY-DOC-06`).
- Alert Severity Involuntary Downgrade (`FINDING-PHASE06-03`).
- Dead Parameter `min_correlation_score` (`FINDING-PHASE05-04`).
- Absence of MITRE ATT&CK Tagging (`FINDING-PHASE05-05`).
- Short-Lived Process Blind Spot (`FINDING-PHASE03-05`).

### 3.4 Quality Assurance & Documentation Drift (10 Findings)
- False Assurance in XSS Security Test Suite (`FINDING-PHASE08-02`).
- Broken Agent Execution Command in README (`DISCREPANCY-DOC-01`).
- Claimed `cmdline` Attribute Missing from Collector (`FINDING-PHASE03-02`, `DISCREPANCY-DOC-02`).
- Missing Documented Rules `RULE_SHELL_SPAWN` / `RULE_SUSPICIOUS_PROCESS` (`FINDING-PHASE05-01`, `DISCREPANCY-DOC-03`).
- Directory Layout Mismatches in README (`DISCREPANCY-DOC-04`).
- API Specification Pending Contradiction (`DISCREPANCY-DOC-05`).
- WSGI Token Validation Bypass (`FINDING-PHASE01-05`).
- Hostname Identity Collisions on Cloned VMs (`FINDING-PHASE03-06`).
- Cross-table Message Deduplication Envelope (`FINDING-PHASE02-02`).
- Status Clock Drift Dependence (`FINDING-PHASE02-04`).

---

## 4. CONCLUSION

This comprehensive register serves as the authoritative technical baseline for all future engineering, remediation, and release readiness planning for the Mini EDR Linux platform.
