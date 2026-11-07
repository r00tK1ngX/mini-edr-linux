# FINAL EVIDENCE INDEX
**Mini EDR for Linux — Final Independent Security Verification & Academic Acceptance**

- **Target Repository:** `https://github.com/r00tK1ngX/mini-edr-linux`
- **Audit Date:** 2026-11-07
- **Audited Commit SHA:** `26cdd4e6f16af42b6fd784431546885a0360597a`
- **Status:** **CROSS-REFERENCED TRACEABILITY INDEX VERIFIED**

---

## 1. COMPONENT-TO-SOURCE & TEST TRACEABILITY INDEX

### 1.1 Web Application Security (`server/web.py`, `server/app.py`)
- **Key Functions:**
  - `is_safe_url`: [server/web.py#L49-L70](file:///home/kali/Projects/mini-edr-linux/server/web.py#L49-L70)
  - `validate_csrf`: [server/web.py#L88-L103](file:///home/kali/Projects/mini-edr-linux/server/web.py#L88-L103)
  - `require_operator_auth`: [server/web.py#L106-L138](file:///home/kali/Projects/mini-edr-linux/server/web.py#L106-L138)
  - `login` (POST CSRF): [server/web.py#L196-L228](file:///home/kali/Projects/mini-edr-linux/server/web.py#L196-L228)
  - `logout` (POST CSRF): [server/web.py#L231-L245](file:///home/kali/Projects/mini-edr-linux/server/web.py#L231-L245)
  - `_resolve_secret_key`: [server/app.py#L23-L45](file:///home/kali/Projects/mini-edr-linux/server/app.py#L23-L45)
- **Automated Regression Suite:**
  - `test_is_safe_url_helper`: [tests/test_web_security_p1.py#L20-L45](file:///home/kali/Projects/mini-edr-linux/tests/test_web_security_p1.py#L20-L45)
  - `test_open_redirect_rejected_on_login`: [tests/test_web_security_p1.py#L47-L70](file:///home/kali/Projects/mini-edr-linux/tests/test_web_security_p1.py#L47-L70)
  - `test_unauthenticated_access_redirects_to_login`: [tests/test_web_security_p1.py#L85-L105](file:///home/kali/Projects/mini-edr-linux/tests/test_web_security_p1.py#L85-L105)
  - `test_token_in_query_string_rejected`: [tests/test_web_security_p1.py#L120-L135](file:///home/kali/Projects/mini-edr-linux/tests/test_web_security_p1.py#L120-L135)
  - `test_login_csrf_validation_missing_token_rejected`: [tests/test_web_security_p1.py#L150-L165](file:///home/kali/Projects/mini-edr-linux/tests/test_web_security_p1.py#L150-L165)
  - `test_logout_via_get_rejected`: [tests/test_web_security_p1.py#L170-L185](file:///home/kali/Projects/mini-edr-linux/tests/test_web_security_p1.py#L170-L185)
  - `test_session_cookie_flags_configured`: [tests/test_web_security_p1.py#L190-L200](file:///home/kali/Projects/mini-edr-linux/tests/test_web_security_p1.py#L190-L200)
  - `test_secret_key_stability_across_reloads`: [tests/test_web_security_p1.py#L202-L215](file:///home/kali/Projects/mini-edr-linux/tests/test_web_security_p1.py#L202-L215)

---

### 1.2 File Integrity Monitoring & Local Event Spool (`agent/spool.py`, `agent/file_integrity.py`)
- **Key Functions:**
  - `EventSpool._init_db`: [agent/spool.py#L80-L119](file:///home/kali/Projects/mini-edr-linux/agent/spool.py#L80-L119)
  - `EventSpool.enqueue_events`: [agent/spool.py#L120-L171](file:///home/kali/Projects/mini-edr-linux/agent/spool.py#L120-L171)
  - `EventSpool.mark_acknowledged`: [agent/spool.py#L205-L229](file:///home/kali/Projects/mini-edr-linux/agent/spool.py#L205-L229)
  - `compute_sha256` (O_NOFOLLOW & fstat): [agent/file_integrity.py#L35-L82](file:///home/kali/Projects/mini-edr-linux/agent/file_integrity.py#L35-L82)
  - `inspect_file`: [agent/file_integrity.py#L84-L141](file:///home/kali/Projects/mini-edr-linux/agent/file_integrity.py#L84-L141)
  - `detect_file_changes`: [agent/file_integrity.py#L209-L292](file:///home/kali/Projects/mini-edr-linux/agent/file_integrity.py#L209-L292)
- **Automated Regression Suite:**
  - `test_fim_toctou_symlink_switch`: [tests/test_fim_reliability_p2.py#L25-L60](file:///home/kali/Projects/mini-edr-linux/tests/test_fim_reliability_p2.py#L25-L60)
  - `test_fim_symlink_pointing_outside_root_is_rejected`: [tests/test_fim_reliability_p2.py#L65-L90](file:///home/kali/Projects/mini-edr-linux/tests/test_fim_reliability_p2.py#L65-L90)
  - `test_spool_enqueue_and_fifo_order`: [tests/test_fim_reliability_p2.py#L95-L125](file:///home/kali/Projects/mini-edr-linux/tests/test_fim_reliability_p2.py#L95-L125)
  - `test_fim_crash_recovery_spool`: [tests/test_fim_reliability_p2.py#L130-L160](file:///home/kali/Projects/mini-edr-linux/tests/test_fim_reliability_p2.py#L130-L160)
  - `test_fim_spool_stable_message_ids`: [tests/test_fim_reliability_p2.py#L165-L185](file:///home/kali/Projects/mini-edr-linux/tests/test_fim_reliability_p2.py#L165-L185)
  - `test_orchestrator_fim_event_retention_on_network_failure`: [tests/test_agent_orchestrator.py#L150-L180](file:///home/kali/Projects/mini-edr-linux/tests/test_agent_orchestrator.py#L150-L180)

---

### 1.3 Detection Engine & Multi-Factor Correlation (`detection/engine.py`, `detection/correlation.py`, `detection/rules.py`)
- **Key Functions:**
  - In-snapshot PPID parent resolution: [detection/engine.py#L58-L73](file:///home/kali/Projects/mini-edr-linux/detection/engine.py#L58-L73)
  - Direct event ID mapping: [detection/engine.py#L96-L102](file:///home/kali/Projects/mini-edr-linux/detection/engine.py#L96-L102)
  - Bounded correlation time window: [detection/correlation.py#L43-L69](file:///home/kali/Projects/mini-edr-linux/detection/correlation.py#L43-L69)
  - Multi-factor risk scoring (0-100): [detection/correlation.py#L100-L175](file:///home/kali/Projects/mini-edr-linux/detection/correlation.py#L100-L175)
  - Process identity (`pid:name:start_time`): [detection/correlation.py#L176-L178](file:///home/kali/Projects/mini-edr-linux/detection/correlation.py#L176-L178)
- **Automated Regression Suite:**
  - `test_detection_event_mapping_integrity`: [tests/test_detection_correctness_p3.py#L25-L65](file:///home/kali/Projects/mini-edr-linux/tests/test_detection_correctness_p3.py#L25-L65)
  - `test_shell_spawn_rule_triggers_with_in_snapshot_parent`: [tests/test_detection_correctness_p3.py#L70-L105](file:///home/kali/Projects/mini-edr-linux/tests/test_detection_correctness_p3.py#L70-L105)
  - `test_correlation_time_window_enforced`: [tests/test_detection_correctness_p3.py#L110-L145](file:///home/kali/Projects/mini-edr-linux/tests/test_detection_correctness_p3.py#L110-L145)
  - `test_pid_reuse_resilience_with_start_time`: [tests/test_detection_correctness_p3.py#L150-L185](file:///home/kali/Projects/mini-edr-linux/tests/test_detection_correctness_p3.py#L150-L185)
  - `test_correlation_associates_only_relevant_event_ids`: [tests/test_detection_correctness_p3.py#L190-L225](file:///home/kali/Projects/mini-edr-linux/tests/test_detection_correctness_p3.py#L190-L225)

---

### 1.4 Data Integrity, Telemetry Ingestion & Pruning (`server/routes.py`, `server/maintenance.py`)
- **Key Functions:**
  - `_compute_canonical_payload_hash`: [server/routes.py#L107-L111](file:///home/kali/Projects/mini-edr-linux/server/routes.py#L107-L111)
  - Idempotency & Conflict (200 vs 409): [server/routes.py#L454-L497](file:///home/kali/Projects/mini-edr-linux/server/routes.py#L454-L497)
  - Parameter chunking (`chunk_size=500`): [server/routes.py#L710-L735](file:///home/kali/Projects/mini-edr-linux/server/routes.py#L710-L735)
  - `prune_telemetry`: [server/maintenance.py#L19-L61](file:///home/kali/Projects/mini-edr-linux/server/maintenance.py#L19-L61)
- **Automated Regression Suite:**
  - `test_process_snapshot_idempotency_payload_hash`: [tests/test_data_integrity_p4.py#L25-L60](file:///home/kali/Projects/mini-edr-linux/tests/test_data_integrity_p4.py#L25-L60)
  - `test_process_snapshot_conflict_rejected`: [tests/test_data_integrity_p4.py#L65-L95](file:///home/kali/Projects/mini-edr-linux/tests/test_data_integrity_p4.py#L65-L95)
  - `test_heartbeat_partial_update_preserves_metadata`: [tests/test_data_integrity_p4.py#L100-L135](file:///home/kali/Projects/mini-edr-linux/tests/test_data_integrity_p4.py#L100-L135)
  - `test_baseline_sync_chunking_large_payload`: [tests/test_data_integrity_p4.py#L140-L175](file:///home/kali/Projects/mini-edr-linux/tests/test_data_integrity_p4.py#L140-L175)
  - `test_telemetry_pruning_removes_old_and_preserves_recent`: [tests/test_resource_reliability_p5.py#L65-L100](file:///home/kali/Projects/mini-edr-linux/tests/test_resource_reliability_p5.py#L65-L100)

---

### 1.5 DOM XSS & Client-Side Hardening (`static/dashboard.js`, `templates/`)
- **Key Functions:**
  - `escapeHtml`: [static/dashboard.js#L383-L396](file:///home/kali/Projects/mini-edr-linux/static/dashboard.js#L383-L396)
  - `renderErrorMessage` (DOM `textContent`): [static/dashboard.js#L97-L104](file:///home/kali/Projects/mini-edr-linux/static/dashboard.js#L97-L104)
  - Delegated click listeners: [static/dashboard.js#L26-L56](file:///home/kali/Projects/mini-edr-linux/static/dashboard.js#L26-L56)
- **Automated Regression Suite:**
  - `test_xss_payload_escaped_in_dashboard_and_modals`: [tests/test_web_security_p1.py#L210-L245](file:///home/kali/Projects/mini-edr-linux/tests/test_web_security_p1.py#L210-L245)
  - `test_attribute_injection_xss_mitigated`: [tests/test_security_reliability.py#L120-L145](file:///home/kali/Projects/mini-edr-linux/tests/test_security_reliability.py#L120-L145)
  - `test_dom_xss_view_evidence_mitigation`: [tests/test_security_reliability.py#L150-L180](file:///home/kali/Projects/mini-edr-linux/tests/test_security_reliability.py#L150-L180)

---

## 2. DYNAMIC RUNTIME VERIFICATION EVIDENCE

### 2.1 Pytest Execution Record
- **Command:** `pytest -v`
- **Output Status:** `287 passed in 16.75s`
- **Pass Rate:** 100.0% (0 failures, 0 errors, 0 skipped)
- **Log Reference:** Task log at `file:///home/kali/.gemini/antigravity-cli/brain/2f030cf6-8c2b-476d-90bd-f71588442318/.system_generated/tasks/task-3892.log`

### 2.2 Live Attack Simulation Record
- **Command:** `python3 scripts/simulate_attack_scenario.py --auto`
- **Executed Pipeline:**
  1. Benign background generation (`syslog`, `sshd`, `bash`).
  2. Dropping suspicious executable in `/tmp/miner_payload`.
  3. FIM change detection (`created` event enqueued and transmitted).
  4. Execution of suspicious process from `/tmp` with 94.5% CPU.
  5. Multi-factor correlation trigger: Suspicious Path (50) + High CPU (30) + FIM Drop (50) = Score 100 (Critical Alert).
  6. Tampering with protected sensitive config `/tmp/mini_edr_demo/secure_config.conf` (High Alert).
- **Result:** Simulated attack executed cleanly, generating correlated Critical alerts and FIM tamper alerts in database.

### 2.3 SQLite Integrity & Concurrency Verification
- `PRAGMA integrity_check;` -> `ok`
- `PRAGMA foreign_key_check;` -> `0 errors`
- `PRAGMA journal_mode;` -> `wal`
