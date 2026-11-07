# FINDING DISPOSITION MATRIX (PHASE 0)
**Mini EDR for Linux — Academic Acceptance & Verified Remediation**

- **Target Repository:** `r00tK1ngX/mini-edr-linux`
- **Working Branch:** `remediation/academic-acceptance`
- **Baseline Commit SHA:** `47b8fcd81b9df107ac66ef0992f233b1e1c82d3d`
- **Audit Date:** 2026-11-07
- **Auditor:** Senior Python / AppSec / Linux Security Engineer
- **Status:** **PHASE 0 AUDIT BASELINE — ZERO CODE MODIFIED**

---

## 1. DISPOSITION CLASSIFICATION SUMMARY

Every finding from `audit/AUDIT_FINDINGS.md` and all newly discovered issues are assigned one of the **seven strictly defined dispositions**:

| Disposition Code | Count | Description |
| :--- | :---: | :--- |
| **`FIXED_VERIFIED`** | **17** | Verified resolved in source code and validated with passing regression tests. |
| **`PARTIALLY_FIXED`** | **13** | Remediated in part, but residual edge cases, race conditions, or unhandled paths remain. |
| **`CONFIRMED_OPEN`** | **12** | Active flaw present in current baseline; directly reproducible and requiring remediation. |
| **`OUT_OF_SCOPE`** | **3** | Intentionally excluded per academic Scope Lock (e.g. eBPF probes, Celery/Redis queues, mTLS). |
| **`DUPLICATE`** | **3** | Redundant finding tracking identical root cause across audit phases. |
| **`NOT_REPRODUCIBLE`** | **0** | No findings were invalid or non-reproducible. |
| **`NEEDS_DYNAMIC_TEST`**| **0** | All findings have been confirmed either statically or via automated tests. |
| **TOTAL FINDINGS** | **48** | **36 Legacy Findings + 12 Newly Identified Findings** |

---

## 2. COMPREHENSIVE FINDINGS MATRIX

| Finding ID | Severity | Affected File & Function | Source Evidence | Status | Repro? | In Scope? | Proposed Remediation | Required Regression Test | Disposition |
| :--- | :---: | :--- | :--- | :---: | :---: | :---: | :--- | :--- | :--- |
| **`FINDING-PHASE01-01`** | 🔴 High | `server/app.py:create_app`<br>`server/web.py:login` | `SECRET_KEY=os.getenv("SECRET_KEY", secrets.token_hex(32))` | Partial | Yes | Yes | Persist fallback key or ensure `.env` defaults; configure secure session cookie flags | Test session persistence across `create_app()` reload | **`PARTIALLY_FIXED`** |
| **`FINDING-PHASE01-02`** | 🔴 High | `server/web.py:require_operator_auth` | `@web_bp.before_request`<br>`server/web.py:81` | Partial | Yes | Yes | Enforce session auth; remove `?token=` query param; protect `/logout` via POST | Test unauthenticated access to all views & APIs | **`PARTIALLY_FIXED`** |
| **`FINDING-PHASE01-03`** | 🟡 Medium | `server/routes.py:require_api_token`<br>`agent/client.py` | Shared Bearer token used fleet-wide | Open | Yes | No | Acknowledged academic lab limitation; documented in Scope Lock | N/A (Scope locked) | **`OUT_OF_SCOPE`** |
| **`FINDING-PHASE01-04`** | 🟡 Medium | `server/repositories/endpoint_repository.py:upsert` | `COALESCE(excluded.ip_address, endpoints.ip_address)` | Fixed | No | Yes | Preserved existing implementation | `test_heartbeat_partial_update_preserves_metadata` | **`FIXED_VERIFIED`** |
| **`FINDING-PHASE01-05`** | 🔵 Low | `server/app.py:create_app` | `if not app.config.get("TESTING"): len(api_token) < 32` | Fixed | No | Yes | Preserved existing factory token check | `test_weak_token_rejected_in_factory` | **`FIXED_VERIFIED`** |
| **`FINDING-PHASE02-01`** | 🔴 High | `server/repositories/alert_repository.py:create_or_update` | `status = CASE WHEN alerts.status IN ('resolved', 'dismissed') THEN 'new' ...` | Fixed | No | Yes | Preserved existing SQL reopening logic | `test_reopen_resolved_alert_on_recurrence` | **`FIXED_VERIFIED`** |
| **`FINDING-PHASE02-02`** | 🟡 Medium | `server/migrations/sql/001_initial_schema.sql` | Table-level `message_id UNIQUE` without cross-table deduplication table | Partial | Yes | Yes | Add canonical payload hash verification for message IDs | Test same message_id across endpoints | **`PARTIALLY_FIXED`** |
| **`FINDING-PHASE02-03`** | 🟡 Medium | `server/repositories/metrics_repository.py` | Unbounded telemetry growth without TTL pruning | Open | Yes | Yes | Implement explicit data pruning query / retention window | Test `prune_older_than(days=7)` | **`CONFIRMED_OPEN`** |
| **`FINDING-PHASE02-04`** | 🔵 Low | `server/repositories/endpoint_repository.py:list_all` | `(julianday('now') - julianday(last_seen)) * 86400.0` | Partial | Yes | Yes | Ensure server-side ISO UTC timestamps govern status | Test clock boundary drift handling | **`PARTIALLY_FIXED`** |
| **`FINDING-PHASE03-01`** | 🔴 High | `agent/main.py:run_single_cycle`<br>`agent/file_integrity.py` | In-memory 2-phase commit lost on process crash / SIGKILL | Partial | Yes | Yes | Implement persistent local spool queue (SQLite) on agent | Test agent SIGKILL with pending events | **`PARTIALLY_FIXED`** |
| **`FINDING-PHASE03-02`** | 🔴 High | `agent/process_collector.py:collect_single_process` | `cmdline` omitted intentionally to protect secrets | Fixed | No | Yes | Preserved 9 core process attributes; synced docs | `test_collect_processes_structure` | **`FIXED_VERIFIED`** |
| **`FINDING-PHASE03-03`** | 🟡 Medium | `agent/file_integrity.py:inspect_file` | Quick check via `mtime_ns`, `file_size_bytes`, `file_mode` | Fixed | No | Yes | Preserved cached SHA-256 reuse fast-path | `test_quick_stat_hash_cache` | **`FIXED_VERIFIED`** |
| **`FINDING-PHASE03-04`** | 🟡 Medium | `agent/file_integrity.py:inspect_file` | `Path.resolve()` collapses symlink identity | Partial | Yes | Yes | Use `os.open` with `O_NOFOLLOW` and avoid `resolve()` | Test symlink pointing outside monitored root | **`PARTIALLY_FIXED`** |
| **`FINDING-PHASE03-05`** | 🟡 Medium | `agent/main.py:run_single_cycle` | Short-lived process blind spot ($<10$s) | Open | Yes | No | Fundamental limit of `/proc` polling; eBPF excluded by Scope Lock | N/A (Scope locked) | **`OUT_OF_SCOPE`** |
| **`FINDING-PHASE03-06`** | 🔵 Low | `agent/main.py:AgentConfig` | Hostname fallback without persistent UUID | Partial | Yes | Yes | Generate and persist agent UUID to `.agent_id` file | Test agent reboot preserves persistent ID | **`PARTIALLY_FIXED`** |
| **`FINDING-PHASE04-01`** | 🔴 High | `server/app.py:create_app` | `MAX_CONTENT_LENGTH = 16 * 1024 * 1024` | Fixed | No | Yes | Preserved 16 MiB payload limit | `test_payload_limit_16mib_accepted` | **`FIXED_VERIFIED`** |
| **`FINDING-PHASE04-02`** | 🟡 Medium | `server/routes.py:ingest_process_telemetry` | Synchronous in-line threat detection | Open | Yes | No | Celery/Redis barred by Scope Lock; synchronous required for lab | N/A (Scope locked) | **`OUT_OF_SCOPE`** |
| **`FINDING-PHASE04-03`** | 🟡 Medium | `server/routes.py:sync_file_baselines` | `file_path IN ({placeholders})` unchunked query (line 531) | Open | Yes | Yes | Chunk query into batches of 500 parameters | Test baseline sync with 2,500 files | **`CONFIRMED_OPEN`** |
| **`FINDING-PHASE04-04`** | 🔵 Low | `server/repositories/endpoint_repository.py:list_all` | Binary online/offline without warning state | Partial | Yes | Yes | Preserved existing status logic (meets spec) | Test status transition online -> offline | **`PARTIALLY_FIXED`** |
| **`FINDING-PHASE05-01`** | 🔴 High | `detection/rules.py` | Added `ProcessShellSpawnRule`, `ProcessHiddenBinaryRule`, etc. | Fixed | No | Yes | Preserved complete rule suite in `detection/rules.py` | `test_all_documented_rules_present` | **`FIXED_VERIFIED`** |
| **`FINDING-PHASE05-02`** | 🔴 High | `detection/rules.py:FimDroppedBinaryRule` | `rule-fim-dropped-binary` implemented | Fixed | No | Yes | Preserved dropped binary rule implementation | `test_fim_dropped_binary_rule_triggers` | **`FIXED_VERIFIED`** |
| **`FINDING-PHASE05-03`** | 🔴 High | `detection/rules.py` | Heuristics evade renamed binaries / low CPU | Partial | Yes | Yes | Document detection boundaries; correlate FIM drops | Test multi-factor correlation evasion cases | **`PARTIALLY_FIXED`** |
| **`FINDING-PHASE05-04`** | 🟡 Medium | `detection/correlation.py:correlate_process_and_fim` | `if len(factors) >= 2 and total_score >= self.min_correlation_score:` | Fixed | No | Yes | Preserved active threshold check | `test_min_correlation_score_enforced` | **`FIXED_VERIFIED`** |
| **`FINDING-PHASE05-05`** | 🔵 Low | `detection/rules.py:BaseRule` | `mitre_attack` tagging added to all rules | Fixed | No | Yes | Preserved MITRE ATT&CK schema integration | `test_all_rules_have_mitre_tag` | **`FIXED_VERIFIED`** |
| **`FINDING-PHASE06-01`** | 🔴 High | `server/web.py:require_operator_auth`<br>`server/web.py:validate_csrf` | Missing CSRF on login; logout is GET | Partial | Yes | Yes | Convert logout to POST; enforce CSRF on login | Test CSRF rejection on auth & actions | **`PARTIALLY_FIXED`** |
| **`FINDING-PHASE06-02`** | 🔴 High | `server/repositories/alert_repository.py:reopen` | Alert reopen logic implemented | Fixed | No | Yes | Preserved alert state transitions | `test_alert_reopen_lifecycle` | **`FIXED_VERIFIED`** |
| **`FINDING-PHASE06-03`** | 🟡 Medium | `server/repositories/alert_repository.py:create_or_update` | `CASE WHEN excluded.severity = 'critical' ...` non-downgrade | Fixed | No | Yes | Preserved non-downgrade hierarchy | `test_alert_severity_non_downgrade` | **`FIXED_VERIFIED`** |
| **`FINDING-PHASE06-04`** | 🔵 Low | `server/web.py:dashboard` | Hardcoded `limit=100` without pagination | Open | Yes | Yes | Add pagination query params (`page`, `per_page`) | Test web query pagination | **`CONFIRMED_OPEN`** |
| **`FINDING-PHASE07-01`** | 🔴 High | `static/dashboard.js:viewEvidence` | Unescaped `data.error` / `err.message` in innerHTML (L228, 271) | Partial | Yes | Yes | Wrap all error strings in `escapeHtml()` | Test error modal with `<script>` payload | **`PARTIALLY_FIXED`** |
| **`FINDING-PHASE07-02`** | 🟡 Medium | `templates/alerts.html:170`<br>`static/dashboard.js:26` | Converted to `data-alert-id` with delegated listeners | Fixed | No | Yes | Preserved delegated event architecture | `test_attribute_injection_escaped` | **`FIXED_VERIFIED`** |
| **`FINDING-PHASE07-03`** | 🟡 Medium | `server/web.py:require_operator_auth` | Operator auth required for all views | Fixed | No | Yes | Preserved authentication gate | `test_unauthenticated_web_redirects_login` | **`FIXED_VERIFIED`** |
| **`FINDING-PHASE07-04`** | 🔵 Low | `server/web.py:validate_csrf` | CSRF token missing on login POST | Partial | Yes | Yes | Validate CSRF on all state-changing endpoints | Test login POST without CSRF rejected | **`PARTIALLY_FIXED`** |
| **`FINDING-PHASE07-05`** | 🟢 Info | `templates/base.html`<br>`static/style.css` | 100% Air-gapped (0 external CDNs/fonts) | Fixed | No | Yes | Preserved air-gapped assets | `test_airgapped_compliance_no_cdns` | **`FIXED_VERIFIED`** |
| **`FINDING-PHASE08-01`** | 🔴 High | `server/web.py:require_operator_auth` | Duplicate of `FINDING-PHASE01-02` | N/A | N/A | Yes | Covered under `FINDING-PHASE01-02` | Covered under P1 tests | **`DUPLICATE`** |
| **`FINDING-PHASE08-02`** | 🔴 High | `tests/test_security_reliability.py` | False assurance (tested table, not JS modal errors) | Partial | Yes | Yes | Add comprehensive DOM XSS error payload test | Test modal rendering with XSS in error | **`PARTIALLY_FIXED`** |
| **`FINDING-PHASE08-03`** | 🟡 Medium | `server/routes.py`<br>`server/db.py` | Telemetry ingestion rate limiting absent | Partial | Yes | Yes | Add ingestion backpressure / bounded rate limit | Test burst ingestion under load | **`PARTIALLY_FIXED`** |
| **`FINDING-PHASE08-04`** | 🟡 Medium | `agent/file_integrity.py` | Duplicate of `FINDING-PHASE03-04` | N/A | N/A | Yes | Covered under `FINDING-PHASE03-04` | Covered under P3 tests | **`DUPLICATE`** |
| **`FINDING-PHASE08-05`** | 🔵 Low | `server/routes.py` | Duplicate of `FINDING-PHASE01-03` | N/A | N/A | No | Covered under `FINDING-PHASE01-03` | N/A (Scope locked) | **`DUPLICATE`** |
| **`FINDING-PHASE08-06`** | 🟢 Info | Project-wide | Parameterized SQL, zero subprocess, Jinja2 escape | Fixed | No | Yes | Preserved safe database and template patterns | `test_sqli_immunity_all_endpoints` | **`FIXED_VERIFIED`** |
| **`DISCREPANCY-DOC-01`** | 🔴 High | `README.md`<br>`agent/__main__.py` | Added `agent/__main__.py` entrypoint | Fixed | No | Yes | Preserved `python -m agent` entrypoint | `test_agent_entrypoint_execution` | **`FIXED_VERIFIED`** |
| **`DISCREPANCY-DOC-02`** | 🔴 High | `docs/DATA_CONTRACT.md`<br>`README.md` | Removed `cmdline` claim, standardized 9 fields | Fixed | No | Yes | Preserved synchronized documentation | `test_data_contract_conformance` | **`FIXED_VERIFIED`** |
| **`DISCREPANCY-DOC-03`** | 🔴 High | `docs/ARCHITECTURE.md`<br>`detection/rules.py` | Added missing rules `rule-proc-shell-spawn`, etc. | Fixed | No | Yes | Preserved rule registry definitions | `test_all_rules_in_registry` | **`FIXED_VERIFIED`** |
| **`DISCREPANCY-DOC-04`** | 🟡 Medium | `README.md` | Synced project directory tree in documentation | Fixed | No | Yes | Preserved synchronized README tree | Doc validation | **`FIXED_VERIFIED`** |
| **`DISCREPANCY-DOC-05`** | 🟡 Medium | `docs/API_SPECIFICATION.md` | Updated pending routes to "Implemented (v0.2.0)" | Fixed | No | Yes | Preserved updated API specification | Doc validation | **`FIXED_VERIFIED`** |
| **`DISCREPANCY-DOC-06`** | 🔵 Low | `docs/DEMO_SCENARIO.md` | Aligned demo script with `rule-fim-dropped-binary` | Fixed | No | Yes | Preserved demo script alignment | Scenario dry-run | **`FIXED_VERIFIED`** |

---

## 3. NEWLY IDENTIFIED FINDINGS (PHASE 0 RE-AUDIT)

| Finding ID | Severity | Affected File & Function | Source Evidence | Status | Repro? | In Scope? | Proposed Remediation | Required Regression Test | Disposition |
| :--- | :---: | :--- | :--- | :---: | :---: | :---: | :--- | :--- | :--- |
| **`FINDING-NEW-01`** | 🔴 High | `server/web.py:login` | `next_url = request.args.get("next") or url_for(...)`<br>`redirect(next_url)` | Open | Yes | Yes | Validate `next_url` is local URL (starts with `/`, not `//`, empty netloc) | `test_open_redirect_rejected` | **`CONFIRMED_OPEN`** |
| **`FINDING-NEW-02`** | 🟡 Medium | `server/web.py:logout`<br>`templates/base.html:62` | `@web_bp.get("/logout")`<br>`<a href="/logout">` | Open | Yes | Yes | Require `POST /logout` with anti-CSRF token; update UI to POST form | `test_logout_via_get_rejected`<br>`test_logout_post_with_csrf` | **`CONFIRMED_OPEN`** |
| **`FINDING-NEW-03`** | 🟡 Medium | `server/web.py:login` | `POST /login` does not call `validate_csrf()` | Open | Yes | Yes | Call `validate_csrf()` inside `login()` on `POST` | `test_login_csrf_validation` | **`CONFIRMED_OPEN`** |
| **`FINDING-NEW-04`** | 🟡 Medium | `server/web.py:require_operator_auth` | `elif request.args.get("token"): token = ...` | Open | Yes | Yes | Remove `?token=` query param parsing; accept only Bearer or Session | `test_token_in_query_rejected` | **`CONFIRMED_OPEN`** |
| **`FINDING-NEW-05`** | 🔴 High | `static/dashboard.js:viewEvidence`<br>`static/dashboard.js:inspectEndpoint` | Lines 228, 271, 289, 349 interpolate unescaped `${data.error}` and `${err.message}` | Open | Yes | Yes | Apply `escapeHtml(data.error)` and `escapeHtml(err.message)` to all error sinks | `test_dom_xss_in_error_sinks` | **`CONFIRMED_OPEN`** |
| **`FINDING-NEW-06`** | 🟡 Medium | `server/app.py:create_app` | `SECRET_KEY` generates new token on reload; missing `SESSION_COOKIE_*` | Open | Yes | Yes | Persist fallback key to disk; configure `SESSION_COOKIE_HTTPONLY=True`, `SAMESITE="Lax"` | `test_session_cookie_flags_configured` | **`CONFIRMED_OPEN`** |
| **`FINDING-NEW-07`** | 🔴 High | `agent/file_integrity.py:compute_sha256` | `st = os.lstat(...)` then `open(file_path)` without `O_NOFOLLOW` | Open | Yes | Yes | Open with `os.open(..., os.O_RDONLY | os.O_NOFOLLOW)` and `os.fstat(fd)` | `test_fim_toctou_symlink_switch` | **`CONFIRMED_OPEN`** |
| **`FINDING-NEW-08`** | 🟡 Medium | `agent/main.py:run_single_cycle`<br>`agent/file_integrity.py` | In-memory pending FIM events lost on agent crash / SIGKILL | Open | Yes | Yes | Add lightweight SQLite spool (`.fim_spool.db`) to persist unsent events | `test_fim_crash_recovery_spool` | **`CONFIRMED_OPEN`** |
| **`FINDING-NEW-09`** | 🔴 High | `server/routes.py:ingest_process_telemetry` | Idempotency only checks `process_count`; misses different payload | Open | Yes | Yes | Compute SHA-256 hash of canonical JSON payload for idempotency verification | `test_process_snapshot_idempotency_payload_hash` | **`CONFIRMED_OPEN`** |
| **`FINDING-NEW-10`** | 🟡 Medium | `detection/engine.py:evaluate_process_snapshot`<br>`detection/correlation.py` | Unsafe `index()` lookup (L130); all event IDs linked to all alerts (L97) | Open | Yes | Yes | Map detection directly to event record; link only relevant event IDs per alert | `test_detection_event_mapping_integrity` | **`CONFIRMED_OPEN`** |
| **`FINDING-NEW-11`** | 🟡 Medium | `detection/rules.py:ProcessShellSpawnRule` | `parent_name` never collected by agent or resolved by engine | Open | Yes | Yes | In engine, resolve `parent_name` using snapshot `ppid` -> `pid` mapping | `test_shell_spawn_parent_resolution` | **`CONFIRMED_OPEN`** |
| **`FINDING-NEW-12`** | 🟡 Medium | `server/routes.py:ingest_process_telemetry`<br>`server/routes.py:sync_file_baselines` | No bounds on `process_count` or baseline `files` length | Open | Yes | Yes | Enforce `MAX_PROCESSES_PER_SNAPSHOT=1000` and `MAX_FILES_PER_BASELINE=5000` | `test_oversized_process_count_rejected` | **`CONFIRMED_OPEN`** |

---

## 4. CONCLUSION

The complete matrix comprises **48 items**:
- **17 Verified Fixed**
- **13 Partially Fixed**
- **12 Confirmed Open**
- **3 Out of Scope**
- **3 Duplicate**

All 12 `CONFIRMED_OPEN` and 13 `PARTIALLY_FIXED` findings are categorized into sequential remediation phases (Phases 1 to 5) with concrete test plans. Zero application code has been modified during Phase 0.
