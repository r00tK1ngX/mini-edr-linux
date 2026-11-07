# PHASE 3 REMEDIATION REPORT — DETECTION CORRECTNESS
**Mini EDR for Linux — Academic Acceptance & Verified Remediation**

- **Project:** Mini EDR Linux (`r00tK1ngX/mini-edr-linux`)
- **Phase:** Phase 3 — Detection Correctness & Threat Correlation
- **Date:** 2026-11-07
- **Branch:** `remediation/academic-acceptance`
- **Base Commit:** `a7abc67`
- **Status:** **COMPLETED & VERIFIED (267 / 267 TESTS PASSED)**

---

## 1. OBJECTIVES & SCOPE

Phase 3 targeted threat detection logic, event correlation mechanics, and alert persistence integrity:
1. Eliminate index mismatch bugs and unsafe list lookups (`index()`) in detection-to-event mapping.
2. Ensure alerts link exclusively to contributing security events rather than linking all snapshot events indiscriminately.
3. Implement parent process resolution (`parent_name`) from the in-snapshot PID->PPID hierarchy to enable accurate shell-spawn and reverse-shell detection.
4. Enforce a bounded correlation time window (`time_window_seconds`) to prevent stale FIM drops from falsely escalating unrelated process executions.
5. Guarantee process identity uniqueness across Linux PID recycling (`pid:process_name:start_time`) to prevent alert key collisions.
6. Provide a comprehensive, standardized, and explainable Rule Registry with input fields, trigger conditions, severity, risk scores, and expected false-positive scenarios.
7. Maintain strict academic boundaries: no exaggerated claims of 100% detection rate or infallible reverse-shell detection.

### Target Findings Addressed

1. **`FINDING-NEW-10` (🟡 Medium / CWE-703):** Unsafe `index()` lookup in single-rule alerts and indiscriminate linking of all snapshot event IDs to every correlated alert.
2. **`FINDING-NEW-11` (🟡 Medium / CWE-703):** `parent_name` never collected or resolved for `ProcessShellSpawnRule`.
3. **`FINDING-PHASE05-03` (🔴 High / CWE-393):** PID reuse collisions and missing correlation time window boundaries.
4. **Database Transaction Consistency:** Ensured atomic commit and rollback in `AlertRepository.create_or_update` using SQLite transaction context managers (`with conn:`).

---

## 2. DETAILED TECHNICAL REMEDIATIONS

### 2.1 Direct Detection-to-Event ID Mapping (`detection/rules.py`, `detection/engine.py`)
- **Direct ID Attachment on `DetectionResult`:**
  - Added `event_id: Optional[int] = None` to the `DetectionResult` dataclass.
  - When `DetectionEngine.evaluate_process_snapshot` persists a detection security event into `security_events`, the returned primary key ID is directly assigned:
    ```python
    saved_event = self.event_repo.record(event_record)
    match.event_id = saved_event["id"]
    created_event_ids.append(saved_event["id"])
    ```
  - For single-rule alerts, `event_id` is passed directly as `d.event_id`. The unsafe `created_event_ids[raw_detections.index(d)]` pattern was completely eliminated, removing any vulnerability to `IndexError` or duplicate detection misalignment when an event persistence call fails.

### 2.2 Granular Correlated Event Linking (`detection/correlation.py`)
- Previously, `correlate_process_and_fim` assigned `associated_event_ids` (the entire snapshot's event IDs) to every correlated alert.
- Refactored `correlate_process_and_fim` to isolate events per process:
  ```python
  proc_event_ids = [d.event_id for d in detections if getattr(d, "event_id", None) is not None]
  fim_event_ids = [fd.event_id for fd in matching_fim if getattr(fd, "event_id", None) is not None]
  correlated_event_ids = list(dict.fromkeys(proc_event_ids + fim_event_ids))
  ```
  Correlated alerts now link strictly to the events belonging to that specific PID and any matched FIM events.

### 2.3 Parent Process Metadata Resolution (`agent/process_collector.py`, `detection/engine.py`)
- **In-Snapshot Hierarchy Resolution:**
  - In `agent/process_collector.py:collect_processes()`, constructed an in-memory dictionary `pid_to_name = {p["pid"]: p["process_name"]}` and enriched every process record with `parent_name = pid_to_name.get(ppid)`.
  - In `detection/engine.py:evaluate_process_snapshot()`, added a secondary resolution pass over `observations` before evaluating detection rules. If `proc.get("parent_name")` is missing, it resolves `parent_name` using `pid_map.get(ppid)`.
  - Enabled `ProcessShellSpawnRule` (`rule-proc-shell-spawn`) to trigger when an interactive shell (`sh`, `bash`, `dash`, `zsh`) has a web daemon parent (`nginx`, `apache2`, `httpd`, `python`, `php`, `node`).

### 2.4 Correlation Time Window Enforcement (`detection/correlation.py`)
- Added `time_window_seconds: int = 300` (default 5 minutes) to `CorrelationEngine`.
- Implemented `_is_within_time_window(fim_detection, proc_detection, reference_time)`:
  - Parses ISO 8601 UTC timestamps from both the FIM event (`occurred_at`) and process metadata (`start_time` or `snapshot_time`).
  - Verifies `abs((proc_dt - fim_dt).total_seconds()) <= self.time_window_seconds`.
  - Stale FIM drop events occurring outside the window are excluded from multi-stage correlation, preventing false incident escalations.

### 2.5 PID Reuse Resilience & Process Identity (`detection/correlation.py`, `detection/rules.py`)
- A Linux PID is not globally unique over time due to kernel PID recycling.
- Process identity is now formed as `proc_identity = f"{pid}:{proc_name}" + (f":{start_time}" if start_time else "")`.
- Correlated alerts generate alert keys using this identity:
  `alert_key = f"{agent_id}:correlated:proc:{proc_identity}"`.
  When a PID is recycled for a new process hours or days later, the distinct `start_time` produces a separate alert key, preventing state collisions or incorrect reopening of past resolved alerts.

### 2.6 Rule Registry Metadata & Documentation (`detection/rules.py`, `detection/RULE_REGISTRY.md`)
- Enhanced `BaseRule` to encapsulate academic documentation attributes:
  - `purpose: str`
  - `input_fields: List[str]`
  - `expected_false_positives: List[str]`
  - `to_dict() -> Dict[str, Any]`
- Added `RuleRegistry.get_rule_catalog()` and `get_rule_by_id(rule_id)` for introspection.
- Published exhaustive documentation in [`detection/RULE_REGISTRY.md`](file:///home/kali/Projects/mini-edr-linux/detection/RULE_REGISTRY.md) detailing all 8 standard rules, trigger conditions, evidence formats, and explicit heuristic boundary statements.

### 2.7 Database Transaction Atomicity (`server/repositories/alert_repository.py`)
- Wrapped `create_or_update` within `with conn:`:
  Ensured that the upsert of the `alerts` record and batch insertion of `alert_events` links occur atomically within a single SQLite transaction, rolling back cleanly if a failure occurs.

---

## 3. VERIFICATION & TEST RESULTS

### 3.1 Dedicated Phase 3 Test Suite (`tests/test_detection_correctness_p3.py`)

A comprehensive 11-test suite was engineered to validate all Phase 3 functional and resilience criteria:

| Test Name | Verification Focus | Result |
| :--- | :--- | :---: |
| `test_detection_to_event_id_direct_mapping` | Direct `d.event_id` assignment without index lookups | ✅ PASSED |
| `test_correlated_alert_links_only_relevant_event_ids` | Correlated alerts link only events for that PID | ✅ PASSED |
| `test_detection_event_mapping_resilience_on_partial_persistence_failure` | DB failure on event 1 does not trigger `IndexError` on event 2 | ✅ PASSED |
| `test_shell_spawn_parent_process_resolution` | PPID->PID mapping resolves parent `nginx` for child `sh` | ✅ PASSED |
| `test_process_collector_enriches_parent_name` | Agent collector enriches `parent_name` across process list | ✅ PASSED |
| `test_correlation_time_window_recent_event_matches` | FIM drop within 300s window correlates into Critical alert | ✅ PASSED |
| `test_correlation_time_window_stale_event_rejected` | FIM drop 2 hours prior is rejected from correlation | ✅ PASSED |
| `test_pid_reuse_distinct_process_identity` | Recycled PID with different start_time yields distinct alert_key | ✅ PASSED |
| `test_rule_registry_catalog_completeness` | All rules declare purpose, inputs, false positives, MITRE tag | ✅ PASSED |
| `test_rule_registry_get_rule_by_id` | Registry retrieves rule instance by ID or returns None | ✅ PASSED |
| `test_heuristic_boundary_transparency` | Rules avoid claims of 100% detection or infallibility | ✅ PASSED |

### 3.2 Full System Regression Results

```
============================= test session starts ==============================
platform linux -- Python 3.14.8, pytest-9.1.1, pluggy-1.7.0
rootdir: /home/kali/Projects/mini-edr-linux
configfile: pytest.ini
collected 267 items

tests/test_agent_client.py ..........                                    [  3%]
tests/test_agent_orchestrator.py .......                                 [  6%]
tests/test_alert_management.py ....................................      [ 19%]
tests/test_api.py ........................................               [ 34%]
tests/test_dashboard.py ...........                                      [ 38%]
tests/test_database.py .............                                     [ 43%]
tests/test_detection.py ..........................                       [ 53%]
tests/test_detection_correctness_p3.py ...........                       [ 57%]
tests/test_file_integrity.py .........                                   [ 61%]
tests/test_fim_reliability_p2.py ..........                              [ 64%]
tests/test_full_system_e2e.py .                                          [ 65%]
tests/test_migrations.py .......                                         [ 67%]
tests/test_phase4_e2e.py ....                                            [ 69%]
tests/test_process_collector.py .............                            [ 74%]
tests/test_repositories.py ............                                  [ 78%]
tests/test_security_reliability.py .........................             [ 88%]
tests/test_system_collector.py ................                          [ 94%]
tests/test_web_security_p1.py ................                           [100%]

============================= 267 passed in 13.77s =============================
```

- **Pass Rate:** 100% (267/267 passed).
- **Regressions:** Zero.

---

## 4. PHASE 3 ACCEPTANCE CHECKLIST

- [x] Unsafe `index()` lookup in detection-to-event mapping completely replaced by direct `DetectionResult.event_id`.
- [x] Correlated alerts link exclusively to contributing security events.
- [x] Parent process name resolution (`parent_name`) implemented in both agent collector and server engine.
- [x] Configurable correlation time window (`time_window_seconds`) enforced.
- [x] PID reuse resilience verified via `start_time` process identity separation.
- [x] Standardized Rule Registry metadata and catalog introspection implemented.
- [x] Complete Rule Registry specification published in [`detection/RULE_REGISTRY.md`](file:///home/kali/Projects/mini-edr-linux/detection/RULE_REGISTRY.md).
- [x] Academic boundary transparency respected (no claims of 100% detection rate).
- [x] Atomic transactions in `AlertRepository.create_or_update`.
- [x] All 267 tests passing.

Phase 3 is completed. Ready for review and authorization to proceed to Phase 4 (Data Integrity).
