# AUDIT REMEDIATION ROADMAP — MINI EDR FOR LINUX
**Actionable Prioritization Matrix, Remediation Specs & Engineering Roadmap**

- **Target Repository:** `r00tK1ngX/mini-edr-linux`
- **Scope:** Resolution of all 36 Audit Findings across Phases 1 to 10
- **Auditor:** Senior Cybersecurity Engineer & Security Auditor (Independent Review)
- **Date:** 2026-11-06
- **Status:** COMPLETED — AUDIT-ONLY (No code modified, zero data altered)

---

## 1. PRIORITIZATION MATRIX OVERVIEW

All 36 findings from the master register have been mapped into 4 strict engineering priority tiers based on exploitability, operational impact, and release readiness:

| Priority | Urgency & SLA | Focus Area | Finding Count | Release Impact |
| :---: | :---: | :--- | :---: | :--- |
| **P0** | **Immediate (24–48h)** | Critical security vulnerabilities & execution crashes | **5** | **Hard Blocker for Release** |
| **P1** | **High (1 Week)** | Access control, data loss, rule defects & broken flows | **4** | **Blocker for Production Deployment** |
| **P2** | **Medium (2–3 Weeks)** | Scalability, DoS resilience, FIM performance & schemas | **6** | Required for Minor Version v1.1.0 |
| **P3** | **Low / Backlog** | Architectural evolution, eBPF upgrade & mTLS | **5** | Roadmap for Major Version v2.0.0 |

---

## 2. P0: IMMEDIATE RELEASE BLOCKERS (EXECUTE BEFORE DEFENSE / DEMO)

### `ACTION-P0-01`: Fix DOM-based XSS in `viewEvidence()` Modal
- **Resolves:** `FINDING-PHASE07-01` (CVSS 7.2)
- **Affected File:** `static/dashboard.js` (Lines 189–221)
- **Technical Fix:**
  Wrap all untrusted telemetry fields (`alert.title`, `alert.description`, `alert.resolution_note`, `ev.title`, `ev.event_type`, and formatted JSON) in `escapeHtml()`.
- **Target Implementation:**
  ```javascript
  // In static/dashboard.js inside viewEvidence(alertId):
  body.innerHTML = `
    <div style="margin-bottom: 1.25rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
        <h3 style="color: #fff; font-size: 1.1rem;">${escapeHtml(alert.title)}</h3>
        <span class="badge badge-${escapeHtml(alert.severity)}">${escapeHtml(alert.severity.toUpperCase())}</span>
      </div>
      <p style="color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 0.75rem;">${escapeHtml(alert.description || "No description provided.")}</p>
      ...
      ${alert.resolution_note ? `...<span style="color: var(--neon-green);">${escapeHtml(alert.resolution_note)}</span>` : ""}
    </div>
    ...
  `;
  ```

---

### `ACTION-P0-02`: Fix Inline Attribute Breakout XSS in Incident Modals
- **Resolves:** `FINDING-PHASE07-02` (CVSS 6.1)
- **Affected Files:** `templates/alerts.html` (Line 170), `templates/dashboard.html` (Line 238)
- **Technical Fix:**
  Remove inline `onclick` string parameter passing. Bind alert IDs and titles via HTML5 data attributes:
  ```html
  <!-- Replace this: -->
  <button type="button" class="btn btn-green btn-sm" onclick="promptResolveAlert({{ a.id }}, '{{ a.title|escape }}')">
  
  <!-- With this: -->
  <button type="button" class="btn btn-green btn-sm btn-resolve"
          data-alert-id="{{ a.id }}"
          data-alert-title="{{ a.title }}">
    RESOLVE
  </button>
  ```
  In `static/dashboard.js`, attach a delegated event listener:
  ```javascript
  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".btn-resolve");
    if (btn) {
      promptResolveAlert(btn.dataset.alertId, btn.dataset.alertTitle);
    }
  });
  ```

---

### `ACTION-P0-03`: Configure `SECRET_KEY` to Prevent HTTP 500 Crashes on Form POST
- **Resolves:** `FINDING-PHASE01-01` (CVSS 7.5)
- **Affected File:** `server/app.py` (Line 30)
- **Technical Fix:**
  Provide a default or environment-loaded secret key in `create_app()`:
  ```python
  import secrets

  app.config.setdefault(
      "SECRET_KEY",
      test_config.get("SECRET_KEY") if test_config else os.getenv("SECRET_KEY", secrets.token_hex(32))
  )
  ```

---

### `ACTION-P0-04`: Increase `MAX_CONTENT_LENGTH` to Accommodate Full Baselines
- **Resolves:** `FINDING-PHASE04-01` (CVSS 7.5)
- **Affected File:** `server/app.py` (Line 34)
- **Technical Fix:**
  Increase maximum payload size from 64 KiB to 16 MiB:
  ```python
  # Change:
  "MAX_CONTENT_LENGTH": 64 * 1024  # 64 KiB
  # To:
  "MAX_CONTENT_LENGTH": 16 * 1024 * 1024  # 16 MiB
  ```

---

### `ACTION-P0-05`: Correct Quickstart Command in `README.md`
- **Resolves:** `DISCREPANCY-DOC-01` (CVSS 7.0)
- **Affected File:** `README.md` (Line 102, Line 232)
- **Technical Fix:**
  Replace `python3 -m agent.orchestrator` with `python3 -m agent.main`.

---

## 3. P1: CRITICAL SECURITY & LOGICAL INTEGRITY (WITHIN 1 WEEK)

### `ACTION-P1-01`: Implement Authentication & Anti-CSRF on Web SOC Console
- **Resolves:** `FINDING-PHASE01-02`, `FINDING-PHASE06-01`, `FINDING-PHASE07-03`, `FINDING-PHASE08-01`
- **Affected Files:** `server/web.py`, `server/app.py`
- **Implementation Strategy:**
  1. Integrate `Flask-WTF` (`CSRFProtect(app)`) to enforce anti-CSRF tokens on all POST requests.
  2. Protect all routes under `web_bp` with a session-based login gate or HTTP Basic Auth decorator:
     ```python
     @web_bp.before_request
     def require_operator_session():
         if request.endpoint and request.endpoint.startswith("web."):
             if not session.get("operator_authenticated"):
                 return redirect(url_for("web.login"))
     ```

---

### `ACTION-P1-02`: Enable Automatic Re-opening of Resolved Alerts on Threat Recurrence
- **Resolves:** `FINDING-PHASE02-01`, `FINDING-PHASE06-02`
- **Affected File:** `server/repositories/alert_repository.py` (Lines 43–65)
- **Implementation Strategy:**
  In `AlertRepository.create_or_update()`, update the SQLite `ON CONFLICT(alert_key)` clause to transition resolved alerts back to `new`:
  ```sql
  ON CONFLICT(alert_key) DO UPDATE SET
      last_seen_at = excluded.last_seen_at,
      status = CASE 
          WHEN alerts.status = 'resolved' THEN 'new' 
          ELSE alerts.status 
      END,
      resolution_note = CASE 
          WHEN alerts.status = 'resolved' THEN NULL 
          ELSE alerts.resolution_note 
      END,
      updated_at = excluded.updated_at
  ```

---

### `ACTION-P1-03`: Implement Agent Outbox Spooling to Prevent FIM Event Loss
- **Resolves:** `FINDING-PHASE03-01` (CVSS 7.5)
- **Affected Files:** `agent/main.py` (Lines 215–245), `agent/file_integrity.py`
- **Implementation Strategy:**
  Do not advance the internal baseline in `AgentOrchestrator._run_fim_cycle()` unless the HTTP client confirms successful transmission (`res.status_code == 200` or `201`). If sending fails, retain previous baseline in memory so that the changes will be recalculated and re-transmitted on the next cycle.

---

### `ACTION-P1-04`: Align Detection Rules and Add Missing `rule-fim-dropped-binary`
- **Resolves:** `FINDING-PHASE05-01`, `FINDING-PHASE05-02`, `DISCREPANCY-DOC-03`, `DISCREPANCY-DOC-06`
- **Affected File:** `detection/rules.py`
- **Implementation Strategy:**
  1. Add `FimDroppedBinaryRule` (`rule-fim-dropped-binary`) to `detection/rules.py` targeting binaries dropped into `/tmp` and `/dev/shm`.
  2. Implement `ProcessShellSpawnRule` (`rule-proc-shell-spawn`) to detect shell spawning from web server parents (`apache2`, `nginx`).
  3. Ensure rule IDs and documentation match exactly.

---

## 4. P2: ARCHITECTURAL HARDENING & RELIABILITY (WITHIN 2–3 WEEKS)

| Action ID | Finding ID | Target Component | Engineering Remediation |
| :--- | :--- | :--- | :--- |
| **`ACTION-P2-01`** | `FINDING-PHASE08-03` | `server/routes.py` | Add `Flask-Limiter` middleware capping ingestion requests (e.g. 60 req/min per agent) to prevent SQLite lock contention. |
| **`ACTION-P2-02`** | `FINDING-PHASE03-03` | `agent/file_integrity.py` | Introduce `os.stat()` `mtime_ns` and `st_size` fast-path cache. Only invoke `hashlib.sha256()` when file metadata changes. |
| **`ACTION-P2-03`** | `FINDING-PHASE03-04`, `FINDING-PHASE08-04` | `agent/file_integrity.py` | Replace `Path.resolve()` with `os.lstat()` and `is_symlink()` to prevent TOCTOU symlink traversal outside monitored paths. |
| **`ACTION-P2-04`** | `FINDING-PHASE06-03` | `server/repositories/alert_repository.py` | Prevent involuntary severity downgrade by using `MAX(alerts.severity_weight, excluded.severity_weight)` in upsert logic. |
| **`ACTION-P2-05`** | `FINDING-PHASE04-03` | `server/repositories/baseline_repository.py` | Chunk `file_path NOT IN ({placeholders})` queries in batches of 500 paths to prevent SQLite parameter variable overflow. |
| **`ACTION-P2-06`** | `FINDING-PHASE03-02`, `DISCREPANCY-DOC-02` | `agent/process_collector.py`, `server/migrations/` | Extract `p.info.get("cmdline")` in `ProcessCollector` and add `cmdline TEXT` column via migration `002_add_cmdline.sql`. |

---

## 5. P3: LONG-TERM ENTERPRISE SCALING (FUTURE RELEASES)

| Action ID | Finding ID | Future Scope | Architectural Evolution |
| :--- | :--- | :--- | :--- |
| **`ACTION-P3-01`** | `FINDING-PHASE03-06` | Persistent Machine UUID | Generate and store a persistent UUID in `/etc/mini_edr/machine-id` instead of volatile hostname to support cloned VMs. |
| **`ACTION-P3-02`** | `FINDING-PHASE01-03`, `FINDING-PHASE08-05` | Mutual TLS (mTLS) | Replace static Bearer token with per-endpoint X.509 client certificates and server CN validation. |
| **`ACTION-P3-03`** | `FINDING-PHASE04-02` | Asynchronous Worker Queue | Decouple detection engine from HTTP ingestion loop using Celery / Redis background worker tasks. |
| **`ACTION-P3-04`** | `FINDING-PHASE03-05` | eBPF Kernel Probe Upgrade | Transition from `/proc` polling to eBPF tracepoints (`sys_enter_execve`, `sys_enter_connect`) for microsecond process capture. |
| **`ACTION-P3-05`** | `FINDING-PHASE02-03` | Telemetry Retention & Vacuum | Implement automated data retention job pruning `process_observations` and `system_metrics` older than 30 days. |

---

## 6. VERIFICATION & REGRESSION TESTING PLAN

Following implementation of each action:
1. Re-run complete test suite: `.venv/bin/pytest -v`.
2. Execute scratch harness `/scratch/audit_phase7_dashboard_comprehensive.py` to confirm zero DOM and attribute XSS.
3. Validate end-to-end attack simulation: `.venv/bin/python scripts/simulate_attack_scenario.py`.
4. Verify PRAGMA integrity: `PRAGMA integrity_check == 'ok'`.
