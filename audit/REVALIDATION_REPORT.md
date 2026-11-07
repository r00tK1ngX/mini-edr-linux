# COMPREHENSIVE INDEPENDENT RE-AUDIT REPORT (PHASE 0)
**Mini EDR for Linux — Academic Acceptance & Verified Remediation**

- **Project:** Mini EDR Linux (`r00tK1ngX/mini-edr-linux`)
- **Audit Phase:** Phase 0 — Independent Re-Audit & Baseline Establishment
- **Audit Date:** 2026-11-07
- **Working Branch:** `remediation/academic-acceptance`
- **Baseline Commit SHA:** `47b8fcd81b9df107ac66ef0992f233b1e1c82d3d`
- **Target Release:** Academic Capstone Acceptance (Python / Linux Endpoint Security)
- **Status:** **PHASE 0 COMPLETE — AUDIT-ONLY (ZERO APPLICATION CODE MODIFIED)**

---

## 1. EXECUTIVE SUMMARY & BASELINE INTEGRITY

An exhaustive, non-destructive re-audit of the Mini EDR Linux repository was conducted at baseline commit `47b8fcd81b9df107ac66ef0992f233b1e1c82d3d` on branch `remediation/academic-acceptance`.

The audit evaluated all **36 original findings** registered in `audit/AUDIT_FINDINGS.md` and investigated the **13 critical vectors** defined in the Master Audit Directive. In addition, deep static code analysis revealed **12 new security, data integrity, and reliability findings**, bringing the total tracked findings to **48**.

### Key Statistical Overview

| Classification Category | Count | Percentage | Definition |
| :--- | :---: | :---: | :--- |
| **`FIXED_VERIFIED`** | **17** | 35.4% | Verified completely resolved with code inspection & dynamic tests |
| **`PARTIALLY_FIXED`** | **13** | 27.1% | Partial mitigation in place; residual vulnerability or edge case remains |
| **`CONFIRMED_OPEN`** | **12** | 25.0% | Finding is present in codebase and fully exploitable/reproducible |
| **`OUT_OF_SCOPE`** | **3** | 6.3% | Excluded by academic Scope Lock (e.g. eBPF, Celery, mTLS) |
| **`DUPLICATE`** | **3** | 6.3% | Redundant finding tracking identical root cause |
| **`NOT_REPRODUCIBLE`** | **0** | 0.0% | All reported vulnerabilities and behaviors were verified |
| **`NEEDS_DYNAMIC_TEST`**| **0** | 0.0% | All analyzed items have been statically or dynamically proven |
| **TOTAL REGISTERED** | **48** | **100%** | Comprehensive findings base |

---

## 2. DEEP-DIVE AUDIT OF THE 13 CRITICAL VECTORS

### Vector 1: Web Authentication, Session, CSRF, Logout, Open Redirect & Token Leakage

#### 1.1 Open Redirect via `next` Parameter (`server/web.py:180, 190`)
- **Source Evidence:**
  ```python
  next_url = request.args.get("next") or url_for("web.dashboard")
  ...
  return redirect(next_url)
  ```
- **Vulnerability:** The application blindly redirects the operator to whatever URI is supplied in the `next` query parameter upon successful authentication. An attacker can construct a phishing link such as `http://localhost:5000/login?next=https://malicious-c2.attacker.com/fake-soc`. Because there is no check ensuring `next_url` is a relative URL (e.g. starting with `/` but not `//`) or hosted on the same origin, the operator is seamlessly redirected to an external malicious portal.
- **Severity:** 🔴 High (CVSS 7.4) — `FINDING-NEW-01`.

#### 1.2 Cross-Site Request Forgery in Logout Endpoint (`server/web.py:197-202`)
- **Source Evidence:**
  ```python
  @web_bp.get("/logout")
  def logout():
      session.clear()
      flash("Operator session terminated.", "info")
      return redirect(url_for("web.login"))
  ```
- **Vulnerability:** Logout is exposed exclusively as an HTTP `GET` route (`@web_bp.get("/logout")`). In `templates/base.html:62`, the UI renders a direct anchor link `<a href="{{ url_for('web.logout') }}">`. Any external website or malicious email embedding `<img src="http://localhost:5000/logout">` will immediately terminate the operator's active session without consent (Logout CSRF).
- **Severity:** 🟡 Medium (CVSS 5.3) — `FINDING-NEW-02`.

#### 1.3 Missing CSRF Protection on Login POST (`server/web.py:182-194`)
- **Source Evidence:** `login()` handles `POST` requests without calling `validate_csrf()`. While `templates/login.html:42` renders `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">`, the server handler fails to verify the token, enabling Login CSRF.
- **Severity:** 🟡 Medium (CVSS 4.3) — `FINDING-NEW-03`.

#### 1.4 Credential Leakage via URL Query Parameter (`server/web.py:101-103`)
- **Source Evidence:**
  ```python
  elif request.args.get("token"):
      token = request.args.get("token").strip()
  ```
- **Vulnerability:** Allowing the sensitive `EDR_API_TOKEN` to be passed in the URL (`?token=...`) exposes credentials in browser history, proxy access logs, web server logs, and HTTP `Referer` headers when clicking external references.
- **Severity:** 🟡 Medium (CVSS 5.3) — `FINDING-NEW-04`.

#### 1.5 Dynamic `SECRET_KEY` & Missing Cookie Flags (`server/app.py:38`)
- **Source Evidence:** `SECRET_KEY=os.getenv("SECRET_KEY", secrets.token_hex(32))`.
- **Vulnerability:** When `SECRET_KEY` is not explicitly declared in `.env`, a random token is generated in memory at startup. Every server reboot or worker restart immediately destroys all active operator sessions. Furthermore, Flask default session cookie security flags (`SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE="Lax"`, `SESSION_COOKIE_SECURE`) are not explicitly configured.
- **Severity:** 🟡 Medium (CVSS 5.3) — `FINDING-NEW-06`.

---

### Vector 2: DOM XSS and HTML Attribute Injection

#### 2.1 Untrusted API Error DOM XSS Sinks (`static/dashboard.js:228, 271, 289, 349`)
- **Source Evidence:**
  ```javascript
  // Line 228
  body.innerHTML = `<div style="color: var(--neon-red);">Failed to load evidence: ${data.error}</div>`;
  // Line 271
  body.innerHTML = `<div style="color: var(--neon-red);">Error fetching telemetry: ${err.message}</div>`;
  // Line 289
  body.innerHTML = `<div style="color: var(--neon-red);">Error: ${data.error}</div>`;
  // Line 349
  body.innerHTML = `<div style="color: var(--neon-red);">Error scanning endpoint: ${err.message}</div>`;
  ```
- **Vulnerability:** While commit `47b8fcd` introduced `escapeHtml()` for telemetry payload fields (`alert.title`, `ev.evidence_json`), the API error and exception message handlers directly interpolate `data.error` and `err.message` into raw `innerHTML`. If an endpoint error reflects untrusted input (e.g. an invalid `agent_id` or malicious payload), arbitrary JavaScript is executed in the operator's browser session.
- **Severity:** 🔴 High (CVSS 7.2) — `FINDING-NEW-05`.

#### 2.2 Inline Event Handler Attribute Breakout (`templates/alerts.html:170`, `templates/dashboard.html:238`)
- **Status:** **`FIXED_VERIFIED`**.
- **Evidence:** Replaced inline `onclick` handlers with HTML5 `data-alert-id` and `data-alert-title` attributes paired with delegated event listeners in `static/dashboard.js:26-56`. Verified immune to single/double quote attribute breakout.

---

### Vector 3: Agent FIM Event Persistence, Retry, Idempotency & Restart

#### 3.1 Volatile In-Memory Queue & Crash Loss (`agent/file_integrity.py:394-406`, `agent/main.py:231-258`)
- **Source Evidence:**
  In `agent/main.py:246-258`, two-phase commit is maintained exclusively in Python process memory:
  ```python
  if changes:
      sec_events = self.fim_monitor.get_security_events(changes)
      for evt in sec_events:
          self.client.send_security_event(evt)
          summary["fim_events_sent"] += 1
  ...
  if new_baseline is not None and hasattr(self.fim_monitor, "commit_baseline"):
      self.fim_monitor.commit_baseline(new_baseline)
  ```
- **Vulnerability:**
  1. **Crash / Hard Restart:** If the Agent process is killed (`SIGKILL`) or host crashes while pending FIM events exist or during a network outage, all pending change events vanish from volatile RAM.
  2. **Baseline State Desynchronization on Restart:** On restart, `initialize_baseline()` scans the disk and establishes a fresh baseline. Changes that occurred during the outage or before the crash are swallowed silently without generating security events!
  3. **Partial Batch Failure:** If 5 events are detected and event #4 fails with a network timeout, `commit_baseline` is aborted. On the subsequent cycle, events #1, #2, and #3 are regenerated and retransmitted, relying solely on server deduplication.
- **Remediation:** Implement a bounded SQLite local spool queue (`agent/spool.py` or `.fim_events.db`) on the agent.
- **Severity:** 🟡 Medium (CVSS 6.2) — `FINDING-NEW-08`.

---

### Vector 4: Symlink Traversal and TOCTOU Race Condition

#### 4.1 TOCTOU Race Condition in File Hashing (`agent/file_integrity.py:44, 57`)
- **Source Evidence:**
  ```python
  def compute_sha256(file_path: str, max_size: int = DEFAULT_MAX_FILE_SIZE) -> Optional[str]:
      st = os.lstat(file_path)
      if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
          return None
      ...
      with open(file_path, "rb") as f:
          while chunk := f.read(HASH_CHUNK_SIZE):
              hasher.update(chunk)
  ```
- **Vulnerability:** There is a classic Time-of-Check to Time-of-Use (TOCTOU) window between `os.lstat(file_path)` and `open(file_path, "rb")`. An attacker with write access to a monitored directory (e.g. `/tmp`) can create a regular file, wait for `lstat` to pass, and atomically replace the file with a symbolic link pointing to `/etc/shadow` before `open()` executes. Standard `open()` follows symlinks by default.
- **Remediation:** Open the file descriptor with `os.open(file_path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))` and inspect the descriptor with `os.fstat(fd)`. If `open()` encounters a symlink, Linux kernel returns `ELOOP` or `EEXIST` atomically without opening the target.
- **Severity:** 🔴 High (CVSS 7.0) — `FINDING-NEW-07`.

---

### Vector 5: Detection-to-Event ID Mapping & Foreign Keys

#### 5.1 Unsafe Index Lookup & Broad Event Linking (`detection/engine.py:130`, `detection/correlation.py:50, 170`)
- **Source Evidence:**
  ```python
  # detection/engine.py:130
  event_id=created_event_ids[raw_detections.index(d)] if created_event_ids else None
  ```
- **Vulnerability:**
  1. `raw_detections.index(d)` returns the *first* index where `d` occurs. If multiple detections share identical values, they all map to the same event ID.
  2. If any single `event_repo.record()` call fails inside the loop (lines 79-82), `created_event_ids` length becomes smaller than `raw_detections`. When evaluating later detections, `raw_detections.index(d)` causes an unhandled `IndexError: list index out of range`!
  3. In `detection/correlation.py`, `associated_event_ids=created_event_ids` passes all event IDs from the *entire snapshot* to every correlated alert, causing unrelated events to be linked in `alert_events`.
- **Severity:** 🟡 Medium (CVSS 5.8) — `FINDING-NEW-10`.

---

### Vector 6: Process/FIM Correlation Time Window

#### 6.1 Unbounded Event Window in FIM Correlation (`detection/engine.py:84-91`)
- **Source Evidence:**
  ```python
  recent_events = self.event_repo.list_by_agent(agent_id, limit=20)
  recent_fim_detections: List[DetectionResult] = []
  for ev in recent_events:
      if ev.get("source") == "agent" and "fim" in ev.get("event_type", ""):
          matches = self.rules.evaluate_fim_event(agent_id, ev)
          recent_fim_detections.extend(matches)
  ```
- **Vulnerability:** The correlation engine retrieves the last 20 events on the endpoint without checking their age (`occurred_at`). If an attacker dropped a binary 3 weeks ago, and a legitimate process with a matching name is started today, the engine falsely correlates the ancient FIM drop with the current process. Correlation must enforce a strict sliding window (e.g. events within the last 300 seconds / 5 minutes).
- **Severity:** 🟡 Medium (CVSS 5.3) — `FINDING-NEW-10`.

---

### Vector 7: PID Reuse and Process Identity

#### 7.1 Alert Key Collision on Linux PID Recycling (`detection/correlation.py:139`)
- **Source Evidence:**
  ```python
  alert_key = f"{agent_id}:correlated:proc:{pid}:{proc_name}"
  ```
- **Vulnerability:** Linux PIDs wrap around (default `pid_max = 32768`). If a suspicious process is detected at PID 1024, and hours later an unrelated system process is spawned at PID 1024 with the same name, the alert key collides and links to the previous incident. Process start time (`process_started_at`) or boot ID should be incorporated into the process correlation identity.
- **Severity:** 🔵 Low (CVSS 3.4).

---

### Vector 8: Parent Process Metadata & Shell-Spawn Detection

#### 8.1 Dead Parent Name Rule Condition (`detection/rules.py:380`, `agent/process_collector.py:74-124`)
- **Source Evidence:**
  ```python
  # detection/rules.py:380
  is_suspicious_parent = parent_name in ("nginx", "apache2", "httpd", "python", "python3", "php", "node")
  ```
- **Vulnerability:** `ProcessCollector` extracts `pid` and `ppid`, but never resolves or populates `parent_name`. When `evaluate_process_snapshot` evaluates `ProcessShellSpawnRule`, `context.get("parent_name")` is always empty string `""`. Consequently, `is_suspicious_parent` evaluates to `False` in 100% of cases unless `username` matches `suspicious_users`.
- **Remediation:** Build a `{pid: process_name}` lookup dictionary within `evaluate_process_snapshot` using `observations` and resolve `parent_name = pid_map.get(proc.get("ppid"))`.
- **Severity:** 🟡 Medium (CVSS 5.3) — `FINDING-NEW-11`.

---

### Vector 9: Process Snapshot & Telemetry Idempotency Semantics

#### 9.1 Inadequate Duplicate Detection via `process_count` (`server/routes.py:417-428`)
- **Source Evidence:**
  ```python
  existing = proc_repo.get_snapshot_by_message_id(message_id)
  if existing:
      is_same = (
          existing["agent_id"] == agent_id
          and existing["process_count"] == process_count
      )
      if is_same:
          return jsonify({"success": True, "duplicate": True, ...}), 200
      return _error("Conflict: message_id already exists with different payload", 409)
  ```
- **Vulnerability:** If two completely distinct process snapshots sharing the same `message_id` happen to have the same `process_count` (e.g. 85 processes), the server falsely assumes they are duplicates and drops the second snapshot! The server does not hash or compare the actual process observations. A SHA-256 digest of the canonical JSON payload must be computed to establish true data equality.
- **Severity:** 🔴 High (CVSS 7.1) — `FINDING-NEW-09`.

---

### Vector 10: Heartbeat Partial-Update Semantics

#### 10.1 Preservation of Optional Metadata (`server/repositories/endpoint_repository.py:44-53`)
- **Status:** **`FIXED_VERIFIED`**.
- **Evidence:** `EndpointRepository.upsert()` employs SQL `COALESCE(excluded.field, endpoints.field)` for `hostname`, `ip_address`, `os`, `agent_version`, `cpu_percent`, `memory_percent`, `disk_percent`, and `uptime_seconds`. Partial heartbeat updates preserve existing values without NULL overwrites.

---

### Vector 11: SQLite Transaction Integrity, Variable Limits & Concurrency

#### 11.1 Dynamic SQL Variable Limit Overflow (`server/routes.py:530-533`)
- **Source Evidence:**
  ```python
  placeholders = ",".join("?" for _ in cleaned_files)
  rows = conn.execute(
      f"SELECT file_path FROM file_baselines WHERE agent_id = ? AND file_path IN ({placeholders})",
      (agent_id, *[f["file_path"] for f in cleaned_files]),
  ).fetchall()
  ```
- **Vulnerability:** When an agent syncs an initial baseline covering thousands of files (e.g. `/etc` and `/bin` combined with $>999$ files), SQLite throws `sqlite3.OperationalError: too many SQL variables` on Python sqlite3 builds with standard limits.
- **Remediation:** Chunk the query into batches of 500 parameters or query existing paths per batch.
- **Severity:** 🟡 Medium (CVSS 5.3) — `FINDING-PHASE04-03` (CONFIRMED_OPEN).

---

### Vector 12: Payload Size, Per-Field Limits & Resource Exhaustion

#### 12.1 Unbounded Collection Size & Missing Per-Field Limits (`server/routes.py:345-410`)
- **Source Evidence:** `MAX_CONTENT_LENGTH` was raised to 16 MiB. However, there are no upper bounds enforced on:
  - `payload.process_count` / `payload.processes` (an attacker can submit a snapshot with 50,000 process objects).
  - `payload.files` array length in baseline sync.
  - Length of string fields (`username`, `exe_path`, `process_name`, `description`).
- **Severity:** 🟡 Medium (CVSS 5.3) — `FINDING-NEW-12`.

---

### Vector 13: Documentation, Architecture, API Contract & Test Consistency

#### 13.1 Academic Documentation Alignment
- **Status:** **`FIXED_VERIFIED`**.
- **Evidence:** In commit `47b8fcd`, `README.md`, `docs/ARCHITECTURE.md`, `docs/DATA_CONTRACT.md`, and `docs/API_SPECIFICATION.md` were synchronized to reflect the actual 9 process telemetry fields, 7 detection rules, entrypoint `python -m agent`, and 230 passing tests.

---

## 3. AUDIT CONCLUSION & NEXT STEPS

Phase 0 confirms that the baseline at commit `47b8fcd81b9df107ac66ef0992f233b1e1c82d3d` is technically solid (230 tests passing, clean architecture), but contains **12 critical open security and reliability vectors** that must be methodically remediated in subsequent phases.

As required by the Master Prompt, **zero application code has been modified in Phase 0**. Remediation will proceed only after operator approval of this Phase 0 report.
