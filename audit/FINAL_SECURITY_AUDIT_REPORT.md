# FINAL SECURITY AUDIT REPORT
**Mini EDR for Linux — Verified Security Architecture, Threat Modeling & Defensible Boundaries**

- **Target Repository:** `https://github.com/r00tK1ngX/mini-edr-linux`
- **Auditor Role:** Senior Python Security Engineer, Linux Security Engineer, AppSec Auditor, and QA Lead
- **Evaluation Date:** 2026-11-07
- **Base Commit:** `26cdd4e6f16af42b6fd784431546885a0360597a`
- **Audit Branch:** `verification/final-academic-acceptance`
- **Scope Certification:** **ACCEPTED WITH DOCUMENTED LIMITATIONS**

---

## 1. AUDIT SCOPE, METHODOLOGY & SKEPTICAL POSTURE

This audit was conducted under an adversarial, evidence-driven methodology. Prior claims of "100% security" or "zero vulnerabilities" have been rejected in favor of empirical runtime verification, static code tracing, regression test execution, and explicit documentation of threat boundaries.

### 1.1 Evaluated Subsystems
1. **Agent Local Spool & Reliability Subsystem (`agent/spool.py`):** Crash resistance, SIGKILL persistence, queue capacity limits, FIFO drop policy, and SQLite corruption recovery.
2. **File Integrity Monitoring (`agent/file_integrity.py`):** TOCTOU symlink traversal defense, cryptographic SHA-256 calculation, metadata fast-path optimization, and timestomping counter-measures.
3. **Web Application Security (`server/web.py`, `server/app.py`):** Authentication lifecycle, session security, Open Redirect mitigation, CSRF validation on all state mutations, and persistent secret key derivation.
4. **Dashboard DOM Sinks (`static/dashboard.js`, `templates/`):** XSS review of template strings, dynamic attribute injection, CSS class injection, and API error message rendering sinks.
5. **Detection & Correlation Engine (`detection/`):** Primary key mapping, parent PPID resolution, PID reuse resilience, bounded time windows, and multi-factor risk scoring (0–100).
6. **Data Integrity & Storage (`server/routes.py`, `server/maintenance.py`):** Canonical JSON payload hashing, idempotency (200 vs 409), transaction atomicity, resource boundaries, and active incident preservation during retention pruning.

---

## 2. SUBSYSTEM DEEP-DIVE VERIFICATION

### 2.1 Agent Spool Reliability & Failure Semantics
- **Bounded Capacity & FIFO Drop:** When network partitions cause spool event count to reach `max_spool_size` (default 1,000), the spool purges acknowledged events first. If still saturated, the oldest pending events are dropped (`DELETE FROM fim_spool ORDER BY id ASC LIMIT ?`).
  > [!IMPORTANT]
  > **Operational Truth:** The system guarantees zero event loss during transient outages (<1,000 events) and graceful agent crashes. Under persistent long-term network partition, it applies a bounded FIFO drop policy to prioritize storage availability over unbounded disk consumption.
- **SQLite Corruption Recovery:** In the event of disk corruption (`sqlite3.DatabaseError`), `EventSpool._init_db()` captures the exception, moves the damaged database to `spool.db.corrupted.<timestamp>`, and re-initializes a clean spool database.
- **SIGKILL & Crash Persistence:** Pending events and baseline state are stored with `PRAGMA journal_mode = WAL` and committed synchronously, ensuring persistence across abrupt process termination.

### 2.2 File Integrity Monitoring (FIM) & Anti-Evasion
- **TOCTOU Symlink Traversal:** `compute_sha256()` uses `os.open()` with `os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC` to atomically open target files. The resulting descriptor is verified via `os.fstat(fd)` before hashing, rejecting symlinks at the kernel layer.
- **Timestomping Defense:** Standard files leverage a fast-path optimization (reusing cached hash if `mtime_ns`, `file_size_bytes`, and `file_mode` match). To eliminate evasion on high-value targets, critical system files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/etc/pam.d/*`, `/etc/crontab`) are subjected to **mandatory full SHA-256 rehashing** on every scan cycle regardless of timestamp.

### 2.3 Web Application Security
- **Stable Secret Key:** Derives `SECRET_KEY` from `data/.secret_key` with permissions `0600`. File writes use atomic replacement (`.tmp` -> `replace`) to prevent race conditions during multi-worker initialization.
- **CSRF & Authentication:**
  - `POST /logout` enforced with per-session anti-CSRF token; `GET /logout` rejected with HTTP 405.
  - `POST /login` validated with `validate_csrf()`; token parameter in query string is stripped and rejected.
  - Session cookies enforce `HttpOnly=True` and `SameSite="Lax"`, with optional HTTPS enforcement via `SESSION_COOKIE_SECURE`.
- **Open Redirect:** Validated using `is_safe_url()`, which rejects backslashes (`\`), protocol-relative schemes (`//`), external domains, and javascript URLs.

### 2.4 Client-Side DOM XSS Review
- **CSS Class Whitelist:** `sanitizeSeverity()` and `sanitizeStatus()` enforce strict whitelisting (`info`, `low`, `medium`, `high`, `critical` and `online`, `offline`), preventing CSS class and attribute injection.
- **DOM Text Sinks:** Dynamic API error messages in modal inspection dialogs are rendered strictly via DOM APIs (`errDiv.textContent = String(message)`), preventing injection through server error responses.
- **HTML Escaping:** All entity fields (`alert.title`, `alert.description`, `ev.event_type`, `ev.evidence_json`, `ep.hostname`) are sanitized using `escapeHtml()`.

### 2.5 Detection Engine & Correlation Correctness
- **Event ID Mapping:** Detection results are mapped directly to database primary keys (`saved_event['id']`). Correlated alerts only associate contributing security event IDs.
- **Parent Process Resolution:** Resolves `parent_name` using in-snapshot PID -> PPID mappings, enabling reliable detection for `ProcessShellSpawnRule` (`nginx -> bash`).
- **PID Reuse Resilience:** Linux PID recycling is handled by constructing composite process identities (`pid:process_name:start_time`) in `alert_key` and correlation hashes.
- **Correlation Window:** Multi-factor correlation is constrained by a 300-second window (`time_window_seconds = 300`), preventing stale FIM events from linking to unrelated process spikes.

### 2.6 Data Integrity & Retention Safety
- **Canonical Payload Hashing:** Ingestion verifies message idempotency via sorted, compact JSON SHA-256 hashing. Duplicate transmissions return HTTP 200 `{"duplicate": true}`; payload tampering with identical `message_id` returns HTTP 409 Conflict.
- **Active Incident Protection:** Telemetry pruning (`server/maintenance.py`) prunes telemetry older than 7 days, but explicitly **preserves all security events linked to active alerts (`new` or `acknowledged`)**, preventing loss of evidence for open investigations.

---

## 3. DOCUMENTED THREAT BOUNDARIES & LIMITATIONS

To maintain academic rigor and avoid exaggerated claims, the following technical limitations are explicitly documented:

1. **User-Space `/proc` Polling Blind Spot:** Processes with lifetimes shorter than the scan interval (<10s) escape snapshot collection. Full kernel visibility would require eBPF probes, which were excluded per Scope Lock.
2. **Lossy Under Prolonged Outages (FIFO Policy):** When the agent's SQLite spool exceeds `max_spool_size` (1,000 events) during prolonged network disconnects, the oldest unacknowledged events are dropped to prevent local disk exhaustion.
3. **Shared Bearer Token:** Agents authenticate using a static Bearer token shared fleet-wide. Production enterprise deployments would require per-agent mTLS certificates or dynamic enrollment tokens.
4. **Metadata Fast-Path Timestomping Boundary:** For non-sensitive files (outside `/etc`), an attacker with root access who restores exact `mtime_ns`, `file_size_bytes`, and `file_mode` will evade hash recomputation until a full rescan is triggered.
5. **Single-Writer Concurrency:** SQLite in WAL mode allows multiple readers but serializes writers with a 10-second busy timeout. High-throughput fleet deployments (>100 active agents) would encounter database contention.
