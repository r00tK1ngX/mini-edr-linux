# PHASE 7 — WEB DASHBOARD & UI/UX AUDIT REPORT
**Mini EDR for Linux — Comprehensive Security & Quality Audit**

- **Target Repository:** `r00tK1ngX/mini-edr-linux`
- **Component Audited:** Web SOC Console (`server/web.py`, `templates/*`, `static/*`)
- **Audit Date:** 2026-11-06
- **Auditor:** Senior Cybersecurity Engineer & Security Auditor (Independent Review)
- **Status:** COMPLETED — AUDIT-ONLY (No code modified, zero data altered)

---

## 1. EXECUTIVE SUMMARY

Phase 7 evaluated the Mini EDR Web Dashboard (`web_bp`), which serves as the primary visual interface and incident response console for SOC operators. The audit covered UI architecture, template rendering, DOM security, client-side scripts, air-gapped compliance, mobile/responsive layout, and interactive triage workflows.

The dashboard features a high-fidelity Cyberpunk SOC Command Center design with custom dark-mode styling, real-time UTC clock, KPI meters, and interactive modals for endpoint telemetry and forensic evidence inspection. Furthermore, the dashboard achieves **100% air-gapped compliance**, with zero remote CDN dependencies, zero external webfonts, and zero third-party tracking scripts.

However, the audit identified **two significant Cross-Site Scripting (XSS) vulnerabilities**:
1. **High-Severity DOM-based XSS (CWE-79)** in `static/dashboard.js:viewEvidence()` where security alert titles, descriptions, and linked event telemetry are directly interpolated into `innerHTML` without HTML entity escaping.
2. **Medium-Severity Inline Attribute Injection XSS (CWE-79)** in `templates/alerts.html:170` and `templates/dashboard.html:238` where alert titles with single quotes break out of inline JavaScript `onclick` handlers despite Jinja2 `|escape`.
3. In addition, the lack of session authentication and CSRF tokens allows unauthorized triage tampering.

---

## 2. AUDIT SCOPE & METHODOLOGY

### 2.1 Audited Files & Components
- **Server Blueprint:** `server/web.py` (430 lines)
- **HTML Templates:**
  - `templates/base.html` (162 lines: Layout, HUD Nav, Modal Deck, Toast Container)
  - `templates/dashboard.html` (285 lines: KPI cards, telemetry charts, recent alerts & events)
  - `templates/endpoints.html` (149 lines: Fleet inventory, status meters, inspection trigger)
  - `templates/alerts.html` (187 lines: Filterable incident table, triage buttons, evidence viewer)
  - `templates/events.html` (124 lines: Security audit log, event filtering)
- **Static Assets:**
  - `static/style.css` (1,012 lines: Cyberpunk HUD theme, CRT scanlines, CSS grid/flexbox)
  - `static/dashboard.js` (328 lines: Clock, modals, alert actions, AJAX telemetry loaders)

### 2.2 Verification Approach
- **Static Code Analysis:** Manual inspection of data-binding, template filters, string interpolations, DOM sinks (`innerHTML`, `textContent`), and inline JavaScript event handlers.
- **Dynamic Local Harness:** Executed `/scratch/audit_phase7_dashboard_comprehensive.py` with malicious payloads (HTML tags, script tags, event handler attributes, single-quote breakouts) to trace rendered HTML and JSON payloads.
- **Air-Gapped & Supply Chain Audit:** Grepped all templates and stylesheets for external URLs (`http://`, `https://`, CDN links, Google Fonts, font-awesome, unpkg).
- **Responsive Layout Inspection:** Evaluated CSS media queries, table scroll containers, and viewport meta tags.

---

## 3. AUDIT FINDINGS

### `FINDING-PHASE07-01` (High) — DOM-based Cross-Site Scripting (DOM XSS) in `viewEvidence()` Modal
- **Classification:** Vulnerability (Confirmed)
- **CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation - Cross-Site Scripting)
- **CVSS v3.1:** 7.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)
- **Affected File:** `static/dashboard.js` (Lines 189–221)
- **Root Cause:**
  When a SOC analyst clicks the **EVIDENCE** button on an alert, `viewEvidence(alertId)` fetches the alert details from `/alerts/<alert_id>/detail` and constructs the modal's HTML using raw template literal interpolation into `body.innerHTML`:
  ```javascript
  // static/dashboard.js: lines 204-221
  body.innerHTML = `
    <div style="margin-bottom: 1.25rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
        <h3 style="color: #fff; font-size: 1.1rem;">${alert.title}</h3>
        <span class="badge badge-${alert.severity}">${alert.severity.toUpperCase()}</span>
      </div>
      <p style="color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 0.75rem;">${alert.description || "No description provided."}</p>
      ...
      ${alert.resolution_note ? `...<span>${alert.resolution_note}</span>` : ""}
    </div>
    ...
    <div>${eventsHtml}</div>
  `;
  ```
  In contrast to `inspectEndpoint()` (lines 258–273), which correctly applied `escapeHtml()` to process names and usernames, `viewEvidence()` passes `alert.title`, `alert.description`, `alert.resolution_note`, `ev.title`, and `formatJsonString(ev.evidence_json)` directly into `body.innerHTML`.
- **Preconditions:** An attacker executes a command, spawns a process, or drops a file containing HTML/JS characters (e.g. `<img src=x onerror=...>`) that triggers an alert or security event.
- **Exploitation Impact:** When a SOC analyst clicks **EVIDENCE** to triage the alert, the malicious script executes in the analyst's browser. The attacker can trigger automatic alert dismissal, forge administrative actions, or hijack active browser sessions.
- **Remediation:**
  Apply `escapeHtml()` to all untrusted JSON fields in `viewEvidence()`:
  ```javascript
  <h3 style="color: #fff; font-size: 1.1rem;">${escapeHtml(alert.title)}</h3>
  <p ...>${escapeHtml(alert.description || "No description provided.")}</p>
  <div>${escapeHtml(ev.title || "Untitled")}</div>
  <pre class="json-viewer">${escapeHtml(formatJsonString(ev.evidence_json))}</pre>
  ```

---

### `FINDING-PHASE07-02` (Medium) — Inline Event Handler Attribute Breakout XSS in Incident Resolution Modals
- **Classification:** Vulnerability (Confirmed)
- **CWE:** CWE-79 / CWE-83 (Improper Neutralization of Script in Attributes)
- **CVSS v3.1:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)
- **Affected Files:**
  - `templates/alerts.html` (Line 170)
  - `templates/dashboard.html` (Line 238)
- **Root Cause:**
  The resolve incident button is rendered as:
  ```jinja2
  <button type="button" class="btn btn-green btn-sm" onclick="promptResolveAlert({{ a.id }}, '{{ a.title|escape }}')">
  ```
  Jinja2's `|escape` filter encodes `'` as `&#39;`. However, in HTML attribute contexts, browsers execute HTML entity decoding *before* passing the string to the JavaScript interpreter (HTML5 Specification §13.2.5). Consequently, an alert title containing `'); malicious_code();//` has its `&#39;` decoded back to `'` by the browser, prematurely terminating the string argument and executing `malicious_code()`.
- **Empirical Proof:**
  Executing scratch harness with title `Alert'); alert(document.domain);//` rendered:
  ```html
  <button type="button" class="btn btn-green btn-sm" onclick="promptResolveAlert(1, 'Alert&#39;); alert(document.domain);//')">
  ```
  Upon user click, the browser parses:
  `promptResolveAlert(1, 'Alert'); alert(document.domain);//')`
- **Remediation:**
  Refactor the template to eliminate inline JavaScript argument concatenation. Bind data using HTML5 data attributes:
  ```html
  <button type="button" class="btn btn-green btn-sm btn-resolve"
          data-alert-id="{{ a.id }}"
          data-alert-title="{{ a.title }}">
    RESOLVE
  </button>
  ```
  Then attach a clean event listener in `static/dashboard.js` via `btn.addEventListener('click', ...)`.

---

### `FINDING-PHASE07-03` (Medium) — Unauthenticated Web Console and Fleet Data Exposure
- **Classification:** Architecture Discrepancy / Security Weakness (Confirmed)
- **CWE:** CWE-306 (Missing Authentication for Critical Function)
- **CVSS v3.1:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)
- **Affected Files:**
  - `server/web.py` (Lines 97–430)
  - `server/app.py` (Lines 53–56)
- **Root Cause:**
  While the REST API (`api_bp`) enforces Bearer token authentication, the web console blueprint (`web_bp`) is completely public. No login prompt, HTTP Basic Auth, session check, or IP restriction exists.
- **Impact:**
  Any user or process on the local network (or container network) can browse to `http://<server>:5000/` and:
  1. View the entire fleet inventory, hostnames, IP addresses, OS versions, and real-time CPU/RAM metrics (`/endpoints`).
  2. Inspect running processes, command lines, executable paths, and monitored file baselines (`/endpoints/<agent_id>/telemetry`).
  3. View all security alerts, detection rule triggers, and raw evidence (`/alerts`, `/alerts/<id>/detail`).
  4. Acknowledge, resolve, or dismiss active security alerts (`/alerts/<id>/acknowledge`, `/resolve`, `/dismiss`).
- **Remediation:**
  Add session-based operator authentication (e.g. Flask-Login or session decorator) or require reverse-proxy authentication (e.g. Authelia, HTTP Basic Auth in Nginx) before exposing the SOC dashboard.

---

### `FINDING-PHASE07-04` (Low) — Missing Anti-CSRF Protection on Web State-Changing POST Actions
- **Classification:** Security Weakness (Confirmed)
- **CWE:** CWE-352 (Cross-Site Request Forgery)
- **CVSS v3.1:** 4.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N)
- **Affected File:** `server/web.py` (Lines 291–402)
- **Root Cause:**
  Endpoints `/alerts/<int:alert_id>/acknowledge`, `/resolve`, and `/dismiss` accept state-changing POST requests via both JSON (`request.is_json`) and HTML form data (`request.form`), but do not validate a CSRF token.
- **Impact:**
  An attacker hosting a malicious site could trick an authenticated SOC analyst into submitting a forged cross-site POST request to dismiss or resolve critical alerts silently.
- **Remediation:**
  Integrate `Flask-WTF` (`CSRFProtect(app)`) to enforce anti-CSRF tokens on all POST/PUT/DELETE web requests.

---

### `FINDING-PHASE07-05` (Informational / Commendation) — 100% Air-Gapped Compliance & Zero External Dependencies
- **Classification:** Design Verification (Passed)
- **Audited Files:** `templates/base.html`, `static/style.css`, `static/dashboard.js`
- **Assessment Results:**
  - **Zero External CDNs:** No Bootstrap, jQuery, Tailwind, or FontAwesome scripts loaded from public CDNs.
  - **Zero Remote Fonts:** Fonts utilize system monospaced stacks (`"JetBrains Mono", "Fira Code", monospace, sans-serif`); no Google Fonts `@import` or `<link>` calls.
  - **Zero Remote Favicon Calls:** Favicon is served as an inline SVG data URI (`data:image/svg+xml,...`).
  - **Zero Tracking:** No telemetry, analytics, or third-party web beacons.
- **Verdict:** Fully compliant with air-gapped industrial, defense, and high-security SOC requirements.

---

## 4. UI/UX & RESPONSIVENESS EVALUATION

| UI Component / View | Visual Design & Hierarchy | Responsive Behavior | Usability & Error Handling | Overall Rating |
| :--- | :--- | :--- | :--- | :--- |
| **HUD Navigation & Header** | Cyberpunk dark aesthetic, glowing neon accents, live UTC clock | Wraps cleanly on mobile (`max-width: 900px`) via flex-direction column | Clear active-page indicators, intuitive brand links | **4.8 / 5.0** |
| **Command Center Overview (`/dashboard`)** | Metric cards with gradient borders, KPI meters, alert distribution | Grid adapts from 4 columns to 1 column on narrower viewports | Empty state messaging present when no alerts/events exist | **4.7 / 5.0** |
| **Endpoints Inventory (`/endpoints`)** | Status badges (ONLINE/OFFLINE), resource progress meters | Table enclosed in `.table-responsive` with horizontal scroll | Search query & status filters work as expected; 404 handled on modal | **4.6 / 5.0** |
| **Alerts & Incidents (`/alerts`)** | Severity badges (CRITICAL/HIGH/MEDIUM/LOW), rule IDs | Table scrollable horizontally; action buttons stacked cleanly | Modal prompts for resolution notes; toast feedback on AJAX complete | **4.4 / 5.0** (Deducted for XSS) |
| **Audit Logs (`/events`)** | Terminal log table, event type pills, timestamp formatting | Table responsive, evidence column truncated cleanly | Severity filter responsive; lacks page size pagination control | **4.5 / 5.0** |
| **Modals (Evidence & Telemetry)** | Cyberpunk HUD overlay, ESC key support, backdrop close | Scrollable modal bodies with capped height (`max-height: 320px`) | `viewEvidence` lacks HTML escaping; `inspectEndpoint` handles escaping well | **4.2 / 5.0** (Deducted for XSS) |

---

## 5. REPRODUCTIONS & EVIDENCE

### 5.1 Verifying DOM XSS in `viewEvidence()`
1. Register an agent and insert a security event whose title contains `<img src=x onerror=alert('DOM_XSS')>`.
2. Generate an alert linked to this event.
3. Open the web browser to `http://127.0.0.1:5000/alerts`.
4. Click the **EVIDENCE** button (`viewEvidence(alertId)`).
5. The modal fetches the JSON detail and directly injects the raw title into `body.innerHTML`.
6. **Result:** The `onerror` handler fires immediately, executing JavaScript in the context of the SOC operator.

### 5.2 Verifying Attribute Breakout XSS in Resolution Button
1. Create an alert with title `Backdoor Detected'); alert('ATTR_XSS');//`.
2. Inspect the rendered HTML on `/alerts`:
   ```html
   <button type="button" class="btn btn-green btn-sm" onclick="promptResolveAlert(1, 'Backdoor Detected&#39;); alert(&#39;ATTR_XSS&#39;);//')">
   ```
3. Clicking the **CONFIRM RESOLVE** button triggers attribute decoding, causing the browser to execute `alert('ATTR_XSS')`.

---

## 6. PHASE 7 CONCLUSION & AUDIT VERDICT

The Web SOC Dashboard demonstrates exceptional visual presentation, functional completeness, and commendable air-gapped isolation. However, client-side input sanitization was inconsistently applied between `inspectEndpoint()` (which escapes) and `viewEvidence()` (which injects raw HTML).

### Summary of Phase 7 Findings:
- **`FINDING-PHASE07-01` (High):** DOM-based XSS in `viewEvidence()` modal via raw `innerHTML`.
- **`FINDING-PHASE07-02` (Medium):** Inline event handler attribute breakout XSS in `alerts.html` and `dashboard.html`.
- **`FINDING-PHASE07-03` (Medium):** Unauthenticated Web SOC Console exposing fleet telemetry and triage actions.
- **`FINDING-PHASE07-04` (Low):** Missing anti-CSRF protection on alert state mutation endpoints.
- **`FINDING-PHASE07-05` (Informational):** 100% air-gapped readiness verified with zero remote dependencies.

Phase 7 is officially **COMPLETED**.
The audit now transitions to **PHASE 8 — SECURITY, HARDENING & RELIABILITY AUDIT**.
