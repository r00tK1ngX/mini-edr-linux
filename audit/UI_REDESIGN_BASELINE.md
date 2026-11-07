# UI REDESIGN BASELINE MAPPING
**Mini EDR for Linux — Web Dashboard UI/UX Refactor**

- **Target Repository:** `r00tK1ngX/mini-edr-linux`
- **Date:** 2026-11-07
- **Auditor / Lead Frontend Engineer:** Senior UI/UX Designer & Senior Frontend Engineer
- **Branch:** `feature/dashboard-minimal-cyberpunk-redesign`
- **Scope Certification:** **READ-ONLY BASELINE RECONNAISSANCE COMPLETE**

---

## 1. COMPONENT & ASSET INVENTORY

| Component / File | Current Role | Modifiable? | Constraints & Dependencies |
| :--- | :--- | :---: | :--- |
| [`templates/base.html`](file:///home/kali/Projects/mini-edr-linux/templates/base.html) | Global layout, Head, Nav, Modals Deck, Toast Container | **YES** | Preserve CSRF meta tag, `#hudClock`, `#toastContainer`, modal IDs (`#evidenceModal`, `#resolveModal`, `#endpointModal`), modal body IDs, close buttons. |
| [`templates/dashboard.html`](file:///home/kali/Projects/mini-edr-linux/templates/dashboard.html) | SOC Command Center Overview (`/dashboard`) | **YES** | Preserve KPI data bindings, gauge values, recent alerts, recent events, button classes `.btn-view-evidence`, `.btn-acknowledge`, `.btn-prompt-resolve`. Must retain strings "SOC COMMAND CENTER", "MONITORED ENDPOINTS", "AVG CPU UTILIZATION", "CRITICAL". |
| [`templates/endpoints.html`](file:///home/kali/Projects/mini-edr-linux/templates/endpoints.html) | Endpoints Fleet Management (`/endpoints`) | **YES** | Preserve filter chips (`all`, `online`, `offline`), search query form `GET ?q=...`, table columns, and inspect button `.btn-inspect-endpoint` with `data-agent-id`. |
| [`templates/alerts.html`](file:///home/kali/Projects/mini-edr-linux/templates/alerts.html) | Incident Response Console (`/alerts`) | **YES** | Preserve multi-factor filters (Status, Severity, Endpoint), action buttons (`.btn-view-evidence`, `.btn-acknowledge`, `.btn-prompt-resolve`, `.btn-dismiss`), and empty state text "NO INCIDENTS MATCHING". Retain "INCIDENT RESPONSE". |
| [`templates/events.html`](file:///home/kali/Projects/mini-edr-linux/templates/events.html) | Security Events Audit Log (`/events`) | **YES** | Preserve filters (Severity, Event Type), table columns, and details JSON viewer (`pretty_json`). Retain "AUDIT LOG". |
| [`templates/login.html`](file:///home/kali/Projects/mini-edr-linux/templates/login.html) | SOC Operator Login Gateway (`/login`) | **YES** | Preserve CSRF token hidden field, `next` hidden field, token input field, submit button. |
| [`static/style.css`](file:///home/kali/Projects/mini-edr-linux/static/style.css) | Global Stylesheet | **YES** | Refactor from aggressive neon/scanlines to Minimal Cyberpunk SOC Command Center with Be Vietnam Pro. Must retain comment "CYBERPUNK". |
| [`static/fonts.css`](file:///home/kali/Projects/mini-edr-linux/static/fonts.css) | Local Font Faces for Be Vietnam Pro (400, 500, 600, 700) | **YES** | 100% self-contained local WOFF2 files in `static/fonts/` for offline/air-gapped compliance. |
| [`static/dashboard.js`](file:///home/kali/Projects/mini-edr-linux/static/dashboard.js) | Frontend AJAX & Modal Interactions | **CONDITIONAL** | Preserve all function signatures (`acknowledgeAlert`, `promptResolveAlert`, `submitResolveAlert`, `dismissAlert`, `viewEvidence`, `inspectEndpoint`, `renderErrorMessage`, `escapeHtml`, `sanitizeSeverity`, `sanitizeStatus`), data attributes, and test-asserted strings. |

---

## 2. FLASK ROUTE & DATA CONTRACT MAPPING

| Route Path | HTTP Method | View Function | Template Rendered / Response Type | Data Context / Parameters |
| :--- | :---: | :--- | :--- | :--- |
| `/` | `GET` | `web.index` | Redirect `302` -> `/dashboard` | None |
| `/dashboard` | `GET` | `web.dashboard` | `dashboard.html` | `total_endpoints`, `online_endpoints`, `offline_endpoints`, `avg_cpu`, `avg_mem`, `avg_disk`, `alert_summary`, `total_events`, `recent_alerts`, `recent_events`, `endpoints` |
| `/endpoints` | `GET` | `web.endpoints` | `endpoints.html` | `endpoints`, `status_filter`, `search_query`, `total_count`, `online_count`, `offline_count` |
| `/endpoints/<agent_id>/telemetry` | `GET` | `web.endpoint_telemetry` | JSON `200` | `{"success": true, "endpoint": {...}, "snapshot": {...}, "processes": [...], "baselines": [...], "baselines_count": int}` |
| `/alerts` | `GET` | `web.alerts` | `alerts.html` | `alerts`, `summary`, `status_filter`, `severity_filter`, `agent_id_filter`, `endpoints` |
| `/alerts/<id>/detail` | `GET` | `web.alert_detail` | JSON `200` | `{"success": true, "alert": {...}, "events": [...]}` |
| `/alerts/<id>/acknowledge` | `POST` | `web.alert_acknowledge` | JSON `200` / Flash Redirect | `{"note": ...}` + CSRF token |
| `/alerts/<id>/resolve` | `POST` | `web.alert_resolve` | JSON `200` / Flash Redirect | `{"resolution_note": ...}` + CSRF token |
| `/alerts/<id>/dismiss` | `POST` | `web.alert_dismiss` | JSON `200` / Flash Redirect | `{"resolution_note": ...}` + CSRF token |
| `/events` | `GET` | `web.events` | `events.html` | `events`, `total_events`, `severity_filter`, `event_type_filter` |
| `/login` | `GET`, `POST` | `web.login` | `login.html` | `error`, `next_url`, `csrf_token` |
| `/logout` | `POST` | `web.logout` | Redirect `302` -> `/login` | `csrf_token` |

---

## 3. JAVASCRIPT BEHAVIOR & DOM SELECTORS MATRIX

| Selector / Element ID | Event / Trigger | Target Function | Expected Behavior |
| :--- | :--- | :--- | :--- |
| `#hudClock` | `setInterval(1000)` | `updateClock()` | Renders real-time UTC timestamp (`YYYY-MM-DD HH:MM:SS UTC`). |
| `.btn-view-evidence` | `click` | `viewEvidence(alertId)` | Opens `#evidenceModal`, calls `/alerts/<id>/detail`, injects sanitized alert details & event list into `#evidenceModalBody`. |
| `.btn-acknowledge` | `click` | `acknowledgeAlert(alertId)` | POST `/alerts/<id>/acknowledge`, updates `#status-badge-${id}` to `ACKNOWLEDGED`, hides `#btn-ack-${id}`, shows Toast. |
| `.btn-prompt-resolve` | `click` | `promptResolveAlert(id, title)` | Sets `#resolveModalAlertTitle`, clears `#resolveNoteInput`, opens `#resolveModal`. |
| `submitResolveAlert()` | `click` (Modal button) | `submitResolveAlert()` | POST `/alerts/<id>/resolve` with note, updates `#status-badge-${id}` to `RESOLVED`, sets `#actions-${id}` to `RESOLVED`, closes modal, shows Toast. |
| `.btn-dismiss` | `click` | `dismissAlert(alertId)` | Confirms via dialog, POST `/alerts/<id>/dismiss`, updates badge to `RESOLVED` and actions to `DISMISSED`, shows Toast. |
| `.btn-inspect-endpoint` | `click` | `inspectEndpoint(agentId)` | Opens `#endpointModal`, calls `/endpoints/<agent_id>/telemetry`, renders endpoint hardware/network stats and process matrix table. |
| `Escape` Key | `keydown` | `closeAllModals()` | Removes `.active` class from all `.modal-backdrop` elements. |
| `.modal-close`, Modal Close Buttons | `click` | `closeAllModals()` | Closes active modal dialogs safely. |
| `#toastContainer` | DOM API | `showToast(msg, type)` | Appends temporary notification toast with auto-fadeout after 4 seconds. |
| `meta[name="csrf-token"]` | Query | `getCsrfToken()` | Reads session anti-CSRF token for inclusion in `X-CSRF-Token` headers. |

---

## 4. TEST SUITE REGRESSION COVENANTS

All 302 automated tests must continue to pass 100% without modification:
1. `tests/test_dashboard.py`:
   - Validates live data rendering, `/` redirect, `/static/style.css` containing "CYBERPUNK", `/static/dashboard.js` containing `acknowledgeAlert`.
   - Validates presence of header strings: "SOC COMMAND CENTER", "MONITORED ENDPOINTS", "AVG CPU UTILIZATION", "INCIDENT RESPONSE", "NO INCIDENTS MATCHING", "AUDIT LOG".
2. `tests/test_web_security_p1.py`:
   - Verifies XSS sanitization across HTML outputs (`<script>`, `<img onerror=...>`, `<svg onload=...>`).
   - Verifies `renderErrorMessage` usage in `dashboard.js`.
3. `tests/test_security_reliability.py`:
   - Verifies attribute injection defense (`data-alert-title` binding without inline `onclick="promptResolveAlert("`).
   - Verifies `viewEvidence` escaping in `dashboard.js`.
4. `tests/test_final_verification.py`:
   - Verifies `VALID_SEVERITIES` and `VALID_STATUSES` whitelists and sanitizers in `dashboard.js`.
