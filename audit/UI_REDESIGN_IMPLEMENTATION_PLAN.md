# UI/UX IMPLEMENTATION PLAN — MINIMAL CYBERPUNK SOC COMMAND CENTER
**Mini EDR for Linux — Web Dashboard Redesign**

- **Target Repository:** `r00tK1ngX/mini-edr-linux`
- **Branch:** `feature/dashboard-minimal-cyberpunk-redesign`
- **Author:** Senior UI/UX Designer & Senior Frontend Engineer
- **Status:** **APPROVED FOR EXECUTION**

---

## 1. DESIGN PHILOSOPHY & TOKENS

### 1.1. Core Identity: "Minimal Cyberpunk — SOC Command Center"
- **Minimalist & Professional:** Elimination of gratuitous scanlines, heavy blur, and chaotic neon glow. Replaced by a high-contrast, clean 1px border aesthetic, intentional spacing, and data-first visualization.
- **Subtle Cyberpunk Flavor:** Deep space palette (`#0B1120`, `#0E1728`, `#121D2E`), crisp cyan accents (`#22D3EE`), mono-font telemetry tags, angular/beveled accents, and live telemetry indicators.
- **Typography Priority:** Primary text in **Be Vietnam Pro** (local WOFF2, offline ready) for 100% legibility in Vietnamese and English. Monospace (`ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace`) reserved strictly for hashes, UUIDs, PIDs, IP addresses, and JSON payloads.

### 1.2. Design Tokens (CSS Variables)

```css
:root {
  /* Color Palette - Minimal Cyberpunk */
  --bg-main: #0B1120;           /* Deep Navy - Canvas */
  --bg-sidebar: #0E1728;        /* Dark Navy - Navigation */
  --bg-card: #121D2E;           /* Surface - Cards & Panels */
  --bg-card-hover: #162439;     /* Surface Hover */
  --bg-card-elevated: #18263A;  /* Modals & Popovers */
  --bg-input: #0A1220;          /* Inputs & Filters */

  /* Text Colors */
  --text-primary: #E6EDF6;      /* Off-white / High contrast */
  --text-secondary: #94A3B8;    /* Slate Muted */
  --text-muted: #64748B;        /* Subtle labels */
  --text-dim: #475569;          /* Inactive / Disclaimers */

  /* Structural Borders */
  --border-color: #26364B;      /* Standard 1px structural border */
  --border-subtle: #1C2B3E;     /* Divider / Row borders */
  --border-focus: #22D3EE;      /* Active / Focus border */

  /* Accent & Status Colors */
  --cyan: #22D3EE;              /* Primary Accent - Cyan */
  --cyan-hover: #67E8F9;        /* Bright Cyan */
  --cyan-dim: rgba(34, 211, 238, 0.12); /* Subtle Cyan wash */
  
  --green: #34D399;             /* Success / Online / Healthy */
  --green-dim: rgba(52, 211, 153, 0.12);
  
  --amber: #FBBF24;             /* Warning / Suspicious / Medium */
  --amber-dim: rgba(251, 191, 36, 0.12);
  
  --red: #F87171;               /* Danger / Critical / High */
  --red-dim: rgba(248, 113, 113, 0.12);
  
  --blue: #60A5FA;              /* Info / Low */
  --blue-dim: rgba(96, 165, 250, 0.12);

  /* Typography */
  --font-family-base: 'Be Vietnam Pro', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --font-family-mono: "JetBrains Mono", "Fira Code", ui-monospace, Menlo, Monaco, Consolas, monospace;

  /* Sizing & Spacing */
  --sidebar-width: 250px;
  --header-height: 64px;
  --radius-sm: 4px;
  --radius-md: 6px;
  --radius-lg: 8px;
  --transition-fast: 0.15s ease-in-out;
}
```

---

## 2. STRUCTURAL ARCHITECTURE: SIDEBAR + TOPBAR + MAIN

### 2.1. Layout Shell (`base.html`)
- **Left Sidebar (`250px` fixed on desktop, slide drawer on tablet/mobile):**
  - Brand Header: Mini EDR Linux Logo + Badge "SOC COMMAND CENTER".
  - Section 1: **TỔNG QUAN** (Dashboard `/dashboard`)
  - Section 2: **GIÁM SÁT AN NINH** (Máy tính đầu cuối `/endpoints`, Cảnh báo an ninh `/alerts`, Nhật ký sự kiện `/events`)
  - Section 3: **HỆ THỐNG** (Agent Status: Online / Offline summary pill)
  - Footer: Version info & Air-gapped certification indicator.
- **Top Header Bar (`64px`):**
  - Left: Contextual Breadcrumb / Title with live status indicator dot.
  - Center/Right:
    - Operational State Pill: "HỆ THỐNG HOẠT ĐỘNG" (Operational).
    - UTC Clock (`#hudClock` preserved for real-time tick).
    - Logout action: Clean POST form with CSRF protection.
- **Main Viewport (`calc(100vh - 64px)`):**
  - Smooth vertical scrolling, standard padding `24px` / `32px`.
  - Consistent header section on every page (Title, description, action buttons).

---

## 3. PAGE-BY-PAGE IMPLEMENTATION DETAILS

### 3.1. `templates/base.html`
- Include `@import url('fonts.css');` via `style.css`.
- Render HTML `<html lang="vi">`.
- Preserve `<meta name="csrf-token" content="{{ csrf_token }}">`.
- Modal elements preserved with identical IDs:
  - `#evidenceModal`, `#evidenceModalBody`, `.modal-close`
  - `#resolveModal`, `#resolveModalAlertTitle`, `#resolveNoteInput`, `submitResolveAlert()`
  - `#endpointModal`, `#endpointModalBody`
  - `#toastContainer`
- Keep test compatibility keywords and structures.

### 3.2. `templates/dashboard.html`
- **Header:** Title: "Tổng quan / Giám sát an ninh máy trạm Linux" (preserves badge `"SOC COMMAND CENTER"`).
- **Metric Cards (4 Grid):**
  1. *Máy tính đầu cuối* — Preserves `"MONITORED ENDPOINTS"` label, shows online/offline ratio, green live dot.
  2. *Sự cố đang mở (Open Incidents)* — Count of unacknowledged + acknowledged alerts.
  3. *Mối đe dọa nghiêm trọng* — Preserves `"CRITICAL"` label, red accent counter.
  4. *Nhật ký sự kiện (Audit Events)* — Total event counter.
- **Telemetry Gauges (3 Grid):**
  1. *CPU trung bình* — Preserves `"AVG CPU UTILIZATION"` label, sleek linear bar gauge + percentage.
  2. *Bộ nhớ RAM trung bình* — Linear bar gauge + percentage.
  3. *Dung lượng Disk trung bình* — Linear bar gauge + percentage.
- **Severity Matrix & Status Distribution:**
  - Low / Medium / High / Critical count cards with subtle color tags.
- **Data Tables (2 Grid):**
  - *Sự cố gần đây (Recent Incidents):* Table with severity badge, alert title, target host, timestamp, action buttons (`.btn-view-evidence`, `.btn-acknowledge`, `.btn-prompt-resolve` with `data-alert-id` and `data-alert-title`).
  - *Nhật ký sự kiện gần đây (Recent Telemetry):* Clean stream with severity tag, event type, endpoint, and timestamp.

### 3.3. `templates/endpoints.html`
- **Filter Tabs:** Tất cả (`ALL`), Đang hoạt động (`ONLINE`), Ngoại tuyến (`OFFLINE`).
- **Search Bar:** Real-time / form filter with query preservation (`search_query`).
- **Endpoints Table:**
  - Hostname & Agent ID (Mono font, truncated with tooltip).
  - Status indicator (Sleek badge: Green for Online, Slate for Offline).
  - IP Address & OS Platform (`Linux ...`).
  - CPU / Memory metrics (percentage pills).
  - Last Seen (relative & ISO timestamp).
  - Actions: Chi tiết (`.btn-inspect-endpoint` with `data-agent-id="{{ ep.agent_id }}"`).

### 3.4. `templates/alerts.html`
- **Header:** Preserves `"INCIDENT RESPONSE"` subtitle/badge.
- **Filter Toolbar:**
  - Status filter (Tất cả, Mới phát hiện / OPEN, Đang xử lý / ACKNOWLEDGED, Đã giải quyết / RESOLVED).
  - Severity filter (Tất cả, CRITICAL, HIGH, MEDIUM, LOW).
  - Endpoint filter (Dropdown of monitored agents).
  - Filter submit and Clear filters buttons.
- **Alerts Table:**
  - Severity badge with pulse dot for Critical/High.
  - Title & Rule ID (High legibility, mono rule name).
  - Endpoint / Hostname.
  - Event Count badge.
  - Status badge (`#status-badge-{{ alert.id }}`).
  - Created At timestamp.
  - Actions (`#actions-{{ alert.id }}`):
    - Evidence: `.btn-view-evidence`
    - Acknowledge: `.btn-acknowledge` (`#btn-ack-{{ alert.id }}`)
    - Resolve: `.btn-prompt-resolve` (`data-alert-id="{{ alert.id }}" data-alert-title="{{ alert.title }}"`)
    - Dismiss: `.btn-dismiss`
- **Empty State:** Preserves `"NO INCIDENTS MATCHING"`.

### 3.5. `templates/events.html`
- **Header:** Preserves `"AUDIT LOG"` subtitle/badge.
- **Filters:**
  - Severity filter dropdown.
  - Event Type filter dropdown.
- **Events Table:**
  - Timestamp (UTC).
  - Endpoint Hostname / ID.
  - Severity badge.
  - Event Type badge (`PROCESS_EXEC`, `FIM_MODIFIED`, `NETWORK_CONNECT`, etc.).
  - Summary / Message.
  - Technical Details viewer (collapsible or formatted JSON in modal/cell).

### 3.6. `templates/login.html`
- Centered Minimal Cyberpunk authentication card.
- Logo with cyan accent.
- Input: Secret Operator Token (`operator_token` / `auth_token`).
- CSRF token hidden input.
- Error flash message banner (danger style).
- Subtle air-gapped / security compliance footer.

---

## 4. CSS STYLESHEET REFACTOR PLAN (`static/style.css`)
- Header comment containing: `/* MINIMAL CYBERPUNK SOC COMMAND CENTER - MINI EDR LINUX */` (preserving `"CYBERPUNK"` requirement).
- `@import url('fonts.css');` at line 1.
- Modern CSS layout using Flexbox and CSS Grid.
- Custom scrollbars with slate/cyan track.
- Badge system: `.badge`, `.badge-critical`, `.badge-high`, `.badge-medium`, `.badge-low`, `.badge-online`, `.badge-offline`, `.badge-open`, `.badge-acknowledged`, `.badge-resolved`.
- Modal design: Modern backdrop blur (`rgba(11, 17, 32, 0.8)`), dark navy modal body, clean header and footer buttons.
- Toast system: Floating bottom-right notifications.
- Responsiveness: Breakpoints at 1024px, 768px, 480px.

---

## 5. QUALITY ASSURANCE & VERIFICATION GATES
1. **Automated Pytest Suite:** All 302 tests must pass with 0 regressions.
2. **Security & Anti-XSS Auditing:** Verify template auto-escaping and sanitizer functions.
3. **Offline Font Verification:** Ensure no external Google Fonts or CDN requests are triggered.
4. **Execution of Attack Simulation:** Run test regression suite covering simulated attacks.
