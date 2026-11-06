# AUDIT ARCHITECTURE — MINI EDR FOR LINUX

**Tài liệu:** Sơ đồ & Phân tích Bản đồ Kiến trúc Thực tế Toàn Hệ thống (Phase 0)  
**Đơn vị thực hiện:** Senior Cybersecurity Engineer / Independent Security Auditor  
**Repository:** `r00tK1ngX/mini-edr-linux`  
**Ngày thực hiện:** 05/11/2026  

---

## 1. Bản Đồ Luồng Dữ Liệu Thực Tế (Actual Data Flow Map)

Dưới đây là luồng xử lý và luân chuyển dữ liệu thực tế được truy vết trực tiếp qua từng file mã nguồn:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               1. LINUX HOST & SUBSYSTEMS                               │
│  - Virtual Filesystem: /proc (PIDs, cmdline, stat, status, exe symlinks)               │
│  - Monitored Directories: /etc, /bin, /sbin (files, SHA-256 hashes, file modes, mtimes)│
│  - Hardware / OS Metrics: CPU times, Virtual Memory, Disk Usage, Network Interfaces    │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ Local Kernel / OS Inspection
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               2. LINUX AGENT SUBSYSTEM                                 │
│                                                                                        │
│   ┌────────────────────────┐  ┌────────────────────────┐  ┌────────────────────────┐   │
│   │  SystemCollector       │  │  ProcessCollector      │  │ FileIntegrityMonitor   │   │
│   │ (agent/system_col...)  │  │ (agent/process_col...) │  │ (agent/file_integrity) │   │
│   └───────────┬────────────┘  └───────────┬────────────┘  └───────────┬────────────┘   │
│               │                           │                           │                │
│               └───────────────────────────┼───────────────────────────┘                │
│                                           ▼                                            │
│                        ┌─────────────────────────────────────┐                         │
│                        │       AgentOrchestrator Loop        │                         │
│                        │          (agent/main.py)            │                         │
│                        └──────────────────┬──────────────────┘                         │
│                                           ▼                                            │
│                        ┌─────────────────────────────────────┐                         │
│                        │          AgentClient                │                         │
│                        │        (agent/client.py)            │                         │
│                        │  - Envelope 1.0 (UUIDv4 msg_id)     │                         │
│                        │  - Bearer Token Auth Header         │                         │
│                        │  - Retry backoff (0.5s, 1.0s, 2.0s) │                         │
│                        └──────────────────┬──────────────────┘                         │
└───────────────────────────────────────────┼────────────────────────────────────────────┘
                                            │ HTTP POST / JSON (Max 64KB)
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              3. FLASK API GATEWAY & SECURITY                           │
│                                                                                        │
│   ┌────────────────────────────────────────────────────────────────────────────────┐   │
│   │ Flask App Factory: server/app.py (create_app)                                  │   │
│   │ API Routes: server/routes.py (api_bp)                                          │   │
│   │                                                                                │   │
│   │ [Layer 1] Security Filters & Guards:                                           │   │
│   │   - require_api_token: Check 'Authorization: Bearer <token>'                   │   │
│   │   - MAX_CONTENT_LENGTH: 64 * 1024 bytes (413 Payload Too Large)                │   │
│   │   - JSON Content-Type Enforcement (400 Bad Request)                            │   │
│   │                                                                                │   │
│   │ [Layer 2] Envelope & Schema Validators:                                        │   │
│   │   - _validate_envelope(): schema_version == "1.0", valid UUIDv4 message_id     │   │
│   │   - ISO 8601 UTC collected_at timestamp parsing                                │   │
│   │   - Metric bounds validation: 0.0 <= metric <= 100.0, uptime >= 0              │   │
│   │   - Hash validation: SHA-256 (64 hex lowercase chars)                          │   │
│   │                                                                                │   │
│   │ [Layer 3] Idempotency & Replay Resistance:                                     │   │
│   │   - Check existing message_id in resource table                                │   │
│   │   - If exact match -> Return HTTP 200 (duplicate: true)                        │   │
│   │   - If conflicting payload -> Return HTTP 409 Conflict                         │   │
│   └───────────────────────────────────────┬────────────────────────────────────────┘   │
└───────────────────────────────────────────┼────────────────────────────────────────────┘
                                            │ Validated Payload
                     ┌──────────────────────┴──────────────────────┐
                     ▼                                             ▼
┌───────────────────────────────────────────┐ ┌──────────────────────────────────────────┐
│         4. DATA ACCESS LAYER (DAL)        │ │         5. DETECTION & CORRELATION       │
│                                           │ │                                          │
│ Repositories: (server/repositories/)      │ │ Package: detection/                      │
│   - EndpointRepository (Upsert, Online)   │ │                                          │
│   - MetricsRepository (Time-series)       │ │ [Core Engine]: detection/engine.py       │
│   - ProcessRepository (Snapshot + Obs)    │ │   - DetectionEngine class                │
│   - BaselineRepository (SHA-256 Baselines)│ │   - Synchronous in-process evaluation    │
│   - EventRepository (Security Events)     │ │                                          │
│   - AlertRepository (Alerts & Lifecycle)  │ │ [Rules Registry]: detection/rules.py     │
│                                           │ │   - RULE_SUSPICIOUS_PROCESS (Critical)   │
│ * 100% Parameterized Queries (?)          │ │   - RULE_SHELL_SPAWN (High)              │
│ * Context-managed atomic transactions     │ │   - RULE_HIGH_CPU_PROCESS (Medium)       │
│                                           │ │   - RULE_FIM_SENSITIVE_FILE (High)       │
│                                           │ │                                          │
│ Database Engine: server/db.py             │ │ [Correlation]: detection/correlation.py  │
│   - SQLite3 Database (data/mini_edr.db)   │ │   - Multi-indicator sliding window       │
│   - PRAGMA journal_mode = WAL             │ │   - Dynamic Risk Score (0 - 100)         │
│   - PRAGMA foreign_keys = ON              │ │   - Alert de-duplication by alert_key    │
│   - PRAGMA busy_timeout = 5000ms          │ │                                          │
└─────────────────────┬─────────────────────┘ └────────────────────┬─────────────────────┘
                      │                                            │
                      │             Saved Alerts & Events          │
                      └─────────────────────┬──────────────────────┘
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                    6. CYBERPUNK WEB DASHBOARD & SOC COMMAND CENTER                     │
│                                                                                        │
│   Controller: server/web.py (web_bp)                                                   │
│   Templates: templates/base.html, dashboard.html, endpoints.html, alerts.html, ...     │
│   Static Assets: static/style.css, static/dashboard.js (100% Offline / Air-gapped)     │
│                                                                                        │
│   Views & Features:                                                                    │
│     - /dashboard : 4 Cyber KPI tiles, 3 Neon resource meters, Severity matrix          │
│     - /endpoints : Fleet liveness (Online/Offline), Live search, Inspect Modal (AJAX)  │
│     - /alerts    : Triage Console, Evidence Modal (JSON), AJAX Actions:                │
│                    * Acknowledge -> status='acknowledged', acknowledged_at=now         │
│                    * Resolve -> status='resolved', resolved_at=now, resolution_note    │
│                    * Dismiss -> status='resolved', false positive resolution note      │
│     - /events    : Security Audit Logs & FIM telemetry timeline                        │
│                                                                                        │
│   State Transition Guards:                                                             │
│     - Block regressing from 'resolved' back to 'acknowledged' (HTTP 400/409)           │
│     - HTML sanitization: escapeHtml() in JS + Jinja2 context escaping                  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Đối Chiếu Kiến Trúc Thực Tế với Tài Liệu Đặc Tả

Qua quá trình rà soát thực tế, phát hiện một số điểm bất nhất giữa tài liệu thiết kế và mã nguồn thực thi:

| Hạng mục Kiến trúc | Mô tả trong Tài liệu (`ARCHITECTURE.md` & `README.md`) | Thực tế trong Mã nguồn | Nhận định Kỹ thuật & Tác động |
|---|---|---|---|
| **Vị trí Detection Package** | Tài liệu ghi `server/detection/` | Thực tế nằm ở thư mục gốc `detection/` (`detection/engine.py`, `detection/rules.py`) | Không ảnh hưởng chức năng vì `detection` được import trực tiếp qua `sys.path`. Tuy nhiên tài liệu mô tả sai cấu trúc thư mục. |
| **Tên Module Agent Orchestrator** | Tài liệu và README ghi `agent/orchestrator.py` và hướng dẫn chạy lệnh `python -m agent.orchestrator` | Thực tế tên file là `agent/main.py`. Lệnh chạy thực tế phải là `python -m agent.main` | **Confirmed Issue:** Người dùng chạy theo README sẽ gặp lỗi `No module named agent.orchestrator`. |
| **Mô hình Thực thi Detection** | Tài liệu nói Detection Engine độc lập | Thực tế Detection Engine được gọi đồng bộ (in-process) ngay bên trong `server/routes.py` khi có request gửi tới | Phù hợp với mô hình đồ án và tải lab vừa/nhỏ. Tuy nhiên nếu lượng request lớn, việc chạy đồng bộ có thể làm tăng độ trễ response. |
| **Quyền truy cập Web Dashboard** | Giao diện SOC Console quản lý sự cố | Chưa có cơ chế đăng nhập (Session / Login form) cho Dashboard | Phù hợp thiết kế đồ án lab nội bộ, nhưng cần ghi rõ trong Threat Model. |
