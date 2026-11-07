# Mini EDR Linux --- Kế hoạch và Báo cáo Kiểm thử Hệ thống (Test Plan & Matrix)

**Tài liệu:** Test Plan & Verification Matrix  
**Phiên bản:** 2.1 (Phases 1-10 Post-Audit Finalized)  
**Ngày cập nhật:** 06/11/2026  
**Dự án:** Mini Endpoint Detection and Response for Linux  
**Repository:** `r00tK1ngX/mini-edr-linux`  
**Kết quả thực tế:** **230/230 tests PASSED (100%)** trong thời gian ~17.9 giây  

---

## 1. Mục tiêu Kiểm thử (Test Objectives)

Kế hoạch kiểm thử nhằm đảm bảo toàn diện các mục tiêu chất lượng kỹ thuật của giải pháp Mini EDR Linux:
1. **Tính chính xác của dữ liệu thu thập (Accuracy):** Xác thực các module Agent trích xuất chính xác thông tin phần cứng, mạng, tiến trình và mã băm toàn vẹn tệp SHA-256.
2. **Tuân thủ Data Contract (Contract Compliance):** Đảm bảo 100% các bản tin trao đổi giữa Agent và Server tuân thủ định dạng Common Telemetry Envelope 1.0, ràng buộc kiểu dữ liệu, ngưỡng chặn và mã băm.
3. **Hiệu quả của Động cơ Phát hiện (Detection Fidelity):** Kiểm tra khả năng phát hiện tức thời các kỹ thuật tấn công (Reverse shell, Hack tools, Leo thang đặc quyền, Can thiệp tệp nhạy cảm) và tính toán điểm rủi ro chính xác.
4. **Vòng đời Cảnh báo & Tính toàn vẹn Trạng thái (State Integrity):** Kiểm tra các bước chuyển trạng thái sự cố an ninh (`new` -> `acknowledged` -> `resolved`), đảm bảo tính bất biến của timestamp và chặn lùi trạng thái.
5. **Độ tin cậy & Khả năng Chống chịu (Reliability & Security Hardening):** Xác minh khả năng chống chịu tấn công tiêm mã SQL (SQLi), Cross-Site Scripting (XSS), chống tấn công gửi lặp (Replay attack via message_id), giới hạn kích thước payload (64KB), che giấu token an toàn và tính toàn vẹn cơ sở dữ liệu (`PRAGMA integrity_check`).

---

## 2. Phạm vi và Cấp độ Kiểm thử (Testing Scope)

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        CÁC CẤP ĐỘ KIỂM THỬ                             │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │ 1. UNIT TESTING (Kiểm thử đơn vị)                              │   │
│   │    - Collectors: System, Process, File Integrity (FIM)         │   │
│   │    - Agent HTTP Client & Orchestrator loop                     │   │
│   │    - Repositories DAL (SQLite Row Mappings)                    │   │
│   │    - Migration Runner & Checksum Verifier                      │   │
│   │    - Detection Rules (Rule Registry & Evaluator)               │   │
│   └────────────────────────────────┬───────────────────────────────┘   │
│                                    │                                   │
│   ┌────────────────────────────────▼───────────────────────────────┐   │
│   │ 2. INTEGRATION TESTING (Kiểm thử tích hợp phân hệ)             │   │
│   │    - Ingestion APIs: /heartbeat, /telemetry/*, /file-baselines │   │
│   │    - Detection Engine kết hợp Data Access Layer                │   │
│   │    - Alert Lifecycle APIs (/acknowledge, /resolve, /dismiss)   │   │
│   │    - Web Dashboard Views & AJAX Modals                         │   │
│   └────────────────────────────────┬───────────────────────────────┘   │
│                                    │                                   │
│   ┌────────────────────────────────▼───────────────────────────────┐   │
│   │ 3. END-TO-END (E2E) TESTING (Kiểm thử toàn chu trình)          │   │
│   │    - Agent Registration -> Baseline -> Suspicious Activity     │   │
│   │    - Telemetry Ingestion -> Alert Generation -> Web SOC Triage │   │
│   │    - Agent Offline Tracking & Recovery Verification            │   │
│   └────────────────────────────────┬───────────────────────────────┘   │
│                                    │                                   │
│   ┌────────────────────────────────▼───────────────────────────────┐   │
│   │ 4. SECURITY & RELIABILITY (Kiểm thử an ninh & độ tin cậy)      │   │
│   │    - SQL Injection Probe Suite (100% Parameterized DAL)        │   │
│   │    - Reflected & Stored XSS Sanitization                       │   │
│   │    - Bearer Token Redaction in Logging & Confidentiality       │   │
│   │    - Payload Bound (MAX_CONTENT_LENGTH 64KB -> HTTP 413)       │   │
│   │    - Message ID Idempotency & Replay Resistance                │   │
│   │    - SQLite PRAGMA integrity_check & foreign_key_check         │   │
│   └────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Ma trận Ca Kiểm thử Chi tiết (Test Matrix)

### 3.1. Phân hệ Linux Agent (`agent/`)

| Test File | Test Case | Mục đích & Mô tả | Dữ liệu đầu vào | Kết quả mong đợi | Thực tế |
|---|---|---|---|---|---|
| `test_system_collector.py` | `test_collect_metrics_valid` | Thu thập metrics hệ thống | Linux host `/proc` | CPU, RAM, Disk $\in [0, 100]$, Uptime $\ge 0$ | **PASS** |
| `test_system_collector.py` | `test_collect_network_ip` | Lấy non-loopback IPv4 | Network interfaces | Chuỗi IPv4 hợp lệ (khác `127.0.0.1`) | **PASS** |
| `test_system_collector.py` | `test_permission_fallback` | Xử lý lỗi quyền truy cập | Mock `PermissionError` | Trả về fallback an toàn, không crash | **PASS** |
| `test_process_collector.py` | `test_scan_processes` | Quét bảng tiến trình | Bảng tiến trình Linux | Trích xuất PID, PPID, exe, RSS, username | **PASS** |
| `test_process_collector.py` | `test_handle_dead_process` | Xử lý tiến trình chết giữa chừng | Mock `NoSuchProcess` | Bỏ qua an toàn và tiếp tục tiến trình khác | **PASS** |
| `test_process_collector.py` | `test_handle_access_denied`| Bắt lỗi quyền root tiến trình | Mock `AccessDenied` | Giữ thông tin cơ bản, không sập Agent | **PASS** |
| `test_file_integrity.py` | `test_compute_sha256` | Băm tệp SHA-256 | Tệp văn bản mẫu | 64 ký tự hex chữ thường chuẩn | **PASS** |
| `test_file_integrity.py` | `test_detect_file_created` | Phát hiện tệp mới | Tạo tệp mới trong thư mục | Trả về sự kiện `created` | **PASS** |
| `test_file_integrity.py` | `test_detect_file_modified`| Phát hiện tệp bị sửa | Thay đổi nội dung tệp | Trả về sự kiện `modified` kèm hash mới | **PASS** |
| `test_file_integrity.py` | `test_detect_file_deleted` | Phát hiện tệp bị xóa | Xóa tệp giám sát | Trả về sự kiện `deleted` (state: missing) | **PASS** |
| `test_file_integrity.py` | `test_fim_symlink_traversal_protection` | Chống tấn công vượt quyền qua symlink | Tạo symlink trỏ tệp nhạy cảm | Từ chối băm symlink giả mạo via `os.lstat` | **PASS** |
| `test_file_integrity.py` | `test_fim_quick_check_caching` | Tối ưu hiệu năng băm bằng cache mtime | Tệp không đổi kích thước & mtime | Tái sử dụng hash cũ, tiết kiệm I/O ổ đĩa | **PASS** |
| `test_agent_client.py` | `test_envelope_creation` | Đóng gói bản tin hợp lệ | Payload telemetry thô | Có UUIDv4 `message_id`, ISO 8601 UTC | **PASS** |
| `test_agent_client.py` | `test_send_heartbeat_auth` | Gửi heartbeat có Bearer Token | Cấu hình API token | Header `Authorization: Bearer <token>` | **PASS** |
| `test_agent_orchestrator.py`| `test_scheduled_cycles` | Điều phối chu kỳ quét | Tần suất chu kỳ 5s/10s | Kích hoạt các collector đúng hẹn | **PASS** |
| `test_agent_orchestrator.py`| `test_orchestrator_fim_event_retention_on_network_failure` | Two-phase commit FIM khi đứt mạng | Mô phỏng Server 500 / Network drop | Giữ nguyên baseline, gửi lại sự kiện | **PASS** |

### 3.2. Phân hệ API Server & Ingestion (`server/routes.py`)

| Test File | Test Case | Mục đích & Mô tả | Dữ liệu đầu vào | Kết quả mong đợi | Thực tế |
|---|---|---|---|---|---|
| `test_api.py` | `test_health_check` | Kiểm tra tình trạng server | `GET /health` | HTTP 200 `{"status": "ok"}` | **PASS** |
| `test_api.py` | `test_auth_missing_token` | Chặn truy cập không xác thực | `POST /heartbeat` không token | HTTP 401 Unauthorized | **PASS** |
| `test_api.py` | `test_auth_invalid_token` | Chặn truy cập sai token | Header token sai | HTTP 401 Unauthorized | **PASS** |
| `test_api.py` | `test_heartbeat_valid` | Tiếp nhận heartbeat hợp lệ | Payload heartbeat chuẩn | HTTP 200, cập nhật `last_seen` | **PASS** |
| `test_api.py` | `test_metrics_ingest` | Tiếp nhận telemetry hệ thống | `POST /telemetry/system` | HTTP 201 Created | **PASS** |
| `test_api.py` | `test_processes_ingest`| Tiếp nhận process snapshot | `POST /telemetry/processes`| HTTP 201 Created, lưu snapshot + obs | **PASS** |
| `test_api.py` | `test_baselines_sync` | Đồng bộ FIM baseline | `POST /file-baselines` | HTTP 200 (processed, created, updated) | **PASS** |
| `test_api.py` | `test_events_ingest` | Tiếp nhận security event | `POST /events` | HTTP 201 Created | **PASS** |
| `test_api.py` | `test_invalid_schema_ver` | Chặn phiên bản contract sai | `schema_version: "2.0"` | HTTP 400 Bad Request | **PASS** |
| `test_api.py` | `test_invalid_uuid` | Chặn message_id không phải UUID | `message_id: "123"` | HTTP 400 Bad Request | **PASS** |
| `test_api.py` | `test_payload_too_large` | Chặn payload vượt ngưỡng cấu hình | Body chuỗi $> 64$ KB (configured) | HTTP 413 Request Entity Too Large | **PASS** |
| `test_api.py` | `test_default_max_content_length_accepts_large_process_snapshot` | Chấp nhận snapshot tiến trình lớn 16MB | Body snapshot dung lượng cao | HTTP 201 Created | **PASS** |
| `test_api.py` | `test_create_app_rejects_weak_token_in_production` | Chặn token yếu trong môi trường prod | Token $< 32$ ký tự hoặc placeholder | Ném lỗi `ValueError` tại factory | **PASS** |

### 3.3. Phân hệ Cơ sở Dữ liệu & DAL (`server/repositories/`, `server/migrations/`)

| Test File | Test Case | Mục đích & Mô tả | Dữ liệu đầu vào | Kết quả mong đợi | Thực tế |
|---|---|---|---|---|---|
| `test_database.py` | `test_connection_wal_mode`| Xác thực cơ chế ghi WAL | Khởi tạo kết nối SQLite | `PRAGMA journal_mode = wal` | **PASS** |
| `test_database.py` | `test_foreign_keys_on` | Xác thực thực thi khóa ngoại | Khởi tạo kết nối SQLite | `PRAGMA foreign_keys = 1` | **PASS** |
| `test_repositories.py` | `test_endpoint_upsert` | Cập nhật endpoint idempotent | 2 heartbeat cùng agent_id | 1 bản ghi duy nhất, update `last_seen`| **PASS** |
| `test_repositories.py` | `test_endpoint_heartbeat_coalesce_preserves_metadata` | Bảo tồn metadata máy trạm qua COALESCE | Heartbeat thiếu metadata | Giữ nguyên metadata cũ, không ghi đè NULL | **PASS** |
| `test_repositories.py` | `test_process_cascade_del`| Xóa tầng cascade observation | Xóa snapshot ID | Tự động xóa các observations con | **PASS** |
| `test_repositories.py` | `test_fim_missing_state` | Bảo toàn lịch sử hash FIM | Tệp bị xóa khỏi máy trạm | Cập nhật `state = 'missing'` | **PASS** |
| `test_repositories.py` | `test_alert_severity_escalation_and_non_downgrade` | Chống hạ cấp độ nghiêm trọng Alert | Ghi nhận event severity thấp hơn | Mức độ nghiêm trọng giữ nguyên/leo thang | **PASS** |
| `test_migrations.py` | `test_apply_all_migrations`| Áp dụng toàn bộ migration | Schema scripts `.sql` | Bảng được tạo đủ, checksum hợp lệ | **PASS** |
| `test_migrations.py` | `test_tampered_migration` | Chặn sửa file migration cũ | Sửa checksum file SQL | Phát hiện gian lận và dừng khởi động | **PASS** |
| `test_migrations.py` | `test_transaction_rollback`| Rollback khi migration lỗi | File SQL chứa cú pháp sai | Rollback toàn bộ, database nguyên vẹn | **PASS** |

### 3.4. Phân hệ Detection Engine (`detection/`)

| Test File | Test Case | Mục đích & Mô tả | Dữ liệu đầu vào | Kết quả mong đợi | Thực tế |
|---|---|---|---|---|---|
| `test_detection.py` | `test_detect_netcat` | Phát hiện công cụ netcat | Tiến trình `nc -lvnp 4444` | Tạo event `RULE_SUSPICIOUS_PROCESS` | **PASS** |
| `test_detection.py` | `test_detect_tmp_binary` | Phát hiện binary trong `/tmp` | Tiến trình `/tmp/malware` | Kích hoạt cảnh báo mức `CRITICAL` | **PASS** |
| `test_detection.py` | `test_detect_shell_spawn`| Phát hiện reverse shell | `apache2` sinh `sh` | Kích hoạt `RULE_SHELL_SPAWN` | **PASS** |
| `test_detection.py` | `test_rule_proc_shell_spawn_detects_web_daemon_shell` | Shell sinh từ dịch vụ web daemon | Tiến trình `sh` dưới user `www-data` | Tạo event `rule-proc-shell-spawn` (HIGH) | **PASS** |
| `test_detection.py` | `test_rule_fim_dropped_binary_detects_new_executables_in_temp_dir` | Bắt dropped binary trong `/tmp` | Tệp mới `/tmp/dropper.elf` | Tạo event `rule-fim-dropped-binary` (HIGH) | **PASS** |
| `test_detection.py` | `test_detect_shadow_mod` | Phát hiện can thiệp `/etc/shadow`| FIM event sửa `/etc/shadow` | Kích hoạt `RULE_FIM_SENSITIVE_FILE` | **PASS** |
| `test_detection.py` | `test_correlation_score` | Tính toán điểm rủi ro tương quan| FIM mod + Suspicious process | Risk score $> 85$, mức `CRITICAL` | **PASS** |
| `test_detection.py` | `test_correlation_min_score_threshold_enforced` | Ngưỡng tương quan tối thiểu | Chuỗi vi phạm điểm thấp $< 60$ | Không sinh Correlated Alert rác | **PASS** |
| `test_detection.py` | `test_fim_dropped_binary_and_process_exec_correlation_e2e` | Tương quan Dropped Binary + Thực thi | Dropper ELF + chạy tiến trình | Kích hoạt Alert tổng hợp `CRITICAL` | **PASS** |
| `test_detection.py` | `test_alert_dedup` | Khử trùng cảnh báo theo key | 3 sự kiện cùng một nguyên nhân| 1 Alert duy nhất, 3 events liên kết | **PASS** |

### 3.5. Phân hệ Quản lý Cảnh báo & Incident Management (`server/routes.py`)

| Test File | Test Case | Mục đích & Mô tả | Dữ liệu đầu vào | Kết quả mong đợi | Thực tế |
|---|---|---|---|---|---|
| `test_alert_management.py` | `test_list_alerts_filters`| Lọc theo status & severity | Query `status=new&severity=high`| Trả về đúng danh sách đã lọc | **PASS** |
| `test_alert_management.py` | `test_alert_detail_events`| Chi tiết cảnh báo kèm events | `GET /alerts/<id>` | Trả về alert + array `events` | **PASS** |
| `test_alert_management.py` | `test_alert_acknowledge` | Xác nhận xử lý sự cố | `POST /alerts/<id>/acknowledge`| Status chuyển `acknowledged` | **PASS** |
| `test_alert_management.py` | `test_alert_resolve` | Đóng cảnh báo có ghi chú | `POST /alerts/<id>/resolve` | Status chuyển `resolved`, lưu note | **PASS** |
| `test_alert_management.py` | `test_alert_dismiss` | Bỏ qua cảnh báo dương tính | `POST /alerts/<id>/dismiss` | Status chuyển `resolved`, note dismiss | **PASS** |
| `test_alert_management.py` | `test_state_guard` | Chặn lùi trạng thái bất hợp lệ | Acknowledge alert đã resolve | HTTP 400 / 409 Bad Request | **PASS** |
| `test_alert_management.py` | `test_ack_idempotency` | Idempotent khi bấm ACK nhiều lần| Gửi 2 lần acknowledge | HTTP 200, không đổi `acknowledged_at`| **PASS** |
| `test_alert_management.py` | `test_alert_summary_stats`| Thống kê tổng quan cảnh báo | `GET /alerts/summary` | Trả về count `by_status`, `by_severity`| **PASS** |

### 3.6. Phân hệ Web Dashboard & SOC Console (`server/web.py`)

| Test File | Test Case | Mục đích & Mô tả | Dữ liệu đầu vào | Kết quả mong đợi | Thực tế |
|---|---|---|---|---|---|
| `test_dashboard.py` | `test_root_redirect` | Chuyển hướng trang chủ | `GET /` | HTTP 302 Redirect về `/dashboard` | **PASS** |
| `test_dashboard.py` | `test_dashboard_overview` | Render Dashboard KPI thật | `GET /dashboard` | HTML chứa 4 cyber tiles và meters | **PASS** |
| `test_dashboard.py` | `test_endpoints_fleet` | Danh sách máy trạm & trạng thái | `GET /endpoints` | HTML danh sách máy Online/Offline | **PASS** |
| `test_dashboard.py` | `test_endpoint_telemetry`| API modal nạp tiến trình & FIM | `GET /endpoints/<id>/telemetry` | JSON `processes` và `fim_count` | **PASS** |
| `test_dashboard.py` | `test_alerts_console` | Giao diện Incident Response | `GET /alerts` | HTML bảng xử lý sự cố an ninh | **PASS** |
| `test_dashboard.py` | `test_alert_detail_modal`| API modal nạp bằng chứng | `GET /alerts/<id>/detail` | JSON `evidence` và `events` | **PASS** |
| `test_dashboard.py` | `test_web_ajax_actions` | AJAX Ack/Resolve/Dismiss | `POST /alerts/<id>/resolve` | JSON `success: true`, toast ready | **PASS** |
| `test_dashboard.py` | `test_events_audit_log` | Giao diện nhật ký kiểm toán | `GET /events` | HTML danh sách security audit logs | **PASS** |

### 3.7. Kiểm thử Tích hợp Toàn hệ thống E2E (`tests/test_full_system_e2e.py`)

| Test File | Test Case | Kịch bản Kiểm thử Vòng đời 8 Bước | Kết quả mong đợi | Thực tế |
|---|---|---|---|---|
| `test_full_system_e2e.py` | `test_full_system_e2e_lifecycle` | **Bước 1:** Agent đăng ký heartbeat & nạp metrics CPU/RAM/Disk ban đầu | Endpoint `online`, metrics lưu DB | **PASS** |
| | | **Bước 2:** Đồng bộ FIM baseline các tệp quan trọng (`/etc/shadow`, `/usr/bin/sudo`) | Lưu 2 baseline records | **PASS** |
| | | **Bước 3:** Agent quét và gửi Process Snapshot chứa `/tmp/nc -lvnp 4444` | Lưu snapshot và 2 observations | **PASS** |
| | | **Bước 4:** Real-time Detection Engine kích hoạt phân tích tương quan | Tự động tạo Alert `CRITICAL` Netcat | **PASS** |
| | | **Bước 5:** Agent gửi sự kiện FIM phát hiện sửa đổi tệp `/etc/shadow` | Tự động tạo Alert `HIGH` Tampering | **PASS** |
| | | **Bước 6:** Web Dashboard SOC truy vấn Overview, Endpoints, Alerts và Events | Hiển thị 100% dữ liệu đồng nhất | **PASS** |
| | | **Bước 7:** SOC Analyst thực hiện quy trình Triage: Acknowledge -> Resolve | Trạng thái cập nhật, chặn lùi status | **PASS** |
| | | **Bước 8:** Agent mất kết nối chuyển `offline`, sau đó gửi heartbeat khôi phục `online` | Trạng thái chuyển đổi chính xác | **PASS** |
| | | **Xác minh toàn vẹn:** Chạy `PRAGMA integrity_check` và `foreign_key_check` | Kết quả `ok`, 0 lỗi khóa ngoại | **PASS** |

### 3.8. Kiểm thử An ninh & Độ tin cậy (`tests/test_security_reliability.py`)

| Nhóm Kiểm thử | Số ca | Kịch bản & Vector Tấn công Thử nghiệm | Kết quả mong đợi | Thực tế |
|---|---|---|---|---|
| **Database Integrity** | 2 | Chạy `PRAGMA integrity_check` và `PRAGMA foreign_key_check` trên DB chứa dữ liệu thật | Trả về `ok`, không có bản ghi mồ côi | **PASS** |
| **SQL Injection** | 7 | Thử nghiệm các vector SQLi: `' OR '1'='1`, `'; DROP TABLE endpoints; --`, `UNION SELECT` trên mọi tham số query và filter (`status`, `severity`, `agent_id`, `rule_id`, `file_path`, pagination) | 100% Parameterized DAL, không bị lỗi cú pháp SQL, không rò rỉ dữ liệu trái phép | **PASS** |
| **DOM XSS & Attribute Sanitization** | 6 | Thử nghiệm payload XSS trong DOM và thuộc tính thẻ HTML: `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`, `javascript:...` trong tên endpoint, title cảnh báo, description, evidence và resolution note | Khử khuẩn an toàn qua `escapeHtml()` và Jinja2 autoescape; loại bỏ inline handlers | **PASS** |
| **Console Authentication & CSRF** | 3 | Truy cập Web Console khi chưa đăng nhập; Gửi request thay đổi trạng thái Alert (`ACK`, `RESOLVE`, `DISMISS`) khi thiếu hoặc sai token CSRF | Chuyển hướng `/login` hoặc trả về HTTP 403 Forbidden; bảo vệ an toàn phiên làm việc | **PASS** |
| **Token Confidentiality & Secret Key** | 3 | Kiểm tra nhật ký server; kiểm tra token độ dài $\ge 32$ ký tự; kiểm tra ký phiên session với SECRET_KEY | Bearer Token được che giấu/redacted an toàn, khóa phiên vững chắc | **PASS** |
| **Input Validation & Bound Limits** | 2 | Gửi payload vượt 64KB, CPU $< 0$ hoặc $> 100$, NaN, Infinity, sai kiểu dữ liệu | Trả về HTTP 413 hoặc HTTP 400, từ chối dữ liệu rác | **PASS** |
| **Idempotency** | 2 | Gửi lại bản tin trùng `message_id`: (1) Cùng nội dung, (2) Khác nội dung (Replay/tampering) | Cùng nội dung: HTTP 200 duplicate; Khác nội dung: HTTP 409 conflict | **PASS** |

### 3.9. Kiểm thử Thực nghiệm Kịch bản Tấn công Live Demo (`scripts/simulate_attack_scenario.py`)

| Bước Demo | Mục tiêu & Hành vi | Tương tác Endpoint / Server | Kết quả Ghi nhận | Thực tế |
|---|---|---|---|---|
| **Bước 1** | Đăng ký máy trạm & gửi Heartbeat đầu tiên | `POST /api/v1/heartbeat` | HTTP 200, Endpoint `demo-workstation-01` Online | **PASS** |
| **Bước 2** | Thiết lập FIM Baseline tệp cấu hình `/tmp/mini_edr_demo/secure_config.conf` | `POST /api/v1/file-baselines` | HTTP 200, lưu SHA-256 ban đầu | **PASS** |
| **Bước 3** | Tấn công sửa tệp nhạy cảm chèn `PERMIT_ROOT_LOGIN=yes` | `POST /api/v1/events` | HTTP 201, kích hoạt Alert `HIGH` FIM Tampering | **PASS** |
| **Bước 4** | Mô phỏng chạy tiến trình độc hại `/tmp/nc -lvnp 4444` | `POST /api/v1/telemetry/processes` | HTTP 201, phát hiện `RULE_SUSPICIOUS_PROCESS`, gán Risk Score 90/100 (`CRITICAL`) | **PASS** |
| **Bước 5** | Tổng kết Alert và hướng dẫn SOC Triage trên Web Console | `GET /api/v1/alerts/summary` | HTTP 200, thống kê 6 Alerts (4 active), hướng dẫn Evidence/ACK/RESOLVE | **PASS** |

---

## 4. Hướng dẫn Chạy Kiểm thử (Test Execution)

Toàn bộ các test cases đều chạy độc lập, tự động khởi tạo cơ sở dữ liệu SQLite trong bộ nhớ tạm (`:memory:` hoặc file temp cô lập), không làm ảnh hưởng đến dữ liệu đang vận hành.

### 4.1. Lệnh chạy toàn bộ 230 test cases

```bash
cd /home/kali/Projects/mini-edr-linux
.venv/bin/pytest -v
```

### 4.2. Lệnh chạy theo từng phân hệ chuyên biệt

```bash
# 1. Chạy riêng kiểm thử Unit Agent
.venv/bin/pytest tests/test_system_collector.py tests/test_process_collector.py tests/test_file_integrity.py -v

# 2. Chạy riêng kiểm thử Ingestion APIs & DAL
.venv/bin/pytest tests/test_api.py tests/test_repositories.py tests/test_database.py -v

# 3. Chạy riêng kiểm thử Detection Engine & Correlation
.venv/bin/pytest tests/test_detection.py tests/test_correlation.py -v

# 4. Chạy riêng kiểm thử Alert Management & Web Dashboard
.venv/bin/pytest tests/test_alert_management.py tests/test_dashboard.py -v

# 5. Chạy riêng kiểm thử Full System E2E Lifecycle
.venv/bin/pytest tests/test_full_system_e2e.py -v

# 6. Chạy riêng kiểm thử An ninh & Độ tin cậy (Security & Reliability)
.venv/bin/pytest tests/test_security_reliability.py -v

# 7. Chạy mô phỏng kịch bản tấn công thực tế trên Server đang chạy
.venv/bin/python scripts/simulate_attack_scenario.py --auto
```
.venv/bin/pytest tests/test_security_reliability.py -v
```

### 4.3. Lệnh kiểm tra độ bao phủ mã (Code Coverage)

```bash
.venv/bin/pytest --cov=server --cov=agent --cov-report=term-missing
```

---

## 5. Kết luận & Đánh giá Nghiệm thu

- **Tỷ lệ vượt qua (Pass Rate):** **100% (214/214 tests PASS)**.
- **Thời gian thực thi:** ~12.5 giây trên môi trường Linux chuẩn.
- **Tiêu chuẩn bảo mật:** Không phát hiện bất kỳ lỗ hổng cơ bản nào (SQLi, XSS, Replay, DoS via payload size, Token leakage).
- **Độ tin cậy dữ liệu:** Đạt 100% tiêu chí toàn vẹn SQLite, ràng buộc khóa ngoại và tính bất biến của chuỗi thời gian sự kiện.
