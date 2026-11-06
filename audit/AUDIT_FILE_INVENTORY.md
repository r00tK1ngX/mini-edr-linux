# AUDIT FILE INVENTORY — MINI EDR FOR LINUX

**Tài liệu:** Danh mục Kiểm kê Toàn bộ File & Module trong Repository (Phase 0)  
**Repository:** `r00tK1ngX/mini-edr-linux`  
**Ngày kiểm kê:** 05/11/2026  
**Tổng số dòng mã nguồn Python:** **10,417 dòng** (Ứng dụng: 5,193 dòng | Kiểm thử: 5,224 dòng)  
**Tổng số dòng Giao diện & Tĩnh:** **2,261 dòng** (Templates: 921 dòng | CSS/JS: 1,340 dòng)  

---

## 1. Phân hệ Ứng dụng Cốt lõi (Core Application Modules)

| Đường dẫn Thực tế | Số dòng | Module / Trách nhiệm Kỹ thuật | Đối chiếu Tài liệu & Bất nhất |
|---|---|---|---|
| `agent/client.py` | 196 | HTTP Client gửi telemetry envelope, Bearer token, retry backoff | Khớp với tài liệu |
| `agent/file_integrity.py` | 360 | Giám sát toàn vẹn tệp (FIM), SHA-256 hash, baseline sync, created/modified/deleted | Khớp với tài liệu |
| `agent/__init__.py` | 71 | Package exports cho Agent module | Khớp với tài liệu |
| `agent/main.py` | 333 | Agent Orchestrator loop, CLI arguments, signal handling, scheduled cycles | ⚠️ **Bất nhất:** Tài liệu và README gọi là `agent/orchestrator.py`, nhưng tên file thực tế là `agent/main.py` |
| `agent/process_collector.py` | 234 | Quét bảng `/proc` qua `psutil`, trích xuất 10 trường dữ liệu tiến trình | Khớp với tài liệu |
| `agent/system_collector.py` | 290 | Thu thập CPU%, RAM%, Disk%, Uptime, Hostname, IPv4 | Khớp với tài liệu |
| `detection/__init__.py` | 31 | Package exports cho Detection Engine | Khớp |
| `detection/correlation.py` | 186 | Phân tích tương quan đa sự kiện, tính điểm rủi ro ($0-100$) | ⚠️ **Bất nhất:** Tài liệu kiến trúc mô tả nằm ở `server/detection/`, thực tế nằm ở root `detection/` |
| `detection/engine.py` | 199 | Lõi điều phối Detection Engine, dispatching alerts | ⚠️ **Bất nhất:** Nằm ở root `detection/`, không phải `server/detection/` |
| `detection/rules.py` | 502 | Định nghĩa các rule: Suspicious process, Shell spawn, High CPU, FIM sensitive file | ⚠️ **Bất nhất:** Nằm ở root `detection/`, không phải `server/detection/` |
| `server/app.py` | 89 | Flask Application Factory (`create_app`), đăng ký blueprints, error handlers | Khớp với tài liệu |
| `server/db.py` | 102 | Quản lý kết nối SQLite3, PRAGMA WAL, foreign keys, busy timeout | Khớp với tài liệu |
| `server/__init__.py` | 0 | Package marker | Khớp |
| `server/routes.py` | 893 | API Ingestion Gateway, Bearer token auth, payload validation, alert REST endpoints | Khớp với tài liệu |
| `server/web.py` | 430 | Web Dashboard Blueprint, views, custom Jinja filters, AJAX triage controllers | Khớp với tài liệu |
| `server/repositories/base.py` | 30 | Base Repository context manager, transaction control | Khớp với tài liệu |
| `server/repositories/endpoint_repository.py` | 144 | CRUD máy trạm, trạng thái Online/Offline theo chu kỳ heartbeat | Khớp với tài liệu |
| `server/repositories/metrics_repository.py` | 130 | Lưu trữ và truy vấn metrics hệ thống | Khớp với tài liệu |
| `server/repositories/process_repository.py` | 209 | Lưu process snapshots và observations (Cascade delete) | Khớp với tài liệu |
| `server/repositories/baseline_repository.py` | 216 | Quản lý FIM baselines, hash check, missing state | Khớp với tài liệu |
| `server/repositories/event_repository.py` | 199 | Quản lý kho Security Events, fingerprint | Khớp với tài liệu |
| `server/repositories/alert_repository.py` | 330 | Quản lý vòng đời Alert, liên kết sự kiện, state guards, summary stats | Khớp với tài liệu |
| `server/repositories/__init__.py` | 19 | Package exports | Khớp |
| `server/migrations/runner.py` | 165 | Migration runner, kiểm tra checksum SHA-256, rollback an toàn | Khớp với tài liệu |
| `server/migrations/001_phase2_data_model.sql` | 150 | Script khởi tạo 8 bảng dữ liệu chuẩn SQLite 3NF | Khớp với tài liệu |

---

## 2. Phân hệ Giao diện & Tài nguyên Tĩnh (Frontend & Web UI)

| Đường dẫn Thực tế | Số dòng | Loại tài nguyên | Mô tả & Vai trò |
|---|---|---|---|
| `templates/base.html` | 162 | Jinja2 HTML Template | Khung layout HUD Cyberpunk, Top navigation bar, Modal deck, Toast container |
| `templates/dashboard.html` | 304 | Jinja2 HTML Template | Màn hình SOC Overview (4 KPI Tiles, 3 Resource Meters, Severity Matrix, Live stream) |
| `templates/endpoints.html` | 150 | Jinja2 HTML Template | Màn hình Endpoint Fleet, bộ lọc Online/Offline, ô tìm kiếm, nút Inspect |
| `templates/alerts.html` | 194 | Jinja2 HTML Template | Màn hình Incident Response Console, bộ lọc đa tiêu chí, nút Evidence/Ack/Resolve/Dismiss |
| `templates/events.html` | 111 | Jinja2 HTML Template | Màn hình Security Audit Logs & FIM Telemetry stream |
| `static/style.css` | 1012 | CSS3 Stylesheet | Bảng màu Neon Cyberpunk, Matrix grid, CRT scanlines, Tech chamfers |
| `static/dashboard.js` | 328 | Vanilla ES6+ JavaScript | Đồng hồ số UTC thời gian thực, AJAX modal loaders, AJAX triage action handlers, Toast |

---

## 3. Phân hệ Bộ Kiểm thử Tự động (Automated Test Suite)

| Tệp Kiểm thử | Số dòng | Số Tests | Phạm vi Kiểm thử |
|---|---|---|---|
| `tests/test_agent_client.py` | 161 | 10 | HTTP client, header authorization, error codes, retries |
| `tests/test_agent_orchestrator.py` | 143 | 6 | Vòng lặp Orchestrator, nạp cấu hình `.env`, bắt lỗi collector |
| `tests/test_alert_management.py` | 598 | 36 | Vòng đời alert, transition guards, idempotency, filtering, stats |
| `tests/test_api.py` | 693 | 38 | API endpoints, Bearer auth, envelope validation, error codes |
| `tests/test_dashboard.py` | 351 | 11 | Render Web views, HTTP redirect, modals JSON API, AJAX triage |
| `tests/test_database.py` | 531 | 13 | Kết nối SQLite, WAL mode, foreign keys, constraints |
| `tests/test_detection.py` | 512 | 22 | Rules evaluation, correlation engine, risk scoring, alert dispatch |
| `tests/test_file_integrity.py` | 250 | 7 | FIM hashing SHA-256, change detection (add, mod, del) |
| `tests/test_full_system_e2e.py` | 340 | 1 | Chu trình E2E khép kín 8 bước toàn hệ thống |
| `tests/test_migrations.py` | 246 | 7 | Schema migration runner, checksum verification, rollback |
| `tests/test_phase4_e2e.py` | 275 | 4 | Ingestion E2E, đa agent đăng ký, message_id idempotency |
| `tests/test_process_collector.py` | 224 | 13 | Quét `/proc`, xử lý NoSuchProcess/AccessDenied, snapshot payload |
| `tests/test_repositories.py` | 417 | 10 | Data Access Layer CRUD trên 7 bảng cơ sở dữ liệu |
| `tests/test_security_reliability.py` | 321 | 20 | 20 bài test an ninh: SQLi probes, XSS, token confidentiality, 64KB |
| `tests/test_system_collector.py` | 162 | 16 | Metrics phần cứng, network IPv4, uptime, permission fallback |
| **Tổng cộng** | **5,224** | **214** | **15 tệp kiểm thử tự động (100% PASS)** |

---

## 4. Scripts & Tiện ích Vận hành (Scripts & Utilities)

| Tệp tin | Số dòng | Quyền hạn | Vai trò & Mục đích |
|---|---|---|---|
| `scripts/seed_demo_data.py` | 268 | `rw-r--r--` | Nạp sẵn 3 Endpoints mẫu, FIM baseline, process snapshot chứa netcat, 3 alerts |
| `scripts/simulate_attack_scenario.py` | 326 | `rwxr-xr-x` | Tiện ích CLI tương tác dẫn dắt kịch bản tấn công demo 5-7 phút cho buổi bảo vệ đồ án |

---

## 5. Tài liệu Đặc tả & Hướng dẫn (Documentation)

| Tệp tài liệu | Số dòng | Vai trò kỹ thuật |
|---|---|---|
| `README.md` | 389 | Tài liệu giới thiệu sản phẩm, hướng dẫn Quickstart, kiến trúc, kiểm thử |
| `Lo_trinh_trien_khai_Mini_EDR_Linux.md` | 1116 | Lộ trình 10 Phases triển khai và checklist nghiệm thu chi tiết |
| `docs/ARCHITECTURE.md` | 370 | Đặc tả kiến trúc phân tầng, 3 Mermaid Sequence Diagrams, Mermaid ERD |
| `docs/DATA_CONTRACT.md` | 562 | Hợp đồng dữ liệu Common Telemetry Envelope 1.0, payloads, timestamp |
| `docs/API_SPECIFICATION.md` | 820 | Đặc tả toàn diện các REST APIs và Web routes |
| `docs/TEST_PLAN.md` | 226 | Kế hoạch kiểm thử và ma trận chi tiết 214 test cases |
| `docs/PRESENTATION_SLIDES_OUTLINE.md` | 397 | Khung thiết kế chi tiết 18 slide thuyết trình, lời thoại và câu hỏi phản biện |
| `docs/DEMO_SCENARIO.md` | 120 | Kịch bản trình diễn sản phẩm 5-7 phút, checklist phòng báo cáo |
| `doAnMiniEDR.txt` | 400 | Đề bài gốc và 6 trụ cột đồ án tốt nghiệp |

---

## 6. Các Tệp Tin Cơ sở Dữ liệu & Bản Sao Lưu (Databases & Backups)

| Đường dẫn | Kích thước | Trạng thái Git | Ghi chú an ninh |
|---|---|---|---|
| `data/mini_edr.db` | ~60 KB | Ignored (`.gitignore`) | Cơ sở dữ liệu hoạt động chính của server hiện tại |
| `data/mini_edr_before_phase2.db` | ~20 KB | Ignored | Bản sao lưu cơ sở dữ liệu cũ trước Phase 2 |
| `data/mini_edr_before_schema_001.db` | ~20 KB | Ignored | Bản sao lưu trước khi áp dụng migration 001 |
| `backups/mini_edr_before_phase2_2.db` | ~24 KB | Ignored | Bản sao lưu dự phòng trong thư mục backups |
| `.env` | 158 bytes | Ignored (`.gitignore`) | Chứa cấu hình cục bộ và `EDR_API_TOKEN` |
| `.env.example` | 514 bytes | Tracked trong Git | Mẫu cấu hình không chứa secret nhạy cảm |
| `config/rules.json` | ~2 KB | Tracked trong Git | File cấu hình mẫu quy tắc (rules definition) |
| `.github/workflows/ci.yml` | 766 bytes | Tracked trong Git | GitHub Actions CI workflow |
