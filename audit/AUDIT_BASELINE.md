# AUDIT BASELINE — MINI EDR FOR LINUX

**Tài liệu:** Báo cáo Baseline Khởi động Cuộc Kiểm toán (Phase 0)  
**Đơn vị thực hiện:** Senior Cybersecurity Engineer / Independent Security Auditor  
**Repository:** `r00tK1ngX/mini-edr-linux`  
**Ngày thực hiện:** 05/11/2026 (22:30 EST)  
**Chế độ kiểm toán:** **AUDIT-ONLY (Chỉ đọc, phân tích và kiểm thử an toàn; tuyệt đối không tự ý sửa mã nguồn, không thay đổi DB, không commit/push/merge)**

---

## 1. Thông tin Phiên bản & Trạng thái Git

| Thuộc tính | Giá trị ghi nhận thực tế | Ghi chú kỹ thuật |
|---|---|---|
| **Repository URL** | `https://github.com/r00tK1ngX/mini-edr-linux.git` | GitHub public repo |
| **Branch đang kiểm toán** | `feature/phase-10-slides-demo` | Chứa toàn bộ deliverables từ Phase 1 đến Phase 10 |
| **Commit Hash kiểm toán** | `c2745e135092cc121f6eae2b146992ae90de6029` | Commit mới nhất của PR #10 |
| **Base Branch `main`** | `f622aa015736d4efb8d53a25e9ab8b2e72bfc747` | Đã merge PR #9 (Phase 1-9) |
| **Trạng thái Working Tree** | Clean (Không có thay đổi chưa commit trước khi lập audit/) | Đảm bảo tính nguyên vẹn |
| **Trạng thái PRs trên GitHub** | PR #1 đến PR #9: ĐÃ MERGE vào `main`<br>PR #10: ĐANG MỞ (Pending merge) | Scope Phase 1 - 10 đầy đủ |

---

## 2. Thông số Môi trường Kỹ thuật (Runtime Environment)

| Thành phần | Phiên bản / Cấu hình thực tế | Ghi chú an ninh & tương thích |
|---|---|---|
| **Hệ điều hành** | Kali Linux `6.18.12+kali-amd64` (x86_64) | Môi trường Linux tiêu chuẩn cho EDR |
| **Python Runtime** | Python `3.14.8` (64-bit) | Runtime mới nhất, tương thích PEP 594 |
| **SQLite Engine** | SQLite `3.46.1` (2024-08-13) | Hỗ trợ đầy đủ WAL mode, Foreign Keys |
| **Virtual Environment** | `/home/kali/Projects/mini-edr-linux/.venv` | Môi trường cô lập độc lập |
| **Flask** | `3.1.3` | WSGI Web Framework |
| **psutil** | `7.2.2` | Thu thập thông số phần cứng & /proc |
| **Jinja2** | `3.1.6` | Template engine (Autoescape enabled) |
| **pytest** | `9.1.1` | Testing harness |
| **Werkzeug** | `3.1.9` | HTTP & WSGI Utilities |
| **python-dotenv** | `1.2.4` | Quản lý biến môi trường |

---

## 3. Baseline Kiểm thử Tự động (Automated Test Baseline)

Đã thực hiện chạy tươi (fresh execution) toàn bộ test suite trên môi trường thực tế:
- **Lệnh thực thi:** `.venv/bin/pytest -v`
- **Cấu hình:** `pytest.ini` (`pythonpath = .`)
- **Kết quả đo lường:**
  - **Tổng số ca kiểm thử phát hiện:** **214 items**
  - **Số ca kiểm thử VƯỢT QUA (PASSED):** **214 (100%)**
  - **Số ca kiểm thử THẤT BẠI (FAILED):** **0**
  - **Số ca kiểm thử BỎ QUA (SKIPPED):** **0**
  - **Số lỗi phát sinh (ERRORS):** **0**
  - **Thời gian thực thi:** **12.37 giây**

### Phân bổ 214 Test Cases theo Phân hệ:
1. `tests/test_agent_client.py`: 10 tests
2. `tests/test_agent_orchestrator.py`: 6 tests
3. `tests/test_alert_management.py`: 36 tests
4. `tests/test_api.py`: 38 tests
5. `tests/test_dashboard.py`: 11 tests
6. `tests/test_database.py`: 13 tests
7. `tests/test_detection.py`: 22 tests
8. `tests/test_file_integrity.py`: 7 tests
9. `tests/test_full_system_e2e.py`: 1 test (8-step lifecycle)
10. `tests/test_migrations.py`: 7 tests
11. `tests/test_phase4_e2e.py`: 4 tests
12. `tests/test_process_collector.py`: 13 tests
13. `tests/test_repositories.py`: 10 tests
14. `tests/test_security_reliability.py`: 20 tests
15. `tests/test_system_collector.py`: 16 tests

---

## 4. Các Giới hạn của Môi trường Kiểm toán (Audit Constraints & Limitations)

1. **Thiếu công cụ đo độ bao phủ mã tự động (`pytest-cov` / `coverage`):** Gói `pytest-cov` không có sẵn trong `.venv`. Auditor không thể suy diễn chỉ số phần trăm coverage tự động mà phải thực hiện rà soát thủ công mức độ bao phủ mã qua từng hàm/phân hệ.
2. **Thiếu công cụ quét mã tĩnh tự động (`bandit`, `safety`, `semgrep`, `flake8`):** Kiểm toán bảo mật và phân tích lỗ hổng mã nguồn được tiến hành thủ công 100% bằng cách truy vết luồng dữ liệu (Data Flow Analysis) và viết kịch bản probe an toàn.
3. **Giới hạn môi trường hộp cát (Sandbox Environment):** Hệ thống chạy trong container/sandbox Linux, không kết nối trực tiếp ra ngoài Internet công cộng (đáp ứng đúng nguyên tắc an toàn số 8 & 9 của bản quy tắc kiểm toán).
4. **Không có quyền Kernel Root tuyệt đối:** Các tác vụ kiểm thử không can thiệp sâu vào nhân kernel Linux hoặc can thiệp tắt các tiến trình PID của host chính, hoàn toàn phù hợp với phạm vi thiết kế của đồ án.
5. **Dịch vụ nền đang chạy:** Tiến trình Flask Server daemon đang lắng nghe tại `http://127.0.0.1:5000` (task background `task-1102`). Mọi kiểm thử dynamic probe trên endpoint nội bộ đều được thực hiện qua cổng này mà không ảnh hưởng tới dữ liệu gốc.
