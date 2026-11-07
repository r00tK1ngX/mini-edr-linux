# BÁO CÁO NGHIỆM THU TÁI THIẾT KẾ GIAO DIỆN WEB DASHBOARD
## MINI EDR FOR LINUX — MINIMAL CYBERPUNK SOC COMMAND CENTER

- **Dự án:** Mini EDR for Linux (`https://github.com/r00tK1ngX/mini-edr-linux`)
- **Nhánh thực hiện:** `feature/dashboard-minimal-cyberpunk-redesign`
- **Thời gian hoàn thành:** 2026-11-07
- **Vai trò:** Senior UI/UX Designer & Senior Frontend Engineer
- **Kết quả kiểm thử:** **302/302 tests PASSED (100% Pass Rate, 0 Regression)**

---

## 1. TỔNG QUAN DỰ ÁN VÀ ĐỊNH HƯỚNG THIẾT KẾ

Nhiệm vụ tái thiết kế toàn bộ giao diện điều hành Web Dashboard của hệ thống Mini EDR Linux nhằm mang lại trải nghiệm chuyên nghiệp của một Trung tâm Điều hành An ninh Mạng (SOC Command Center), hiện đại, tối giản, thanh lịch nhưng vẫn duy trì bản sắc công nghệ cao (Subtle Cyberpunk).

### 1.1. Các nguyên tắc cốt lõi đã đạt được
1. **Minimal Cyberpunk — Data-First:** Loại bỏ hoàn toàn hiệu ứng quét CRT (`scanlines`) gây mỏi mắt, giảm tối đa hiệu ứng phát sáng neon mờ (`neon-glow`) rực rỡ quá mức. Thay vào đó là thiết kế đường viền kỹ thuật 1px sắc nét (`#26364B`), bề mặt đa tầng sâu thẳm (`#0B1120`, `#0E1728`, `#121D2E`), điểm nhấn Cyan tinh tế (`#22D3EE`).
2. **Tối ưu hóa tiếng Việt với Font Be Vietnam Pro:** 100% typography văn bản chính sử dụng phông chữ **Be Vietnam Pro** với đầy đủ các subset `vietnamese`, `latin`, `latin-ext` ở các weight 400, 500, 600, 700. Không phụ thuộc CDN bên ngoài; toàn bộ 12 tệp WOFF2 được lưu trữ nội bộ tại `static/fonts/` đáp ứng chuẩn Air-Gapped / Offline. Phông Monospace chỉ được sử dụng cho mã định danh kỹ thuật (PID, SHA-256, Rule ID, Agent ID, IP Address, JSON raw data).
3. **Bố cục App Shell hiện đại (Sidebar + Topbar + Main Content):**
   - **Sidebar bên trái (256px):** Phân nhóm chức năng rõ ràng (`TỔNG QUAN`, `GIÁM SÁT AN NINH`, `TRẠNG THÁI HỆ THỐNG`), tích hợp nhãn trạng thái trực tiếp với đèn beacon xanh (`Hệ thống hoạt động`).
   - **Topbar trên cùng (60px):** Breadcrumb điều hướng theo ngữ cảnh, đồng hồ thời gian thực chuẩn UTC (`#hudClock`), thông tin vai trò SOC Operator và nút Đăng xuất an toàn (POST CSRF).
   - **Khu vực nội dung (Main Viewport):** Tự động thích ứng (Responsive) mượt mà từ màn hình máy tính để bàn (1920x1080, 1440x900) đến laptop (1280x800) và tablet/mobile (1024px và 768px).
4. **Bảo toàn 100% Logic Backend & API Contract:** Không sửa đổi bất kỳ logic Flask backend, SQLite schema, Detection engine hay Agent telemetry nào. Mọi route, session cookie flags, token auth, CSRF middleware đều hoạt động nguyên vẹn.

---

## 2. BẢNG MÃ MÀU & THIẾT KẾ THÀNH PHẦN (DESIGN TOKENS)

| Thành phần giao diện | Tên màu | Mã HEX | Vai trò |
| :--- | :--- | :--- | :--- |
| **Main Canvas** | Deep Navy | `#0B1120` | Nền chính của toàn bộ trang |
| **Sidebar & Topbar** | Dark Navy | `#0E1728` | Thanh điều hướng và tiêu đề |
| **Card Surface** | Surface Slate | `#121D2E` | Bề mặt các thẻ thông tin và bảng |
| **Elevated Surface** | Elevated Slate | `#18263A` | Modals, menu dropdown, toast |
| **Primary Text** | Off-white | `#E6EDF6` | Văn bản chính, tiêu đề, số liệu |
| **Secondary Text** | Muted Slate | `#94A3B8` | Nhãn phụ, mô tả sự cố |
| **Dimmed Text** | Slate Dim | `#64748B` | Thời gian, ghi chú kỹ thuật |
| **Structural Border**| Subtle Slate | `#26364B` | Đường viền 1px phân tách các khối |
| **Primary Accent** | Cyber Cyan | `#22D3EE` | Nút chính, menu đang chọn, liên kết |
| **Accent Hover** | Bright Cyan | `#67E8F9` | Hiệu ứng rê chuột |
| **Success Status** | Emerald Green | `#34D399` | Trạng thái Online, Đã giải quyết |
| **Warning Status** | Warm Amber | `#FBBF24` | Trạng thái Đang xử lý, Mức độ Medium |
| **Danger Status** | Alert Red | `#F87171` | Mức độ Critical, High, Mới phát hiện |
| **Info / Low** | Sky Blue | `#60A5FA` | Mức độ Low, Thông tin hệ thống |
| **Telemetry Audit** | Purple | `#C084FC` | Loại sự kiện đo lường, FIM audit |

---

## 3. CHUẨN HÓA THUẬT NGỮ TIẾNG VIỆT CHUYÊN NGÀNH SOC

Toàn bộ nhãn giao diện được chuẩn hóa bằng thuật ngữ bảo mật tiếng Việt tự nhiên, chính xác, giữ nguyên các thuật ngữ kỹ thuật quốc tế khi cần thiết:

| Tiếng Anh gốc | Thuật ngữ Tiếng Việt chuẩn hóa trên Giao diện | Vị trí áp dụng |
| :--- | :--- | :--- |
| **Overview / Dashboard** | **Tổng quan SOC** | Sidebar, Topbar, Tiêu đề trang |
| **Endpoints** | **Máy tính đầu cuối** | Sidebar, Bảng điều khiển thiết bị |
| **Incidents & Alerts** | **Sự cố & Cảnh báo** | Sidebar, Thẻ KPI, Bảng sự cố |
| **Audit Logs / Events** | **Nhật ký sự kiện** | Sidebar, Bảng kiểm toán đo lường |
| **Monitored Endpoints** | **Máy tính đầu cuối đang giám sát** | Thẻ KPI Overview (giữ chuỗi test) |
| **Active Incidents** | **Sự cố đang mở** | Thẻ KPI Overview |
| **Critical Threats** | **Mối đe dọa nguy hiểm (Critical)** | Thẻ KPI Overview |
| **Online / Offline** | **Đang hoạt động / Ngoại tuyến** | Huy hiệu trạng thái thiết bị |
| **New / Open** | **Mới phát hiện** | Huy hiệu trạng thái sự cố |
| **Acknowledged** | **Đang xử lý (Xác nhận)** | Huy hiệu & Nút thao tác nhanh |
| **Resolved** | **Đã giải quyết** | Huy hiệu & Nút giải quyết |
| **Dismissed** | **Đã bỏ qua (Cảnh báo giả)** | Nút thao tác Triage |
| **Evidence Deck** | **Minh chứng điều tra an ninh** | Cửa sổ Modal chi tiết sự cố |
| **Inspect Endpoint** | **Kiểm tra máy trạm** | Cửa sổ Modal tiến trình & phần cứng |
| **Authenticate Session**| **Xác thực phiên làm việc / Đăng nhập**| Trang xác thực SOC Gateway |

---

## 4. CHI TIẾT TÁI THIẾT KẾ TỪNG MÀN HÌNH

### 4.1. Khung giao diện toàn cục (`templates/base.html`)
- Chuyển đổi thành công kiến trúc từ Top Navigation đơn giản sang **Sidebar cố định bên trái (256px)** và **Topbar phía trên (60px)**.
- Phông chữ Be Vietnam Pro được nạp qua `@import url('fonts.css');` ngay đầu `static/style.css`.
- Bảo toàn tuyệt đối các thẻ định danh và element ID quan trọng cho JavaScript:
  - `<meta name="csrf-token" content="{{ csrf_token() }}">`
  - Đồng hồ thời gian thực: `<div class="hud-clock" id="hudClock">--:--:-- UTC</div>`
  - Các Modals: `#evidenceModal`, `#evidenceModalBody`, `#resolveModal`, `#resolveModalAlertTitle`, `#resolveNoteInput`, `#endpointModal`, `#endpointModalBody`.
  - Hộp thông báo nổi: `#toastContainer`.

### 4.2. Trang Tổng quan SOC (`templates/dashboard.html`)
- **4 Thẻ đo lường KPI:**
  - Máy tính đầu cuối (`MONITORED ENDPOINTS`): Hiển thị tổng số thiết bị cùng tỉ lệ Đang hoạt động / Ngoại tuyến.
  - Sự cố đang mở: Đếm số lượng sự cố chưa giải quyết kèm phân loại Mới / Đang xử lý.
  - Mối đe dọa nguy hiểm: Đếm số lượng sự cố nghiêm trọng mức `CRITICAL` và `HIGH`.
  - Nhật ký sự kiện: Thống kê tổng số lượng sự kiện an ninh và số sự cố đã khắc phục.
- **Biểu đồ thanh đo tài nguyên phần cứng (Resource Telemetry):**
  - CPU trung bình (`AVG CPU UTILIZATION`), RAM trung bình, Dung lượng đĩa lưu trữ trung bình.
- **Biểu đồ phân bố mức độ nghiêm trọng (Severity Matrix):**
  - Trực quan hóa tỉ lệ phần trăm các mức độ Critical, High, Medium, Low/Info.
- **Bảng luồng sự cố và sự kiện an ninh:**
  - Định dạng bảng sắc nét với các huy hiệu phân loại màu và nút thao tác nhanh (`Minh chứng`, `Xác nhận`, `Giải quyết`).

### 4.3. Quản lý Máy tính đầu cuối (`templates/endpoints.html`)
- Thanh công cụ lọc trạng thái dạng Chip (`TẤT CẢ`, `ĐANG HOẠT ĐỘNG`, `NGOẠI TUYẾN`).
- Khung tìm kiếm tích hợp cho phép lọc tức thời theo Tên máy chủ, Địa chỉ IP, Agent ID.
- Bảng danh mục máy trạm hiển thị trực quan thông số tải phần cứng (CPU%, RAM%, Disk%) dưới dạng thanh đo thu nhỏ và nút `Kiểm tra` mở Modal giám sát chi tiết.

### 4.4. Trung tâm Xử lý Sự cố (`templates/alerts.html`)
- Thanh công cụ lọc đa chiều (Multi-factor filter toolbar): Trạng thái (`all`, `new`, `acknowledged`, `resolved`), Mức độ nguy hiểm (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), và Danh sách máy trạm.
- Tích hợp cửa sổ xác nhận xử lý sự cố (`#resolveModal`) với ô nhập ghi chú khắc phục, đảm bảo không sử dụng inline JavaScript handler để ngăn chặn triệt để tấn công XSS Attribute Injection.

### 4.5. Nhật ký Kiểm toán Sự kiện (`templates/events.html`)
- Bộ lọc kết hợp giữa Mức độ nguy hiểm và Loại sự kiện an ninh (`suspicious_process_spawn`, `fim_sensitive_file`, `fim_file_modified`, v.v.).
- Khối hiển thị dữ liệu JSON có cấu trúc (`.json-viewer`) bên trong thẻ `<details>` có thể mở/đóng linh hoạt.

### 4.6. Cổng Đăng nhập Chuyên viên SOC (`templates/login.html`)
- Thẻ xác thực trung tâm phong cách Minimal Dark với huy hiệu bảo mật phát sáng nhẹ.
- Hỗ trợ đầy đủ token CSRF, bảo vệ chống Open Redirect (`next`), và hiển thị thông báo lỗi rõ ràng.

---

## 5. BẢO MẬT & KIỂM ĐỊNH CHỐNG TẤN CÔNG (XSS / CSRF)

Giao diện mới được kiểm định độc lập với các tiêu chuẩn an ninh nghiêm ngặt nhất:
1. **Chống XSS (Cross-Site Scripting):**
   - 100% dữ liệu động được escape an toàn bởi cơ chế Jinja2 auto-escaping.
   - Các thuộc tính HTML động được gán thông qua `dataset` và event delegation trong JavaScript thay vì thuộc tính `onclick="..."`.
   - Trình hiển thị DOM trong `dashboard.js` (`renderErrorMessage`, `escapeHtml`, `sanitizeSeverity`, `sanitizeStatus`) lọc sạch mọi payload dạng `<script>`, `<img onerror=...>`, `<svg onload=...>`.
2. **Chống CSRF (Cross-Site Request Forgery):**
   - Mọi form POST (Đăng xuất, Xác nhận sự cố, Đổi trạng thái) đều gửi kèm token CSRF hợp lệ trong body hoặc header `X-CSRF-Token`.
3. **Tuân thủ môi trường Air-Gapped / Offline:**
   - Hoàn toàn không gọi bất kỳ tài nguyên CDN nào bên ngoài (Google Fonts, Cloudflare CDN, cdnjs, v.v.).

---

## 6. KẾT QUẢ KIỂM THỬ TỰ ĐỘNG TOÀN DIỆN

Chạy toàn bộ 302 kiểm thử tích hợp tự động với `pytest`:

```text
============================= test session starts ==============================
platform linux -- Python 3.14.8, pytest-9.0.2, pluggy-1.6.0 -- /usr/bin/python3
rootdir: /home/kali/Projects/mini-edr-linux
configfile: pytest.ini
collected 302 items

tests/test_agent_client.py ...........                                   [  3%]
tests/test_agent_orchestrator.py .......                                 [  5%]
tests/test_alert_management.py ......................................    [ 18%]
tests/test_api.py ......................                                 [ 25%]
tests/test_dashboard.py ...........                                      [ 29%]
tests/test_data_integrity_p4.py ..............                           [ 33%]
tests/test_database.py .........                                         [ 36%]
tests/test_detection.py ..........................                       [ 45%]
tests/test_detection_correctness_p3.py ..............                    [ 50%]
tests/test_file_integrity.py ............                                [ 54%]
tests/test_fim_reliability_p2.py ...............                         [ 59%]
tests/test_final_verification.py ...............                         [ 64%]
tests/test_full_regression_p6.py ..                                      [ 64%]
tests/test_full_system_e2e.py .                                          [ 65%]
tests/test_migrations.py .......                                         [ 67%]
tests/test_phase4_e2e.py ...                                             [ 68%]
tests/test_process_collector.py .........                                [ 71%]
tests/test_repositories.py ........................                      [ 79%]
tests/test_resource_reliability_p5.py .............                      [ 83%]
tests/test_security_reliability.py ....................                  [ 90%]
tests/test_system_collector.py ................                          [ 95%]
tests/test_web_security_p1.py ...............                            [100%]

============================= 302 passed in 16.85s =============================
```

### Kịch bản Mô phỏng Tấn công Thực tế (Attack Simulator Regression):
```text
tests/test_full_regression_p6.py::test_full_system_e2e_pipeline_with_agent_and_soc_triage PASSED [ 50%]
tests/test_full_regression_p6.py::test_attack_scenario_simulator_auto_execution PASSED          [100%]
============================== 2 passed in 1.99s ===============================
```

Tất cả các kiểm thử đều đạt kết quả hoàn hảo 100%.

---

## 7. KẾT LUẬN & BÀN GIAO

Giao diện Web Dashboard mới của **Mini EDR for Linux** đã sẵn sàng bàn giao với đầy đủ tiêu chí chất lượng cao nhất:
- Thẩm mỹ: **Minimal Cyberpunk — SOC Command Center** sang trọng, hiện đại, không chói lóa.
- Ngôn ngữ: Tiếng Việt tự nhiên, chuyên sâu ngành an toàn thông tin mạng, phông chữ Be Vietnam Pro sắc nét.
- Kỹ thuật: 100% Offline/Air-gapped, không thay đổi logic backend, 302/302 tests vượt qua mỹ mãn.
