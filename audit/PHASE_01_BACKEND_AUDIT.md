# BÁO CÁO KIỂM TOÁN PHÂN HỆ — PHASE 1: BACKEND FOUNDATION AUDIT

**Dự án:** Mini Endpoint Detection and Response for Linux (`r00tK1ngX/mini-edr-linux`)  
**Phân hệ Kiểm toán:** Flask Backend, Application Factory, API Routing, Authentication & Ingestion Gateway  
**Ngày thực hiện:** 05/11/2026 (22:40 EST)  
**Tình trạng Nghiệm thu:** **PARTIAL** (Đã kiểm chứng đầy đủ chức năng và bảo mật cơ bản, nhưng phát hiện 2 lỗi High, 2 lỗi Medium và 1 lỗi Low)  

---

## 1. Tổng quan Đánh giá Phân hệ Backend

Flask Backend đóng vai trò API Gateway trung tâm và bộ điều khiển giao diện web của hệ thống Mini EDR. Phân hệ được xây dựng dựa trên kiến trúc Application Factory (`server/app.py`), chia làm 2 Blueprints chính:
1. `api_bp` ([`server/routes.py`](file:///home/kali/Projects/mini-edr-linux/server/routes.py)): Chịu trách nhiệm tiếp nhận và kiểm thực toàn bộ các bản tin telemetry từ Agent, quản lý RESTful API cho sự cố an ninh.
2. `web_bp` ([`server/web.py`](file:///home/kali/Projects/mini-edr-linux/server/web.py)): Phục vụ hiển thị giao diện Cyberpunk SOC Dashboard và điều khiển các tác vụ Triage.

---

## 2. Kết quả Trả lời Các Câu hỏi Kiểm toán Bắt buộc

### ❓ 1. Có API endpoint nào thiếu authentication không?
- **Tại phân hệ API Gateway (`/api/v1/*`):** **KHÔNG.** Toàn bộ 13 routes dưới `api_bp` đều được bảo vệ nghiêm ngặt bởi middleware `@api_bp.before_request` (`require_agent_token`). Bất kỳ request nào thiếu token, sai token, hoặc không đúng định dạng `Bearer <token>` đều bị từ chối với HTTP 401 Unauthorized và header `WWW-Authenticate: Bearer realm="mini-edr"`.
- **Tại phân hệ Web Dashboard (`web_bp`):** **CÓ.** Toàn bộ các route phục vụ giao diện Web (`/dashboard`, `/endpoints`, `/endpoints/<agent_id>/telemetry`, `/alerts`, `/alerts/<id>/detail`, `/alerts/<id>/acknowledge`, `/alerts/<id>/resolve`, `/alerts/<id>/dismiss`, `/events`) đều **hoàn toàn không có cơ chế xác thực**. Bất kỳ ai truy cập vào cổng 5000 đều có thể xem toàn bộ tiến trình, mã băm FIM và thực thi đóng/mở/bỏ qua cảnh báo sự cố an ninh (*Chi tiết tại FINDING-PHASE01-02*).
- **Endpoint công khai dự kiến:** `GET /health` nằm ở root `app` không yêu cầu token theo đúng chuẩn thiết kế Health Check.

### ❓ 2. Có route nào chỉ được bảo vệ trong một cách khởi chạy nhưng bị bỏ qua trong Application Factory không?
- **CÓ.** Logic kiểm tra độ mạnh của Token (độ dài $\ge 32$ ký tự, loại bỏ token mặc định `"replace-with-a-long-random-token"`) nằm ở khối `if __name__ == "__main__":` của [`server/app.py`](file:///home/kali/Projects/mini-edr-linux/server/app.py) (dòng 73-83). Nếu ứng dụng được khởi chạy thông qua Application Factory bởi máy chủ WSGI (Gunicorn / uWSGI) hoặc lệnh `flask run`, đoạn mã kiểm tra này bị bỏ qua, cho phép server khởi động ngay cả khi biến `EDR_API_TOKEN` rỗng (*Chi tiết tại FINDING-PHASE01-05*).

### ❓ 3. Có nguy cơ token bị ghi vào log hoặc trả về response không?
- **KHÔNG.** Đã kiểm tra toàn bộ mã nguồn xử lý log và các route trả về response. Server chỉ log các chuỗi tĩnh (ví dụ: `"Failed to record system telemetry"`, `"Failed to record process snapshot"`). Header `Authorization` và giá trị token không bao giờ được ghi vào log và không bao giờ xuất hiện trong response body của các mã lỗi 401, 400, 404, 500.

### ❓ 4. Có thể giả mạo `agent_id` hoặc endpoint identity không?
- **CÓ.** Hệ thống sử dụng một Bearer Token đối xứng dùng chung (Pre-Shared Key - PSK) cho toàn bộ hạm đội máy trạm. Giá trị `agent_id` được trích xuất trực tiếp từ payload JSON do client tự khai báo (`payload["agent_id"]`). Server không có cơ chế liên kết danh tính mật mã học (như chứng chỉ mTLS hoặc khóa riêng của từng máy trạm). Do đó, bất kỳ máy trạm nào sở hữu token đều có thể gửi telemetry mạo danh bất kỳ `agent_id` nào khác trong hệ thống (*Chi tiết tại FINDING-PHASE01-03*).

### ❓ 5. Request malformed có làm server crash không?
- **KHÔNG.** Bộ hàm `_validate_envelope()` và các hàm kiểm tra dữ liệu đầu vào (`is_valid_number`, `is_valid_uuid4`, `is_valid_iso8601_utc`, `is_valid_sha256`) trong [`server/routes.py`](file:///home/kali/Projects/mini-edr-linux/server/routes.py) xử lý rất chặt chẽ.
  - JSON sai cú pháp: Trả về HTTP 400 Bad Request.
  - Content-Type không phải JSON: Trả về HTTP 400.
  - Body không phải dict (ví dụ gửi mảng `[]`): Trả về HTTP 400.
  - Số dạng `NaN`, `Infinity`, số âm: Bị chặn đứng bởi hàm `is_valid_number()`.
  - Giá trị Boolean (`True`/`False`): Hàm `is_valid_number()` có kiểm tra `isinstance(value, bool)` nên không bị lọt lỗi kế thừa `bool` từ `int` trong Python.

### ❓ 6. Payload quá lớn có được kiểm soát không?
- **CÓ.** Server cấu hình `app.config["MAX_CONTENT_LENGTH"] = 64 * 1024` (64 KB). Khi client gửi payload vượt quá ngưỡng này với `Content-Type: application/json`, Werkzeug tự động ngắt kết nối và error handler `@app.errorhandler(413)` trả về JSON chuẩn HTTP 413: `{"success": false, "error": "Request body is too large"}`.

### ❓ 7. Heartbeat thiếu trường tùy chọn có làm mất dữ liệu cũ không?
- **CÓ.** Đây là một khiếm khuyết trong câu lệnh SQL `ON CONFLICT(agent_id) DO UPDATE SET` tại [`server/repositories/endpoint_repository.py`](file:///home/kali/Projects/mini-edr-linux/server/repositories/endpoint_repository.py). Nếu một agent gửi heartbeat sau đó mà không kèm các trường tùy chọn (`ip_address`, `agent_version`, `metrics`), câu lệnh UPDATE thực hiện gán thẳng `ip_address = excluded.ip_address` khiến dữ liệu IP và phiên bản trước đó bị xóa trắng thành `NULL` (*Chi tiết tại FINDING-PHASE01-04*).

### ❓ 8. Có kiểm soát thời gian và trạng thái endpoint hợp lý không?
- **CÓ.** Server không tin tưởng thời gian do client gửi lên cho trường `last_seen`; thay vào đó Server tự sinh mốc thời gian UTC trên máy chủ bằng `utc_now()`. Trạng thái `online` và `offline` được tính toán tự động thông qua SQLite `julianday('now') - julianday(last_seen)` với ngưỡng `OFFLINE_AFTER_SECONDS` (mặc định 15s).

---

## 3. Danh Sách Các Phát Hiện Kiểm Toán Chi Tiết (Findings)

---

### 🔴 FINDING-PHASE01-01: Thiếu cấu hình `SECRET_KEY` gây crash (HTTP 500) khi thực hiện Triage qua HTML Form
- **Mức độ nghiêm trọng:** **HIGH** (CVSS: 7.5 - High)
- **Phase ảnh hưởng:** Phase 1 (Backend Foundation) & Phase 7 (Web Dashboard)
- **File / Vị trí:** [`server/app.py`](file:///home/kali/Projects/mini-edr-linux/server/app.py#L36-L41) & [`server/web.py`](file:///home/kali/Projects/mini-edr-linux/server/web.py#L327)
- **Mô tả kỹ thuật:**
  Trong [`server/app.py`](file:///home/kali/Projects/mini-edr-linux/server/app.py), hàm `create_app()` không cấu hình `app.secret_key` hoặc `app.config["SECRET_KEY"]`. Trong khi đó, các route xử lý sự cố trong [`server/web.py`](file:///home/kali/Projects/mini-edr-linux/server/web.py) (`web_acknowledge_alert`, `web_resolve_alert`, `web_dismiss_alert`) được thiết kế hỗ trợ cả JSON AJAX và Form POST truyền thống. Khi một Form POST được gửi lên, code gọi hàm `flash(...)` của Flask để hiển thị thông báo. Vì Flask không có `SECRET_KEY`, hàm `flash()` truy cập vào `session["_flashes"]` và gây ra ngoại lệ nghiêm trọng:
  ```text
  RuntimeError: The session is unavailable because no secret key was set. Set the secret_key on the application to something unique and secret.
  ```
- **Các bước tái hiện (Reproduction Steps):**
  1. Khởi động Flask Server.
  2. Tạo 1 alert mẫu có ID = 1.
  3. Gửi HTTP POST dạng form: `curl -X POST http://127.0.0.1:5000/alerts/1/acknowledge -d "note=Testing"`
  4. Server trả về HTTP 500 kèm lỗi `RuntimeError: The session is unavailable because no secret key was set`.
- **Tác động an ninh & vận hành:** Gây từ chối dịch vụ (DoS) tức thời đối với bất kỳ thao tác xử lý sự cố nào sử dụng form HTML thay vì fetch JSON.
- **Biện pháp khắc phục khuyến nghị:**
  Bổ sung `SECRET_KEY` vào `app.config` trong `server/app.py`, nạp từ biến môi trường `os.getenv("SECRET_KEY", secrets.token_hex(32))`.

---

### 🔴 FINDING-PHASE01-02: Phân hệ Web Dashboard (`web_bp`) thiếu hoàn toàn cơ chế xác thực và phân quyền
- **Mức độ nghiêm trọng:** **HIGH** (CVSS: 8.2 - High)
- **Phase ảnh hưởng:** Phase 1 (Backend Foundation) & Phase 7 (Web Dashboard)
- **File / Vị trí:** [`server/web.py`](file:///home/kali/Projects/mini-edr-linux/server/web.py#L1-L430)
- **Mô tả kỹ thuật:**
  Trong khi toàn bộ phân hệ API `/api/v1/*` được bảo vệ bằng Bearer Token, thì Blueprint `web_bp` đăng ký tại thư mục gốc `/` hoàn toàn không có bất kỳ bộ lọc xác thực (Authentication filter), session check hay HTTP Basic Auth nào. Mọi endpoint điều khiển và xem dữ liệu nhạy cảm đều mở công khai:
  - `GET /endpoints/<agent_id>/telemetry`: Đọc toàn bộ danh sách tiến trình, mã băm FIM và cấu hình của máy trạm.
  - `GET /alerts/<alert_id>/detail`: Xem chi tiết bằng chứng JSON của cuộc tấn công.
  - `POST /alerts/<alert_id>/acknowledge`, `/resolve`, `/dismiss`: Cho phép bất kỳ ai gửi yêu cầu JSON để đóng cảnh báo hoặc đánh dấu bỏ qua (dismiss) sự cố mà không cần bất kỳ quyền hạn nào.
- **Các bước tái hiện (Reproduction Steps):**
  1. Gửi request unauthenticated: `curl -X POST http://127.0.0.1:5000/alerts/1/dismiss -H "Content-Type: application/json" -d '{"resolution_note": "Dismissed by unauthenticated attacker"}'`
  2. Server trả về HTTP 200: `{"success": true, "status": "resolved"}`.
  3. Cảnh báo nguy hiểm trên hệ thống bị kẻ tấn công vô hiệu hóa hoàn toàn mà không cần token.
- **Tác động an ninh:** Phá vỡ ranh giới tin cậy (Trust Boundary) giữa Quản trị viên SOC và người dùng mạng; lộ lọt toàn bộ thông tin tình báo máy trạm và cho phép kẻ tấn công can thiệp làm sai lệch hồ sơ điều tra sự cố số.
- **Biện pháp khắc phục khuyến nghị:**
  Tích hợp cơ chế đăng nhập Session/Cookie cho Web Console, hoặc áp dụng HTTP Basic Auth / IP Whitelisting giới hạn chỉ cho phép truy cập từ máy trạm của chuyên viên SOC.

---

### 🟡 FINDING-PHASE01-03: Sử dụng Token đối xứng dùng chung (Pre-Shared Key) không ràng buộc định danh máy trạm
- **Mức độ nghiêm trọng:** **MEDIUM** (CVSS: 5.3 - Medium)
- **Phase ảnh hưởng:** Phase 1 (Backend Foundation) & Phase 4 (End-to-End)
- **File / Vị trí:** [`server/routes.py`](file:///home/kali/Projects/mini-edr-linux/server/routes.py#L21-L48) & [`server/routes.py`](file:///home/kali/Projects/mini-edr-linux/server/routes.py#L206-L217)
- **Mô tả kỹ thuật:**
  Hệ thống sử dụng một chuỗi khóa bí mật duy nhất (`EDR_API_TOKEN`) cài đặt trên mọi Agent. Khi nhận bản tin, Server chỉ kiểm tra xem client có chuỗi token này hay không, sau đó chấp nhận giá trị `agent_id` trong body JSON mà không đối chiếu với danh tính thực sự của máy gửi (không có mTLS client certificate hoặc per-agent key).
- **Tác động an ninh:** Nếu kẻ tấn công chiếm quyền điều khiển một máy trạm trong mạng và trích xuất được `EDR_API_TOKEN` từ file cấu hình của Agent, kẻ tấn công có thể mạo danh bất kỳ máy chủ nào khác (như Domain Controller hay Database Server) để bơm dữ liệu giả mạo.
- **Biện pháp khắc phục khuyến nghị:**
  Triển khai cơ chế cấp phát token riêng cho từng Agent (Per-agent Enrollment Token) hoặc sử dụng xác thực hai chiều mTLS trong các phiên bản mở rộng sau đồ án.

---

### 🟡 FINDING-PHASE01-04: Câu lệnh Heartbeat Upsert ghi đè giá trị `NULL` lên siêu dữ liệu tùy chọn của máy trạm
- **Mức độ nghiêm trọng:** **MEDIUM** (Độ toàn vẹn dữ liệu)
- **Phase ảnh hưởng:** Phase 1 & Phase 2 (Data Model)
- **File / Vị trí:** [`server/repositories/endpoint_repository.py`](file:///home/kali/Projects/mini-edr-linux/server/repositories/endpoint_repository.py#L43-L53)
- **Mô tả kỹ thuật:**
  Câu lệnh SQL trong `upsert()`:
  ```sql
  ON CONFLICT(agent_id) DO UPDATE SET
      hostname = excluded.hostname,
      ip_address = excluded.ip_address,
      os = excluded.os,
      agent_version = excluded.agent_version,
      ...
  ```
  Nếu máy trạm gửi bản tin Heartbeat rút gọn (không truyền `ip_address` hoặc `agent_version`), các trường này sẽ nhận giá trị `None` trong Python và gán `NULL` vào SQLite, ghi đè và làm biến mất vĩnh viễn IP Address và Agent Version đã thu thập trước đó.
- **Các bước tái hiện (Reproduction Steps):**
  1. Gửi heartbeat đầy đủ có `ip_address: "192.168.1.50"`, `agent_version: "1.0.0"`. Kiểm tra DB thấy có đủ IP.
  2. Gửi heartbeat thứ hai chỉ có `agent_id`, `hostname`, `os`.
  3. Truy vấn lại `GET /api/v1/endpoints`: Trường `ip_address` và `agent_version` bị chuyển thành `None`.
- **Biện pháp khắc phục khuyến nghị:**
  Sửa câu lệnh SQL sử dụng hàm `COALESCE`:
  ```sql
  ip_address = COALESCE(excluded.ip_address, endpoints.ip_address),
  agent_version = COALESCE(excluded.agent_version, endpoints.agent_version)
  ```

---

### 🔵 FINDING-PHASE01-05: Kiểm tra độ mạnh của Token bị bỏ qua khi khởi chạy bằng WSGI / Application Factory
- **Mức độ nghiêm trọng:** **LOW**
- **Phase ảnh hưởng:** Phase 1 (Backend Foundation)
- **File / Vị trí:** [`server/app.py`](file:///home/kali/Projects/mini-edr-linux/server/app.py#L73-L83)
- **Mô tả kỹ thuật:**
  Đoạn mã kiểm tra `len(api_token) >= 32` và từ chối token mẫu nằm bên trong `if __name__ == "__main__":` thay vì nằm trong hàm `create_app()`. Khi server được import hoặc chạy bởi Gunicorn (`gunicorn "server.app:create_app()"`), đoạn mã kiểm tra này hoàn toàn không được thực thi.
- **Biện pháp khắc phục khuyến nghị:**
  Chuyển logic kiểm tra token vào trực tiếp bên trong hàm `create_app()` để áp dụng đồng nhất cho mọi phương thức khởi chạy.

---

### ⚪ FINDING-PHASE01-06: Chưa triển khai Rate Limiting và Phân quyền vai trò (RBAC)
- **Mức độ nghiêm trọng:** **INFORMATIONAL**
- **Mô tả kỹ thuật:**
  Server không có cơ chế giới hạn tần suất (Rate Limiting). Mã lỗi HTTP 403 Forbidden có trong tài liệu đặc tả nhưng chưa được triển khai trong mã nguồn do hệ thống chưa có phân quyền vai trò (Role-Based Access Control).

---

## 4. Bảng Tổng Hợp Kiểm Thử Dynamic Trực Tiếp (Phase 1 Probes)

| Ca Kiểm thử | Đầu vào Thử nghiệm | Kết quả Mong đợi | Kết quả Thực tế | Đánh giá |
|---|---|---|---|---|
| **Health Check** | `GET /health` | HTTP 200 `{"status": "ok"}` | HTTP 200 | **PASS** |
| **Missing Token** | `GET /api/v1/endpoints` (No header) | HTTP 401 Unauthorized | HTTP 401 `{"error": "unauthorized"}` | **PASS** |
| **Invalid Token** | Header `Authorization: Bearer wrong-tok` | HTTP 401 Unauthorized | HTTP 401 | **PASS** |
| **Malformed Auth Scheme** | Header `Authorization: Basic dXNlcg==` | HTTP 401 Unauthorized | HTTP 401 | **PASS** |
| **Non-JSON Body** | `POST /api/v1/heartbeat` (text/plain) | HTTP 400 Bad Request | HTTP 400 `{"error": "Content-Type must be application/json"}` | **PASS** |
| **Malformed JSON** | `POST /api/v1/heartbeat` (`{"broken`) | HTTP 400 Bad Request | HTTP 400 `{"error": "Request body must be a valid JSON object"}` | **PASS** |
| **Missing Required Fields** | Heartbeat chỉ có `agent_id` | HTTP 400 Bad Request | HTTP 400 `{"error": "Missing required field: hostname"}` | **PASS** |
| **Metric Boundary CPU > 100** | `metrics: {"cpu_percent": 150.0}` | HTTP 400 Bad Request | HTTP 400 `{"error": "Metric must be between 0 and 100: cpu_percent"}` | **PASS** |
| **Non-numeric Metric (NaN)** | `metrics: {"cpu_percent": NaN}` | HTTP 400 Bad Request | HTTP 400 `{"error": "Invalid numeric metric: cpu_percent"}` | **PASS** |
| **Boolean Injection in Metric** | `metrics: {"cpu_percent": true}` | HTTP 400 Bad Request | HTTP 400 `{"error": "Invalid numeric metric: cpu_percent"}` | **PASS** |
| **Payload Oversized (>64KB)** | JSON Body 65KB | HTTP 413 Payload Too Large | HTTP 413 `{"error": "Request body is too large"}` | **PASS** |
| **Form POST Triage Action** | `POST /alerts/1/acknowledge` (Form data) | HTTP 302 Redirect hoặc 200 | **HTTP 500 RuntimeError: missing secret_key** | ❌ **FAIL** (Finding 01) |
| **Unauthenticated Triage Action** | `POST /alerts/1/dismiss` (JSON data) | HTTP 401 Unauthorized | **HTTP 200 Success (State mutated)** | ❌ **FAIL** (Finding 02) |

---

## 5. Kết luận Giai đoạn Phase 1

- **Tình trạng:** **PARTIAL**
- **Đánh giá tổng quan:** Phân hệ Backend API Gateway (`/api/v1/*`) được triển khai rất chỉn chu về xác thực Bearer token, chống timing-attack (`compare_digest`), kiểm tra giới hạn 64KB và bắt lỗi dữ liệu đầu vào. Tuy nhiên, phân hệ Web Dashboard (`web_bp`) chưa được áp dụng bảo vệ xác thực và thiếu `SECRET_KEY` dẫn đến lỗi sập ứng dụng HTTP 500 khi xử lý form truyền thống.

Báo cáo chi tiết đã được lưu trữ độc lập tại [`audit/PHASE_01_BACKEND_AUDIT.md`](file:///home/kali/Projects/mini-edr-linux/audit/PHASE_01_BACKEND_AUDIT.md).
Tôi sẵn sàng bước sang **PHASE 2 — DATABASE & DATA INTEGRITY AUDIT**. Xin mời bạn xác nhận để tiếp tục!