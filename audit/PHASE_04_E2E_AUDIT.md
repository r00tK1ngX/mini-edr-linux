# BÁO CÁO KIỂM TOÁN PHÂN HỆ — PHASE 4: END-TO-END INTEGRATION AUDIT

**Dự án:** Mini Endpoint Detection and Response for Linux (`r00tK1ngX/mini-edr-linux`)  
**Phân hệ Kiểm toán:** Tích hợp Đầu-Cuối (Agent $\rightarrow$ API Gateway $\rightarrow$ Ingestion $\rightarrow$ SQLite DB $\rightarrow$ Real-time Detection $\rightarrow$ Alert Lifecycle $\rightarrow$ Web SOC Dashboard)  
**Ngày thực hiện:** 06/11/2026 (01:30 EST)  
**Tình trạng Nghiệm thu:** **PARTIAL** (Đã chứng minh luồng tích hợp cơ bản giữa các phân hệ hoạt động liền mạch; tuy nhiên phát hiện 1 lỗi High nghiêm trọng liên quan đến giới hạn kích thước payload 64 KB làm tê liệt đồng bộ FIM và snapshot tiến trình trên Linux thực tế, 2 lỗi Medium về nghẽn pipeline do xử lý phát hiện đồng bộ và rủi ro tràn biến SQL, 1 lỗi Low)  

---

## 1. Tổng quan Luồng Tích Hợp Toàn Diện (End-to-End Pipeline)

Phase 4 kiểm chứng tính liên kết và độ tin cậy của toàn bộ chu trình sống dữ liệu trong hệ thống Mini EDR:
1. **Khởi tạo và Đăng ký Máy trạm:**
   - Agent khởi động, gửi bản tin `POST /api/v1/heartbeat`.
   - Máy chủ tiếp nhận, xác thực Bearer token, thực hiện câu lệnh `upsert` vào bảng `endpoints` trong SQLite, chuyển trạng thái máy trạm sang `online`.
2. **Đồng bộ Đường cơ sở File (FIM Baseline Sync):**
   - Agent quét các thư mục giám sát, đóng gói danh sách file vào phong bì Data Contract, gửi `POST /api/v1/file-baselines`.
   - Máy chủ kiểm tra ràng buộc, lưu trữ trạng thái băm ban đầu vào bảng `file_baselines`.
3. **Tiếp nhận Tiến trình & Động cơ Phát hiện Đồng bộ (Real-time Ingestion & Detection):**
   - Agent quét tiến trình định kỳ, gửi `POST /api/v1/telemetry/processes`.
   - API Gateway ghi dữ liệu vào `process_snapshots` và `process_observations`.
   - Ngay trong luồng xử lý HTTP, server gọi `DetectionEngine.evaluate_process_snapshot()` để quét các luật (đường dẫn đáng ngờ, tiến trình ngụy trang, mức sử dụng CPU bất thường).
   - Nếu phát hiện vi phạm, hệ thống tự động sinh bản ghi trong `security_events`, tương quan và mở cảnh báo trong bảng `alerts`.
4. **Phản chiếu Giao diện SOC & Xử lý Sự cố (Triage Pipeline):**
   - Dashboard hiển thị cảnh báo mới với trạng thái `new` và mức độ rủi ro tương ứng.
   - Chuyên viên SOC bấm vào chi tiết để xem bằng chứng (Evidence modal) và thực thi chuyển đổi trạng thái: `acknowledged` $\rightarrow$ `resolved` kèm ghi chú xử lý.
5. **Cơ chế Chuyển đổi Trạng thái Sống/Chết (Online / Offline Transition):**
   - Khi Agent ngừng gửi tín hiệu vượt quá ngưỡng `OFFLINE_AFTER_SECONDS` (mặc định 15s), máy chủ tự động chuyển trạng thái endpoint sang `offline`.
   - Khi Agent gửi heartbeat mới, máy trạm tự động được kích hoạt lại trạng thái `online`.

---

## 2. Kết quả Trả lời Các Câu hỏi Kiểm toán Bắt buộc

### ❓ 1. Dữ liệu từ Agent có được lưu trữ toàn vẹn và chính xác vào Database không?
- **ĐỐI VỚI DỮ LIỆU CỠ NHỎ (< 64 KB):** **CÓ.**
  - Mọi trường dữ liệu từ Agent (hostname, IP, OS, metrics, PID, username, exe_path, SHA-256) đều được chuyển đổi kiểu dữ liệu an toàn và lưu trữ chính xác vào các bảng tương ứng trong SQLite mà không bị sai lệch kiểu hay mất mát dữ liệu.
- **ĐỐI VỚI MÔI TRƯỜNG LINUX THỰC TẾ (> 64 KB):** **KHÔNG — BỊ TỪ CHỐI HOÀN TOÀN.**
  - Do máy chủ áp đặt giới hạn `MAX_CONTENT_LENGTH = 64 * 1024` (64 KB), các bản tin đồng bộ FIM chứa nhiều hơn ~300 files hoặc danh sách tiến trình chứa nhiều hơn ~250 tiến trình đều bị máy chủ ngắt kết nối và trả về **HTTP 413 Request body is too large** (*Chi tiết tại FINDING-PHASE04-01*).

### ❓ 2. Động cơ Phát hiện (Detection Engine) có tự động kích hoạt ngay khi nhận telemetry không?
- **CÓ.**
  - Cả hai route `/api/v1/telemetry/processes` và `/api/v1/events` đều tích hợp lời gọi trực tiếp đến `DetectionEngine` ngay sau khi lưu dữ liệu vào database.
  - Kiểm thử thực nghiệm với tiến trình độc hại `/tmp/nc` cho thấy cảnh báo an ninh được tạo ngay lập tức trong cùng chu trình request và sẵn sàng trên Dashboard.
  - *Tuy nhiên:* Việc kích hoạt đồng bộ (In-line synchronous execution) này tạo ra nút thắt cổ chai hiệu năng nghiêm trọng cho toàn bộ hệ thống (*Chi tiết tại FINDING-PHASE04-02*).

### ❓ 3. Quá trình Triage từ Web Dashboard có đồng bộ hoàn hảo xuống Database và API không?
- **CÓ (KHI DÙNG JSON API) / GẶP LỖI 500 (KHI DÙNG FORM HTML).**
  - Khi gửi request JSON đến `/alerts/<id>/acknowledge` và `/alerts/<id>/resolve`, trạng thái `status`, `updated_at`, và `resolution_note` được cập nhật tức thì vào bảng `alerts`.
  - Nếu gửi qua form HTML thông thường trên trình duyệt, server bị crash HTTP 500 do thiếu `SECRET_KEY` đã được chỉ ra ở Phase 1 ([`FINDING-PHASE01-01`](file:///home/kali/Projects/mini-edr-linux/audit/PHASE_01_BACKEND_AUDIT.md#finding-phase01-01)).

### ❓ 4. Cơ chế chuyển trạng thái Online/Offline có hoạt động ổn định khi có nhiều máy trạm không?
- **CÓ.**
  - Kiểm thử với 2 Agent chạy độc lập cho thấy: khi cả hai ngưng gửi heartbeat quá thời gian quy định, cả hai đều chuyển sang `offline`. Khi Agent 1 gửi lại heartbeat, chỉ Agent 1 trở lại `online` trong khi Agent 2 vẫn duy trì `offline`.

### ❓ 5. Khi Server gặp sự cố hoặc tải cao, Agent có khả năng tự phục hồi luồng dữ liệu không?
- **CHƯA ĐẦY ĐỦ.**
  - Agent chỉ có cơ chế retry kết nối ngắn hạn (3 lần với Exponential Backoff). Nếu Server không phản hồi sau 3 lần, Agent hủy bỏ hoàn toàn gói tin telemetry của chu kỳ đó.
  - Do thiếu hàng đợi lưu đệm ngoại tuyến (Outbox), toàn bộ dữ liệu tiến trình và sự kiện an ninh trong thời gian Server chết đều bị xóa sổ, không có cơ chế gửi bù khi Server hồi phục.

---

## 3. Danh Sách Các Phát Hiện Kiểm Toán Chi Tiết (Findings)

---

### 🔴 FINDING-PHASE04-01: Giới hạn `MAX_CONTENT_LENGTH = 64 KB` làm tê liệt đồng bộ FIM và snapshot tiến trình trên hệ thống thực tế (Lỗi HTTP 413)
- **Mức độ nghiêm trọng:** **HIGH** (CVSS: 7.7 - High)
- **Phase ảnh hưởng:** Phase 1 (Backend Gateway), Phase 3 (Agent Serialization) & Phase 4 (E2E Integration)
- **File / Vị trí:** [`server/app.py`](file:///home/kali/Projects/mini-edr-linux/server/app.py#L36), [`agent/main.py`](file:///home/kali/Projects/mini-edr-linux/agent/main.py#L56), [`agent/file_integrity.py`](file:///home/kali/Projects/mini-edr-linux/agent/file_integrity.py#L230)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  1. Trong [`server/app.py`](file:///home/kali/Projects/mini-edr-linux/server/app.py):
     ```python
     app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # 64 KB
     ```
  2. Trong [`agent/main.py`](file:///home/kali/Projects/mini-edr-linux/agent/main.py):
     Cấu hình mặc định của Agent giám sát các thư mục: `["/etc", "/bin", "/tmp"]`.
  3. Trên bất kỳ bản phân phối Linux thực tế nào (Debian, Ubuntu, Kali, CentOS):
     - Thư mục `/bin` và `/etc` chứa từ 1,000 đến 4,000 files.
     - Mỗi bản ghi FIM JSON chiếm khoảng 200 bytes.
     - Dung lượng của bản tin đồng bộ đường cơ sở (`POST /api/v1/file-baselines`) cho 500 files là **104 KB** (cho toàn bộ `/bin` là $> 500\text{ KB}$).
  4. Tương tự, một máy chủ hoặc máy trạm Linux thông thường chạy từ 250 đến 400 tiến trình. Bản tin `POST /api/v1/telemetry/processes` cho 300 tiến trình có dung lượng **71.4 KB**.
  5. Cả Agent và Server đều không triển khai cơ chế phân trang (Pagination), chia nhỏ gói tin (Chunking) hay nén dữ liệu (Gzip/zstd).
  6. Khi Agent gửi bản tin vượt quá 64 KB, máy chủ Werkzeug lập tức từ chối và ngắt kết nối với mã lỗi chuẩn **HTTP 413 Request body is too large**.
  7. Client coi HTTP 413 là lỗi $4xx$ không thể cứu vãn nên không retry; Orchestrator ghi log lỗi và **không bao giờ thiết lập được FIM baseline** (`fim_initialized` mãi mãi là `False`).
- **Các bước Tái hiện Thực nghiệm (Reproduction Steps):**
  1. Khởi tạo Flask Server với cấu hình chuẩn.
  2. Đăng ký endpoint `audit-node-01`.
  3. Gửi payload FIM chứa 500 file (kích thước 104,074 bytes) hoặc Snapshot chứa 300 tiến trình (kích thước 71,390 bytes).
  4. Kết quả thực nghiệm: 100% trả về **HTTP 413 `{"error": "Request body is too large", "success": false}`**.
- **Tác động (Impact):**
  Mini EDR **hoàn toàn không thể vận hành tính năng FIM trên môi trường Linux thực tế** nếu sử dụng cấu hình mặc định. Bất kỳ máy trạm nào có trên 250 tiến trình đều bị mất hoàn toàn khả năng thu thập dữ liệu tiến trình. Các test suite trước đây vượt qua được là do chỉ chạy mock trong thư mục tạm có 1-2 file.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  1. Nâng giới hạn `MAX_CONTENT_LENGTH` trên Server lên tối thiểu **10 MB** (`10 * 1024 * 1024`).
  2. Bổ sung cơ chế phân lô (Chunking/Batching) ở Agent: chia nhỏ danh sách file thành từng đợt tối đa 100 files mỗi request (`chunk_size = 100`).

---

### 🟡 FINDING-PHASE04-02: Xử lý phát hiện đồng bộ ngay trong luồng Ingestion gây nghẽn đường ống dữ liệu (Synchronous Pipeline Bottleneck)
- **Mức độ nghiêm trọng:** **MEDIUM** (CVSS: 6.1 - Medium)
- **Phase ảnh hưởng:** Phase 1 (Ingestion Gateway), Phase 4 (E2E Integration) & Phase 5 (Detection Engine)
- **File / Vị trí:** [`server/routes.py`](file:///home/kali/Projects/mini-edr-linux/server/routes.py#L444-L449)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Trong route `POST /api/v1/telemetry/processes`, máy chủ thực thi tuần tự trong cùng một request thread:
  1. Parse JSON payload và validate dữ liệu.
  2. Ghi snapshot và toàn bộ observations vào SQLite (chiếm khóa ghi DB).
  3. Khởi tạo `DetectionEngine` và chạy toàn bộ các luật regex, đối chiếu hash, kiểm tra ngưỡng trên hàng trăm tiến trình.
  4. Thực hiện các truy vấn đọc/ghi phụ để tương quan và chèn cảnh báo.
  5. Trả về HTTP 201 cho Agent.
  Khi có nhiều Agent (ví dụ 5-10 máy) cùng gửi snapshot đồng thời:
  - Các worker của Flask bị giữ chân lâu bởi thao tác CPU-intensive của regex và I/O của SQLite.
  - Thời gian phản hồi của request tăng vọt từ vài chục ms lên hàng giây.
  - Khi thời gian xử lý vượt quá `request_timeout = 5.0s` của Agent, Agent sẽ ném ngoại lệ `AgentConnectionError` (Timeout) và bỏ cuộc.
- **Tác động (Impact):**
  Nghẽn cổ chai nghiêm trọng khi mở rộng quy mô (Scalability failure). Hệ thống EDR không thể chịu tải thực tế nếu hạm đội máy trạm tăng lên.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  Tách rời (Decouple) khâu Ingestion và khâu Detection bằng hàng đợi bất đồng bộ:
  - Route Ingestion chỉ làm nhiệm vụ xác thực, lưu trữ nhanh và trả về ngay HTTP 201.
  - Sử dụng hàng đợi trong bộ nhớ (ví dụ `queue.Queue` với Background Worker thread, hoặc Celery/Redis) để kéo dữ liệu snapshot ra phân tích phát hiện độc lập.

---

### 🟡 FINDING-PHASE04-03: Nguy cơ tràn biến tham số SQL (`too many SQL variables`) khi đối chiếu Baseline theo lô
- **Mức độ nghiêm trọng:** **MEDIUM** (CVSS: 5.5 - Medium)
- **Phase ảnh hưởng:** Phase 2 (Database Queries) & Phase 4 (Integration Route)
- **File / Vị trí:** [`server/routes.py`](file:///home/kali/Projects/mini-edr-linux/server/routes.py#L529-L534)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Trong route `POST /api/v1/file-baselines`:
  ```python
  placeholders = ",".join("?" for _ in cleaned_files)
  rows = conn.execute(
      f"SELECT file_path FROM file_baselines WHERE agent_id = ? AND file_path IN ({placeholders})",
      (agent_id, *[f["file_path"] for f in cleaned_files]),
  ).fetchall()
  ```
  Số lượng dấu hỏi `?` được sinh động tương ứng với độ dài của mảng `cleaned_files`.
  Trong SQLite, giới hạn số lượng tham số truy vấn (`SQLITE_MAX_VARIABLE_NUMBER`) mặc định là **999** (đối với SQLite cũ) hoặc **32,766** (đối với SQLite hiện đại).
  Nếu giới hạn kích thước payload được nới lỏng và Agent gửi một mảng lớn vượt quá ngưỡng biến của SQLite, câu lệnh sẽ gây sập unhandled exception: `sqlite3.OperationalError: too many SQL variables`, dẫn đến HTTP 500 Internal Server Error.
- **Tác động (Impact):**
  Lỗi sập dịch vụ (Denial of Service) ngoài ý muốn khi xử lý các đợt đồng bộ danh mục lớn.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  Chia nhỏ mảng đường dẫn thành từng cụm tối đa 500 phần tử để truy vấn (Chunking), hoặc tạo bảng tạm (Temporary table) để thực hiện `INNER JOIN`.

---

### 🔵 FINDING-PHASE04-04: Hiện tượng dao động trạng thái (State Flip-Flop) giữa Online và Offline do thiếu dải trễ (Hysteresis)
- **Mức độ nghiêm trọng:** **LOW** (CVSS: 3.1 - Low)
- **Phase ảnh hưởng:** Phase 1 (Heartbeat Management) & Phase 4 (Dashboard Reflection)
- **File / Vị trí:** [`server/repositories/endpoint_repository.py`](file:///home/kali/Projects/mini-edr-linux/server/repositories/endpoint_repository.py#L101)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Trạng thái `online`/`offline` chỉ dựa vào điều kiện nhị phân cứng: `(now - last_seen) > OFFLINE_AFTER_SECONDS` (15 giây).
  Với chu kỳ heartbeat 5 giây, nếu mạng có độ trễ hoặc máy trạm bị gián đoạn nhẹ đúng 3 nhịp heartbeat, endpoint lập tức bị chuyển thành `offline`, rồi 2 giây sau nhận được heartbeat lại chuyển thành `online`.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  Bổ sung trạng thái trung gian `unresponsive` / `warning` trước khi chuyển hẳn sang `offline`, hoặc đặt ngưỡng timeout bằng ít nhất $4 \times \text{heartbeat\_interval}$ (ví dụ 20s - 30s) kèm cơ chế lọc nhiễu.

---

## 4. Ma Trận Kiểm Thử Thực Nghiệm Phân Hệ Tích Hợp Đầu-Cuối

Auditor đã xây dựng kịch bản kiểm thử độc lập [`audit_phase4_e2e.py`](file:///home/kali/.gemini/antigravity-cli/brain/2f030cf6-8c2b-476d-90bd-f71588442318/scratch/audit_phase4_e2e.py) và thực thi trực tiếp trên hệ thống:

| STT | Hạng mục Kiểm thử | Kỳ vọng | Kết quả Thực tế | Trạng thái |
| :---: | :--- | :--- | :--- | :---: |
| 1 | **Multi-Agent Registration** | Đăng ký thành công 2 Agent độc lập | Cả 2 máy trạm đăng ký thành công | **PASS** |
| 2 | **Endpoint API Count** | API `/endpoints` hiển thị đúng 2 máy trạm | Trả về `count == 2` | **PASS** |
| 3 | **FIM Payload Size Boundary** | Payload FIM 500 file (104 KB) gửi lên Server | Bị từ chối với HTTP 413 Request Too Large | **CONFIRMED (Lỗi High)** |
| 4 | **Process Snapshot Boundary** | Snapshot 300 tiến trình (71 KB) gửi lên Server | Bị từ chối với HTTP 413 Request Too Large | **CONFIRMED (Lỗi High)** |
| 5 | **Valid Telemetry Ingestion** | Snapshot hợp lệ (< 64 KB) lưu trữ trọn vẹn | Trả về HTTP 201 Created | **PASS** |
| 6 | **Synchronous Alert Creation** | Tạo cảnh báo ngay trong chu trình ingest | Alert được sinh tức thì (độ trễ ~62ms) | **PASS** |
| 7 | **Alert Triage: Acknowledge** | Chuyển trạng thái sang `acknowledged` qua JSON | Cập nhật DB và trả về đúng status | **PASS** |
| 8 | **Alert Triage: Resolve** | Chuyển trạng thái sang `resolved` qua JSON | Cập nhật DB và trả về đúng status | **PASS** |
| 9 | **Offline Transition Timing** | Chuyển thành `offline` sau khi vượt ngưỡng chờ | Sau 3.2s không có tín hiệu, cả 2 thành offline | **PASS** |
| 10 | **Selective Online Reactivation**| Gửi heartbeat cho node-01 để hồi phục | Node-01 trở lại `online`, Node-02 vẫn `offline` | **PASS** |
| 11 | **Database Integrity Check** | `PRAGMA integrity_check` trên DB tích hợp | Trả về `['ok']` | **PASS** |
| 12 | **Foreign Key Consistency** | Không có bản ghi mồ côi giữa các bảng | `PRAGMA foreign_key_check` = 0 lỗi | **PASS** |

---

## 5. Kết luận Phân hệ Phase 4

1. **Thành tựu đã đạt được:**
   - Dòng chảy dữ liệu tích hợp giữa các phân hệ (Agent $\rightarrow$ API $\rightarrow$ DB $\rightarrow$ Detection $\rightarrow$ Dashboard) đã chứng minh được tính thông suốt trên phạm vi đồ án.
   - Các bảng cơ sở dữ liệu liên kết chặt chẽ, bảo toàn tính toàn vẹn khóa ngoại và hỗ trợ tra cứu chéo mượt mà.
   - Cơ chế quản lý trạng thái máy trạm (Heartbeat & Dynamic Offline Calculation) hoạt động chính xác theo thời gian thực.
2. **Khiếm khuyết cấu trúc cần khắc phục ngay:**
   - **Gỡ bỏ nút thắt 64 KB (`MAX_CONTENT_LENGTH`)** để tính năng FIM và Process Snapshot có thể thu thập dữ liệu trên máy trạm thực tế thay vì bị lỗi HTTP 413 ([`FINDING-PHASE04-01`](#finding-phase04-01)).
   - **Tách rời luồng phát hiện khỏi luồng nhận tin HTTP** để tránh nghẽn server và timeout Agent khi mở rộng ([`FINDING-PHASE04-02`](#finding-phase04-02)).

**Xếp loại phân hệ Phase 4:** **ĐẠT TIÊU CHUẨN CÓ ĐIỀU KIỆN (PARTIAL - CONDITIONAL PASS)**.
