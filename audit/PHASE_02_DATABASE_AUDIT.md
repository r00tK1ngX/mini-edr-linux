# BÁO CÁO KIỂM TOÁN PHÂN HỆ — PHASE 2: DATABASE & DATA INTEGRITY AUDIT

**Dự án:** Mini Endpoint Detection and Response for Linux (`r00tK1ngX/mini-edr-linux`)  
**Phân hệ Kiểm toán:** SQLite Database Engine, Migration Framework, Data Access Layer (Repository Pattern), Invariant Constraints & Data Integrity  
**Ngày thực hiện:** 05/11/2026 (22:50 EST)  
**Tình trạng Nghiệm thu:** **PARTIAL** (Mô hình dữ liệu, cơ chế khóa ngoại, transaction và migration runner được thiết kế rất chuẩn mực; tuy nhiên phát hiện 1 lỗi High liên quan đến vòng đời Alert re-opening, 2 lỗi Medium về khử trùng lặp toàn cục và thiếu chính sách lưu trữ / dọn dẹp dữ liệu, 1 lỗi Low)  

---

## 1. Tổng quan Kiến trúc Dữ liệu & Data Access Layer

Phân hệ Database của Mini EDR for Linux được xây dựng trên nền tảng **SQLite 3**, áp dụng mô hình phân lớp rõ ràng:
1. **Quản lý Kết nối & Cấu hình PRAGMA** ([`server/db.py`](file:///home/kali/Projects/mini-edr-linux/server/db.py)):
   - Kích hoạt chế độ ghi chép nhật ký **Write-Ahead Logging (`PRAGMA journal_mode = WAL`)** để hỗ trợ truy cập đọc/ghi song song.
   - Luôn thiết lập `PRAGMA foreign_keys = ON` và `PRAGMA busy_timeout = 5000` (5 giây) trên từng kết nối mới.
   - Từ chối khởi tạo database `:memory:` trong môi trường production/file-backed để tránh sai lệch đa tiến trình.
2. **Khung Di chuyển Dữ liệu Tự động (Migration Framework)** ([`server/migrations/runner.py`](file:///home/kali/Projects/mini-edr-linux/server/migrations/runner.py)):
   - Khám phá các file SQL có quy chuẩn định danh `^\d{3,}_[a-z0-9][a-z0-9_]*\.sql$`.
   - Băm SHA-256 toàn bộ nội dung file migration và lưu vết trong bảng `schema_migrations`.
   - Ngăn chặn việc sửa đổi hoặc xóa các file migration đã từng được áp dụng.
   - Phân tách câu lệnh bằng hàm `sqlite3.complete_statement` của chính SQLite, tránh lỗi ngắt dòng sai lệch khi có dấu chấm phẩy lồng trong chuỗi.
3. **Mô hình Dữ liệu Quan hệ (Data Model)** ([`server/migrations/001_phase2_data_model.sql`](file:///home/kali/Projects/mini-edr-linux/server/migrations/001_phase2_data_model.sql)):
   - Gồm 7 bảng dữ liệu quan hệ: `endpoints`, `system_metrics`, `process_snapshots`, `process_observations`, `file_baselines`, `security_events`, `alerts` và 1 bảng liên kết nhiều-nhiều `alert_events`.
   - Ràng buộc toàn vẹn khóa ngoại kết hợp chính sách `ON DELETE RESTRICT` (cho các bảng gốc) và `ON DELETE CASCADE` (cho dữ liệu chi tiết phụ thuộc).
4. **Mẫu Thiết kế Repository (Repository Pattern)** ([`server/repositories/`](file:///home/kali/Projects/mini-edr-linux/server/repositories/)):
   - Lớp cơ sở [`BaseRepository`](file:///home/kali/Projects/mini-edr-linux/server/repositories/base.py) quản lý transaction tự động bằng context manager `with conn:`.
   - Tách biệt rõ ràng các kho lưu trữ: `EndpointRepository`, `ProcessRepository`, `BaselineRepository`, `MetricsRepository`, `EventRepository`, `AlertRepository`.

---

## 2. Kết quả Trả lời Các Câu hỏi Kiểm toán Bắt buộc

### ❓ 1. Có thể tạo dữ liệu mồ côi (Orphan records) không?
- **KHÔNG.** 
  - Toàn bộ các bảng lưu trữ dữ liệu phụ thuộc (`system_metrics`, `process_snapshots`, `file_baselines`, `security_events`, `alerts`) đều có ràng buộc:
    ```sql
    FOREIGN KEY (agent_id) REFERENCES endpoints(agent_id) ON DELETE RESTRICT
    ```
  - Bảng `process_observations` tham chiếu đến `process_snapshots(id)` với `ON DELETE CASCADE`.
  - Bảng `alert_events` tham chiếu cả `alerts(id)` và `security_events(id)` với `ON DELETE CASCADE`.
  - Auditor đã thử nghiệm chèn trực tiếp bản ghi vào `system_metrics` với `agent_id` không tồn tại; SQLite đã ném ngoại lệ `sqlite3.IntegrityError: FOREIGN KEY constraint failed` và chặn đứng hoàn toàn. Khi xóa `endpoints`, SQLite từ chối với lỗi RESTRICT nếu còn dữ liệu con.

### ❓ 2. Có thể lưu dữ liệu trùng lặp không?
- **TẠI CẤP ĐỘ TỪNG BẢNG:** **KHÔNG.**
  - `system_metrics`, `process_snapshots`, `security_events` đều có ràng buộc `message_id TEXT NOT NULL UNIQUE`.
  - `file_baselines` có khóa chính kép `PRIMARY KEY (agent_id, file_path)`.
  - `process_observations` có khóa chính kép `PRIMARY KEY (snapshot_id, pid)`.
  - `alerts` có ràng buộc `alert_key TEXT NOT NULL UNIQUE`.
  - `alert_events` có khóa chính kép `PRIMARY KEY (alert_id, event_id)` kết hợp `INSERT OR IGNORE`.
- **TẠI CẤP ĐỘ TOÀN HỆ THỐNG:** **CÓ THỂ XẢY RA TRÙNG LẶP LIÊN BẢNG.** 
  - Chưa có bảng trung tâm quản lý khử trùng lặp `message_id` trên toàn hệ thống (*Chi tiết tại FINDING-PHASE02-01*).

### ❓ 3. Có transaction nào bị ghi một phần (Partial write) không?
- **KHÔNG.** 
  - Lớp `BaseRepository._connection` đóng gói toàn bộ thao tác trong khối `with conn:`. Trong thư viện `sqlite3` của Python, context manager này tự động phát lệnh `COMMIT` khi khối code hoàn tất thành công và tự động phát lệnh `ROLLBACK` khi có bất kỳ ngoại lệ nào xảy ra.
  - Kiểm thử thực nghiệm: Khi tạo một Snapshot gồm 2 tiến trình, trong đó tiến trình thứ 2 cố tình vi phạm CHECK constraint (`pid = -5`), toàn bộ transaction bị hủy bỏ: không có bất kỳ bản ghi `process_snapshots` mồ côi nào tồn tại trong database.

### ❓ 4. Có race condition khi nhiều Agent gửi dữ liệu đồng thời không?
- **KHÔNG BỊ CRASH HOẶC THẤT THOÁT DỮ LIỆU.**
  - Nhờ kích hoạt chế độ **WAL (Write-Ahead Logging)**, các tiến trình đọc không chặn tiến trình ghi và ngược lại.
  - Khi có xung đột ghi giữa các luồng, `PRAGMA busy_timeout = 5000` cho phép luồng đợi tối đa 5000ms để khóa ghi được giải phóng thay vì ném lỗi `database is locked` ngay lập tức.
  - Auditor đã chạy kiểm thử stress test với 5 luồng ghi song song (50 bản ghi liên tục), 100% bản ghi được ghi nhận thành công, 0 lỗi khóa cơ sở dữ liệu.

### ❓ 5. Migration có chạy lặp lại an toàn không (Idempotency)?
- **CÓ.**
  - Runner ghi nhớ phiên bản đã chạy vào bảng `schema_migrations`.
  - Khi gọi `apply_migrations()` nhiều lần liên tiếp, hàm kiểm tra tập hợp phiên bản đã áp dụng và trả về danh sách rỗng `[]`, không can thiệp hay thay đổi bất kỳ cấu trúc bảng nào hiện hữu.
  - Runner còn tích hợp cơ chế phát hiện giả mạo: nếu nội dung file SQL bị sửa đổi sau khi đã apply, runner sẽ ném ngoại lệ `MigrationError: Migration ... was modified after application` và hủy thực thi.

### ❓ 6. Rollback có bảo toàn dữ liệu không?
- **CÓ.**
  - Cả trong Migration Runner (sử dụng `BEGIN IMMEDIATE` kèm `ROLLBACK` khi lỗi statement) và Repository Pattern (dùng context manager `with conn:`), mọi trạng thái thất bại đều khôi phục chính xác về trạng thái trước đó. Dữ liệu hiện có không bị hư hại.

### ❓ 7. Foreign key và Index có đúng mục đích không?
- **ĐẠT CHUẨN CAO.**
  - 100% các quan hệ quan trọng đều có khóa ngoại.
  - Các bảng con đều có chỉ mục bao phủ các trường truy vấn phổ biến:
    - `idx_system_metrics_agent_collected` trên `(agent_id, collected_at DESC)`
    - `idx_process_snapshots_agent_collected` trên `(agent_id, collected_at DESC)`
    - `idx_process_observations_name` trên `(process_name)`
    - `idx_process_observations_exe_path` trên `(exe_path)`
    - `idx_file_baselines_agent_state` trên `(agent_id, state)`
    - `idx_security_events_agent_occurred` trên `(agent_id, occurred_at DESC)`
    - `idx_security_events_severity_occurred` trên `(severity, occurred_at DESC)`
    - `idx_alerts_status_severity` trên `(status, severity, last_seen_at DESC)`
    - `idx_alerts_agent_status` trên `(agent_id, status, last_seen_at DESC)`
    - `idx_alert_events_event` trên `(event_id)`

### ❓ 8. Database có thể phục hồi sau lỗi ghi hoặc restart không?
- **CÓ.**
  - Định dạng SQLite WAL với cơ chế ghi tuần tự vào file `-wal` và tự động checkpoint sang file chính đảm bảo tính chất ACID (Atomicity, Consistency, Isolation, Durability) ngay cả khi ứng dụng bị ngắt đột ngột (SIGKILL) hoặc máy chủ tắt nguồn.
  - Kiểm tra thực nghiệm trên database thực tế `data/mini_edr.db`: lệnh `PRAGMA integrity_check` trả về `['ok']` và `PRAGMA foreign_key_check` trả về 0 lỗi vi phạm.

### ❓ 9. Có truy vấn SQL nào ghép chuỗi không an toàn?
- **KHÔNG.**
  - Đã rà soát toàn bộ các file trong [`server/repositories/`](file:///home/kali/Projects/mini-edr-linux/server/repositories/).
  - Mọi tham số từ phía người dùng đều được truyền qua dạng tham số hóa chuẩn (`?` hoặc `:name`).
  - Tại các hàm xây dựng mệnh đề `WHERE` động (như `list_alerts`, `list_recent`, `count` trong `AlertRepository` và `EventRepository`), chuỗi động duy nhất được ghép là các mệnh đề tĩnh cố định (như `"severity = ?"`, `"status = ?"`), còn giá trị thực tế luôn được thêm vào danh sách `params` và truyền vào `cursor.execute(sql, tuple(params))`.

### ❓ 10. Có nguy cơ SQL Injection không?
- **KHÔNG.**
  - Auditor đã đưa các chuỗi tấn công kinh điển (`' OR '1'='1`, `'; DROP TABLE endpoints; --`, `1 UNION SELECT 1,2...`) vào toàn bộ các phương thức tìm kiếm và lọc dữ liệu của các Repository. Tất cả đều được SQLite xử lý thuần túy như chuỗi ký tự thông thường, không phát sinh bất kỳ lỗi cú pháp hay rò rỉ dữ liệu ngoài ý muốn.

---

## 3. Danh Sách Các Phát Hiện Kiểm Toán Chi Tiết (Findings)

---

### 🔴 FINDING-PHASE02-01: Điểm mù tái nhiễm: Alert đã xử lý (Resolved) không bao giờ tự mở lại khi mối nguy tái diễn
- **Mức độ nghiêm trọng:** **HIGH** (CVSS: 7.4 - High)
- **Phase ảnh hưởng:** Phase 2 (Database Data Model & Lifecycle) & Phase 6 (Alert Management)
- **File / Vị trí:** [`server/repositories/alert_repository.py`](file:///home/kali/Projects/mini-edr-linux/server/repositories/alert_repository.py#L56-L62)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Trong phương thức `AlertRepository.create_or_update()`, câu lệnh SQL xử lý trùng lặp dựa trên `alert_key` như sau:
  ```sql
  INSERT INTO alerts ( ... )
  VALUES ( ... )
  ON CONFLICT(alert_key) DO UPDATE SET
      title = excluded.title,
      description = excluded.description,
      severity = excluded.severity,
      last_seen_at = excluded.last_seen_at,
      updated_at = excluded.updated_at
  RETURNING *;
  ```
  Trường `status` **hoàn toàn không được cập nhật**. Khi một chuyên viên phân tích SOC đã xử lý xong cảnh báo và chuyển trạng thái về `resolved`, nếu kẻ tấn công kích hoạt lại chính xác hành vi đó trên cùng endpoint (tạo ra cùng `alert_key = <agent_id>:<rule_id>:<fingerprint>`):
  1. Bản ghi `alerts` hiện có chỉ được cập nhật `last_seen_at` và `updated_at`.
  2. Trạng thái `status` vẫn giữ nguyên là `'resolved'`.
  3. SOC Dashboard mặc định chỉ hiển thị các cảnh báo mở (`status IN ('new', 'acknowledged')`).
  4. Hệ thống cũng không hề cung cấp phương thức `reopen()` hay API chuyển trạng thái từ `resolved` về `new`.
- **Điều kiện Kích hoạt (Preconditions):**
  Một cảnh báo đã từng được tạo, sau đó được đóng bởi operator (`status = 'resolved'`). Sau đó máy trạm tiếp tục bị tấn công hoặc tái nhiễm mã độc tương tự.
- **Các bước Tái hiện (Reproduction Steps):**
  1. Tạo cảnh báo `audit-alert-key-1` với trạng thái ban đầu là `new`.
  2. Gọi `alert_repo.resolve(alert_id, note="Malware removed")` -> `status` chuyển thành `resolved`.
  3. Agent gửi lên một sự kiện bảo mật mới tương ứng, Detection Engine gọi `alert_repo.create_or_update()` với `alert_key = 'audit-alert-key-1'`.
  4. Kiểm tra bản ghi trong DB: `status` vẫn là `resolved`, không hề có cảnh báo mở mới nào được kích hoạt để báo động cho SOC.
- **Tác động (Impact):**
  Kẻ tấn công có thể lợi dụng điều này để lẩn tránh hoàn toàn sự giám sát của SOC sau khi sự cố ban đầu được đóng ("Silent Evasion via Resolved Alert State"). SOC sẽ hoàn toàn mù trước các đợt tấn công lặp lại.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  1. Cập nhật câu lệnh `ON CONFLICT(alert_key)` để tự động kích hoạt lại trạng thái cảnh báo nếu nó đã bị đóng:
     ```sql
     ON CONFLICT(alert_key) DO UPDATE SET
         title = excluded.title,
         description = excluded.description,
         severity = excluded.severity,
         status = CASE 
             WHEN alerts.status = 'resolved' THEN 'new' 
             ELSE alerts.status 
         END,
         last_seen_at = excluded.last_seen_at,
         updated_at = excluded.updated_at
     ```
  2. Hoặc bổ sung cửa sổ thời gian (time-window bucket) vào thuật toán sinh `alert_key` (ví dụ gom cụm theo ngày/tuần: `<agent_id>:<rule_id>:<date>:<fingerprint>`).

---

### 🟡 FINDING-PHASE02-02: Khử trùng lặp `message_id` chỉ giới hạn cục bộ theo bảng, thiếu bảng Deduplication toàn cục
- **Mức độ nghiêm trọng:** **MEDIUM** (CVSS: 4.8 - Medium)
- **Phase ảnh hưởng:** Phase 2 (Database) & Data Contract Phase 2
- **File / Vị trí:** [`server/migrations/001_phase2_data_model.sql`](file:///home/kali/Projects/mini-edr-linux/server/migrations/001_phase2_data_model.sql#L33), [`server/routes.py`](file:///home/kali/Projects/mini-edr-linux/server/routes.py#L288)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Theo đặc tả `DATA_CONTRACT.md`, mỗi bản tin từ Agent gửi lên đều mang một UUID v4 duy nhất `message_id` ở cấp độ phong bì (`Message Envelope`).
  Tuy nhiên, trong cơ sở dữ liệu, ràng buộc `UNIQUE` đối với `message_id` được đặt riêng lẻ trên từng bảng (`system_metrics.message_id`, `process_snapshots.message_id`, `security_events.message_id`). Không có bảng quản lý `ingested_messages` toàn cục.
  Nếu một client lỗi gửi cùng một `message_id` sang route `/api/v1/telemetry/system` rồi lại gửi chính `message_id` đó sang `/api/v1/telemetry/processes`, cả hai bản tin đều được chấp nhận và lưu vào 2 bảng khác nhau mà không bị phát hiện là tái sử dụng mã định danh thông điệp.
- **Tác động (Impact):**
  Phá vỡ tính toàn vẹn của mô hình Message Tracking và Idempotency toàn cục theo thiết kế EDR phân tán.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  Tạo một bảng quản lý chung `ingested_messages(message_id TEXT PRIMARY KEY, agent_id TEXT, message_type TEXT, received_at TEXT)` hoặc trigger xác thực `message_id` trước khi chèn vào các bảng nghiệp vụ.

---

### 🟡 FINDING-PHASE02-03: Thiếu cơ chế giới hạn thời gian lưu trữ (TTL) và dọn dẹp dữ liệu (Database Pruning)
- **Mức độ nghiêm trọng:** **MEDIUM** (CVSS: 5.3 - Medium)
- **Phase ảnh hưởng:** Phase 2 (Database Capacity & Reliability)
- **File / Vị trí:** [`server/db.py`](file:///home/kali/Projects/mini-edr-linux/server/db.py), [`server/repositories/process_repository.py`](file:///home/kali/Projects/mini-edr-linux/server/repositories/process_repository.py)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Trong toàn bộ codebase không có bất kỳ tác vụ định kỳ (background worker, cron job, hoặc CLI command) nào để xóa/prune các bản ghi telemetry cũ (như `process_observations` và `system_metrics`).
  Với tần suất gửi telemetry định kỳ của Agent (5s cho metrics, 10-30s cho process snapshot):
  - 1 Endpoint thu thập trung bình ~150 tiến trình mỗi snapshot.
  - Trong 24 giờ, 1 endpoint sinh ra: $8,640 \text{ snapshots} \times 150 \approx 1,296,000$ bản ghi `process_observations`.
  - Cơ sở dữ liệu SQLite sẽ tăng trưởng dung lượng không giới hạn, dẫn đến cạn kiệt ổ đĩa (Disk Full / DoS) và làm suy giảm hiệu năng các truy vấn phân tích / tổng hợp.
- **Tác động (Impact):**
  Rủi ro từ chối dịch vụ (DoS) đối với máy chủ Backend sau một thời gian vận hành liên tục; làm chậm tốc độ nạp trang Dashboard khi bảng tiến trình phình to hàng chục triệu dòng.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  Bổ sung một hàm dọn dẹp dữ liệu (ví dụ: `purge_old_telemetry(retention_days=7)`) và hỗ trợ lệnh chạy ngầm hoặc endpoint admin bảo trì định kỳ kèm lệnh `VACUUM`.

---

### 🔵 FINDING-PHASE02-04: Tính toán trạng thái Offline phụ thuộc vào chênh lệch đồng hồ SQLite `julianday`
- **Mức độ nghiêm trọng:** **LOW** (CVSS: 3.1 - Low)
- **Phase ảnh hưởng:** Phase 2 (Database Repository) & Phase 1
- **File / Vị trí:** [`server/repositories/endpoint_repository.py`](file:///home/kali/Projects/mini-edr-linux/server/repositories/endpoint_repository.py#L98-L105)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Hàm `EndpointRepository.list_all()` cập nhật trạng thái `offline` trực tiếp bằng câu lệnh:
  ```sql
  UPDATE endpoints
  SET status = CASE
      WHEN (julianday('now') - julianday(last_seen)) * 86400.0 > ?
      THEN 'offline'
      ELSE 'online'
  END
  ```
  `julianday('now')` sử dụng đồng hồ hệ thống UTC tại thời điểm thực thi câu lệnh SQL của máy chủ SQLite. Nếu `last_seen` được ghi nhận từ một nguồn có định dạng chuỗi không đồng nhất hoặc nếu đồng hồ của máy chủ bị trôi (clock drift / NTP step), việc chuyển đổi này có thể đánh dấu sai lệch trạng thái các máy trạm thành offline hàng loạt.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  Truyền trực tiếp mốc thời gian UTC hiện tại từ Python (`now_iso = datetime.now(timezone.utc).isoformat()`) làm tham số truy vấn thay vì phụ thuộc vào hàm `julianday('now')` của engine SQLite.

---

## 4. Ma Trận Kiểm Thử Thực Nghiệm Phân Hệ Cơ Sở Dữ Liệu

Auditor đã xây dựng kịch bản kiểm thử độc lập [`audit_phase2_db.py`](file:///home/kali/.gemini/antigravity-cli/brain/2f030cf6-8c2b-476d-90bd-f71588442318/scratch/audit_phase2_db.py) và thực thi trực tiếp trên máy ảo. Kết quả chi tiết như sau:

| STT | Hạng mục Kiểm thử | Kỳ vọng | Kết quả Thực tế | Trạng thái |
| :---: | :--- | :--- | :--- | :---: |
| 1 | **Migration Apply & Ordering** | Khởi tạo bảng thành công, lưu vết vào `schema_migrations` | Áp dụng đúng 1 migration (`001_phase2_data_model`), bảng được khởi tạo đầy đủ | **PASS** |
| 2 | **Migration Idempotency** | Chạy lại nhiều lần không sinh lỗi, không nhân bản bảng | Trả về 0 migration mới, database nguyên vẹn | **PASS** |
| 3 | **Migration Tamper Detection** | Phát hiện khi nội dung file SQL bị sửa sau khi apply | Bắt đúng ngoại lệ `MigrationError: was modified after application` | **PASS** |
| 4 | **PRAGMA foreign_keys** | Bắt buộc bật `PRAGMA foreign_keys = 1` | `PRAGMA foreign_keys = 1` trên mọi kết nối | **PASS** |
| 5 | **PRAGMA busy_timeout** | Đặt thời gian chờ khóa bảng $\ge 5000\text{ms}$ | `PRAGMA busy_timeout = 5000` | **PASS** |
| 6 | **PRAGMA journal_mode** | Chế độ nhật ký phải là `WAL` | `PRAGMA journal_mode = WAL` | **PASS** |
| 7 | **Foreign Key: Orphan Block** | Chèn bản ghi con với `agent_id` giả mạo phải bị chặn | Ném lỗi `FOREIGN KEY constraint failed` ngay lập tức | **PASS** |
| 8 | **Foreign Key: RESTRICT** | Xóa Endpoint khi còn telemetry phải bị chặn | Ném lỗi `FOREIGN KEY constraint failed` (RESTRICT) | **PASS** |
| 9 | **Foreign Key: CASCADE** | Xóa Snapshot phải tự động xóa sạch các Observations | Xóa snapshot 1 làm giảm 2 observations về 0 | **PASS** |
| 10 | **CHECK Constraint: CPU %** | Chặn giá trị CPU ngoài dải $[0, 100]$ (thử $150\%$) | Ném lỗi `CHECK constraint failed: cpu_percent >= 0 AND cpu_percent <= 100` | **PASS** |
| 11 | **CHECK Constraint: SHA-256** | Chặn mã băm không đúng 64 ký tự hex chữ thường | Ném lỗi `CHECK constraint failed: length(sha256) = 64 AND sha256 NOT GLOB...` | **PASS** |
| 12 | **CHECK Constraint: File Mode**| Chặn file_mode $> 4095$ (thử mode 5000) | Ném lỗi `CHECK constraint failed: file_mode >= 0 AND file_mode <= 4095` | **PASS** |
| 13 | **Transaction Rollback** | Lỗi ở 1 dòng trong batch phải rollback toàn bộ cha con | Snapshot bị hủy bỏ hoàn toàn, không có bản ghi mồ côi | **PASS** |
| 14 | **Duplicate `message_id`** | Chặn insert cùng `message_id` trong cùng bảng | Ném lỗi `UNIQUE constraint failed: system_metrics.message_id` | **PASS** |
| 15 | **Cross-table `message_id`** | Thử tái sử dụng cùng `message_id` ở 2 bảng khác nhau | Được chấp nhận (Bộc lộ thiếu sót Deduplication toàn cục) | **CONFIRMED** |
| 16 | **Alert Re-opening Lifecycle** | Thử tái kích hoạt hành vi trên alert đã `resolved` | Alert giữ nguyên trạng thái `resolved` (Bộc lộ lỗi High) | **CONFIRMED** |
| 17 | **Concurrent Writes** | 5 luồng ghi đồng thời (50 records) vào SQLite WAL | 0 lỗi khóa bảng (`database is locked`), 100% bản ghi lưu trữ chuẩn | **PASS** |
| 18 | **SQL Injection Probing** | Truyền payloads SQLi vào toàn bộ các phương thức repo | 100% tham số hóa an toàn, không có lỗi cú pháp hay lộ dữ liệu | **PASS** |
| 19 | **Live DB Integrity Check** | Chạy kiểm tra toàn vẹn trên `data/mini_edr.db` | `PRAGMA integrity_check` = `['ok']` | **PASS** |
| 20 | **Live DB Foreign Key Check**| Quét toàn bộ khóa ngoại trên database thực tế | `PRAGMA foreign_key_check` = 0 vi phạm | **PASS** |

---

## 5. Kết luận Phân hệ Phase 2

1. **Điểm mạnh xuất sắc:**
   - Việc tuân thủ chuẩn SQLite WAL, thiết lập timeout chống nghẽn 5000ms, và bắt buộc bật `foreign_keys = ON` cho từng kết nối là thiết kế chuyên nghiệp, vượt xa mức độ của một đồ án sinh viên thông thường.
   - Cơ chế Migration Runner tự xây dựng rất chắc chắn: băm SHA-256 chống sửa đổi, phát hiện mất file, và phân tích statement hoàn chỉnh bằng engine của SQLite.
   - Ràng buộc dữ liệu (CHECK constraints) được định nghĩa chi tiết từ regex hex SHA-256, dải phần trăm $0-100\%$, đến tính hợp lệ của timestamp logic theo từng trạng thái.
2. **Hạn chế then chốt cần khắc phục:**
   - Cần bổ sung logic mở lại cảnh báo (`status = 'new'`) khi phát hiện mối nguy tái diễn trên `alert_key` đã xử lý ([`FINDING-PHASE02-01`](#finding-phase02-01)).
   - Cần bổ sung cơ chế Pruning / TTL định kỳ cho bảng tiến trình và số liệu để ngăn ngừa cạn kiệt dung lượng đĩa ([`FINDING-PHASE02-03`](#finding-phase02-03)).

**Xếp loại phân hệ Phase 2:** **ĐẠT TIÊU CHUẨN CÓ ĐIỀU KIỆN (PARTIAL - CONDITIONAL PASS)**.
