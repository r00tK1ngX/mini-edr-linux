# BÁO CÁO KIỂM TOÁN PHÂN HỆ — PHASE 6: ALERT MANAGEMENT & SOC WORKFLOW AUDIT

**Dự án:** Mini Endpoint Detection and Response for Linux (`r00tK1ngX/mini-edr-linux`)  
**Phân hệ Kiểm toán:** Quản lý Sự cố An ninh, Máy trạng thái Cảnh báo (Alert State Machine) & Quy trình Điều hành SOC Triage  
**Ngày thực hiện:** 06/11/2026 (04:55 EST)  
**Tình trạng Nghiệm thu:** **PARTIAL** (Đã hiện thực hóa máy trạng thái chuyển đổi chuẩn SOC `NEW` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `RESOLVED`, có state guard chặn lùi trạng thái và liên kết bằng chứng; tuy nhiên phát hiện 2 lỗi High nghiêm trọng về triệt tiêu cảnh báo không xác thực/CSRF và sự cố bị khóa chết không thể mở lại, 1 lỗi Medium về hạ cấp độ nghiêm trọng cảnh báo ngoài ý muốn, 1 lỗi Low)  

---

## 1. Tổng quan Phân hệ Quản lý Sự cố & Vòng đời Cảnh báo

Phân hệ Alert Management là cầu nối trọng yếu giữa Động cơ phát hiện (Detection Engine) và Chuyên viên phân tích an ninh (SOC Analyst), đảm bảo mọi nguy cơ an ninh đều được gom cụm, theo dõi trạng thái và lưu vết xử lý minh bạch:
1. **Mô hình Dữ liệu Sự cố (`alerts` & `alert_events`)** ([`server/migrations/001_phase2_data_model.sql`](file:///home/kali/Projects/mini-edr-linux/server/migrations/001_phase2_data_model.sql#L274-L377)):
   - Khử trùng lặp cảnh báo dựa trên khóa gom cụm duy nhất `alert_key` (dạng `<agent_id>:<rule_id>:<fingerprint>` hoặc `<agent_id>:correlated:proc:<pid>:<proc_name>`).
   - Liên kết nhiều-nhiều giữa Cảnh báo (`alerts`) và Sự kiện thô (`security_events`) thông qua bảng cầu nối `alert_events` kèm chính sách `ON DELETE CASCADE`.
2. **Máy trạng thái Cảnh báo (Alert State Machine)** ([`server/repositories/alert_repository.py`](file:///home/kali/Projects/mini-edr-linux/server/repositories/alert_repository.py)):
   - Các trạng thái hợp lệ: `new` (Mới phát hiện) $\rightarrow$ `acknowledged` (SOC đang điều tra) $\rightarrow$ `resolved` (Đã xử lý / Cô lập).
   - Cho phép chuyển đổi trực tiếp: `new` $\rightarrow$ `resolved` hoặc bỏ qua báo động giả (`dismiss`).
   - Ràng buộc CHECK trong cơ sở dữ liệu: Trạng thái `acknowledged` bắt buộc phải có mốc thời gian `acknowledged_at`, trạng thái `resolved` bắt buộc có `resolved_at`.
3. **Cổng giao tiếp Xử lý Sự cố (Triage Interfaces)**:
   - RESTful API có xác thực Bearer token: `/api/v1/alerts/*` ([`server/routes.py`](file:///home/kali/Projects/mini-edr-linux/server/routes.py)).
   - Web Console SOC Dashboard: `/alerts/*` ([`server/web.py`](file:///home/kali/Projects/mini-edr-linux/server/web.py)).

---

## 2. Kết quả Trả lời Các Câu hỏi Kiểm toán Bắt buộc

### ❓ 1. Máy trạng thái (State Machine) có ngăn chặn được các bước chuyển trạng thái bất hợp lệ không?
- **CÓ (ĐỐI VỚI BƯỚC LÙI `RESOLVED` $\rightarrow$ `ACKNOWLEDGED`).**
  - Cả trong `server/routes.py` (dòng 780) và `server/web.py` (dòng 311) đều có **State Transition Guard**:
    ```python
    if alert["status"] == "resolved":
        return _error("Resolved alert cannot be acknowledged", 400)
    ```
  - Nếu một cảnh báo đã đóng (`resolved`), hệ thống từ chối chuyển ngược lại về `acknowledged`.
- **TUY NHIÊN — BỊ KHÓA CHẾT VĨNH VIỄN (NO REOPEN CAPABILITY):**
  - Hệ thống **hoàn toàn không có hàm `reopen()` hay API nào để mở lại cảnh báo đã đóng**. Nếu chuyên viên SOC bấm nhầm "Resolve" hoặc nếu cuộc tấn công tái diễn, cảnh báo đó bị đóng vĩnh viễn, không có cách nào đưa về trạng thái mở (*Chi tiết tại FINDING-PHASE06-02*).

### ❓ 2. Các thao tác Triage (Acknowledge, Resolve, Dismiss) có tính lũy thừa (Idempotent) không?
- **CÓ.**
  - Nếu gửi lệnh Acknowledge nhiều lần liên tiếp trên một alert đang `acknowledged`, server trả về HTTP 200 kèm dữ liệu hiện tại mà không sinh thêm lỗi hay ghi đè mốc thời gian ban đầu.
  - Tương tự với lệnh Resolve và Dismiss: gọi lặp lại trả về HTTP 200, và ghi chú `resolution_note` cũ được bảo toàn nếu request mới không truyền ghi chú mới nhờ câu lệnh `COALESCE(?, resolution_note)`.

### ❓ 3. Bằng chứng an ninh (Evidence) có được liên kết đầy đủ với Cảnh báo không?
- **CÓ.**
  - Thông qua bảng `alert_events`, một cảnh báo có thể liên kết với nhiều sự kiện bảo mật.
  - API `GET /api/v1/alerts/<id>` và Web route `GET /alerts/<id>/detail` thực hiện câu lệnh `JOIN` và trả về toàn bộ danh sách `events` kèm chi tiết payload/evidence_json gốc.
  - Khi xóa một bản ghi trong bảng `alerts`, cơ chế `ON DELETE CASCADE` tự động dọn sạch các liên kết trong `alert_events`, không để lại dữ liệu rác.

### ❓ 4. Các thao tác Triage trên Web Dashboard có được bảo vệ chống tấn công không?
- **HOÀN TOÀN KHÔNG — LỖ NẰNG BẢO MẬT NGHIÊM TRỌNG.**
  - Toàn bộ các route `/alerts/<id>/acknowledge`, `/alerts/<id>/resolve`, `/alerts/<id>/dismiss` trong [`server/web.py`](file:///home/kali/Projects/mini-edr-linux/server/web.py) **không yêu cầu bất kỳ hình thức xác thực nào**.
  - Hệ thống **hoàn toàn không có mã thông báo chống giả mạo yêu cầu chéo trang (CSRF Tokens)**. Bất kỳ kẻ tấn công nào cũng có thể đóng sạch toàn bộ cảnh báo an ninh của SOC (*Chi tiết tại FINDING-PHASE06-01*).

### ❓ 5. Khi cùng một mối nguy tái diễn, độ nghiêm trọng của cảnh báo có được bảo toàn không?
- **KHÔNG — NGUY CƠ BỊ HẠ CẤP ĐỘ NGHIÊM TRỌNG (SEVERITY DOWNGRADE).**
  - Trong `AlertRepository.create_or_update()`, câu lệnh SQL `ON CONFLICT(alert_key) DO UPDATE SET severity = excluded.severity` tự động ghi đè mức độ nghiêm trọng bằng giá trị mới.
  - Nếu một cuộc tấn công ban đầu tạo ra cảnh báo `CRITICAL`, nhưng sự kiện lặp lại sau đó có mức `MEDIUM`, toàn bộ sự cố trên hàng đợi SOC bị tự động hạ cấp xuống `MEDIUM` (*Chi tiết tại FINDING-PHASE06-03*).

---

## 3. Danh Sách Các Phát Hiện Kiểm Toán Chi Tiết (Findings)

---

### 🔴 FINDING-PHASE06-01: Thao tác Triage trên Web Console không xác thực và thiếu CSRF Token cho phép kẻ tấn công tự do dập tắt cảnh báo
- **Mức độ nghiêm trọng:** **HIGH** (CVSS: 8.1 - High)
- **Phase ảnh hưởng:** Phase 1, Phase 6 (SOC Workflow) & Phase 7 (Web Dashboard)
- **File / Vị trí:** [`server/web.py`](file:///home/kali/Projects/mini-edr-linux/server/web.py#L291-L390)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Trong [`server/web.py`](file:///home/kali/Projects/mini-edr-linux/server/web.py), các route xử lý sự cố an ninh:
  - `POST /alerts/<id>/acknowledge`
  - `POST /alerts/<id>/resolve`
  - `POST /alerts/<id>/dismiss`
  hoàn toàn không có decorator bảo vệ xác thực (ngược lại với `/api/v1/*` có `require_agent_token`).
  Đồng thời, ứng dụng không tích hợp bất kỳ cơ chế kiểm soát CSRF nào (như `Flask-WTF` hoặc `CSRFProtect`).
- **Các bước Tái hiện Thực nghiệm (Reproduction Steps):**
  Đã kiểm chứng độc lập tại scratch test script:
  1. Tạo cảnh báo `Active Malware Detected` với mức độ `HIGH`.
  2. Từ một terminal không có token, gửi request:
     `curl -X POST http://127.0.0.1:5000/alerts/1/dismiss -H "Content-Type: application/json"`
  3. Kết quả: Request thành công với HTTP 200, cảnh báo bị chuyển ngay sang `resolved` với ghi chú `"Dismissed by operator (false positive / ignored)"`.
- **Tác động (Impact):**
  1. Bất kỳ ai trong mạng nội bộ truy cập được cổng 5000 đều có thể đóng, bỏ qua toàn bộ sự cố an ninh mà SOC đang theo dõi.
  2. Kẻ tấn công có thể lừa chuyên viên SOC bấm vào một liên kết độc hại trên trình duyệt (CSRF attack) để ngầm gửi lệnh đóng các cảnh báo mã độc đang hoạt động.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  1. Bổ sung cơ chế xác thực phiên làm việc (Session Authentication / HTTP Basic / OAuth2) cho toàn bộ Blueprint `web_bp`.
  2. Cài đặt thư viện `flask-wtf` và kích hoạt CSRF protection trên tất cả các form và request POST của Web Dashboard.

---

### 🔴 FINDING-PHASE06-02: Sự cố đã xử lý (Resolved) bị khóa chết vĩnh viễn, không có cơ chế Reopen khi SOC thao tác nhầm hoặc mối nguy tái diễn
- **Mức độ nghiêm trọng:** **HIGH** (CVSS: 7.2 - High)
- **Phase ảnh hưởng:** Phase 2, Phase 6 (Alert Lifecycle) & Phase 7 (Dashboard Triage)
- **File / Vị trí:** [`server/repositories/alert_repository.py`](file:///home/kali/Projects/mini-edr-linux/server/repositories/alert_repository.py), [`server/routes.py`](file:///home/kali/Projects/mini-edr-linux/server/routes.py#L780)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  1. Máy trạng thái cảnh báo của hệ thống chỉ là đường một chiều: `new` $\rightarrow$ `acknowledged` $\rightarrow$ `resolved`.
  2. State Guard trong `routes.py` và `web.py` chặn đứng việc chuyển trạng thái từ `resolved` sang `acknowledged` (HTTP 400).
  3. Hệ thống **không có bất kỳ hàm `reopen()` hay API nào** để chuyển trạng thái từ `resolved` về `new`.
  4. Đồng thời, như đã phát hiện ở [`FINDING-PHASE02-01`](file:///home/kali/Projects/mini-edr-linux/audit/PHASE_02_DATABASE_AUDIT.md#finding-phase02-01), câu lệnh `ON CONFLICT(alert_key)` khi phát hiện mối nguy lặp lại cũng không tự mở lại cảnh báo.
- **Tác động (Impact):**
  Nếu một chuyên viên SOC thao tác nhầm (bấm nhầm nút Resolve hoặc Dismiss một cuộc tấn công APT đang diễn ra), sự cố đó sẽ bị khóa chết vĩnh viễn ở trạng thái đóng. Kẻ tấn công có thể tiếp tục hoạt động trên máy trạm mà không bao giờ bị phát hiện lại trên hàng đợi SOC.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  1. Bổ sung phương thức `AlertRepository.reopen(alert_id, note=None)`: cập nhật `status = 'new'`, `updated_at = utc_now()`, ghi chú lý do mở lại sự cố.
  2. Mở route API `POST /api/v1/alerts/<id>/reopen` và nút bấm "Re-open Incident" trên giao diện Web Dashboard.

---

### 🟡 FINDING-PHASE06-03: Mức độ nghiêm trọng của Cảnh báo bị hạ cấp ngoài ý muốn (Involuntary Severity Downgrade) khi có sự kiện lặp lại
- **Mức độ nghiêm trọng:** **MEDIUM** (CVSS: 5.7 - Medium)
- **Phase ảnh hưởng:** Phase 2 (Alert Repository Upsert) & Phase 6 (Incident Prioritization)
- **File / Vị trí:** [`server/repositories/alert_repository.py`](file:///home/kali/Projects/mini-edr-linux/server/repositories/alert_repository.py#L59)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Trong phương thức `AlertRepository.create_or_update()`:
  ```sql
  ON CONFLICT(alert_key) DO UPDATE SET
      title = excluded.title,
      description = excluded.description,
      severity = excluded.severity,
      last_seen_at = excluded.last_seen_at,
      updated_at = excluded.updated_at
  ```
  Câu lệnh gán thẳng `severity = excluded.severity`.
  Trong vận hành thực tế: Một sự cố ban đầu có thể được phân loại là `CRITICAL` (ví dụ do tương quan đa nhân tố đạt 90 điểm). Sau đó, máy trạm tiếp tục gửi lên một sự kiện đơn lẻ cùng `alert_key` đó với mức `MEDIUM` (ví dụ chỉ có CPU cao 30 điểm). Câu lệnh `ON CONFLICT` lập tức đè giá trị `CRITICAL` thành `MEDIUM`.
- **Tác động (Impact):**
  Làm sai lệch mức độ ưu tiên xử lý của SOC; một sự cố nghiêm trọng có thể bị tụt xuống đáy hàng đợi do bị hạ cấp tự động ngoài ý muốn.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  Sử dụng thang bậc ưu tiên (Severity Rank) trong câu lệnh SQL để chỉ cho phép nâng cấp độ nghiêm trọng, không bao giờ tự động hạ cấp:
  ```sql
  severity = CASE
      WHEN excluded.severity = 'critical' THEN 'critical'
      WHEN excluded.severity = 'high' AND alerts.severity != 'critical' THEN 'high'
      WHEN excluded.severity = 'medium' AND alerts.severity NOT IN ('critical', 'high') THEN 'medium'
      ELSE alerts.severity
  END
  ```

---

### 🔵 FINDING-PHASE06-04: Giao diện Web Console giới hạn cứng 100 cảnh báo và thiếu thanh điều hướng phân trang (Pagination)
- **Mức độ nghiêm trọng:** **LOW** (CVSS: 3.5 - Low)
- **Phase ảnh hưởng:** Phase 6 & Phase 7 (Dashboard Alert View)
- **File / Vị trí:** [`server/web.py`](file:///home/kali/Projects/mini-edr-linux/server/web.py#L254), [`templates/alerts.html`](file:///home/kali/Projects/mini-edr-linux/templates/alerts.html)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Hàm `web.alerts()` gọi `alert_repo.list_alerts(..., limit=100)`. Giao diện `alerts.html` hoàn toàn không có tham số `offset` hay các nút bấm Next/Previous Page. Khi hệ thống tích lũy trên 100 cảnh báo, chuyên viên SOC không thể xem các cảnh báo cũ hơn qua giao diện web trừ khi áp dụng bộ lọc thật hẹp.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  Bổ sung tham số `page` và `per_page` vào route `web.alerts()`, tích hợp thanh phân trang (Pagination Bar) ở chân bảng danh sách cảnh báo.

---

## 4. Ma Trận Kiểm Thử Thực Nghiệm Phân Hệ Alert Management

Auditor đã xây dựng kịch bản kiểm thử độc lập [`audit_phase6_alert.py`](file:///home/kali/.gemini/antigravity-cli/brain/2f030cf6-8c2b-476d-90bd-f71588442318/scratch/audit_phase6_alert.py) và thực thi trực tiếp trên hệ thống:

| STT | Hạng mục Kiểm thử | Kỳ vọng | Kết quả Thực tế | Trạng thái |
| :---: | :--- | :--- | :--- | :---: |
| 1 | **Alert Creation (Status: NEW)** | Tạo alert mới có trạng thái `new` | `status == 'new'`, `severity == 'critical'` | **PASS** |
| 2 | **Evidence Linking** | Liên kết đúng sự kiện bảo mật nguồn | `alert_events` liên kết chính xác event ID | **PASS** |
| 3 | **Triage: NEW $\rightarrow$ ACK** | Chuyển sang `acknowledged` kèm ghi chú | Cập nhật `acknowledged_at` và resolution_note | **PASS** |
| 4 | **Acknowledge Idempotency** | Gọi lặp lại không sinh lỗi, giữ nguyên note | Trả về HTTP 200, note cũ được bảo toàn | **PASS** |
| 5 | **Triage: ACK $\rightarrow$ RESOLVED** | Chuyển sang `resolved` kèm lý do xử lý | Cập nhật `resolved_at` và status | **PASS** |
| 6 | **State Guard: Block Reversal** | Chặn lùi trạng thái từ `resolved` về `ack` | Bị chặn với HTTP 400 Bad Request | **PASS** |
| 7 | **Incident Reopen API** | Có API mở lại sự cố khi cần | Không tồn tại endpoint (404) | **CONFIRMED (Lỗi High)** |
| 8 | **Severity Downgrade Flaw** | Mức độ cảnh báo bị đè bởi sự kiện nhẹ hơn | `critical` bị hạ thành `medium` trên cùng key | **CONFIRMED (Lỗi Med)** |
| 9 | **Web Triage Unauthenticated** | Route web triage không đòi token | Gọi thành công mà không cần Bearer token | **CONFIRMED (Lỗi High)** |
| 10 | **Unauthenticated Dismissal** | Kẻ tấn công đóng sạch cảnh báo qua web | Alert chuyển sang `resolved` thành công | **CONFIRMED (Lỗi High)** |
| 11 | **Summary Aggregation** | Thống kê số lượng theo status và severity | Tổng hợp đúng `open`, `resolved`, `critical` | **PASS** |
| 12 | **API Pagination Validation** | Kiểm soát biên `limit` và `offset` | Chặn `limit=0` (400), chấp nhận dải hợp lệ | **PASS** |
| 13 | **Web Hardcoded Limit 100** | Kiểm tra phân trang trên giao diện Web | Cố định `limit=100`, không có `offset`/page | **CONFIRMED (Lỗi Low)** |

---

## 5. Kết luận Phân hệ Phase 6

1. **Điểm sáng:**
   - Quy trình điều hành sự cố (Triage Workflow) được thiết kế bài bản theo tiêu chuẩn vận hành SOC chuyên nghiệp (`NEW` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `RESOLVED`).
   - Tính lũy thừa (Idempotency) được xử lý rất tốt, bảo toàn ghi chú xử lý của chuyên viên cấp trước.
   - Bằng chứng JSON (Evidence Linking) và khóa ngoại nhiều-nhiều giữa Alert và Security Events hoạt động tin cậy.
2. **Hạn chế then chốt cần khắc phục:**
   - **Bịt lỗ hổng Web Triage Unauthenticated & CSRF**: Phải bắt buộc xác thực và thêm CSRF token cho tất cả các thao tác chuyển trạng thái sự cố ([`FINDING-PHASE06-01`](#finding-phase06-01)).
   - **Bổ sung tính năng Reopen Incident**: Cho phép mở lại cảnh báo đã đóng để khắc phục sai sót của con người và bẫy các đợt tấn công tái diễn ([`FINDING-PHASE06-02`](#finding-phase06-02)).
   - **Bảo toàn cấp độ nghiêm trọng cao nhất**: Sửa câu lệnh SQL Upsert để ngăn chặn việc hạ cấp tự động từ `critical` xuống `medium` ([`FINDING-PHASE06-03`](#finding-phase06-03)).

**Xếp loại phân hệ Phase 6:** **ĐẠT TIÊU CHUẨN CÓ ĐIỀU KIỆN (PARTIAL - CONDITIONAL PASS)**.
