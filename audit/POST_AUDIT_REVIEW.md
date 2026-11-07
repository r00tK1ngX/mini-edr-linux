# POST-AUDIT REVIEW & REMEDIATION FEASIBILITY SPECIFICATION
**Mini EDR for Linux — Academic Finalization Review (Stage A)**

- **Target Repository:** `r00tK1ngX/mini-edr-linux`
- **Branch:** `main` (Commit `7d1968a`)
- **Review Date:** 2026-11-06
- **Reviewers:** Senior Python Engineer, Cybersecurity Engineer & Software Quality Auditor
- **Status:** COMPLETED — AUDIT-ONLY (Stage A Gate Check)

---

## 1. MỤC TIÊU VÀ PHẠM VI KHÓA (SCOPE LOCK ALIGNMENT)

Báo cáo này thực hiện đánh giá toàn diện sau kiểm toán (Post-Audit Review) nhằm chuẩn bị cho quá trình hoàn thiện đồ án tốt nghiệp Python (**Mini EDR for Linux**). 

Tuân thủ nghiêm ngặt nguyên tắc **SCOPE LOCK** theo chỉ thị của chủ dự án:
1. **Bảo toàn phạm vi học thuật (Academic Capstone):** Tập trung vào tính đúng đắn, an toàn cơ bản, toàn vẹn dữ liệu, chất lượng mã nguồn Python, kiểm thử tự động và năng lực bảo vệ trước hội đồng.
2. **Loại trừ tuyệt đối tính năng Enterprise không thuộc đề tài:** Không đưa vào eBPF, Machine Learning, cơ sở dữ liệu phân tán (PostgreSQL/Redis), hàng đợi tác vụ nền (Celery), kiến trúc Microservices (Kubernetes), cô lập mạng tự động hay tự ý diệt tiến trình (kill process/quarantine).
3. **Chiến lược đối với thuộc tính `cmdline`:** Tuân thủ chỉ đạo của chủ dự án — **không bổ sung trích xuất dòng lệnh `cmdline` đầy đủ vào Agent** (nhằm tránh tăng dung lượng bộ nhớ, nguy cơ rò rỉ token/mật khẩu trong process args và tăng độ phức tạp schema SQLite). Thay vào đó, khắc phục triệt để bằng cách **chuẩn hóa tài liệu kỹ thuật** (`README.md`, `ARCHITECTURE.md`, `DEMO_SCENARIO.md`, `SLIDES`) phản ánh chính xác 9 trường thông tin thực tế được thu thập.

---

## 2. XÁC MINH HIỆN TRẠNG TOÀN BỘ 36 PHÁT HIỆN TRÊN NHÁNH `main`

Toàn bộ 36 phát hiện trong [`audit/AUDIT_FINDINGS.md`](file:///home/kali/Projects/mini-edr-linux/audit/AUDIT_FINDINGS.md) đã được đối chiếu trực tiếp trên mã nguồn hiện tại của nhánh `main`:

| Mã Phát hiện | Phân loại | Severity & CVSS | Tình trạng trên `main` | Đánh giá Tính khả thi & Hướng xử lý |
| :--- | :---: | :---: | :---: | :--- |
| **`FINDING-PHASE01-01`** | Lỗi ứng dụng | 🔴 High (7.5) | **Đang tồn tại** | Thiếu `SECRET_KEY` trong `server/app.py`. Cần bổ sung vào `create_app()` trong **Giai đoạn B**. |
| **`FINDING-PHASE01-02`** | Lỗ hổng bảo mật | 🔴 High (7.5) | **Đang tồn tại** | Web Dashboard (`web_bp`) không có xác thực. Triển khai session login đơn giản cho lab trong **Giai đoạn B**. |
| **`FINDING-PHASE01-03`** | Thiết kế học thuật | 🟡 Medium (6.5) | **Đang tồn tại** | Dùng chung token Bearer. Trong phạm vi lab đề tài là hợp lệ; chuẩn hóa tài liệu ghi rõ giới hạn lab trong **Giai đoạn G**. |
| **`FINDING-PHASE01-04`** | Toàn vẹn dữ liệu | 🟡 Medium (5.3) | **Đang tồn tại** | Upsert heartbeat ghi đè NULL lên `ip_address`, `agent_version`. Cần dùng `COALESCE` trong **Giai đoạn C**. |
| **`FINDING-PHASE01-05`** | Kiểm soát cấu hình | 🔵 Low (3.7) | **Đang tồn tại** | Logic kiểm tra độ dài token nằm ngoài `create_app()`. Đưa vào factory trong **Giai đoạn E**. |
| **`FINDING-PHASE02-01`** | Toàn vẹn dữ liệu | 🔴 High (7.1) | **Đang tồn tại** | Cảnh báo đã Resolved không được mở lại khi mã độc tái kích hoạt. Cần sửa `ON CONFLICT` trong **Giai đoạn C**. |
| **`FINDING-PHASE02-02`** | Thiết kế dữ liệu | 🟡 Medium (5.3) | **Đang tồn tại** | Ràng buộc UNIQUE `message_id` chỉ nằm ở cấp bảng. Hợp lệ trong phạm vi đồ án; giữ nguyên thiết kế. |
| **`FINDING-PHASE02-03`** | Quản trị tài nguyên | 🟡 Medium (5.3) | **Đang tồn tại** | Không có TTL dọn dẹp metrics cũ. Thêm script hoặc tài liệu hóa trong **Giai đoạn G**. |
| **`FINDING-PHASE02-04`** | Lệch đồng hồ | 🔵 Low (3.1) | **Đang tồn tại** | Trạng thái Online/Offline dựa vào `julianday('now')`. Hợp lệ cho môi trường lab nội bộ. |
| **`FINDING-PHASE03-01`** | Toàn vẹn dữ liệu | 🔴 High (7.5) | **Đang tồn tại** | Mất event FIM khi gửi thất bại do Agent vội vàng cập nhật baseline bộ nhớ. Sửa trong **Giai đoạn C**. |
| **`FINDING-PHASE03-02`** | Lệch tài liệu | 🔴 High (6.8) | **Đang tồn tại** | `ProcessCollector` không thu thập `cmdline`. Theo chỉ thị, **không sửa code**, sửa tài liệu trong **Giai đoạn G**. |
| **`FINDING-PHASE03-03`** | Hiệu năng Agent | 🟡 Medium (5.3) | **Đang tồn tại** | FIM băm byte toàn bộ tệp mỗi chu kỳ. Thêm kiểm tra nhanh `mtime`/`size` trong **Giai đoạn C**. |
| **`FINDING-PHASE03-04`** | An toàn đường dẫn | 🟡 Medium (5.5) | **Đang tồn tại** | `Path.resolve()` duyệt symlink ra ngoài phạm vi. Sửa dùng `os.lstat` trong **Giai đoạn C**. |
| **`FINDING-PHASE03-05`** | Giới hạn kỹ thuật | 🟡 Medium (5.3) | **Đang tồn tại** | Bỏ lỡ tiến trình $<10$s do polling `/proc`. Giới hạn cố hữu của Polling; giữ nguyên và giải trình trong Slide 18. |
| **`FINDING-PHASE03-06`** | Định danh máy trạm | 🔵 Low (3.3) | **Đang tồn tại** | Định danh bằng hostname. Hợp lệ cho môi trường demo lab đồ án. |
| **`FINDING-PHASE04-01`** | Độ tin cậy hệ thống | 🔴 High (7.5) | **Đang tồn tại** | `MAX_CONTENT_LENGTH = 64KB` từ chối baseline $>500$ tệp (HTTP 413). Tăng lên 16MB trong **Giai đoạn C**. |
| **`FINDING-PHASE04-02`** | Hiệu năng Ingestion | 🟡 Medium (5.3) | **Đang tồn tại** | Detection engine chạy đồng bộ trong request HTTP. Scope lock không cho phép Celery; giữ nguyên, tối ưu query. |
| **`FINDING-PHASE04-03`** | Giới hạn SQLite | 🟡 Medium (5.3) | **Đang tồn tại** | `file_path NOT IN ({placeholders})` có thể tràn biến SQL nếu $>999$ files. Cắt batch trong **Giai đoạn C**. |
| **`FINDING-PHASE04-04`** | Ổn định trạng thái | 🔵 Low (3.1) | **Đang tồn tại** | Không có hysteresis cho trạng thái Offline. Hợp lệ cho ngưỡng 15s của đồ án. |
| **`FINDING-PHASE05-01`** | Tính đúng đắn Rule | 🔴 High (7.2) | **Đang tồn tại** | Thiếu rule `rule-proc-shell-spawn` và lệch mã rule so với tài liệu. Chuẩn hóa trong **Giai đoạn D**. |
| **`FINDING-PHASE05-02`** | Logic phát hiện | 🔴 High (7.1) | **Đang tồn tại** | `FimSensitiveFileRule` chỉ quét `/etc`, bỏ sót binary thả vào `/tmp`. Bổ sung rule trong **Giai đoạn D**. |
| **`FINDING-PHASE05-03`** | Giới hạn Heuristic | 🔴 High (7.5) | **Đang tồn tại** | Vượt mặt rule bằng đổi tên binary. Giới hạn tự nhiên của heuristic; nêu rõ trong tài liệu **Giai đoạn G**. |
| **`FINDING-PHASE05-04`** | Mã thừa (Dead code) | 🟡 Medium (4.3) | **Đang tồn tại** | `min_correlation_score` không được đánh giá trong `CorrelationEngine`. Dọn dẹp trong **Giai đoạn D**. |
| **`FINDING-PHASE05-05`** | Chuẩn hóa SOC | 🔵 Low (3.1) | **Đang tồn tại** | Chưa gắn nhãn MITRE ATT&CK. Bổ sung tag kỹ thuật (T1059, T1053, T1036) trong **Giai đoạn D**. |
| **`FINDING-PHASE06-01`** | Lỗ hổng bảo mật | 🔴 High (7.5) | **Đang tồn tại** | Triage endpoints không có CSRF bảo vệ. Bổ sung token bảo vệ trong **Giai đoạn B**. |
| **`FINDING-PHASE06-02`** | Máy trạng thái | 🔴 High (7.1) | **Đang tồn tại** | Cảnh báo Resolved không có API mở lại khi mã độc quay lại. Xử lý đồng bộ với `PHASE02-01` trong **Giai đoạn C**. |
| **`FINDING-PHASE06-03`** | Toàn vẹn dữ liệu | 🟡 Medium (5.3) | **Đang tồn tại** | Hạ mức nghiêm trọng ngoài ý muốn từ Critical xuống Medium. Sửa logic `MAX()` trong **Giai đoạn C**. |
| **`FINDING-PHASE06-04`** | Trải nghiệm UI | 🔵 Low (3.1) | **Đang tồn tại** | Hardcode `limit=100` không có nút phân trang. Hợp lệ cho quy mô demo lab. |
| **`FINDING-PHASE07-01`** | 🔴 **LỖ HỔNG NGUY HIỂM** | 🔴 High (7.2) | **Đang tồn tại** | **DOM XSS** trong `viewEvidence()` modal qua raw `innerHTML`. Phải sửa triệt để ngay trong **Giai đoạn B**. |
| **`FINDING-PHASE07-02`** | 🔴 **LỖ HỔNG NGUY HIỂM** | 🟡 Medium (6.1) | **Đang tồn tại** | **Attribute Injection XSS** trong nút Resolve. Chuyển sang HTML5 data attributes trong **Giai đoạn B**. |
| **`FINDING-PHASE07-03`** | Lỗ hổng bảo mật | 🟡 Medium (5.3) | **Đang tồn tại** | Lộ tiến trình và hash FIM ra mạng nội bộ không xác thực. Khắc phục bằng Auth Gate trong **Giai đoạn B**. |
| **`FINDING-PHASE07-04`** | Lỗ hổng bảo mật | 🔵 Low (4.3) | **Đang tồn tại** | Thiếu anti-CSRF token cho form POST. Sửa trong **Giai đoạn B**. |
| **`FINDING-PHASE07-05`** | Đánh giá tích cực | 🟢 Info (N/A) | **ĐÃ XÁC MINH** | 100% Air-Gapped compliant (0 CDN, 0 remote font, 0 tracking). Bảo tồn tuyệt đối. |
| **`FINDING-PHASE08-01`** | Phân định STRIDE | 🔴 High (7.5) | **Đang tồn tại** | Đồng nhất với `PHASE01-02` & `PHASE07-03`: Thiếu boundary bảo vệ Web SOC. Sửa trong **Giai đoạn B**. |
| **`FINDING-PHASE08-02`** | Chất lượng QA | 🔴 High (7.2) | **Đang tồn tại** | Test XSS hiện tại chỉ test Jinja2 escaping, bỏ qua DOM sinks. Thêm test DOM XSS trong **Giai đoạn B**. |
| **`FINDING-PHASE08-03`** | Độ tin cậy DoS | 🟡 Medium (5.3) | **Đang tồn tại** | Nguy cơ nghẽn khóa SQLite khi nhiều Agent spam. Tối ưu transaction và timeout trong **Giai đoạn C**. |
| **`FINDING-PHASE08-04`** | Lỗ hổng symlink | 🟡 Medium (5.5) | **Đang tồn tại** | Đồng nhất với `PHASE03-04`: Symlink TOCTOU traversal. Sửa trong **Giai đoạn C**. |
| **`FINDING-PHASE08-05`** | Phân định STRIDE | 🔵 Low (3.8) | **Đang tồn tại** | Đồng nhất với `PHASE01-03`: Dùng chung Bearer token. Tài liệu hóa giới hạn trong **Giai đoạn G**. |
| **`FINDING-PHASE08-06`** | Đánh giá tích cực | 🟢 Info (N/A) | **ĐÃ XÁC MINH** | Miễn nhiễm 100% SQLi, Command Injection, SSTI và ReDoS. Bảo tồn nguyên vẹn. |
| **`DISCREPANCY-DOC-01`** | Lỗi tài liệu thực thi | 🔴 High (7.0) | **Đang tồn tại** | Lệnh `python3 -m agent.orchestrator` bị lỗi `ModuleNotFoundError`. Sửa README thành `agent.main` trong **Giai đoạn G**. |
| **`DISCREPANCY-DOC-02`** | Lệch tài liệu | 🔴 High (6.8) | **Đang tồn tại** | Quảng bá `cmdline` trong README/Slide/Architecture. Sửa đồng bộ tài liệu thành 9 trường trong **Giai đoạn G**. |
| **`DISCREPANCY-DOC-03`** | Lệch tài liệu | 🔴 High (7.1) | **Đang tồn tại** | Tên rule `RULE_SUSPICIOUS_PROCESS` và `RULE_SHELL_SPAWN`. Đồng bộ hóa rule và tài liệu trong **Giai đoạn D & G**. |
| **`DISCREPANCY-DOC-04`** | Lệch đường dẫn | 🟡 Medium (4.0) | **Đang tồn tại** | Cây thư mục README ghi `server/detection/`, `system_metrics_repository.py`. Sửa đúng trong **Giai đoạn G**. |
| **`DISCREPANCY-DOC-05`** | Mâu thuẫn nội bộ | 🟡 Medium (4.0) | **Đang tồn tại** | Bảng tóm tắt API ghi "Designed; pending" dù code đã chạy. Đổi thành "Implemented" trong **Giai đoạn G**. |
| **`DISCREPANCY-DOC-06`** | Kịch bản demo | 🔵 Low (3.0) | **Đang tồn tại** | Mô tả kích hoạt dropped binary trong `/tmp`. Đồng bộ hóa sau khi bổ sung rule ở **Giai đoạn D**. |

---

## 3. PHÂN ĐỊNH PHẠM VI HỌC THUẬT (IN-SCOPE VS OUT-OF-SCOPE)

Nhằm đảm bảo dự án giữ vững tính chất một đồ án môn học Python xuất sắc, đơn giản, minh bạch và không bị biến tướng thành hệ thống thương mại quá tải:

### 3.1 Nhóm Trong Phạm vi Khắc phục Code (In-Scope Code Remediation)
1. **Khắc phục triệt để lỗ hổng Web & DOM XSS (Giai đoạn B):**
   - Loại bỏ nguy cơ DOM XSS trong `static/dashboard.js:viewEvidence()` bằng hàm `escapeHtml()`.
   - Loại bỏ nguy cơ Attribute Breakout XSS trong `templates/alerts.html` và `dashboard.html`.
   - Bổ sung `SECRET_KEY` trong `server/app.py` để bảo vệ các Form POST khỏi bị HTTP 500 runtime crash.
   - Thiết lập cơ chế bảo vệ phiên đăng nhập chuyên viên SOC đơn giản, an toàn cho Web Console (`web_bp`) bằng session-based authentication phù hợp môi trường lab.
2. **Khắc phục lỗi toàn vẹn dữ liệu & dung lượng payload (Giai đoạn C):**
   - Tăng `MAX_CONTENT_LENGTH` từ 64KB lên 16MB để không bị rớt bản tin đồng bộ FIM hợp lệ.
   - Sửa logic Agent không vội vàng nâng baseline bộ nhớ khi gửi bản tin HTTP thất bại, chống mất mát sự kiện FIM.
   - Sửa câu lệnh SQLite `ON CONFLICT` để tự động mở lại (`new`) các cảnh báo đã từng `resolved` khi mối đe dọa tái xuất hiện.
   - Chặn đứng lỗi tụt mức độ nghiêm trọng cảnh báo (Severity downgrade).
   - Ngăn chặn lỗi TOCTOU symlink traversal trong FIM.
3. **Chuẩn hóa Động cơ Phát hiện (Giai đoạn D):**
   - Bổ sung rule `rule-fim-dropped-binary` để chuỗi tấn công thả mã độc vào `/tmp` kích hoạt chính xác điểm tương quan $+50$.
   - Chuẩn hóa các Rule ID và mô tả kỹ thuật giữa `rules.py` và `test_detection.py`.
   - Dọn dẹp dead parameter `min_correlation_score`.

### 3.2 Nhóm Ngoài Phạm vi Code — Xử lý bằng "Documentation Honesty" (Out-of-Scope)
1. **Trường dữ liệu tiến trình `cmdline`:**
   - *Quyết định:* **KHÔNG SỬA CODE** (Không thêm `cmdline` vào `ProcessCollector` hay schema database).
   - *Lý do kỹ thuật:* Trong Linux, trích xuất đầy đủ command line từ `/proc/<pid>/cmdline` tốn kém IO, có thể chứa dữ liệu nhạy cảm (như mật khẩu, token trong tham số CLI), và 9 trường thông tin hiện tại (`pid`, `ppid`, `name`, `exe_path`, `username`, `status`, `cpu_percent`, `memory_percent`, `process_started_at`) đã hoàn toàn đáp ứng xuất sắc các quy tắc phát hiện của đề tài.
   - *Biện pháp:* Cập nhật toàn bộ tài liệu (`README.md`, `ARCHITECTURE.md`, `SLIDES`, `DEMO`) để xác nhận rõ ràng rằng EDR thu thập 9 trường cốt lõi phục vụ bảo mật an toàn.
2. **Xác thực chứng chỉ mTLS per-agent:**
   - *Quyết định:* Giữ nguyên cơ chế Pre-Shared Key (Bearer token).
   - *Biện pháp:* Nêu rõ trong `docs/ARCHITECTURE.md` và Slide 18 rằng mô hình PSK được chọn lọc cho môi trường lab nội bộ; giải pháp mTLS là hướng mở rộng tương lai.
3. **Bắt tiến trình đoản mệnh bằng eBPF:**
   - *Quyết định:* Giữ nguyên cơ chế quét `/proc` qua `psutil`.
   - *Biện pháp:* Trình bày rõ ràng giới hạn kỹ thuật của Polling và đưa eBPF vào lộ trình phát triển tương lai trong Slide báo cáo bảo vệ.
4. **Hàng đợi bất đồng bộ Celery / Redis:**
   - *Quyết định:* Giữ nguyên xử lý đồng bộ trong Flask và SQLite WAL mode, đảm bảo hệ thống có thể chạy ngay lập tức bằng `python3 -m server.app` mà không cần cài đặt các daemon bên ngoài.

---

## 4. TÁCH BIỆT KẾT QUẢ KIỂM THỬ (AUTOMATED SUITE VS EMPIRICAL PROBES)

Nhằm bảo đảm tính minh bạch tuyệt đối, tránh nhầm lẫn giữa kết quả của bộ test có sẵn và các bài probe phát hiện lỗ hổng của kiểm toán viên:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. AUTOMATED TEST REGRESSION SUITE (Hệ thống test có sẵn trong repo):       │
│    - Tổng số test: 214 bài test                                             │
│    - Kết quả thực tế: 214 PASSED (100%) trong 12.07s                        │
│    - Nhận xét: Toàn bộ code logic, routing, DAL, DB migration, collectors    │
│      hoạt động hoàn hảo theo đúng các kịch bản đã viết test.                │
├─────────────────────────────────────────────────────────────────────────────┤
│ 2. INDEPENDENT EMPIRICAL AUDIT PROBES (Các bài test thực nghiệm do Auditor):│
│    - Tổng số probe thực nghiệm: 8 kịch bản nâng cao                         │
│    - Probe 1 (DOM XSS in viewEvidence): CONFIRMED VULNERABLE                │
│    - Probe 2 (Attribute Breakout XSS): CONFIRMED VULNERABLE                 │
│    - Probe 3 (Missing SECRET_KEY crash on form): CONFIRMED CRASH            │
│    - Probe 4 (64KB Payload Limit Drop): CONFIRMED PAYLOAD DROP              │
│    - Probe 5 (Resolved Alert Recurrence Lock): CONFIRMED LOGIC FLAW         │
│    - Probe 6 (FIM Event Loss on Network Drop): CONFIRMED EVENT LOSS         │
│    - Probe 7 (Missing cmdline in Collector): CONFIRMED ATTRIBUTE ABSENT     │
│    - Probe 8 (Air-gapped Compliance Check): CONFIRMED 100% AIR-GAPPED PASS  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. ÁNH XẠ KẾ HOẠCH HÀNH ĐỘNG VÀ REGRESSION TESTS CHO CÁC GIAI ĐOẠN TIẾP THEO

| Giai đoạn Kế tiếp | Mục tiêu Cốt lõi | Danh sách Finding Xử lý | File Mã nguồn Thay đổi | Kịch bản Regression Test Bắt buộc |
| :--- | :--- | :--- | :--- | :--- |
| **Giai đoạn B: Security** | Khắc phục triệt để XSS, thiếu Secret Key, bổ sung Auth & CSRF cho Web Console | `FINDING-PHASE07-01`<br>`FINDING-PHASE07-02`<br>`FINDING-PHASE01-01`<br>`FINDING-PHASE01-02`<br>`FINDING-PHASE06-01`<br>`FINDING-PHASE07-03`<br>`FINDING-PHASE07-04`<br>`FINDING-PHASE08-01`<br>`FINDING-PHASE08-02` | `static/dashboard.js`<br>`templates/alerts.html`<br>`templates/dashboard.html`<br>`templates/base.html`<br>`server/app.py`<br>`server/web.py` | 1. Test tiêm `<script>` và `<img onerror>` vào `viewEvidence` không kích hoạt DOM XSS.<br>2. Test tiêu đề alert có dấu nháy đơn `'` không gây vỡ attribute `onclick`.<br>3. Test gửi Form POST không bị lỗi thiếu secret key.<br>4. Test truy cập Web Console bắt buộc phiên làm việc an toàn.<br>5. Chạy lại 214 tests có sẵn. |
| **Giai đoạn C: Data Integrity** | Khắc phục mất event FIM, tăng dung lượng payload, mở lại cảnh báo Resolved, chống tụt severity | `FINDING-PHASE04-01`<br>`FINDING-PHASE03-01`<br>`FINDING-PHASE02-01`<br>`FINDING-PHASE06-02`<br>`FINDING-PHASE06-03`<br>`FINDING-PHASE01-04`<br>`FINDING-PHASE03-03`<br>`FINDING-PHASE03-04`<br>`FINDING-PHASE04-03` | `server/app.py`<br>`agent/main.py`<br>`agent/file_integrity.py`<br>`server/repositories/alert_repository.py`<br>`server/repositories/endpoint_repository.py`<br>`server/repositories/baseline_repository.py` | 1. Test gửi baseline 104KB (500+ tệp) thành công HTTP 200.<br>2. Test mô phỏng ngắt mạng khi gửi FIM: Agent giữ baseline cũ và gửi lại sau khi mạng hồi phục.<br>3. Test cảnh báo đã Resolved tự động mở lại (`new`) khi nhận event cùng key.<br>4. Test không tụt severity từ Critical xuống Medium.<br>5. Chạy lại toàn bộ test suite. |
| **Giai đoạn D: Detection Engine** | Bổ sung rule FIM dropped binary, chuẩn hóa Rule ID và dọn dẹp dead parameter | `FINDING-PHASE05-01`<br>`FINDING-PHASE05-02`<br>`FINDING-PHASE05-04`<br>`FINDING-PHASE05-05`<br>`DISCREPANCY-DOC-03`<br>`DISCREPANCY-DOC-06` | `detection/rules.py`<br>`detection/engine.py`<br>`tests/test_detection.py` | 1. Test tệp binary thả vào `/tmp` kích hoạt rule `rule-fim-dropped-binary`.<br>2. Test chuỗi tương quan FIM drop + Process execution đạt Risk Score $\ge 90$ (Critical).<br>3. Test toàn bộ các rule ID khớp chuẩn.<br>4. Chạy lại `tests/test_detection.py`. |
| **Giai đoạn E: Python Code Quality** | Kiểm tra toàn bộ type hints, docstrings, exception handling, logging và dọn dead code | `FINDING-PHASE01-05`<br>Code Quality Review | Toàn bộ codebase `server/`, `agent/`, `detection/` | 1. Kiểm tra không có circular imports.<br>2. Kiểm tra đóng mở kết nối SQLite đúng chuẩn.<br>3. Chạy flake8/ruff/mypy nếu có.<br>4. Chạy toàn bộ 214 tests. |
| **Giai đoạn F: Full Regression** | Chạy kiểm thử hồi quy toàn diện, E2E và tính toàn vẹn SQLite | Toàn bộ hệ thống | Toàn bộ | 1. Chạy full `pytest -v`.<br>2. Chạy `simulate_attack_scenario.py`.<br>3. Chạy `PRAGMA integrity_check`. |
| **Giai đoạn G: Documentation** | Đồng bộ hóa 100% tài liệu kỹ thuật, sửa lệnh chạy Agent, xóa quảng cáo `cmdline` | `DISCREPANCY-DOC-01`<br>`DISCREPANCY-DOC-02`<br>`DISCREPANCY-DOC-04`<br>`DISCREPANCY-DOC-05` | `README.md`<br>`docs/ARCHITECTURE.md`<br>`docs/DATA_CONTRACT.md`<br>`docs/API_SPECIFICATION.md`<br>`docs/TEST_PLAN.md`<br>`docs/DEMO_SCENARIO.md`<br>`docs/PRESENTATION_SLIDES_OUTLINE.md` | 1. Kiểm tra lệnh `python3 -m agent.main` chạy mượt mà theo README.<br>2. Kiểm tra toàn bộ slide và docs không còn mâu thuẫn. |

---

## 6. KẾT LUẬN GIAI ĐOẠN A & ĐỀ XUẤT HÀNH ĐỘNG TIẾP THEO

Giai đoạn A (Post-Audit Review) đã hoàn tất việc rà soát, phân loại và lập đặc tả kỹ thuật chi tiết cho toàn bộ 36 phát hiện. Kế hoạch khắc phục đảm bảo tuân thủ nghiêm ngặt nguyên tắc **Scope Lock**, giữ vững bản sắc một đồ án môn học Python xuất sắc, an toàn, ổn định và tự tin bảo vệ trước Hội đồng.

**Trạng thái hiện tại:** Sẵn sàng chuyển sang **GIAI ĐOẠN B — SECURITY REMEDIATION**.
Kính xin Chủ dự án phê duyệt kế hoạch trên để bắt đầu tiến hành Giai đoạn B!
