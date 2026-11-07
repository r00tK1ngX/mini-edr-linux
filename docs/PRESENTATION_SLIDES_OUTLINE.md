# Mini EDR Linux — Đề cương Slide Bảo vệ Đồ án Tốt nghiệp (Presentation Outline)

**Đề tài:** Xây dựng Hệ thống Giám sát và Phát hiện Hành vi Đáng ngờ trên Máy tính Linux (Mini EDR for Linux)  
**Tác giả:** r00tK1ngX  
**Thời lượng trình bày:** 15 – 20 phút (Bao gồm 5–7 phút Live Demo)  
**Cấu trúc bài thuyết trình:** 13 Slides Học thuật Chuẩn mực

---

### SLIDE 1: Trang Tiêu đề & Thông tin Chung
* **Tiêu đề đề tài:** Xây dựng Hệ thống Giám sát và Phát hiện Hành vi Đáng ngờ trên Máy tính Linux (Mini EDR for Linux)
* **Người thực hiện:** r00tK1ngX
* **Giảng viên hướng dẫn:** [Tên Giảng viên Hướng dẫn]
* **Công nghệ chủ đạo:** Python 3.10+, Flask, SQLite WAL, Vanilla JavaScript ES6+, Linux `/proc`, Cryptography SHA-256.
* **Mã nguồn:** `r00tK1ngX/mini-edr-linux`

---

### SLIDE 2: Đặt vấn đề & Bối cảnh Nghiên cứu
* **Bối cảnh An ninh:**
  * Linux chiếm ưu thế tuyệt đối trong hạ tầng máy chủ, đám mây và thiết bị IoT.
  * Các cuộc tấn công nhắm vào Linux ngày càng gia tăng (Reverse shells, Cryptomining, can thiệp cấu hình nhạy cảm `/etc/shadow`, leo thang đặc quyền).
* **Khoảng trống Giải pháp:**
  * Các giải pháp Enterprise EDR (CrowdStrike, SentinelOne) quá nặng nề, mã nguồn đóng, chi phí cao và khó triển khai trong môi trường phòng thí nghiệm/nghiên cứu.
  * Nhu cầu cấp thiết về một giải pháp Mini EDR bằng ngôn ngữ Python: gọn nhẹ, giải thích được (explainable), chuẩn học thuật, độc lập mạng (Air-gapped ready) và dễ kiểm chứng.

---

### SLIDE 3: Mục tiêu Nghiên cứu & Khóa Phạm vi (Scope Lock)
* **Mục tiêu Trọng tâm:**
  1. Xây dựng Agent giám sát Linux độc lập, tiêu thụ tài nguyên tối thiểu.
  2. Triển khai FIM (File Integrity Monitoring) sử dụng hàm băm mật mã học SHA-256.
  3. Xây dựng Detection Engine phát hiện mối nguy theo thời gian thực và ánh xạ khung MITRE ATT&CK.
  4. Thiết kế Cyberpunk Web Dashboard trực quan hóa trạng thái hạm đội và hỗ trợ quy trình xử lý sự cố chuẩn SOC.
* **Nguyên tắc Khóa Phạm vi (Scope Lock):**
  * Ưu tiên tính đúng đắn, an toàn và độ tin cậy của mã nguồn Python.
  * Không bổ sung các thành phần ngoài phạm vi đồ án môn học (Không eBPF, không ML hộp đen, không PostgreSQL/Redis/Celery/Kubernetes).
  * Không tự động tiêu diệt tiến trình (`kill -9`) để bảo đảm an toàn hệ thống máy chấm thi.

---

### SLIDE 4: Kiến trúc Tổng quan Hệ thống (System Architecture)
* **Mô hình Client-Server Phân tán 4 Tầng:**
  1. **Tầng Thu thập (Linux Agent):** System Collector, Process Collector, File Integrity Monitor.
  2. **Tầng API Gateway & An ninh:** Bearer Token Guard, Schema Validator, Payload Limiter (16 MiB), UUIDv4 Idempotency.
  3. **Tầng Động cơ Phát hiện & DAL:** Detection Engine (7 Rules MITRE ATT&CK), Correlation Engine (Ngưỡng $\ge 60$), Data Access Layer (100% Parameterized SQL).
  4. **Tầng Lưu trữ & Giao diện:** SQLite 3 (Chế độ WAL, khóa ngoại BẬT), Cyberpunk SOC Command Center (Session Auth & CSRF Protection).
* **Đặc tả luồng dữ liệu:** Sơ đồ trao đổi bản tin chuẩn Common Telemetry Envelope 1.0.

---

### SLIDE 5: Phân hệ Linux Agent & Kỹ thuật Thu thập Dữ liệu
* **Thu thập Thông số Hệ thống:** Đo lường CPU, RAM, Disk và Uptime với cơ chế xử lý lỗi phân quyền an toàn (Fail-soft).
* **Thu thập Bảng Tiến trình Linux:**
  * Quét `/proc` định kỳ trích xuất 9 thuộc tính cốt lõi: PID, PPID, process name, username, exe path, cmdline, cpu%, mem%, rss_bytes, started_at.
  * Xử lý ngoại lệ Linux kernel: `NoSuchProcess`, `AccessDenied`, `ZombieProcess`.
* **Giám sát Toàn vẹn Tệp tin (FIM):**
  * Băm SHA-256 trên các tệp cấu hình hệ thống nhạy cảm.
  * **Cơ chế Two-Phase Commit:** Tách biệt `scan_for_changes` và `commit_baseline`; chỉ cập nhật baseline khi Server tiếp nhận thành công, chống mất dữ liệu khi rớt mạng.
  * **Chống Symlink Traversal (TOCTOU):** Dùng `os.lstat()` và kiểm tra cờ `stat.S_ISLNK()` trước khi đọc tệp.

---

### SLIDE 6: Động cơ Phát hiện & Tương quan Sự kiện (Detection Engine)
* **Danh mục 7 Quy tắc An ninh Ánh xạ MITRE ATT&CK:**
  1. `rule-proc-suspicious-path` (T1059.004): Tiến trình chạy từ `/tmp`, `/dev/shm` hoặc công cụ tấn công (`nc`, `nmap`).
  2. `rule-proc-shell-spawn` (T1059.004): Shell tương tác sinh ra từ web service daemon (`www-data`).
  3. `rule-proc-high-cpu` (T1496): Tiến trình chiếm dụng $\ge 85.0\%$ CPU kéo dài (Cryptomining).
  4. `rule-fim-sensitive-file` (T1003.008): Sửa đổi `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`.
  5. `rule-fim-dropped-binary` (T1105): Tệp thực thi ELF hoặc script mới thả vào thư mục tạm.
  6. `rule-fim-critical-deleted` (T1070.004): Xóa tệp hệ thống quan trọng.
  7. `rule-fim-service-tamper` (T1543.002): Thay đổi trái phép service unit `systemd`.
* **Phân tích Tương quan & Điểm Rủi ro (Risk Scoring):**
  * Khung thời gian trượt (Sliding Window = 300s).
  * Thực thi ngưỡng tương quan `min_correlation_score >= 60.0` để chặn cảnh báo giả/rác.

---

### SLIDE 7: Tính Toàn vẹn Dữ liệu & Lưu trữ Cơ sở Dữ liệu (SQLite)
* **Mô hình Dữ liệu 3NF:** 7 bảng quan hệ chuẩn hóa cao với khóa ngoại ràng buộc chặt chẽ.
* **Cơ chế SQLite WAL (Write-Ahead Logging):**
  * Cho phép đọc và ghi đồng thời mà không nghẽn cơ sở dữ liệu.
  * Cấu hình `PRAGMA busy_timeout = 10000` (10s) chống lỗi `database is locked`.
* **Bảo tồn Siêu dữ liệu Máy trạm:** Sử dụng câu lệnh `COALESCE` trong tầng DAL để giữ nguyên thông tin máy trạm khi nhận heartbeat định kỳ.
* **Bảo toàn Cấp độ Nghiêm trọng (Non-downgrade Severity):** Mức độ nghiêm trọng của cảnh báo không bao giờ bị hạ thấp khi có sự kiện mới gửi đến.
* **Alert Reopening:** Tự động mở lại cảnh báo về trạng thái `new` nếu sự cố tái diễn sau khi đã được đánh dấu `resolved`.

---

### SLIDE 8: An toàn Thông tin & Phòng thủ Chiều sâu (Security Hardening)
* **Xác thực Đa tầng:**
  * Ingestion API: Bearer Token mật mã học $\ge 32$ ký tự, so khớp thời gian thực `hmac.compare_digest`.
  * Web Console: Đăng nhập phiên có chữ ký mã hóa (`SECRET_KEY`), bảo vệ bằng CSRF Token (`X-CSRF-Token`).
* **Phòng chống Tiêm mã SQL (SQL Injection):** 100% câu truy vấn sử dụng Parameterized SQL qua tầng DAL.
* **Phòng chống XSS (DOM & Stored):**
  * Khử khuẩn toàn diện bằng hàm `escapeHtml()` ở Client JavaScript.
  * Jinja2 Autoescape mặc định ở Backend.
  * Loại bỏ hoàn toàn các thuộc tính inline `onclick`, chuyển sang event delegation với dataset attributes.
* **Chống Tấn công DoS:** Cấu hình trần `EDR_MAX_CONTENT_LENGTH = 16 MiB`.

---

### SLIDE 9: Bảng Điều khiển Cyberpunk SOC & Quy trình Triage
* **Thiết kế Giao diện Cyberpunk Hacker:** Dark HUD theme, neon glowing, matrix grid, 100% không cần Internet (Air-gapped ready).
* **4 Màn hình Chức năng:**
  1. `/dashboard`: 4 Cyber KPI tiles, thanh đo tài nguyên thời gian thực, ma trận mức độ nghiêm trọng.
  2. `/endpoints`: Quản lý hạm đội máy trạm, tìm kiếm tức thì, modal INSPECT tiến trình và FIM.
  3. `/alerts`: Bảng điều khiển ứng cứu sự cố, modal xem Evidence JSON chi tiết.
  4. `/events`: Nhật ký kiểm toán an ninh toàn hệ thống.
* **Quy trình Xử lý Sự cố Chuẩn SOC:**
  `NEW` $\longrightarrow$ `ACKNOWLEDGED` $\longrightarrow$ `RESOLVED` (Kèm biên bản ghi chú và timestamp bất biến).

---

### SLIDE 10: Trình diễn Thực tế (Live Attack Simulation Demo)
* **Diễn tập Trực tiếp 5 Bước (5–7 Phút):**
  * **Bước 1:** Khởi động Agent, đăng ký `demo-workstation-01` Online trên Web Dashboard.
  * **Bước 2:** Thiết lập FIM Baseline cho tệp cấu hình bảo mật.
  * **Bước 3:** Hacker tấn công chèn `PERMIT_ROOT_LOGIN=yes` $\rightarrow$ FIM phát hiện, sinh cảnh báo `HIGH`.
  * **Bước 4:** Hacker mở Reverse Shell `/tmp/nc -lvnp 4444` $\rightarrow$ Detection Engine phân tích tương quan, sinh cảnh báo `CRITICAL` (Điểm rủi ro: 90/100).
  * **Bước 5:** SOC Analyst đăng nhập Web Console, mở modal Evidence, thực hiện ACK và RESOLVE không cần reload trang.

---

### SLIDE 11: Kết quả Đánh giá & Kiểm thử Tự động (Verification)
* **Kết quả Pytest Toàn diện:**
  * **230/230 ca kiểm thử PASSED (100% Pass rate)** trong thời gian **17.92 giây**.
  * Bao phủ 13 test suites từ Unit, Integration, E2E đến Security Probes.
* **Kiểm tra Tính Toàn vẹn SQLite:**
  * `PRAGMA integrity_check`: `ok`.
  * `PRAGMA foreign_key_check`: 0 vi phạm khóa ngoại.
* **Độ ổn định & Khả năng Chống chịu:**
  * Vượt qua 100% các vector tấn công SQL Injection và XSS.
  * Không phát sinh rò rỉ bộ nhớ hay deadlock kết nối database.

---

### SLIDE 12: Giới hạn Đề tài & Hướng Phát triển Tương lai
* **Giới hạn Đề tài (Trung thực Học thuật):**
  * Hoạt động tối ưu trong quy mô phòng lab (1 – 50 endpoints).
  * Phát hiện dựa trên quy tắc (Rule-based), chưa phân tích hành vi bất thường bằng Machine Learning.
  * Giám sát thông qua `/proc` có độ trễ chu kỳ, chưa chặn sự kiện tức thời ở tầng kernel.
* **Hướng Phát triển Mở rộng:**
  * Nâng cấp lên công nghệ **eBPF (Extended Berkeley Packet Filter)** để bắt các syscalls (`execve`, `connect`) với độ trễ microsecond.
  * Tích hợp giao thức gRPC hai chiều hỗ trợ phản ứng tự động (Cô lập máy trạm Host Isolation từ Web Console).
  * Mở rộng cơ sở dữ liệu phân tán (PostgreSQL/TimescaleDB) khi triển khai quy mô lớn.

---

### SLIDE 13: Kết luận & Phiên Hỏi - Đáp (Q&A)
* **Tổng kết Đóng góp:**
  * Xây dựng thành công một hệ thống Mini EDR hoàn chỉnh, tuân thủ nghiêm ngặt chuẩn mực kỹ thuật và bảo mật của một đồ án Python chất lượng cao.
  * Hệ thống hoạt động tin cậy, có thể tái lập, kiểm thử tự động 100% và sẵn sàng bảo vệ học thuật.
* **Lời cảm ơn:** Trân trọng cảm ơn Quý Thầy Cô trong Hội đồng Chấm thi và Giảng viên Hướng dẫn đã theo dõi và đóng góp ý kiến.
* **Q&A:** Sẵn sàng tiếp nhận câu hỏi và phản biện từ Hội đồng.
