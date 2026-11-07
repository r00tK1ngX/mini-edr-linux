# MINI EDR LINUX — TÀI LIỆU CÂU HỎI & TRẢ LỜI BẢO VỆ ĐỒ ÁN
**Academic Defense Question & Answer Guide — Linux Endpoint Detection and Response**

- **Đề tài:** Xây dựng hệ thống Mini EDR (Endpoint Detection and Response) trên Linux
- **Sinh viên thực hiện:** r00tK1ngX
- **Đối tượng sử dụng:** Chuẩn bị bảo vệ trước Hội đồng Chấm thi / Giảng viên Phản biện
- **Mục tiêu:** Cung cấp câu trả lời chuyên sâu, chuẩn xác về mặt kỹ thuật (Deep-dive), có căn cứ thực nghiệm và bảo vệ thành công các quyết định thiết kế kiến trúc của đề tài.

---

## 📑 MỤC LỤC CÁC CÂU HỎI TRỌNG TÂM

1. [Q1: Tại sao đồ án không sử dụng eBPF (Extended Berkeley Packet Filter) mà lại dùng User-space Polling qua `/proc`?](#q1-tại-sao-đồ-án-không-sử-dụng-ebpf-mà-lại-dùng-user-space-polling-qua-proc)
2. [Q2: Tại sao lại chọn cơ sở dữ liệu SQLite (WAL mode) thay vì PostgreSQL hay MySQL?](#q2-tại-sao-lại-chọn-cơ-sở-dữ-liệu-sqlite-wal-mode-thay-vì-postgresql-hay-mysql)
3. [Q3: Hệ thống xử lý Race Condition, Lỗi mạng và Trùng lặp Dữ liệu (Idempotency) như thế nào?](#q3-hệ-thống-xử-lý-race-condition-lỗi-mạng-và-trùng-lặp-dữ-liệu-idempotency-như-thế-nào)
4. [Q4: Phân hệ FIM phòng thủ trước tấn công Symlink Traversal và TOCTOU (Time-of-Check to Time-of-Use) ra sao?](#q4-phân-hệ-fim-phòng-thủ-trước-tấn-công-symlink-traversal-và-toctou-ra-sao)
5. [Q5: Đánh giá tỷ lệ Dương tính giả (False Positive) và Âm tính giả (False Negative) của Động cơ Phát hiện?](#q5-đánh-giá-tỷ-lệ-dương-tính-giả-false-positive-và-âm-tính-giả-false-negative-của-động-cơ-phát-hiện)
6. [Q6: Tại sao hệ thống chủ động KHÔNG thu thập toàn bộ `cmdline` hoặc biến môi trường `environ` của tiến trình?](#q6-tại-sao-hệ-thống-chủ-động-không-thu-thập-toàn-bộ-cmdline-hoặc-biến-môi-trường-environ-của-tiến-trình)
7. [Q7: Cơ chế Local Event Spool hoạt động như thế nào khi Agent bị mất mạng hoặc bị tắt đột ngột (SIGKILL)?](#q7-cơ-chế-local-event-spool-hoạt-động-như-thế-nào-khi-agent-bị-mất-mạng-hoặc-bị-tắt-đột-ngột-sigkill)
8. [Q8: Tại sao hệ thống không tự động diệt tiến trình (Auto Kill Process) hay tự động cô lập tệp độc hại?](#q8-tại-sao-hệ-thống-không-tự-động-diệt-tiến-trình-auto-kill-process-hay-tự-động-cô-lập-tệp-độc-hại)

---

## NỘI DUNG GIẢI TRÌNH CHI TIẾT

### Q1: Tại sao đồ án không sử dụng eBPF mà lại dùng User-space Polling qua `/proc`?

**Trả lời:**
Quyết định không sử dụng eBPF và lựa chọn User-space Polling là một **quyết định thiết kế có tính toán (Architectural Trade-off)** dựa trên 4 yếu tố cốt lõi:

1. **Khả năng Tương thích và Độc lập Môi trường (Portability & Zero Dependencies):**
   - eBPF đòi hỏi Linux Kernel phiên bản mới ($\ge 5.8$ cho BTF/CO-RE), yêu cầu cài đặt gói `linux-headers`, trình biên dịch `clang`/`llvm`, và thư viện `libbpf` hoặc `bcc`.
   - Trong môi trường đánh giá học thuật, đồ án cần chạy được ngay lập tức trên bất kỳ bản phân phối Linux nào (Ubuntu 20.04/22.04/24.04, Debian 11/12, Kali Linux, Alpine) dưới dạng **Pure Python**, không phụ thuộc vào C-extension hay kernel compilation.
2. **Nguyên tắc Đặc quyền Tối thiểu (Principle of Least Privilege):**
   - eBPF yêu cầu quyền `CAP_SYS_ADMIN` hoặc `CAP_BPF` và quyền `root` tuyệt đối để nạp bytecode vào không gian kernel.
   - Agent của Mini EDR được thiết kế để có thể thu thập tiến trình và thông số hệ thống dưới quyền người dùng thông thường không cần root cho các tác vụ chuẩn, giảm thiểu rủi ro biến chính EDR Agent thành bề mặt tấn công leo thang đặc quyền.
3. **An toàn Hệ thống (System Stability):**
   - Một lỗi lập trình trong eBPF probe hoặc kernel panic có thể làm sập toàn bộ hệ điều hành của máy trạm. Trái lại, User-space Agent nếu gặp lỗi chỉ dừng tiến trình người dùng mà không bao giờ ảnh hưởng tới độ ổn định của Linux kernel.
4. **Giới hạn Thừa nhận (Acknowledged Boundary):**
   - Hệ thống ghi nhận rõ ràng giới hạn kỹ thuật: Polling qua `/proc` có chu kỳ (10 giây) sẽ có "điểm mù" (blind spot) đối với các tiến trình tồn tại siêu ngắn ($<10$s). Đồ án tập trung vào tính đúng đắn, minh bạch của dữ liệu và quy trình phân tích tương quan trong phạm vi môn học thay vì cạnh tranh với các giải pháp Enterprise EDR cấp thương mại.

---

### Q2: Tại sao lại chọn cơ sở dữ liệu SQLite (WAL mode) thay vì PostgreSQL hay MySQL?

**Trả lời:**
Lựa chọn SQLite kết hợp chế độ **WAL (Write-Ahead Logging)** được tối ưu hóa cho mục tiêu học thuật và tự đóng gói (Self-contained):

1. **Đóng gói Trọn vẹn (Zero Operational Overhead):**
   - Đồ án có thể được đóng gói nguyên khối, sao chép sang máy của Hội đồng hoặc máy ảo của sinh viên và khởi chạy tức thì bằng lệnh `python -m server.app` mà không cần cài đặt, cấu hình user/password, mở port mạng hay khởi động dịch vụ PostgreSQL daemon.
2. **Khả năng Xử lý Đồng thời với WAL Mode (Single-Writer, Multiple-Reader):**
   - SQLite ở chế độ truyền thống (Rollback Journal) khóa toàn bộ tệp database khi có lệnh ghi.
   - Khi kích hoạt `PRAGMA journal_mode = WAL`, SQLite cho phép **các tiến trình đọc (Web Dashboard, Alert Query) thực thi đồng thời 100% với tiến trình ghi (Telemetry Ingestion)** mà không bị tranh chấp (No lock contention).
3. **Tính Toàn vẹn Dữ liệu Chuẩn ACID:**
   - Hệ thống thiết lập `PRAGMA foreign_keys = ON;` và `PRAGMA busy_timeout = 10000;`.
   - Toàn bộ thao tác ghi quan sát tiến trình, sự kiện an ninh và cảnh báo đều được bọc trong ngữ cảnh giao dịch `with conn:` đảm bảo Rollback nguyên tử khi có ngoại lệ, vượt qua các kiểm tra `PRAGMA integrity_check` và `PRAGMA foreign_key_check`.
4. **Cơ chế Thu gom Dữ liệu Quá hạn (TTL Retention Pruning):**
   - Để ngăn database phình to không giới hạn, phân hệ `server/maintenance.py` cung cấp hàm `prune_telemetry(retention_days=7)` kết hợp `ON DELETE CASCADE` tự động giải phóng bản ghi quan sát cũ.

---

### Q3: Hệ thống xử lý Race Condition, Lỗi mạng và Trùng lặp Dữ liệu (Idempotency) như thế nào?

**Trả lời:**
Mini EDR Linux giải quyết triệt để vấn đề trùng lặp và xung đột dữ liệu bằng cơ chế **Canonical JSON SHA-256 Hashing (`FINDING-NEW-09`)**:

1. **Định danh Bản tin bằng UUIDv4 Duy nhất:**
   - Mỗi bản tin gửi từ Agent được gắn một `message_id` dạng UUID v4 ổn định. Nếu Agent gửi lại bản tin do timeout mạng, cùng `message_id` sẽ được tái sử dụng.
2. **Xác thực Nội dung Chuẩn tắc (Canonical JSON Hash):**
   - Máy chủ không chỉ kiểm tra `message_id` mà còn tính toán mã băm SHA-256 trên biểu diễn JSON chuẩn tắc (sắp xếp key alphabet và loại bỏ khoảng trắng dư thừa):
     ```python
     canonical_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))
     payload_hash = hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()
     ```
3. **Ngữ nghĩa Phản hồi HTTP Chuẩn RESTful:**
   - **Cùng `message_id` + Cùng `payload_hash`:** Máy chủ xác định đây là bản tin gửi lặp do mạng chậm $\to$ Trả về `200 OK` với `{"duplicate": true}` và không ghi đè dữ liệu.
   - **Cùng `message_id` + Khác `payload_hash`:** Máy chủ phát hiện xung đột dữ liệu bất thường $\to$ Trả về ngay lập tức `409 Conflict` (`"Conflict: message_id already exists with different payload"`).
4. **Chống tràn Giới hạn Biến SQLite (Chunking Bulk Queries):**
   - Khi đồng bộ số lượng tệp baseline lớn (>999 tệp), máy chủ phân đoạn thành từng nhóm 500 tham số (`chunk_size = 500`) để thực thi câu truy vấn `IN (...)`, loại trừ hoàn toàn lỗi `sqlite3.OperationalError: too many SQL variables`.

---

### Q4: Phân hệ FIM phòng thủ trước tấn công Symlink Traversal và TOCTOU ra sao?

**Trả lời:**
Tấn công **TOCTOU (Time-of-Check to Time-of-Use)** và **Symlink Traversal** là lỗ hổng kinh điển trong các hệ thống giám sát tệp tin: kẻ tấn công thay thế một tệp bình thường bằng liên kết tượng trưng trỏ tới `/etc/shadow` ngay giữa thời điểm kiểm tra và đọc tệp.

Mini EDR phòng thủ bằng kỹ thuật 3 lớp:

1. **Tiền kiểm tra `lstat`:** Sử dụng `os.lstat(norm_path)` thay vì `os.stat()`. `lstat` không giải quyết symlink mà kiểm tra trực tiếp inode của liên kết. Nếu phát hiện `stat.S_ISLNK(st.st_mode)`, Agent bỏ qua tệp ngay lập tức.
2. **Khóa mở tệp chống chuyển hướng (`O_NOFOLLOW | O_CLOEXEC`):**
   - Agent không dùng hàm `open()` thông thường mà sử dụng lời gọi hệ thống cấp thấp:
     ```python
     fd = os.open(norm_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
     ```
   - Cờ `os.O_NOFOLLOW` bắt buộc Linux kernel từ chối mở tệp (ném lỗi `OSError: [Errno 40] Too many levels of symbolic links`) nếu thành phần cuối cùng của đường dẫn là một symlink.
3. **Xác thực Descriptor qua `os.fstat(fd)`:**
   - Sau khi mở thành công file descriptor, hàm `os.fstat(fd)` được gọi trên chính `fd` đang mở để kiểm tra lại `stat.S_ISREG(st.st_mode)`. Bằng cách này, kẻ tấn công không thể hoán đổi tệp trên đĩa trong lúc tệp đang được đọc.

---

### Q5: Đánh giá tỷ lệ Dương tính giả (False Positive) và Âm tính giả (False Negative) của Động cơ Phát hiện?

**Trả lời:**
Đồ án tiếp cận bài toán phát hiện theo trường phái **Explainable Threat Detection (Phát hiện có thể giải thích được)** và định lượng ranh giới rõ ràng:

1. **Kiểm soát Dương tính giả (False Positives):**
   - Hệ thống không nâng độ nhạy của quy tắc chỉ để tạo ra nhiều cảnh báo ảo.
   - **Cơ chế Tương quan Đa sự kiện (Multi-Factor Correlation):** Một tiến trình chạy từ `/tmp` chưa đủ để nâng lên mức `CRITICAL`. Hệ thống yêu cầu kết hợp giữa sự kiện FIM (tệp nhị phân mới xuất hiện trong `/tmp`) và sự kiện tiến trình thực thi từ chính tệp đó trong khung thời gian trượt `time_window_seconds = 300s`.
   - **PID Reuse Resilience:** Kết hợp định danh tiến trình duy nhất `pid:process_name:start_time` để tránh việc tái sử dụng PID của Linux kernel làm sai lệch ngữ cảnh cảnh báo.
   - Tài liệu [`detection/RULE_REGISTRY.md`](file:///home/kali/Projects/mini-edr-linux/detection/RULE_REGISTRY.md) liệt kê rõ ràng các kịch bản FP dự kiến cho từng quy tắc (ví dụ: trình cài đặt tự giải nén trong `/tmp`, bảo trì SSH bởi quản trị viên).
2. **Thừa nhận về Âm tính giả (False Negatives):**
   - Hệ thống thừa nhận các kỹ thuật nâng cao nằm ngoài phạm vi User-space Polling: Memory-only injection (reflective DLL/ELF injection), Kernel rootkit, process hollowing hoặc mã độc thực thi trong thời gian $< 10$ giây giữa 2 chu kỳ quét.
   - Việc minh bạch ranh giới kỹ thuật thể hiện tư duy học thuật nghiêm túc, không đưa ra tuyên bố phóng đại về "khả năng ngăn chặn 100% mọi cuộc tấn công".

---

### Q6: Tại sao hệ thống chủ động KHÔNG thu thập toàn bộ `cmdline` hoặc biến môi trường `environ` của tiến trình?

**Trả lời:**
Đây là quyết định tuân thủ **Nguyên tắc Bảo mật theo Thiết kế (Privacy & Security by Design)**:

1. **Ngăn ngừa Rò rỉ Dữ liệu Nhạy cảm (Credential Leakage):**
   - Trên Linux, người dùng hoặc script quản trị thường xuyên truyền mật khẩu, token API, hoặc database connection string trực tiếp qua command line (ví dụ: `mysql -u root -pMySecretPassword`, `curl -H "Authorization: Bearer my-api-token"`).
   - Biến môi trường (`/proc/<pid>/environ`) chứa các biến như `AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`.
   - Nếu EDR Agent thu thập toàn bộ `cmdline` và `environ` gửi về Server lưu vào SQLite, chính máy chủ EDR sẽ trở thành "mỏ vàng" để kẻ tấn công khai thác đánh cắp thông tin đăng nhập.
2. **Bộ 9 Thuộc tính Cốt lõi Đủ cho Nhận diện:**
   - Hệ thống tiêu chuẩn hóa 9 thuộc tính: `pid`, `ppid`, `process_name`, `parent_name`, `username`, `exe_path`, `cpu_percent`, `memory_percent`, `rss_bytes`, `process_started_at`.
   - Dữ liệu này hoàn toàn đủ để nhận diện các hành vi nguy hiểm (đường dẫn bất thường `/tmp/nc`, shell sinh từ web server `apache2` $\to$ `sh`, chiếm dụng CPU 99%) mà vẫn bảo vệ tuyệt đối bí mật của người dùng.

---

### Q7: Cơ chế Local Event Spool hoạt động như thế nào khi Agent bị mất mạng hoặc bị tắt đột ngột (SIGKILL)?

**Trả lời:**
Để giải quyết bài toán mất mát sự kiện an ninh khi mạng gặp sự cố hoặc Agent bị crash, phân hệ [`agent/spool.py`](file:///home/kali/Projects/mini-edr-linux/agent/spool.py) được xây dựng theo mô hình **Store-and-Forward**:

1. **Hàng đợi SQLite Cục bộ Bền vững (`fim_spool`):**
   - Mọi sự kiện biến động tệp tin FIM trước khi gửi qua mạng đều được ghi nhận bền vững vào cơ sở dữ liệu SQLite cục bộ trên máy trạm với trạng thái `status = 'pending'`.
2. **Khôi phục Nguyên vẹn sau Sự cố Crash (SIGKILL Resilient):**
   - Khi Agent bị tắt đột ngột bằng `kill -9` hoặc máy trạm mất điện, dữ liệu trong tệp SQLite cục bộ vẫn được bảo toàn nhờ cơ chế WAL journal. Khi Agent khởi động lại, Orchestrator tự động quét hàng đợi spool và tiếp tục gửi các sự kiện còn tồn đọng.
3. **Xác nhận Hai pha & Thoát Hàng đợi (Draining & Acknowledgment):**
   - Sau khi máy chủ phản hồi `201 Created` kèm `message_id`, Agent mới đánh dấu bản tin là `acknowledged`.
4. **Kiểm soát Dung lượng & Chính sách FIFO Drop:**
   - Hàng đợi có dung lượng giới hạn `DEFAULT_MAX_SPOOL_EVENTS = 1000`. Khi chạm trần, Agent tự động thanh lọc các sự kiện đã xác nhận. Nếu mạng mất kéo dài và hàng đợi pending đầy, chính sách FIFO drop sẽ loại bỏ bản ghi pending cũ nhất để ngăn chặn hành vi làm cạn kiệt ổ đĩa trên endpoint.

---

### Q8: Tại sao hệ thống không tự động diệt tiến trình (Auto Kill Process) hay tự động cô lập tệp độc hại?

**Trả lời:**
Quyết định này phục vụ tính an toàn học thuật và triết lý vận hành chuẩn SOC:

1. **An toàn Tuyệt đối cho Môi trường Đánh giá (Safety First):**
   - Trong buổi bảo vệ đồ án, phần mềm EDR sẽ được cài đặt trực tiếp trên máy của Hội đồng hoặc máy lab. Cơ chế tự động kill process nếu kích hoạt sai (False Positive) có thể vô tình tắt tiến trình hệ thống, trình duyệt hoặc môi trường demo của thầy cô.
2. **Triết lý EDR — Con người là Trung tâm Quyết định (Human-in-the-Loop):**
   - Mục tiêu của hệ thống EDR là cung cấp cho Chuyên viên Phân tích An ninh (SOC Analyst) thông tin chi tiết, bằng chứng có thể giải thích được và đề xuất khuyến nghị xử lý.
   - Quản trị viên sử dụng giao diện Cyberpunk Web Dashboard để xem bằng chứng JSON (`EVIDENCE`), tiếp nhận sự cố (`ACK`) và hoàn tất khắc phục (`RESOLVE`) kèm ghi chú kiểm toán rõ ràng.
