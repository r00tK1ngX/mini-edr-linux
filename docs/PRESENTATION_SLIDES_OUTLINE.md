# Cấu trúc Slide Thuyết trình Báo cáo & Demo Đề tài Mini EDR Linux

**Tài liệu:** Khung Thiết kế Slide Thuyết minh Đồ án Tốt nghiệp / Báo cáo Nghiên cứu Kỹ thuật  
**Đề tài:** Xây dựng Giải pháp Mini Endpoint Detection and Response (EDR) cho Môi trường Linux  
**Số lượng Slide chuẩn:** 18 Trang (Phù hợp thời lượng trình bày 15--20 phút + 5--7 phút Demo)  
**Tác giả / Sinh viên thực hiện:** r00tK1ngX  

---

## Bố cục Tổng quan 5 Phần (Agenda)

- **Phần I: Bối cảnh, Mục tiêu & Phạm vi Đề tài** (Slide 1 -- 4)
- **Phần II: Kiến trúc Hệ thống & Thiết kế Kỹ thuật** (Slide 5 -- 9)
- **Phần III: Động cơ Phát hiện & Cơ chế Quản lý Sự cố** (Slide 10 -- 13)
- **Phần IV: Gia cố Bảo mật & Kết quả Kiểm thử** (Slide 14 -- 15)
- **Phần V: Trình diễn Demo, Đánh giá & Hướng phát triển** (Slide 16 -- 18)

---

## Chi tiết Từng Slide Thuyết trình

---

### 🖥️ Slide 1: Trang Bìa (Title Slide)
- **Tiêu đề lớn:** HỆ THỐNG GIÁM SÁT VÀ PHÁT HIỆN MỐI ĐE DỌA ĐẦU CUỐI CHO MÔI TRƯỜNG LINUX (MINI EDR FOR LINUX)
- **Mục đích:** Giới thiệu tên đề tài, người thực hiện, giảng viên hướng dẫn và tạo ấn tượng ban đầu chuyên nghiệp.
- **Nội dung hiển thị:**
  - Tên đề tài: *Nghiên cứu, Thiết kế và Triển khai Hệ thống Mini Endpoint Detection and Response (EDR) trên Hệ điều hành Linux*.
  - Sinh viên thực hiện: `r00tK1ngX`.
  - Chuyên ngành: An toàn Thông tin / Công nghệ Phần mềm.
  - Ngày báo cáo: Tháng 11/2026.
  - Repository mã nguồn: `github.com/r00tK1ngX/mini-edr-linux`.
- **Gợi ý Trực quan / Bố cục:**
  - Tông màu nền tối (Dark mode / Cyberpunk: `#06090e`), logo trường học góc trái, logo dự án dạng khiên an ninh (Shield/Terminal) với viền Cyan phát sáng.
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Kính thưa quý Thầy Cô trong Hội đồng chấm đồ án tốt nghiệp và các bạn sinh viên có mặt hôm nay. Em tên là ..., hôm nay em xin phép được báo cáo kết quả nghiên cứu và triển khai đề tài: 'Xây dựng giải pháp Mini Endpoint Detection and Response (EDR) cho môi trường Linux'. Đề tài hướng tới việc xây dựng một hệ thống giám sát an ninh đầu cuối dạng mô-đun, gọn nhẹ, có khả năng phát hiện hành vi bất thường và hỗ trợ phản ứng sự cố theo thời gian thực."*

---

### 🎯 Slide 2: Đặt Vấn đề & Bối cảnh Thực tiễn (Problem Statement)
- **Tiêu đề:** BỐI CẢNH AN NINH MẠNG VÀ BÀI TOÁN GIÁM SÁT ĐẦU CUỐI LINUX
- **Mục đích:** Làm rõ lý do tại sao cần làm EDR trên Linux, những khoảng trống của giải pháp truyền thống.
- **Nội dung hiển thị:**
  - **Linux là xương sống của hạ tầng máy chủ & đám mây:** Hơn 90% cloud workloads và web servers chạy Linux.
  - **Mối đe dọa gia tăng mạnh mẽ:** Mã độc đào tiền ảo (cryptomining), backdoor reverse shell, khai thác leo thang đặc quyền (Privilege Escalation), can thiệp tệp tin cấu hình (`/etc/passwd`, `/etc/shadow`).
  - **Hạn chế của giải pháp truyền thống (Antivirus/Firewall):**
    - Antivirus dựa trên chữ ký tĩnh (Signature-based AV) dễ dàng bị vượt qua bởi obfuscation hoặc Living-off-the-Land Binaries (LOLBins).
    - Các giải pháp EDR thương mại (CrowdStrike, SentinelOne) thường quá nặng nề, mã nguồn đóng, chi phí bản quyền cực cao và không phù hợp môi trường học thuật/lab nội bộ.
  - **Nhu cầu cấp thiết:** Cần một giải pháp EDR gọn nhẹ, mã nguồn mở, hoạt động độc lập và minh bạch về cơ chế phát hiện (Explainable Detection).
- **Gợi ý Trực quan / Bố cục:**
  - Bố cục 2 cột đối chiếu: Cột trái "Thách thức An ninh trên Linux", Cột phải "Khoảng trống của Antivirus truyền thống vs Yêu cầu của EDR".
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Như quý Thầy Cô đã biết, Linux hiện chiếm lĩnh phần lớn hạ tầng máy chủ và điện toán đám mây. Tuy nhiên, các kỹ thuật tấn công hiện đại ngày nay ít khi dùng mã độc dạng file nhị phân truyền thống, mà chuyển sang lợi dụng các tiện ích sẵn có của hệ thống (LOLBins) như netcat, bash, curl để mở reverse shell, hoặc âm thầm sửa đổi các tệp tin cấu hình. Các phần mềm Antivirus truyền thống hầu như bất lực trước các hành vi này. Do đó, nhu cầu về một hệ thống EDR có khả năng giám sát hành vi tiến trình và tính toàn vẹn của tệp tin theo thời gian thực là vô cùng cấp thiết."*

---

### 🎯 Slide 3: Mục tiêu Đề tài & Phạm vi Nghiên cứu (Objectives & Scope)
- **Tiêu đề:** MỤC TIÊU VÀ PHẠM VI NGHIÊN CỨU
- **Mục đích:** Xác định rõ ràng những gì đề tài cam kết giải quyết và những gì nằm ngoài phạm vi để bảo vệ tính khả thi.
- **Nội dung hiển thị:**
  - **Mục tiêu nghiên cứu:**
    1. Thiết kế kiến trúc Client-Server mô-đun hóa, đảm bảo tính mở rộng và an toàn dữ liệu.
    2. Xây dựng Linux Agent chạy nền, thu thập telemetry hệ thống, tiến trình và toàn vẹn tệp (FIM).
    3. Xây dựng Detection Engine phát hiện theo quy tắc rõ ràng kết hợp tương quan đa sự kiện.
    4. Xây dựng SOC Dashboard hiện đại phục vụ quản trị và xử lý sự cố.
  - **Phạm vi & Giới hạn thiết kế:**
    - Hệ điều hành mục tiêu: Linux (Ubuntu, Debian, Kali Linux).
    - Cơ sở dữ liệu: SQLite cấu hình chuẩn công nghiệp (WAL mode, Foreign Keys ON).
    - Quy mô thử nghiệm: Mạng nội bộ từ 1 đến 50 endpoints.
    - **An toàn tuyệt đối cho Endpoint:** Phiên bản đồ án chủ động *không gửi lệnh kill tiến trình tự động từ xa*, chỉ giám sát và cảnh báo nhằm bảo vệ tính toàn vẹn của môi trường demo.
- **Gợi ý Trực quan / Bố cục:**
  - Bảng chia 2 phần: "Mục tiêu Kỹ thuật Đạt được" (xanh lá) và "Giới hạn Phạm vi Đồ án" (vàng cam).
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Để giải quyết bài toán trên, mục tiêu cốt lõi của đề tài là xây dựng một hệ thống Mini EDR hoàn chỉnh từ Agent, Server, Detection Engine cho tới SOC Dashboard. Để đảm bảo tính khả thi và an toàn tuyệt đối trong khuôn khổ đồ án, hệ thống tập trung vào môi trường Linux, sử dụng SQLite WAL mode cho hiệu năng cao và đặc biệt tuân thủ nguyên tắc an toàn: chỉ tập trung phát hiện, cảnh báo và hỗ trợ SOC phân tích chứ không tự ý can thiệp kill tiến trình của hệ thống."*

---

### 🏛️ Slide 4: 6 Trụ Cột Nền Tảng của Hệ thống (6 Core Pillars)
- **Tiêu đề:** 6 TRỤ CỘT CỐT LÕI CỦA MINI EDR LINUX
- **Mục đích:** Tóm tắt 6 phân hệ lớn theo đúng yêu cầu đề tài `doAnMiniEDR.txt`.
- **Nội dung hiển thị:**
  1. **Quản lý Thiết bị Đầu cuối (Endpoint Inventory):** Theo dõi trạng thái liveness (Online/Offline) theo nhịp tim Heartbeat.
  2. **Giám sát Tiến trình (Process Monitoring):** Trích xuất snapshot bảng `/proc` (PID, PPID, User, Path, CPU/RAM, RSS).
  3. **Giám sát Toàn vẹn Tệp (File Integrity Monitoring - FIM):** Theo dõi tệp nhạy cảm với mã băm **SHA-256** (phát hiện Created, Modified, Deleted).
  4. **Phát hiện Mối nguy (Suspicious Behavior Detection):** Quy tắc rõ ràng, phát hiện công cụ pentest, shell spawning và tính điểm rủi ro.
  5. **Quản lý Vòng đời Sự cố (Incident Management):** Quy trình chuẩn SOC (Acknowledge, Resolve, Dismiss) với máy trạng thái nghiêm ngặt.
  6. **Trực quan hóa Dữ liệu (SOC Dashboard):** Bảng điều khiển Cyberpunk Hacker, hiển thị 100% số liệu thực từ SQLite.
- **Gợi ý Trực quan / Bố cục:**
  - 6 khối hộp (Hexagon hoặc Cards) xếp thành 2 hàng 3 cột, có icon tương ứng cho từng trụ cột.
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Hệ thống Mini EDR được cấu thành từ 6 trụ cột cốt lõi: Quản lý hạm đội máy trạm theo chu kỳ heartbeat; Giám sát sâu tiến trình qua /proc; Giám sát toàn vẹn tệp bằng mật mã học SHA-256; Động cơ phân tích tương quan và tính điểm rủi ro; Quản lý vòng đời sự cố theo chuẩn máy trạng thái SOC; và cuối cùng là Giao diện điều hành trực quan độc lập không phụ thuộc Internet."*

---

### 🏗️ Slide 5: Kiến trúc Tổng thể Hệ thống (System Architecture)
- **Tiêu đề:** KIẾN TRÚC TỔNG THỂ HỆ THỐNG
- **Mục đích:** Trình diễn bức tranh kiến trúc phân tầng (Client-Server Architecture).
- **Nội dung hiển thị:**
  - **Linux Agent (Client):** Gồm 3 Collector (System, Process, FIM), Orchestrator loop và Agent HTTP Client.
  - **Giao thức Giao tiếp:** HTTP/JSON dựa trên chuẩn **Common Telemetry Envelope 1.0** (Bearer Token, UUIDv4 message_id chống replay).
  - **Flask API Server (Backend Gateway):** Xác thực Token, kiểm tra kích thước payload (64KB), Schema validator.
  - **Detection & Correlation Engine:** Rule Registry, Dynamic Risk Scoring, Alert Dispatcher.
  - **Data Access Layer (DAL):** 100% Parameterized SQL, cách ly nghiệp vụ khỏi database.
  - **SQLite3 Database Engine:** Chế độ WAL (Write-Ahead Logging), Foreign Keys enforcement.
  - **Web Dashboard:** Flask Blueprint + Jinja2 + Vanilla CSS/JS.
- **Gợi ý Trực quan / Bố cục:**
  - Đưa sơ đồ kiến trúc khối từ [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) lên slide với các đường mũi tên luồng dữ liệu phát sáng.
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Đây là sơ đồ kiến trúc tổng thể của hệ thống. Mô hình được chia làm 3 tầng rõ rệt: Tầng Client là Linux Agent chạy ngầm trên máy trạm; Tầng Trung tâm là Flask Server đảm nhận vai trò API Gateway, tích hợp Detection Engine và Tầng DAL; Tầng Lưu trữ là SQLite chạy ở chế độ WAL cho phép đọc ghi đồng thời mà không bị lock; và Tầng Trình diễn là Web Dashboard phục vụ chuyên viên SOC."*

---

### 🐧 Slide 6: Phân hệ Linux Agent (Linux Agent & Collectors)
- **Tiêu đề:** PHÂN HỆ LINUX AGENT & BỘ THU THẬP DỮ LIỆU
- **Mục đích:** Đi sâu vào kỹ thuật cài đặt Agent trên máy trạm Linux.
- **Nội dung hiển thị:**
  - **System Collector:** Thu thập thông số phần cứng tĩnh và động (CPU%, RAM%, Disk%, Uptime) qua thư viện chuẩn và `psutil`.
  - **Process Collector:**
    - Quét bảng tiến trình Linux qua hệ thống tệp ảo `/proc`.
    - Trích xuất 10 trường thông tin: `pid`, `ppid`, `name`, `username`, `exe_path`, `cmdline`, `cpu_percent`, `memory_percent`, `rss_bytes`, `started_at`.
    - Xử lý phân quyền an toàn: Bắt gọn các ngoại lệ `NoSuchProcess`, `AccessDenied`, `ZombieProcess` mà không làm dừng Agent.
  - **File Integrity Monitor (FIM):**
    - Quét đệ quy các thư mục được chỉ định (`/etc`, `/bin`, `/sbin`).
    - Tính toán mã băm SHA-256 (64 ký tự hex chữ thường).
    - So khớp với Baseline để phát hiện biến động: `created`, `modified`, `deleted`.
  - **Orchestrator Loop:** Điều phối chu kỳ quét độc lập (Heartbeat 10s, Telemetry 10s, FIM scan).
- **Gợi ý Trực quan / Bố cục:**
  - Sơ đồ các Collector hội tụ vào Orchestrator và đóng gói qua HTTP Client.
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Phân hệ Agent được thiết kế với tiêu chí gọn nhẹ và an toàn: Collector quét dữ liệu từ nhân /proc nhưng không yêu cầu quyền root tuyệt đối cho các tác vụ đo lường thông thường; FIM sử dụng mã băm SHA-256 để bảo đảm tính toàn vẹn; và Orchestrator điều phối các chu kỳ thu thập nhịp nhàng, có cơ chế bắt lỗi phân quyền an toàn để Agent không bao giờ bị crash đột ngột."*

---

### 📨 Slide 7: Hợp đồng Dữ liệu & Chuẩn Hóa Envelope (Data Contract)
- **Tiêu đề:** THIẾT KẾ DATA CONTRACT & COMMON TELEMETRY ENVELOPE
- **Mục đích:** Giải thích cách thức dữ liệu được chuẩn hóa và chống tấn công gửi lặp (Replay attack).
- **Nội dung hiển thị:**
  - **Common Telemetry Envelope 1.0:**
    ```json
    {
      "schema_version": "1.0",
      "message_id": "550e8400-e29b-41d4-a716-446655440000",
      "agent_id": "ubuntu-lab-01",
      "collected_at": "2026-11-05T12:00:00.000Z",
      "payload": { ... }
    }
    ```
  - **Đặc tả Trường:**
    - `schema_version`: Chặn cứng phiên bản không tương thích (chỉ chấp nhận `"1.0"`).
    - `message_id`: Mã UUIDv4 duy nhất cho mỗi bản tin logic, phục vụ khử trùng lặp (Idempotency).
    - `collected_at`: Mốc thời gian do Agent ghi nhận (ISO 8601 UTC).
    - `received_at`: Mốc thời gian do Server đóng dấu khi tiếp nhận (Server-owned timestamp).
  - **Cơ chế Idempotency:** Gửi lặp cùng `message_id` và cùng nội dung ➔ HTTP 200 (duplicate); cùng `message_id` nhưng nội dung khác ➔ HTTP 409 (conflict).
- **Gợi ý Trực quan / Bố cục:**
  - Hiển thị cấu trúc JSON envelope bên trái, bảng giải thích và luồng kiểm tra Idempotency bên phải.
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Để đảm bảo tính nhất quán giữa Client và Server, toàn bộ dữ liệu trao đổi được chuẩn hóa qua Common Telemetry Envelope 1.0. Mỗi bản tin bắt buộc phải có một UUIDv4 message_id duy nhất. Cơ chế này vừa giúp hệ thống chống lại tấn công phát lại (Replay Attack), vừa đảm bảo tính bất biến: nếu mạng chập chờn Agent gửi lại bản tin cũ, Server sẽ tự nhận diện và không bao giờ ghi trùng rác vào cơ sở dữ liệu."*

---

### 🗄️ Slide 8: Thiết kế Cơ sở Dữ liệu & Sơ đồ ERD (Database Schema & ERD)
- **Tiêu đề:** MÔ HÌNH DỮ LIỆU & QUAN HỆ TOÀN VẸN (ERD)
- **Mục đích:** Chứng minh tính toàn vẹn và chuẩn hóa của cơ sở dữ liệu SQLite.
- **Nội dung hiển thị:**
  - Hệ thống gồm **8 bảng dữ liệu** được thiết kế chuẩn 3NF:
    1. `endpoints`: Quản lý danh mục máy trạm, trạng thái Online/Offline và last seen.
    2. `system_metrics`: Lịch sử tài nguyên chuỗi thời gian (CPU, RAM, Disk, Uptime).
    3. `process_snapshots`: Nhật ký từng chu kỳ quét tiến trình của Agent.
    4. `process_observations`: Chi tiết từng tiến trình trong snapshot (khóa ghép `snapshot_id + pid`, quan hệ `ON DELETE CASCADE`).
    5. `file_baselines`: Trạng thái chuẩn của tệp (`present` hoặc `missing` để bảo toàn lịch sử điều tra).
    6. `security_events`: Kho dữ liệu sự kiện an ninh với fingerprint và bằng chứng JSON.
    7. `alerts`: Quản lý cảnh báo an ninh, khử trùng lặp qua `alert_key` duy nhất.
    8. `alert_events`: Bảng cầu nối quan hệ N - N giữa Alert và Security Events.
- **Gợi ý Trực quan / Bố cục:**
  - Đưa sơ đồ Mermaid ERD từ [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) lên slide, làm nổi bật các mối quan hệ khóa ngoại (FK) và cascade delete.
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Mô hình cơ sở dữ liệu của Mini EDR gồm 8 bảng có quan hệ chặt chẽ. Điểm đặc biệt trong thiết kế là: khi một tệp FIM bị xóa trên máy trạm, hệ thống không xóa bản ghi mà chuyển trạng thái sang missing để bảo toàn dấu vết mã băm phục vụ điều tra số (Forensics); và bảng cầu nối alert_events cho phép một cảnh báo có thể xâu chuỗi nhiều sự kiện an ninh liên quan."*

---

### ⚙️ Slide 9: Data Access Layer & Migration Framework (DAL & DB Engine)
- **Tiêu đề:** TẦNG TRUY CẬP DỮ LIỆU (DAL) & MIGRATION TỰ ĐỘNG
- **Mục đích:** Nhấn mạnh tính chuyên nghiệp trong thiết kế phần mềm và độ an toàn của dữ liệu.
- **Nội dung hiển thị:**
  - **Kiến trúc Data Access Layer (DAL):**
    - Cách ly hoàn toàn mã SQL khỏi route logic thông qua các Repository (`EndpointRepo`, `ProcessRepo`, `AlertRepo`...).
    - **100% Parameterized Queries:** Sử dụng tham số hóa (`?`), tuyệt đối cấm nối chuỗi SQL.
    - Context Manager tự động quản lý transaction (commit khi thành công, tự động rollback khi có lỗi).
  - **SQLite3 Cấu hình Chuẩn Công nghiệp:**
    - Bật chế độ `PRAGMA journal_mode = WAL` (Write-Ahead Logging) cho phép đọc ghi đồng thời cực nhanh.
    - Bật `PRAGMA foreign_keys = ON` thực thi ràng buộc toàn vẹn quan hệ.
    - Thiết lập `busy_timeout = 5000ms` chống nghẽn khóa database.
  - **Migration Framework:**
    - Tự động quét và thực thi các file migration `.sql` theo thứ tự phiên bản.
    - Quản lý mã băm SHA-256 của từng migration file trong bảng `schema_migrations`, phát hiện ngay hành vi sửa đổi trái phép cấu trúc database.
- **Gợi ý Trực quan / Bố cục:**
  - Biểu đồ luồng: Route ➔ DAL Repository ➔ SQLite WAL Database.
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Để đảm bảo tính độc lập và an toàn tuyệt đối, hệ thống xây dựng tầng Data Access Layer riêng biệt. 100% truy vấn đều được tham số hóa ngăn chặn triệt để lỗ hổng SQL Injection. SQLite được tối ưu với chế độ WAL cho phép Dashboard vừa truy vấn dữ liệu vừa tiếp nhận hàng chục nghìn metrics từ Agent mà không bị nghẽn; kèm theo Migration runner tự động kiểm tra checksum SHA-256 của từng script schema."*

---

### 🧠 Slide 10: Động cơ Phát hiện Quy tắc (Explainable Detection Rules)
- **Tiêu đề:** ĐỘNG CƠ PHÁT HIỆN: CÁC QUY TẮC GIẢI THÍCH ĐƯỢC
- **Mục đích:** Trình bày danh mục các quy tắc phát hiện mối đe dọa rõ ràng (không phải hộp đen).
- **Nội dung hiển thị:**
  - **Triết lý thiết kế:** Explainable Rules --- Mọi cảnh báo sinh ra đều chỉ rõ lý do, tiến trình, đường dẫn và bằng chứng cụ thể.
  - **Danh mục Quy tắc Cốt lõi:**
    1. `RULE_SUSPICIOUS_PROCESS` (**CRITICAL**):
       - Phát hiện các công cụ pentest/hack điển hình: `nc`, `netcat`, `nmap`, `mimikatz`, `socat`, `chisel`...
       - Phát hiện binary thực thi từ thư mục tạm bất thường: `/tmp`, `/dev/shm`.
    2. `RULE_SHELL_SPAWN` (**HIGH**):
       - Phát hiện shell tương tác (`bash`, `sh`, `zsh`) được sinh ra từ các tiến trình web server (`apache2`, `nginx`) hoặc môi trường runtime (`python`, `php`) --- Dấu hiệu điển hình của Web Shell / RCE.
    3. `RULE_HIGH_CPU_PROCESS` (**MEDIUM**):
       - Phát hiện tiến trình chiếm dụng $> 85\%$ CPU liên tục (Dấu hiệu Cryptomining hoặc DoS).
    4. `RULE_FIM_SENSITIVE_FILE` (**HIGH**):
       - Phát hiện can thiệp tệp tin nhạy cảm: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`.
- **Gợi ý Trực quan / Bố cục:**
  - Bảng tổng hợp các quy tắc có phân chia màu sắc theo Severity (Đỏ - Vàng - Cam) và icon kỹ thuật tương ứng.
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Động cơ phát hiện của Mini EDR được xây dựng dựa trên nguyên lý 'Explainable Detection' - phát hiện có thể giải thích được. Thay vì dùng mô hình hộp đen khó kiểm chứng, hệ thống định nghĩa các quy tắc rõ ràng phản ánh các kỹ thuật tấn công thực tế: từ việc mở reverse shell bằng netcat, chạy mã độc từ /tmp, web server sinh shell tương tác, cho tới việc can thiệp vào các tệp mật khẩu như /etc/shadow."*

---

### 🔍 Slide 11: Động cơ Tương quan & Đánh giá Điểm Rủi ro (Correlation & Risk Scoring)
- **Tiêu đề:** TƯƠNG QUAN ĐA SỰ KIỆN & THUẬT TOÁN ĐIỂM RỦI RO
- **Mục đích:** Giải thích cách hệ thống tránh dương tính giả (False Positives) và khử trùng lặp cảnh báo.
- **Nội dung hiển thị:**
  - **Bài toán Dương tính Giả:** Một tiến trình ngốn CPU cao có thể chỉ là tác vụ nén file thông thường, không nhất thiết là mã độc.
  - **Cơ chế Tương quan (Correlation Engine):**
    - Kết hợp nhiều chỉ số trên cùng endpoint trong cửa sổ thời gian xác định.
    - Công thức tính điểm rủi ro:
      $$\text{Risk Score} = \min(100, \sum w_i \times \text{indicator}_i)$$
    - *Ví dụ tương quan:*
      - CPU cao ($> 85\%$) đơn thuần: Risk Score $= 40$ (Mức LOW/MEDIUM).
      - CPU cao ($> 85\%$) + Binary chạy trong `/tmp`: Risk Score $= 85$ (Nâng lên **CRITICAL**).
      - Chạy `/tmp/nc` + Sửa đổi `/etc/shadow`: Risk Score $= 95$ (**CRITICAL**).
  - **Khử trùng lặp Cảnh báo (De-duplication):**
    - Sử dụng `alert_key` dạng `<agent_id>:<rule_id>:<fingerprint>`.
    - Tránh tình trạng 'Alert Fatigue' (lụt cảnh báo): Cùng một mối nguy đang diễn ra chỉ cập nhật `last_seen_at` và gắn thêm sự kiện vào `alert_events` thay vì tạo hàng trăm cảnh báo trùng lặp.
- **Gợi ý Trực quan / Bố cục:**
  - Đồ họa minh họa: Các sự kiện riêng lẻ đi vào bộ lọc tương quan và đẩy thang đo rủi ro lên mức Đỏ (Critical).
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Một trong những vấn đề lớn nhất của các hệ thống an ninh là 'Alert Fatigue' - chuyên viên SOC bị quá tải bởi hàng nghìn cảnh báo giả. Mini EDR giải quyết bài toán này bằng Động cơ tương quan và Khử trùng lặp: Nếu một tiến trình chạy trong /tmp và đồng thời FIM báo tệp /etc/shadow bị sửa đổi, hệ thống sẽ tự động tổng hợp thành một sự cố duy nhất và đẩy thang điểm rủi ro lên mức 95/100."*

---

### 🚨 Slide 12: Vòng đời Xử lý Sự cố An ninh (Incident Management)
- **Tiêu đề:** QUẢN LÝ VÒNG ĐỜI SỰ CỐ & STATE TRANSITION GUARDS
- **Mục đích:** Trình bày máy trạng thái hữu hạn và tính toàn vẹn của hồ sơ sự cố SOC.
- **Nội dung hiển thị:**
  - **Máy trạng thái 3 giai đoạn (State Machine):**
    ```text
    [NEW] ──(Acknowledge)──► [ACKNOWLEDGED] ──(Resolve)──► [RESOLVED]
      │                                                      ▲
      └──────────────────────(Dismiss)───────────────────────┘
    ```
  - **Các Thao tác Xử lý:**
    - `Acknowledge`: Tiếp nhận điều tra, lưu vết thời điểm `acknowledged_at`.
    - `Resolve`: Đóng cảnh báo, bắt buộc nhập ghi chú khắc phục (`resolution_note`), lưu vết `resolved_at`.
    - `Dismiss`: Bỏ qua cảnh báo dương tính giả với ghi chú giải trình.
  - **Cơ chế Bảo vệ Chuyển dịch Trạng thái (State Guard):**
    - Chặn lùi trạng thái từ `resolved` về `acknowledged` (Trả về HTTP 400/409).
    - Tính Idempotent: Bấm nhiều lần cùng thao tác không làm thay đổi timestamp ban đầu.
- **Gợi ý Trực quan / Bố cục:**
  - Sơ đồ chuyển dịch trạng thái có mũi tên màu sắc, kèm ảnh chụp giao diện modal nhập ghi chú giải quyết trên Dashboard.
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Vòng đời sự cố trong Mini EDR tuân thủ nghiêm ngặt máy trạng thái hữu hạn: Từ New sang Acknowledged và kết thúc tại Resolved. Hệ thống có cơ chế State Guard ngăn chặn việc tùy tiện lùi trạng thái từ Resolved về Acknowledged, bảo đảm tính toàn vẹn và bất biến của hồ sơ điều tra sự cố số."*

---

### 🌐 Slide 13: Bảng Điều khiển SOC Command Center (Cyberpunk Web Dashboard)
- **Tiêu đề:** GIAO DIỆN BẢNG ĐIỀU KHIỂN SOC COMMAND CENTER
- **Mục đích:** Trình diễn phong cách thiết kế hiện đại và trải nghiệm người dùng tối ưu.
- **Nội dung hiển thị:**
  - **Phong cách Thiết kế Cyberpunk Hacker:**
    - Tông nền tối Deep Space (`#06090e`), lưới ma trận Matrix Grid, font monospace kỹ thuật (`JetBrains Mono`).
    - Bảng màu Neon phát sáng: Cyan, Matrix Green, Red, Amber, Purple.
  - **Tính năng Kỹ thuật Độc lập (Air-gapped Ready):**
    - 100% tài nguyên CSS và Vanilla JS nằm trong máy cục bộ, không phụ thuộc CDN hay Internet.
  - **4 Phân hệ Giao diện:**
    1. `/dashboard`: 4 Cyber KPI Tiles, thanh đo tài nguyên trung bình mạng phát sáng neon, ma trận phân bố mức độ nghiêm trọng.
    2. `/endpoints`: Quản lý hạm đội máy trạm, tìm kiếm tức thời, modal nạp danh sách tiến trình qua AJAX.
    3. `/alerts`: Incident Response Console, lọc đa tiêu chí, modal Evidence JSON và các nút thao tác AJAX tức thời kèm Toast notification.
    4. `/events`: Nhật ký kiểm toán sự kiện an ninh và telemetry FIM.
- **Gợi ý Trực quan / Bố cục:**
  - Ghép ảnh chụp màn hình thực tế (Mockups) của 4 trang giao diện trên khung nền Cyberpunk.
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Giao diện Web Dashboard được thiết kế theo phong cách Cyberpunk SOC Command Center với bảng màu neon rực rỡ nhưng mang tính thực dụng cao. Toàn bộ mã nguồn CSS và JS đều là thuần túy, hoạt động hoàn hảo trong môi trường mạng nội bộ cô lập (Air-gapped). Mọi thao tác từ xem bằng chứng JSON cho tới Acknowledge hay Resolve đều diễn ra tức thời qua AJAX mà không cần reload trang."*

---

### 🛡️ Slide 14: Kiến trúc An toàn & Gia cố Hệ thống (Security Hardening)
- **Tiêu đề:** BẢO MẬT & GIA CỐ HỆ THỐNG (SECURITY HARDENING)
- **Mục đích:** Chứng minh sản phẩm đã được rà soát và phòng vệ chống lại các lỗ hổng OWASP/CWE phổ biến.
- **Nội dung hiển thị:**
  - **Xác thực Mật mã học (Authentication):** Bearer Token bảo vệ 100% các API `/api/v1/*`.
  - **Che giấu Token (Token Redaction):** Tự động lọc và che giấu token trong toàn bộ hệ thống log, ngăn ngừa rò rỉ credential.
  - **Chống Tiêm mã SQL (SQL Injection Defense):** 100% câu truy vấn qua tầng DAL đều dùng tham số hóa, đã vượt qua bộ test probe SQLi nâng cao.
  - **Chống Tấn công XSS (XSS Sanitization):** Bật Autoescape mặc định trong Jinja2 và khử mã độc HTML động (`escapeHtml`) trong JavaScript DOM.
  - **Chống Tấn công Gửi lặp (Replay Attack Defense):** Ràng buộc `message_id` UUIDv4 duy nhất cho từng bản tin telemetry.
  - **Phòng chống Từ chối Dịch vụ (DoS Prevention):** Cấu hình `MAX_CONTENT_LENGTH = 64KB` chặn đứng payload kích thước lớn làm cạn kiệt RAM.
- **Gợi ý Trực quan / Bố cục:**
  - Bảng ma trận đối chiếu: "Nguy cơ Tấn công" vs "Giải pháp Gia cố trong Mini EDR".
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Để một sản phẩm an ninh có thể tin cậy được, bản thân nó phải an toàn trước. Mini EDR áp dụng chiến lược phòng thủ theo chiều sâu: từ việc che giấu token trong log, sử dụng 100% parameterized SQL chống SQLi, escape dữ liệu đầu ra chống XSS, cho tới việc giới hạn 64KB kích thước payload và dùng UUIDv4 chống replay attack."*

---

### 🧪 Slide 15: Kế hoạch & Kết quả Kiểm thử Toàn diện (Testing Matrix)
- **Tiêu đề:** KẾT QUẢ KIỂM THỬ TOÀN DIỆN: 214/214 TESTS PASSED
- **Mục đích:** Cung cấp bằng chứng thực nghiệm định lượng về chất lượng phần mềm.
- **Nội dung hiển thị:**
  - **Quy mô Kiểm thử:** Tổng cộng **214 ca kiểm thử tự động** bao phủ 4 cấp độ:
    - *Unit Tests (102 tests):* Kiểm thử các Collector, Client, FIM, Repositories DAL, Detection Rules, Migrations.
    - *Integration Tests (71 tests):* Kiểm thử API Ingestion, Alert APIs, Web Dashboard Controllers.
    - *Full-System E2E Lifecycle (21 tests):* Kiểm thử khép kín toàn bộ vòng đời 8 bước từ Agent đăng ký đến phát hiện, cảnh báo và SOC Triage.
    - *Security & Reliability (20 tests):* Kiểm thử SQLi probes, XSS vectors, PRAGMA integrity, Payload bounds, Idempotency.
  - **Chỉ số Chất lượng:**
    - Tỷ lệ vượt qua: **100% (214/214 PASSED)**.
    - Thời gian chạy toàn bộ test suite: **~12.5 giây**.
    - Tính toàn vẹn SQLite: `PRAGMA integrity_check` trả về `ok`, 0 lỗi khóa ngoại.
- **Gợi ý Trực quan / Bố cục:**
  - Biểu đồ tròn tỷ lệ 100% xanh lá, kèm ảnh chụp terminal kết quả chạy `pytest -v` thành công rực rỡ.
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Chất lượng của Mini EDR được bảo chứng qua 214 ca kiểm thử tự động với tỷ lệ pass tuyệt đối 100%. Toàn bộ test suite chạy chỉ trong 12.5 giây, kiểm chứng từ từng hàm tính hash SHA-256 nhỏ nhất cho tới chu trình E2E đầy đủ và các bài test tấn công thử nghiệm SQL Injection, XSS."*

---

### 🎬 Slide 16: Kịch bản Trình diễn Thực tế (Live Demo Overview)
- **Tiêu đề:** TRÌNH DIỄN SẢN PHẨM & KỊCH BẢN TẤN CÔNG THỰC TẾ
- **Mục đích:** Chuyển tiếp mượt mà từ phần slide sang phần mở trình duyệt và terminal để demo trực tiếp.
- **Nội dung hiển thị:**
  - **Sơ đồ Kịch bản Demo (5--7 phút):**
    1. *Khởi động & Fleet Overview:* Kiểm tra máy trạm `demo-workstation-01` kết nối Heartbeat.
    2. *Tấn công Can thiệp Tệp (FIM Tampering):* Chỉnh sửa trái phép file cấu hình ➔ FIM phát hiện đổi SHA-256 ➔ Sinh Alert `HIGH`.
    3. *Tấn công Reverse Shell:* Chạy `/tmp/nc -lvnp 4444` ➔ Detection Engine tính Risk Score $= 90$ ➔ Sinh Alert `CRITICAL`.
    4. *SOC Incident Response:* Xem Evidence JSON ➔ Acknowledge ➔ Resolve kèm ghi chú giải quyết ➔ Trình diễn Toast Notification và State Guard.
    5. *Kiểm tra Toàn vẹn:* Chạy `pytest` chứng minh độ ổn định.
- **Gợi ý Trực quan / Bố cục:**
  - Sơ đồ flowchart các bước demo với icon Hacker vs SOC Analyst.
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Sau đây, em xin phép được bước sang phần quan trọng nhất: Trình diễn sản phẩm trực tiếp. Em sẽ mô phỏng một kịch bản tấn công thực tế gồm hành vi sửa đổi tệp cấu hình và chạy reverse shell qua netcat từ thư mục /tmp để Hội đồng quan sát trực tiếp cách hệ thống phát hiện, tính điểm rủi ro và hỗ trợ SOC xử lý sự cố."*

---

### 🏆 Slide 17: Đánh giá Kết quả Đạt được (Achievements vs Objectives)
- **Tiêu đề:** TỔNG KẾT KẾT QUẢ ĐẠT ĐƯỢC
- **Mục đích:** Khẳng định đề tài đã hoàn thành 100% mục tiêu ban đầu theo đúng đề bài.
- **Nội dung hiển thị:**
  - **Bảng Đối chiếu Kết quả:**
    | Yêu cầu Đề tài | Kết quả Đạt được | Đánh giá |
    |---|---|---|
    | Giám sát Endpoint & Heartbeat | Tự động đổi trạng thái Online/Offline theo ngưỡng 15s | **Hoàn thành 100%** |
    | Thu thập Tiến trình Linux | Quét `/proc`, trích xuất 10 trường dữ liệu chi tiết | **Hoàn thành 100%** |
    | Giám sát Toàn vẹn Tệp (FIM) | Mã băm SHA-256, phát hiện Created/Modified/Deleted | **Hoàn thành 100%** |
    | Phát hiện Dấu hiệu Bất thường | Explainable Rules, Correlation, Risk Score $0-100$ | **Hoàn thành 100%** |
    | Quản lý Sự cố Chuẩn SOC | Acknowledge, Resolve with note, Dismiss, State Guards | **Hoàn thành 100%** |
    | Bảng điều khiển Web Dashboard | Cyberpunk Hacker HUD, 100% dữ liệu thật, Air-gapped | **Hoàn thành 100%** |
  - **Giá trị Đóng góp:** Cung cấp một khung kiến trúc EDR giáo dục và thực nghiệm hoàn chỉnh, có tài liệu kỹ thuật chuẩn xác và mã nguồn sẵn sàng mở rộng.
- **Gợi ý Trực quan / Bố cục:**
  - Bảng có dấu tích xanh `[✔]` cho tất cả các tiêu chí nghiệm thu.
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Nhìn lại toàn bộ quá trình nghiên cứu, đề tài đã hoàn thành 100% các tiêu chí nghiệm thu đề ra: từ thu thập telemetry, FIM SHA-256, động cơ tương quan cho tới giao diện điều hành và quản lý vòng đời sự cố. Sản phẩm đã chứng minh tính đúng đắn và độ tin cậy qua 214 bài test tự động."*

---

### 🚀 Slide 18: Giới hạn & Hướng Phát triển Tương lai (Limitations & Future Work)
- **Tiêu đề:** GIỚI HẠN CỦA HỆ THỐNG & HƯỚNG PHÁT TRIỂN
- **Mục đích:** Thể hiện tư duy khoa học khiêm tốn, nhận biết rõ giới hạn của giải pháp và tầm nhìn mở rộng trong thực tế.
- **Nội dung hiển thị:**
  - **Giới hạn Hiện tại của Đồ án:**
    - Quét bảng tiến trình qua `/proc` có chu kỳ (polling) nên có thể bỏ lỡ các tiến trình đoản mệnh (short-lived processes chạy và tắt dưới 1 giây).
    - Cơ sở dữ liệu SQLite phù hợp quy mô lab vừa và nhỏ ($< 50$ máy trạm).
    - Chưa có kênh tương tác ngược từ xa để gửi lệnh cô lập máy trạm (Host Isolation).
  - **Định hướng Mở rộng Tương lai:**
    1. **Nâng cấp sang công nghệ eBPF (Extended Berkeley Packet Filter):** Bắt sự kiện syscalls (`execve`, `connect`, `openat`) trực tiếp trong nhân kernel với độ trễ microsecond.
    2. **Tích hợp Kênh Hai chiều (gRPC / WebSockets):** Cho phép chuyên viên SOC gửi lệnh cách ly máy trạm hoặc đóng băng tiến trình nghi vấn ngay từ Web Console.
    3. **Chuyển đổi sang Cơ sở Dữ liệu Phân tán:** Sử dụng PostgreSQL hoặc Elasticsearch / ClickHouse khi mở rộng quy mô lên hàng nghìn thiết bị.
  - **Lời cảm ơn:** Kính gửi lời cảm ơn sâu sắc tới Giảng viên hướng dẫn và quý Thầy Cô trong Hội đồng!
- **Gợi ý Trực quan / Bố cục:**
  - Hai cột: "Giới hạn Hiện tại" bên trái, "Lộ trình Nâng cấp eBPF & gRPC" bên phải; dòng chữ cảm ơn trang trọng ở cuối slide.
- **Lời thoại Thuyết minh (Speaker Notes):**
  > *"Cuối cùng, em cũng nhận thức rõ các giới hạn của hệ thống hiện tại, đặc biệt là cơ chế polling /proc có thể bỏ lỡ các tiến trình đoản mệnh. Trong tương lai, hướng nghiên cứu tiếp theo sẽ là chuyển đổi sang eBPF ở tầng nhân Linux và bổ sung kênh gRPC hai chiều để phản ứng tức thời. Em xin chân thành cảm ơn quý Thầy Cô trong Hội đồng đã lắng nghe và em rất mong nhận được những ý kiến đóng góp quý báu ạ!"*

---

## 4. Bộ Câu hỏi Phản biện Dự kiến từ Hội đồng & Gợi ý Trả lời

1. **Câu hỏi 1: Tại sao em lại chọn quét `/proc` thay vì dùng eBPF hoặc Auditd?**
   - *Gợi ý trả lời:* *"Dạ thưa Thầy/Cô, việc chọn quét `/proc` và thư viện `psutil` trong phiên bản đồ án này nhằm tối ưu hóa tính độc lập, gọn nhẹ và khả năng tương thích cao trên mọi bản phân phối Linux mà không đòi hỏi kernel headers phức tạp hay quyền root can thiệp sâu vào kernel. Đây là bước đệm kiến trúc hoàn hảo để kiểm chứng logic phát hiện và Data Contract trước khi nâng cấp lên eBPF trong tương lai ạ."*

2. **Câu hỏi 2: Tại sao hệ thống không gửi lệnh tự động `kill` tiến trình độc hại khi phát hiện?**
   - *Gợi ý trả lời:* *"Dạ thưa Thầy/Cô, trong thiết kế an ninh công nghiệp (SOAR/EDR), việc tự động kill tiến trình mà không có sự xác nhận của chuyên viên SOC là con dao hai lưỡi có thể dẫn đến việc tự làm sập các dịch vụ trọng yếu của máy chủ khi xảy ra dương tính giả. Do đó, hệ thống tập trung cung cấp bằng chứng JSON chính xác và hỗ trợ SOC Triage để con người ra quyết định cuối cùng, đảm bảo an toàn tuyệt đối cho hệ thống ạ."*

3. **Câu hỏi 3: SQLite có đáp ứng được hiệu năng khi có nhiều Agent gửi dữ liệu cùng lúc không?**
   - *Gợi ý trả lời:* *"Dạ thưa Thầy/Cô, hệ thống đã cấu hình SQLite ở chế độ WAL (Write-Ahead Logging) kết hợp busy timeout 5000ms. Chế độ WAL cho phép các luồng đọc (Web Dashboard) và luồng ghi (Ingestion API) hoạt động song song mà không khóa lẫn nhau. Với quy mô đồ án từ 1 đến 50 endpoints gửi chu kỳ 10-15 giây, tải ghi chỉ khoảng 3-5 transactions/giây, hoàn toàn nằm trong ngưỡng xử lý mượt mà của SQLite (vốn có thể chịu tải hàng nghìn transaction/giây) ạ."*
