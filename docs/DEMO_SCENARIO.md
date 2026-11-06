# Mini EDR Linux --- Kịch bản Trình diễn Trực tiếp (Live Demo Scenario)

**Tài liệu:** Kịch bản Demo Bảo vệ Đồ án Tốt nghiệp (5--7 phút)  
**Phiên bản:** 1.0  
**Dự án:** Mini Endpoint Detection and Response for Linux  
**Repository:** `r00tK1ngX/mini-edr-linux`  

---

## 1. Chuẩn bị Trước Buổi Báo cáo (Pre-flight Checklist)

Trước khi bước vào phòng bảo vệ, người báo cáo cần kiểm tra và chuẩn bị sẵn các cửa sổ trên máy tính:

1. **Cửa sổ 1 --- Trình duyệt Web (Mở sẵn 4 tab tại `http://127.0.0.1:5000`):**
   - Tab 1: `http://127.0.0.1:5000/dashboard` (SOC Command Center Overview).
   - Tab 2: `http://127.0.0.1:5000/endpoints` (Fleet Inventory).
   - Tab 3: `http://127.0.0.1:5000/alerts` (Incident Response Console).
   - Tab 4: `http://127.0.0.1:5000/events` (Security Audit Logs).
2. **Cửa sổ 2 --- Terminal chia đôi (Split Screen):**
   - **Terminal Trái (Server Logs):** Chạy Flask Server với log thời gian thực:
     ```bash
     cd /home/kali/Projects/mini-edr-linux
     source .venv/bin/activate
     python -m server.app
     ```
   - **Terminal Phải (Attacker / Agent Simulation):** Sẵn sàng để thực thi kịch bản tấn công:
     ```bash
     cd /home/kali/Projects/mini-edr-linux
     source .venv/bin/activate
     ```
3. **Dữ liệu chuẩn bị sẵn:**
   - Đã chạy nạp dữ liệu nền sinh động:
     ```bash
     python scripts/seed_demo_data.py
     ```
4. **Video dự phòng (Backup Video):**
   - Chuẩn bị sẵn 1 video quay màn hình chất lượng cao (1080p) ghi lại toàn bộ 7 phút demo này vào USB hoặc thư mục cục bộ phòng trường hợp máy chiếu hoặc hệ thống gặp trục trặc bất khả kháng.

---

## 2. Kịch bản Trình diễn Chi tiết (Thời lượng: 5--7 Phút)

### ⏱️ Phút 00:00 -- 01:00: Giới thiệu Tổng quan Giao diện SOC Command Center
- **Thao tác:** Đứng tại Tab 1 (`/dashboard`), phóng to toàn màn hình (F11).
- **Thuyết minh:**
  > *"Kính thưa Hội đồng, đây là Bảng điều khiển trung tâm SOC Command Center của Mini EDR được thiết kế theo phong cách Cyberpunk Hacker hiện đại. Mọi số liệu hiển thị tại đây 100% là dữ liệu động thực tế truy vấn từ SQLite Database:*
  > - *4 Cyber KPI Tiles trên cùng cho thấy tổng số thiết bị trong mạng, số sự cố đang kích hoạt, các mối đe dọa mức độ nghiêm trọng và tổng số sự kiện an ninh tiếp nhận.*
  > - *Phía dưới là 3 thanh đo tài nguyên trung bình mạng gồm CPU, RAM, Disk phát sáng Neon. Khi một chỉ số vượt ngưỡng 85%, thanh đo sẽ tự động chuyển màu đỏ cảnh báo.*
  > - *Bên cạnh là Ma trận phân bố mức độ nghiêm trọng và dòng sự cố đang diễn ra theo thời gian thực."*

---

### ⏱️ Phút 01:00 -- 02:30: Quản lý Hạm đội Máy trạm & Kiểm tra Chi tiết Tiến trình
- **Thao tác:** Chuyển sang Tab 2 (`/endpoints`).
- **Thuyết minh:**
  > *"Tại phân hệ Endpoints, hệ thống quản lý danh mục toàn bộ các máy trạm Linux trong mạng nội bộ:*
  > - *Các máy trạm gửi Heartbeat định kỳ. Nếu quá 15 giây không nhận được tín hiệu, máy trạm sẽ tự động chuyển sang badge màu xám OFFLINE. Khi Agent kết nối lại, hệ thống tự động đổi sang badge màu xanh neon ONLINE.*
  > - *Em có thể tìm kiếm tức thời theo hostname hoặc IP address.*
  > - *Bây giờ, em bấm vào nút **INSPECT** tại máy `endpoint-ubuntu-prod`. Hệ thống sẽ mở một Cyber Modal gọi AJAX tải toàn bộ danh sách tiến trình snapshot đang chạy trong nhân `/proc` của máy trạm cùng số lượng tệp FIM đang được bảo vệ mà không cần reload trang."*

---

### ⏱️ Phút 02:30 -- 04:00: Kích hoạt Kịch bản Tấn công & Giám sát Toàn vẹn Tệp (FIM)
- **Thao tác:** Chuyển sang Terminal Phải, chạy script mô phỏng tấn công:
  ```bash
  python scripts/simulate_attack_scenario.py
  ```
  Nhấn `[ENTER]` để thực hiện Bước 1 (Gửi Heartbeat) và Bước 2 (Khởi tạo FIM Baseline). Sau đó bấm `[ENTER]` để kích hoạt Bước 3 (Tấn công can thiệp tệp cấu hình).
- **Thuyết minh:**
  > *"Em vừa khởi tạo kịch bản: Giả sử kẻ tấn công chiếm được quyền chỉnh sửa tệp cấu hình `/tmp/mini_edr_demo/secure_config.conf` và thêm cấu hình `PERMIT_ROOT_LOGIN=yes`.*
  > - *Module File Integrity Monitoring (FIM) của Agent lập tức tính toán lại mã băm mật mã học **SHA-256** của tệp.*
  > - *Nhận thấy mã băm mới khác hoàn toàn so với Baseline chuẩn ban đầu, Agent lập tức đóng gói bản tin Security Event theo chuẩn Common Telemetry Envelope 1.0 gửi về API Server.*
  > - *Detection Engine lập tức khớp quy tắc `RULE_FIM_SENSITIVE_FILE` và tự động sinh cảnh báo an ninh mức độ HIGH."*

---

### ⏱️ Phút 04:00 -- 05:00: Tấn công Reverse Shell & Động cơ Phát hiện Thời gian thực
- **Thao tác:** Tại Terminal Phải, nhấn `[ENTER]` để kích hoạt Bước 4 (Chạy `/tmp/nc` reverse shell).
- **Thuyết minh:**
  > *"Tiếp theo, kẻ tấn công thực thi một tiện ích mạng nguy hiểm là netcat từ thư mục tạm `/tmp/nc -lvnp 4444` để thiết lập backdoor kết nối ngược (Reverse Shell):*
  > - *Process Collector quét bảng `/proc` và gửi Process Snapshot về Server.*
  > - *Detection Engine chạy thuật toán phân tích tương quan: Phát hiện binary chạy trong đường dẫn bất thường `/tmp` kết hợp tên tiến trình `nc` nằm trong danh mục hack tools.*
  > - *Điểm rủi ro (Risk Score) được nâng lên mức **90/100 (CRITICAL)** và một Alert đặc biệt nghiêm trọng được tạo ra ngay lập tức!"*

---

### ⏱️ Phút 05:00 -- 06:15: Quy trình Xử lý Sự cố An ninh Chuẩn SOC (Incident Triage)
- **Thao tác:** Chuyển sang Tab 3 (`/alerts`), nhấn `F5` hoặc quan sát danh sách vừa cập nhật.
- **Thuyết minh:**
  > *"Quay trở lại màn hình SOC Console tại `/alerts`:*
  > - *Hội đồng có thể thấy cảnh báo `CRITICAL: Reverse Shell or Suspicious Utility Detected` vừa xuất hiện ở đầu bảng với badge nhấp nháy đỏ rực rỡ.*
  > - *Em bấm nút **EVIDENCE**: Modal Cyberpunk hiển thị toàn bộ bằng chứng JSON gốc gồm đường dẫn thực thi `/tmp/nc`, dòng lệnh `cmdline`, PID và các security events liên quan.*
  > - *Là chuyên viên phân tích SOC, em thực hiện quy trình Triage:*
  >   1. *Bấm nút **ACK**: Toast notification 'ALERT ACKNOWLEDGED' hiện lên, trạng thái sự cố lập tức đổi sang ACKNOWLEDGED.*
  >   2. *Sau khi điều tra và cô lập tiến trình độc hại, em bấm nút **RESOLVE**: Modal hiện lên yêu cầu nhập ghi chú xử lý. Em điền 'Đã cô lập PID 4444 và khôi phục tệp FIM' rồi bấm Xác nhận.*
  >   3. *Trạng thái sự cố chuyển sang RESOLVED màu xanh lá, lưu vết chính xác thời điểm và nội dung ghi chú.*
  > - *Đặc biệt, hệ thống có **State Transition Guard**: Nếu em cố tình bấm lại ACK trên một alert đã Resolved, hệ thống sẽ chặn đứng và báo lỗi, đảm bảo tính toàn vẹn của hồ sơ pháp y số."*

---

### ⏱️ Phút 06:15 -- 07:00: Chứng minh Độ tin cậy Kỹ thuật & Kết luận
- **Thao tác:** Mở terminal, chạy lệnh test toàn hệ thống:
  ```bash
  .venv/bin/pytest -q
  ```
- **Thuyết minh:**
  > *"Để chứng minh tính ổn định, tin cậy và an toàn của hệ thống, toàn bộ mã nguồn của Mini EDR được kiểm thử tự động qua **214 ca kiểm thử (Test Cases)** bao phủ từ Unit Collector, API Ingestion, Detection Engine, DAL, Web UI cho đến kiểm thử an ninh chống SQL Injection, XSS, Replay Attack và kiểm tra toàn vẹn cơ sở dữ liệu `PRAGMA integrity_check`.*
  > - *Toàn bộ **214/214 tests đều đạt 100%** trong thời gian chỉ 12 giây.*
  > - *Em xin kết thúc phần trình diễn sản phẩm và kính mời quý Thầy/Cô trong Hội đồng đặt câu hỏi phản biện ạ!"*

---

## 3. Xử lý Sự cố Kỹ thuật Thường gặp (Troubleshooting)

| Tình huống | Nguyên nhân khả dĩ | Cách khắc phục tức thời |
|---|---|---|
| Server báo lỗi `Port already in use` | Tiến trình Flask trước chưa tắt | Chạy `fuser -k 5000/tcp` rồi khởi động lại `python -m server.app` |
| Không nạp được dữ liệu mẫu | Database bị khóa hoặc chưa migration | Xóa file `data/mini_edr.db` và chạy lại `python scripts/seed_demo_data.py` |
| Modal trên Web không mở | JavaScript bị chặn hoặc lỗi cache | Bấm `Ctrl + Shift + R` để làm mới sạch cache trình duyệt |
| Máy chiếu bị mất kết nối | Sự cố phần cứng/cáp | Lập tức chuyển sang trình chiếu Video Demo dự phòng 1080p chuẩn bị sẵn trong USB |
