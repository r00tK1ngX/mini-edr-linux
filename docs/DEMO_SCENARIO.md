# Mini EDR Linux — Kịch bản Diễn tập & Trình diễn Thực tế (Demo Scenario)

**Tài liệu:** Demo Scenario & Defense Choreography Guide  
**Phiên bản:** 2.0 (Academic Defense Edition)  
**Thời lượng dự kiến:** 5 – 7 phút  
**Đối tượng:** Hội đồng Chấm thi / Giảng viên Hướng dẫn / Chuyên gia Đánh giá  
**Mục tiêu:** Chứng minh toàn diện tính đúng đắn của chức năng thu thập, phát hiện theo thời gian thực (Real-time Detection), tính toàn vẹn dữ liệu (Data Integrity) và quy trình ứng cứu sự cố an ninh (SOC Triage) trên giao diện Web Console.

---

## 1. Chuẩn bị Môi trường Demo (Pre-flight Checklist)

Trước khi bắt đầu bài thuyết trình, người trình bày thực hiện các bước chuẩn bị sau:

### 1.1. Cửa sổ dòng lệnh (Terminal Tabs)
Chuẩn bị 2 cửa sổ terminal đã kích hoạt môi trường ảo Python:
* **Terminal 1 (Backend Server):**
  ```bash
  cd /home/kali/Projects/mini-edr-linux
  source .venv/bin/activate
  python3 -m server.app
  ```
  *Ghi chú:* Server sẽ lắng nghe tại `http://127.0.0.1:5000`.

* **Terminal 2 (Attack Simulation / Operator CLI):**
  ```bash
  cd /home/kali/Projects/mini-edr-linux
  source .venv/bin/activate
  ```

### 1.2. Trình duyệt Web (Browser)
* Mở trình duyệt tại địa chỉ: `http://127.0.0.1:5000`
* Hệ thống sẽ tự động điều hướng về màn hình đăng nhập an toàn: `http://127.0.0.1:5000/login`

---

## 2. Kịch bản Diễn tập Chi tiết 5 Bước (Step-by-step Walkthrough)

Tiện ích kịch bản tấn công thực tế [`scripts/simulate_attack_scenario.py`](file:///home/kali/Projects/mini-edr-linux/scripts/simulate_attack_scenario.py) được thiết kế đặc biệt cho buổi thuyết trình với tính năng bấm phím `[ENTER]` tương tác từng bước:

```bash
python3 scripts/simulate_attack_scenario.py
```

```text
╔════════════════════════════════════════════════════════════════════╗
║                MINI EDR LINUX - LIVE DEFENSE DEMO                  ║
║         Attack Simulation & Real-time Detection Trigger            ║
╚════════════════════════════════════════════════════════════════════╝
[+] Server Target: http://127.0.0.1:5000
[+] Token configured: eC4-K9...Ai4E
[✔] Mini EDR Server đang hoạt động (Status: 200 OK)
```

---

### [BƯỚC 1] Đăng ký Máy trạm & Gửi Heartbeat đầu tiên

* **Mục đích:** Mô phỏng một máy trạm Linux mới khởi động Agent, gửi bản tin Heartbeat để báo cáo danh tính (`demo-workstation-01`), địa chỉ IP (`192.168.10.88`) và thông số tài nguyên ban đầu (CPU, RAM, Disk, Uptime).
* **Thao tác CLI:** Người trình bày nhấn `[ENTER]`.
* **Kết quả Terminal:**
  ```text
  [✔] Server Response (200): Endpoint 'demo-workstation-01' đã Online!
      Kiểm tra trên Web Dashboard: http://127.0.0.1:5000/endpoints
  ```
* **Thuyết minh & Trình diễn Web:**
  1. Trên trình duyệt, đăng nhập với Token hệ thống tại `/login`.
  2. Chuyển sang tab **FLEET (`/endpoints`)**.
  3. Chỉ cho Hội đồng thấy máy trạm `demo-workstation-01` xuất hiện với huy hiệu xanh `ONLINE`.
  4. Bấm nút **INSPECT** để xem thông số tài nguyên thời gian thực.

---

### [BƯỚC 2] Thiết lập Baseline Toàn vẹn Tệp (FIM Baseline)

* **Mục đích:** Mô phỏng Agent thiết lập hồ sơ băm mật mã học SHA-256 ban đầu cho một tệp cấu hình an ninh trọng yếu (`/tmp/mini_edr_demo/secure_config.conf`).
* **Nội dung tệp mẫu ban đầu:**
  ```text
  ALLOW_USER=kali
  SECURE_MODE=1
  PERMIT_ROOT_LOGIN=no
  ```
* **Thao tác CLI:** Người trình bày nhấn `[ENTER]`.
* **Kết quả Terminal:**
  ```text
  [✔] FIM Baseline khởi tạo thành công (200):
      File: /tmp/mini_edr_demo/secure_config.conf
      Initial SHA-256: 6afa248d7a9654dcf57a324902aced5434abe6ce4a87e2c73423a66ce0d99437
  ```
* **Thuyết minh:** Giải thích cơ chế FIM sử dụng `os.lstat()` chống tấn công vượt quyền Symlink (TOCTOU) và thuật toán băm SHA-256 tiêu chuẩn bảo mật.

---

### [BƯỚC 3] Tấn công Chỉnh sửa Trái phép Tệp (FIM Tampering Attack)

* **Mục đích:** Mô phỏng kẻ tấn công thâm nhập và sửa đổi cấu hình tệp để mở cửa hậu đăng nhập quyền Root:
  ```text
  PERMIT_ROOT_LOGIN=yes # HACKED!
  BACKDOOR_KEY=payload_x
  ```
* **Thao tác CLI:** Người trình bày nhấn `[ENTER]`.
* **Kết quả Terminal:**
  ```text
  [!] Nội dung tệp đã bị sửa đổi trái phép!
      New SHA-256: f8ba84e6b7ed49f220d74a51fab9f129afbf1dd6d236dce34b8b0880244711b0
  [✔] Security Event đã tiếp nhận (201): Detection Engine kích hoạt!
      Alert HIGH đã được tạo tự động trên Dashboard!
  ```
* **Thuyết minh & Trình diễn Web:**
  1. Mở tab **EVENTS (`/events`)**: Chỉ cho Hội đồng sự kiện `fim_modified` với mã băm cũ và mã băm mới.
  2. Mở tab **INCIDENTS (`/alerts`)**: Một cảnh báo an ninh mức độ **HIGH** với tiêu đề *"File Modified: secure_config.conf"* đã tự động được sinh ra.

---

### [BƯỚC 4] Mô phỏng Chạy Tiến trình Độc hại (/tmp/nc Reverse Shell)

* **Mục đích:** Hacker khởi chạy một backdoor reverse shell từ thư mục tạm `/tmp` với tham số lắng nghe cổng 4444: `/tmp/nc -lvnp 4444 -e /bin/bash`.
* **Thao tác CLI:** Người trình bày nhấn `[ENTER]`.
* **Kết quả Terminal:**
  ```text
  [✔] Process Snapshot tiếp nhận (201):
      Phát hiện vi phạm: RULE_SUSPICIOUS_PROCESS
      Tiến trình độc hại: /tmp/nc (PID 4444)
      Risk Score: 90 / 100 (Mức CRITICAL)
      Quan sát trên Web Dashboard: http://127.0.0.1:5000/alerts
  ```
* **Thuyết minh:**
  * Giải thích Detection Engine phát hiện vi phạm dựa trên quy tắc đường dẫn bất thường (`/tmp`) kết hợp công cụ nhị phân nguy hiểm (`nc`).
  * Chỉ rõ cơ chế tương quan (Correlation Engine): Hệ thống tính toán điểm rủi ro đạt **90/100**, tự động nâng mức cảnh báo lên **CRITICAL** (nghiêm trọng nhất).

---

### [BƯỚC 5] Phản ứng Sự cố & Triage trên SOC Web Console

* **Mục đích:** Người thuyết trình đóng vai Chuyên viên An ninh SOC (SOC Analyst) thực hiện quy trình ứng cứu sự cố chuẩn mực.
* **Các bước thao tác trực tiếp trên giao diện `/alerts`:**
  1. **Xem Bằng chứng (Inspect Evidence):**
     * Click vào nút **EVIDENCE** trên cảnh báo Netcat.
     * Modal Cyberpunk mở ra hiển thị toàn bộ JSON Evidence: đường dẫn `/tmp/nc`, PID `4444`, PPID, command line và các sự kiện an ninh liên kết.
     * Giải thích tính an toàn: Dữ liệu được escape HTML nghiêm ngặt, triệt tiêu nguy cơ DOM XSS.
  2. **Tiếp nhận Sự cố (Acknowledge):**
     * Click nút **ACK**.
     * Badge trạng thái lập tức chuyển từ `NEW` sang `ACKNOWLEDGED` (màu vàng cảnh báo) kèm thông báo Toast mà không tải lại trang (Zero Reload AJAX).
  3. **Kết luận & Đóng Sự cố (Resolve):**
     * Click nút **RESOLVE**.
     * Nhập ghi chú khắc phục: `Đã cô lập PID 4444 và khôi phục tệp FIM ban đầu`.
     * Click **CONFIRM RESOLUTION**.
     * Cảnh báo lập tức chuyển sang trạng thái `RESOLVED` (màu xanh lá) và lưu vết thời gian giải quyết cùng ghi chú.
     * Giải thích cơ chế bảo vệ: Thao tác gửi kèm `X-CSRF-Token` bảo vệ chống tấn công CSRF và cơ chế máy trạng thái chặn không cho lùi trạng thái về `acknowledged`.

---

## 3. Phương án Dự phòng (Fallback & Contingency Plan)

Trong trường hợp buổi bảo vệ gặp sự cố mạng đột xuất hoặc môi trường máy chiếu không cho phép gõ dòng lệnh, người trình bày có thể kích hoạt phương án dự phòng nạp dữ liệu tức thì:

```bash
# Nạp dữ liệu mẫu hoàn chỉnh 3 máy trạm, 3 sự cố, 3 sự kiện FIM:
python3 scripts/seed_demo_data.py
```

Dữ liệu sẽ được nạp đầy đủ vào database và hiển thị ngay trên Web Dashboard, đảm bảo bài thuyết trình không bị gián đoạn.
