# BÁO CÁO KIỂM TOÁN PHÂN HỆ — PHASE 3: LINUX AGENT AUDIT

**Dự án:** Mini Endpoint Detection and Response for Linux (`r00tK1ngX/mini-edr-linux`)  
**Phân hệ Kiểm toán:** Linux Agent (`SystemCollector`, `ProcessCollector`, `FileIntegrityMonitor`, `AgentClient`, `AgentOrchestrator`)  
**Ngày thực hiện:** 05/11/2026 (23:35 EST)  
**Tình trạng Nghiệm thu:** **PARTIAL** (Các module thu thập dữ liệu có tính độc lập cao, bắt lỗi tốt chống crash; tuy nhiên phát hiện 2 lỗi High nghiêm trọng về mất sự kiện vĩnh viễn và thiếu trường dòng lệnh `cmdline`, 3 lỗi Medium về hiệu năng/I-O FIM và điểm mù tiến trình ngắn hạn, 1 lỗi Low)  

---

## 1. Tổng quan Đánh giá Phân hệ Linux Agent

Agent là nguồn dữ liệu đầu vào duy nhất và quan trọng nhất của toàn bộ giải pháp Mini EDR, chịu trách nhiệm liên tục trích xuất trạng thái máy trạm Linux và truyền tải về máy chủ Backend. Phân hệ bao gồm 5 thành phần chính:
1. **System Collector** ([`agent/system_collector.py`](file:///home/kali/Projects/mini-edr-linux/agent/system_collector.py)): Trích xuất danh tính máy trạm (`hostname`, `ip_address`, `os`) và số liệu hiệu năng tài nguyên (`cpu_percent`, `memory_percent`, `disk_percent`, `uptime_seconds`).
2. **Process Collector** ([`agent/process_collector.py`](file:///home/kali/Projects/mini-edr-linux/agent/process_collector.py)): Quét danh sách tiến trình đang thực thi thông qua thư viện `psutil`, trích xuất `pid`, `ppid`, `name`, `username`, `exe`, `cpu`, `memory`, `rss_bytes`, `create_time`.
3. **File Integrity Monitor (FIM)** ([`agent/file_integrity.py`](file:///home/kali/Projects/mini-edr-linux/agent/file_integrity.py)): Thiết lập đường cơ sở (Baseline) các file trong thư mục giám sát (`/etc`, `/bin`, `/tmp`), băm SHA-256 theo khối 64 KiB, phát hiện các thay đổi tạo mới (`created`), sửa đổi nội dung/quyền (`modified`), hoặc xóa (`deleted`).
4. **HTTP Client** ([`agent/client.py`](file:///home/kali/Projects/mini-edr-linux/agent/client.py)): Đóng gói request với Bearer token, hỗ trợ cơ chế retry với hàm mũ (Exponential Backoff), phân loại lỗi HTTP 401/4xx không retry vô hạn.
5. **Agent Orchestrator** ([`agent/main.py`](file:///home/kali/Projects/mini-edr-linux/agent/main.py)): Điều phối vòng lặp thu thập đa chu kỳ (Heartbeat 5s, Process 10s, FIM 30s), bắt tín hiệu `SIGINT`/`SIGTERM` để dừng an toàn.

---

## 2. Kết quả Trả lời Các Câu hỏi Kiểm toán Bắt buộc

### ❓ 1. Agent có gửi nhầm identity không?
- **CÓ THỂ XẢY RA TRÙNG LẶP / NHẦM LẪN DANH TÍNH.**
  - Trong [`agent/main.py`](file:///home/kali/Projects/mini-edr-linux/agent/main.py#L73-L77), biến `agent_id` được xác định theo thứ tự: biến môi trường `EDR_AGENT_ID` $\rightarrow$ hàm `get_hostname()` $\rightarrow$ mặc định cứng `"lab-linux-01"`.
  - Agent **hoàn toàn không sinh và không lưu trữ bất kỳ mã máy duy nhất (Machine UUID / Persistent Agent UUID)** nào trên ổ đĩa cục bộ (ví dụ: `/var/lib/mini-edr/agent_id` hoặc trích xuất `/etc/machine-id`).
  - Nếu triển khai Agent trên nhiều máy trạm clone từ một image VM hoặc container có cùng hostname mặc định (như `ubuntu`, `localhost`, `kali`), tất cả các máy trạm này sẽ gửi telemetry dùng chung một `agent_id`, dẫn đến việc ghi đè trạng thái và làm sai lệch toàn bộ bức tranh an ninh mạng (*Chi tiết tại FINDING-PHASE03-06*).

### ❓ 2. Dữ liệu gửi lên có match với Data Contract không?
- **CÓ.** Toàn bộ 5 loại phong bì gửi lên Server đều khớp 100% với đặc tả JSON Schema trong `DATA_CONTRACT.md`:
  - `POST /api/v1/heartbeat`: Gửi dict thông tin định danh và số liệu tài nguyên `metrics`.
  - `POST /api/v1/telemetry/system`: Bao gồm `schema_version: "1.0"`, `message_id` (UUID v4), `collected_at` (ISO 8601 UTC), `payload` (chứa 4 chỉ số tài nguyên).
  - `POST /api/v1/telemetry/processes`: Chứa `process_count` và mảng `processes` với các khóa chuẩn hóa.
  - `POST /api/v1/file-baselines`: Mảng `files` chứa `file_path`, `sha256` (64 ký tự thường), `file_mode`, `state`.
  - `POST /api/v1/events`: Chứa `event_type`, `severity`, `source: "agent"`, `fingerprint`, `evidence`.

### ❓ 3. Agent có crash khi gặp file bị lock, permission denied, hoặc zombie process không?
- **KHÔNG.** Agent có khả năng tự phục hồi và bắt lỗi rất tốt:
  - *Zombie process:* Hàm `collect_single_process()` bắt đúng `psutil.ZombieProcess` và `psutil.NoSuchProcess`, bỏ qua nhẹ nhàng và trả về `None`.
  - *Process AccessDenied:* Bắt `psutil.AccessDenied` và trả về fallback an toàn: `{"pid": proc.pid, "process_name": "proc-<pid>"}`.
  - *File bị lock / Permission denied:* Hàm `compute_sha256()` và `inspect_file()` bắt `(PermissionError, FileNotFoundError, IsADirectoryError, OSError)` và trả về `None` thay vì làm sập tiến trình.
  - *File dung lượng lớn:* Bỏ qua việc băm các file $> 50\text{MB}$ (`DEFAULT_MAX_FILE_SIZE`), ngăn ngừa tràn RAM.

### ❓ 4. FIM có bị loop hoặc tốn tài nguyên CPU/IO không?
- **VỀ LOOP THƯ MỤC:** **KHÔNG.** `scan_monitored_paths()` sử dụng `os.walk(..., followlinks=False)` nên không bao giờ bị rơi vào vòng lặp vô tận khi duyệt thư mục symlink.
- **VỀ TIÊU TỐN CPU & DISK I/O:** **CÓ — RẤT NGHIÊM TRỌNG.**
  - Thuật toán `scan_monitored_paths()` không có cơ chế Fast-path kiểm tra `mtime` hay `file_size` trước khi băm. Cứ mỗi chu kỳ 30 giây, Agent mở và đọc tuần tự toàn bộ byte của hàng nghìn file trong `/bin`, `/etc`, `/tmp` để tính SHA-256 từ đầu (*Chi tiết tại FINDING-PHASE03-03*).
  - Cấu hình mặc định giám sát `/tmp` với `recursive=True` nhưng **hoàn toàn không có danh sách loại trừ (Exclusion / Ignore list)**, dẫn đến việc liên tục băm các file tạm thời của hệ điều hành và tạo ra bão sự kiện giả mạo (False Positive Storm).

### ❓ 5. Symlink loop / dangling symlink có làm Agent crash không?
- **KHÔNG CRASH, NHƯNG BỊ SAI LỆCH LOGIC ĐỊNH DANH ĐƯỜNG DẪN.**
  - Dangling symlink (symlink trỏ vào đích không tồn tại) được bắt bởi `FileNotFoundError`/`OSError` và trả về `None`.
  - Symlink loop (A trỏ B, B trỏ A) được bắt bởi `OSError: [Errno 40] Too many levels of symbolic links` và trả về `None`.
  - *Tuy nhiên:* Lệnh `Path(file_path).resolve()` phân giải thẳng symlink ra đích thực tế, khiến cho mọi symlink trỏ đến cùng một file bị gộp chung vào một khóa duy nhất trong baseline, làm mất dấu đường dẫn thực tế đang được giám sát (*Chi tiết tại FINDING-PHASE03-04*).

### ❓ 6. Agent có xử lý khi Server tạm thời down không?
- **VỀ TIẾN TRÌNH ORCHESTRATOR:** Không bị crash. Vòng lặp chính bắt ngoại lệ `AgentConnectionError`, ghi log cảnh báo và tiếp tục chạy chu kỳ sau.
- **VỀ TÍNH TOÀN VẸN SỰ KIỆN:** **MẤT DỮ LIỆU SỰ CỐ VĨNH VIỄN (DATA LOSS).**
  - FIM cập nhật trạng thái cơ sở `self.baseline` ngay trong bộ nhớ trước khi gửi sự kiện. Nếu Server bị tắt hoặc mất mạng đúng lúc Agent gửi `send_security_event()`, request bị thất bại. Sang chu kỳ kế tiếp, Agent so sánh file trên đĩa với baseline đã bị cập nhật mới, thấy không có khác biệt nữa $\rightarrow$ **Sự kiện an ninh bị bỏ rơi và không bao giờ được gửi lại** (*Chi tiết tại FINDING-PHASE03-01*).

---

## 3. Danh Sách Các Phát Hiện Kiểm Toán Chi Tiết (Findings)

---

### 🔴 FINDING-PHASE03-01: Mất sự kiện an ninh vĩnh viễn khi mất kết nối mạng do cập nhật Baseline bộ nhớ sớm (Thiếu Outbox Spooling)
- **Mức độ nghiêm trọng:** **HIGH** (CVSS: 7.5 - High)
- **Phase ảnh hưởng:** Phase 3 (Linux Agent FIM & Orchestrator) & Phase 4 (E2E Integration)
- **File / Vị trí:** [`agent/file_integrity.py`](file:///home/kali/Projects/mini-edr-linux/agent/file_integrity.py#L347), [`agent/main.py`](file:///home/kali/Projects/mini-edr-linux/agent/main.py#L239-L245)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Trong phương thức `FileIntegrityMonitor.check_for_changes()`:
  ```python
  def check_for_changes(self) -> List[Dict[str, Any]]:
      current_scan = self.scan()
      self.baseline, events = detect_file_changes(self.baseline, current_scan)
      return events
  ```
  `self.baseline` bị ghi đè ngay lập tức bằng dữ liệu quét mới nhất (`current_scan`).
  Trong [`agent/main.py`](file:///home/kali/Projects/mini-edr-linux/agent/main.py):
  ```python
  changes = self.fim_monitor.check_for_changes()
  if changes:
      sec_events = self.fim_monitor.get_security_events(changes)
      for evt in sec_events:
          self.client.send_security_event(evt)
  ```
  Nếu máy chủ Backend bị khởi động lại, bảo trì hoặc mạng gặp sự cố chập chờn, lời gọi `send_security_event()` sẽ ném lỗi `AgentConnectionError`. Lỗi này được khối `try...except` của Orchestrator bắt và ghi log cảnh báo.
  Tuy nhiên, **ở chu kỳ kế tiếp (30 giây sau)**:
  `self.baseline` trong bộ nhớ đã chứa mã hash mới của file bị tấn công. Khi hàm `check_for_changes()` quét lại, nó thấy hash trên đĩa trùng với hash trong `self.baseline` $\rightarrow$ `changes` trả về rỗng `[]`.
  Do Agent không có hàng đợi lưu đệm ngoại tuyến (Local Spool / Outbox Buffer), sự kiện thay đổi file an ninh (ví dụ sửa đổi `/etc/shadow`) **bị xóa sổ vĩnh viễn khỏi hàng đợi phát hiện**.
- **Điều kiện Kích hoạt (Preconditions):**
  Kẻ tấn công sửa đổi file nhạy cảm trong lúc kết nối mạng giữa Agent và Server bị gián đoạn (hoặc trong lúc Server đang khởi động lại).
- **Các bước Tái hiện (Reproduction Steps):**
  Đã kiểm chứng độc lập bằng thực nghiệm tại scratch test script:
  1. Khởi tạo baseline cho file `shadow_loss_test` (hash $H_1$).
  2. Ghi đè file bằng nội dung độc hại (hash $H_2$).
  3. Chu kỳ 1: `check_for_changes()` phát hiện 1 sự kiện `modified`.
  4. Giả lập Server mất mạng: Lệnh gửi mạng thất bại.
  5. Chu kỳ 2: Khôi phục mạng, `check_for_changes()` chạy lại.
  6. Kết quả thực tế: `events` trả về `0`. Sự kiện không bao giờ được truyền tải đến Server.
- **Tác động (Impact):**
  Thất thoát hoàn toàn dấu vết xâm nhập (Forensic Evidence Loss). Kẻ tấn công chỉ cần làm gián đoạn mạng máy trạm trong vài giây khi thực thi mã độc là có thể vô hiệu hóa khả năng cảnh báo của FIM.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  1. Chỉ cập nhật bản ghi trong `self.baseline` sau khi Server đã phản hồi HTTP 201 Created thành công cho sự kiện tương ứng.
  2. Triển khai bộ đệm sự kiện cục bộ (Local Outbox Buffer hoặc SQLite hàng đợi trên máy trạm) để lưu vết các sự kiện chưa gửi thành công và thực hiện cơ chế gửi bù (Replay/Drain queue) khi mạng thông suốt.

---

### 🔴 FINDING-PHASE03-02: Sai lệch nghiêm trọng giữa Thiết kế và Hiện thực: Agent không hề thu thập dòng lệnh `cmdline`
- **Mức độ nghiêm trọng:** **HIGH** (CVSS: 7.1 - High)
- **Phase ảnh hưởng:** Phase 3 (Process Collector) & Phase 5 (Detection Engine)
- **File / Vị trí:** [`agent/process_collector.py`](file:///home/kali/Projects/mini-edr-linux/agent/process_collector.py#L21-L31)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Trong các tài liệu kiến trúc chính thức và slide thuyết trình:
  - `ARCHITECTURE.md` (dòng 100): Khẳng định Agent trích xuất: `pid`, `ppid`, `name`, `username`, `exe_path`, **`cmdline`**, `cpu_percent`, `memory_percent`, `rss_bytes`, `process_started_at`.
  - `PRESENTATION_SLIDES_OUTLINE.md` (dòng 120): Ghi rõ trích xuất 10 trường thông tin bao gồm dòng lệnh `cmdline`.
  - `DEMO_SCENARIO.md` (dòng 92): Hướng dẫn giám khảo bấm nút EVIDENCE để xem "đường dẫn thực thi `/tmp/nc`, dòng lệnh `cmdline`, PID...".
  **Tuy nhiên, trong mã nguồn thực tế tại [`agent/process_collector.py`](file:///home/kali/Projects/mini-edr-linux/agent/process_collector.py):**
  ```python
  PROCESS_ATTRS = (
      "pid",
      "ppid",
      "name",
      "username",
      "exe",
      "cpu_percent",
      "memory_percent",
      "memory_info",
      "create_time",
  )
  ```
  Trường **`cmdline` hoàn toàn không có trong danh sách thuộc tính thu thập**!
  Cơ sở dữ liệu bảng `process_observations` cũng không có cột `cmdline`.
- **Tác động (Impact):**
  1. Không thể phát hiện các cuộc tấn công sử dụng các công cụ hợp pháp (Living-off-the-Land - LotL) thông qua tham số dòng lệnh, ví dụ: `bash -i >& /dev/tcp/...`, `python3 -c "import pty;..."`, `nc -e /bin/sh`, `curl | bash`.
  2. Toàn bộ kịch bản demo và tài liệu báo cáo khẳng định hiển thị `cmdline` cho giám khảo là **không có thật trong luồng vận hành thực tế của Agent** (chỉ có dữ liệu giả lập trong kịch bản mock).
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  1. Thêm `"cmdline"` vào tuple `PROCESS_ATTRS` trong `agent/process_collector.py`.
  2. Nối mảng tham số dòng lệnh thành chuỗi `cmdline = " ".join(info.get("cmdline") or [])`.
  3. Bổ sung cột `cmdline TEXT` vào bảng `process_observations` và cập nhật API ingestion payload.

---

### 🟡 FINDING-PHASE03-03: Băm lại toàn bộ byte file trên mỗi chu kỳ FIM gây quá tải I/O và nghẽn CPU
- **Mức độ nghiêm trọng:** **MEDIUM** (CVSS: 5.8 - Medium)
- **Phase ảnh hưởng:** Phase 3 (FIM Performance & Scalability)
- **File / Vị trí:** [`agent/file_integrity.py`](file:///home/kali/Projects/mini-edr-linux/agent/file_integrity.py#L76-L84)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Hàm `inspect_file()` thực hiện đọc và tính toán `compute_sha256()` trên mọi file tìm thấy trong mỗi chu kỳ quét:
  ```python
  st = os.stat(resolved_path, follow_symlinks=False)
  ...
  sha256_hash = compute_sha256(resolved_path, max_size=max_size)
  ```
  Hàm này không hề kiểm tra đối chiếu `st_mtime_ns` hoặc `st_size` với bản ghi baseline trước đó.
  Trên một hệ thống Linux thông thường, thư mục `/bin` và `/etc` chứa hàng nghìn file nhị phân (trên máy kiểm toán Kali có tới hơn 4,100 files).
  Cứ mỗi 30 giây, Agent đọc hàng trăm megabytes dữ liệu từ ổ cứng để tính toán SHA-256 từ đầu cho các file tĩnh không hề bị thay đổi, gây chiếm dụng CPU cao và nghẽn Disk I/O (chúng tôi đã đo đạc thấy một lượt quét FIM mặc định trên Kali mất tới hơn 30 giây).
- **Tác động (Impact):**
  Làm suy giảm nghiêm trọng hiệu năng của máy trạm được giám sát; gây tốn pin trên laptop và cạn kiệt hạn mức IOPS trên các máy ảo Cloud.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  Áp dụng chiến lược kiểm tra nhanh (Stat Fast-Path):
  Trước khi đọc đĩa để tính SHA-256, hãy so sánh `st.st_mtime_ns == prev['mtime_ns']` và `st.st_size == prev['file_size_bytes']` và `st.st_mode == prev['file_mode']`. Nếu 3 thông số này hoàn toàn không đổi, tái sử dụng mã hash cũ từ baseline mà không cần đọc lại byte từ đĩa.

---

### 🟡 FINDING-PHASE03-04: Phân giải Symlink sớm (`Path.resolve()`) làm sụp đổ định danh đường dẫn giám sát (CWE-59)
- **Mức độ nghiêm trọng:** **MEDIUM** (CVSS: 5.3 - Medium)
- **Phase ảnh hưởng:** Phase 3 (FIM Symlink Handling)
- **File / Vị trí:** [`agent/file_integrity.py`](file:///home/kali/Projects/mini-edr-linux/agent/file_integrity.py#L75)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Trong `inspect_file()`:
  ```python
  resolved_path = str(Path(file_path).resolve())
  st = os.stat(resolved_path, follow_symlinks=False)
  ```
  `Path.resolve()` tự động phân giải toàn bộ các symbolic link đến file đích cuối cùng. Sau đó, kết quả được gán khóa trong dictionary theo `resolved_path`:
  1. Nếu trong thư mục giám sát có nhiều symlinks cùng trỏ vào một file đích (ví dụ `/bin/sh` và `/bin/bash`), chúng bị gộp chung thành một bản ghi duy nhất, làm mất định danh đường dẫn symlink đang được giám sát.
  2. Nếu kẻ tấn công thay đổi symlink `target.txt` đang trỏ vào file an toàn sang trỏ vào `/etc/hosts` hoặc `/etc/shadow`, FIM không hề báo sự kiện `modified` trên symlink `target.txt`, mà lại báo sự kiện `created` trên file `/etc/hosts` (*Đã kiểm chứng thực nghiệm tại test suite*).
- **Tác động (Impact):**
  Gây sai lệch ngữ cảnh điều tra sự cố; không phát hiện được kỹ thuật tấn công chuyển hướng symlink (Symlink Hijacking / Redirection).
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  Giữ nguyên đường dẫn gốc `file_path` làm khóa định danh trong baseline. Sử dụng `os.lstat()` để kiểm tra thuộc tính của chính symlink thay vì gọi `Path.resolve()`.

---

### 🟡 FINDING-PHASE03-05: Điểm mù toàn diện đối với các tiến trình ngắn hạn (< 10s) do cơ chế thăm dò người dùng (Userspace Polling)
- **Mức độ nghiêm trọng:** **MEDIUM** (CVSS: 6.2 - Medium)
- **Phase ảnh hưởng:** Phase 3 (Process Collector Architecture)
- **File / Vị trí:** [`agent/process_collector.py`](file:///home/kali/Projects/mini-edr-linux/agent/process_collector.py), [`agent/main.py`](file:///home/kali/Projects/mini-edr-linux/agent/main.py#L54)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Mini EDR Agent thu thập tiến trình hoàn toàn dựa trên cơ chế thăm dò định kỳ (Polling) ở tầng người dùng bằng `psutil.process_iter()` với chu kỳ mặc định là 10 giây (`process_interval = 10.0`).
  Hệ thống **không tích hợp bất kỳ cơ chế thu thập sự kiện ở tầng nhân Linux (Kernel-level Event Stream)** nào, chẳng hạn như:
  - Linux eBPF (`sched_process_exec`, `sched_process_exit`)
  - Linux Netlink Process Connector (`cn_proc`)
  - Linux Audit Framework (`auditd`)
- **Tác động (Impact):**
  Bất kỳ lệnh độc hại nào được thực thi và kết thúc trong khoảng thời gian giữa 2 chu kỳ quét (ví dụ: một reverse shell thực thi trong 2 giây rồi thoát, hoặc lệnh trích xuất mật khẩu `cat /etc/shadow > /tmp/out`) đều **hoàn toàn vô hình đối với EDR**. Không có bất kỳ dấu vết tiến trình nào được ghi lại trong snapshot.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  Ghi nhận rõ ràng giới hạn kiến trúc này trong báo cáo đồ án (giới hạn phạm vi mức học phần: Userspace Polling EDR). Đề xuất hướng phát triển Phase tương lai sử dụng eBPF hoặc Netlink Connector để giám sát tiến trình hướng sự kiện thời gian thực (Event-driven).

---

### 🔵 FINDING-PHASE03-06: Danh tính Agent phụ thuộc Hostname, thiếu định danh duy nhất bền vững (Local Machine UUID)
- **Mức độ nghiêm trọng:** **LOW** (CVSS: 3.8 - Low)
- **Phase ảnh hưởng:** Phase 3 (Agent Configuration & Identity)
- **File / Vị trí:** [`agent/main.py`](file:///home/kali/Projects/mini-edr-linux/agent/main.py#L73-L77)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Agent chỉ xác định `agent_id` qua biến môi trường hoặc `get_hostname()`. Nếu không có cấu hình môi trường, hai máy trạm cùng mạng có hostname trùng nhau sẽ đè dữ liệu của nhau trên Server.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  Tạo và ghi một file UUID ngẫu nhiên tại `/var/lib/mini-edr/agent_id` (hoặc trong thư mục dữ liệu của Agent) ở lần chạy đầu tiên, và luôn đọc mã UUID này cho mọi phiên chạy sau.

---

## 4. Ma Trận Kiểm Thử Thực Nghiệm Phân Hệ Linux Agent

Auditor đã xây dựng kịch bản kiểm thử độc lập [`audit_phase3_agent.py`](file:///home/kali/.gemini/antigravity-cli/brain/2f030cf6-8c2b-476d-90bd-f71588442318/scratch/audit_phase3_agent.py) và thực thi trực tiếp trên môi trường máy ảo. Kết quả thực tế:

| STT | Hạng mục Kiểm thử | Kỳ vọng | Kết quả Thực tế | Trạng thái |
| :---: | :--- | :--- | :--- | :---: |
| 1 | **Hostname Resolution** | Lấy được hostname hợp lệ khác rỗng | Trả về `sandbox` | **PASS** |
| 2 | **OS Info Extraction** | Trích xuất tên phân phối Linux | Trả về `Kali GNU/Linux Rolling` | **PASS** |
| 3 | **CPU % Calculation** | Nằm trong dải hợp lệ $[0.0, 100.0]$ | Trả về `9.1%` | **PASS** |
| 4 | **Memory % Calculation** | Nằm trong dải hợp lệ $[0.0, 100.0]$ | Trả về `78.2%` | **PASS** |
| 5 | **Disk % Calculation** | Nằm trong dải hợp lệ $[0.0, 100.0]$ | Trả về `0.0%` (container root) | **PASS** |
| 6 | **Uptime Extraction** | Giá trị số dương $\ge 0.0$ | Trả về `67601.8s` | **PASS** |
| 7 | **System Envelope Match** | Khớp 100% Data Contract `telemetry/system` | Đầy đủ `schema_version`, `message_id`, payload | **PASS** |
| 8 | **Process `cmdline` Collect** | Có thu thập trường dòng lệnh `cmdline` | `cmdline` KHÔNG có trong `PROCESS_ATTRS` | **FAILED (Lỗi High)** |
| 9 | **Process Sorting** | Danh sách tiến trình sắp xếp theo PID tăng dần | `is_sorted == True` | **PASS** |
| 10 | **Zombie Process Handling** | Bỏ qua zombie process nhẹ nhàng | Bắt `psutil.ZombieProcess` trả về `None` | **PASS** |
| 11 | **AccessDenied Fallback** | Fallback tên tiến trình dạng `proc-<pid>` | Trả về `proc-99999` an toàn, không sập | **PASS** |
| 12 | **FIM File Creation** | Phát hiện file mới tạo trong thư mục giám sát | Nhận diện đúng sự kiện `created` | **PASS** |
| 13 | **FIM File Modification** | Phát hiện thay đổi nội dung file | Nhận diện đúng sự kiện `modified` | **PASS** |
| 14 | **FIM File Deletion** | Đánh dấu missing và bảo lưu hash lịch sử | Trạng thái `missing`, hash 64-hex giữ nguyên | **PASS** |
| 15 | **FIM Symlink Identity** | Symlink phải có khóa định danh riêng | Bị gộp vào khóa file đích (Lỗi CWE-59) | **CONFIRMED (Lỗi Med)** |
| 16 | **FIM Large File Skip** | File $> 50\text{MB}$ phải bỏ qua băm SHA-256 | Bỏ qua an toàn, không tràn RAM | **PASS** |
| 17 | **FIM Network Loss Dropping** | Sự kiện an ninh không bị mất khi mất mạng | Sự kiện mất vĩnh viễn ở chu kỳ sau | **CONFIRMED (Lỗi High)** |
| 18 | **Client Bearer Header** | Header có `Authorization: Bearer <token>` | Header sinh chuẩn xác | **PASS** |
| 19 | **Client 401 Fast Fail** | Gặp HTTP 401 không được retry vô tận | Bắt `AgentAuthenticationError` lập tức | **PASS** |
| 20 | **Orchestrator Fault Isolation** | Server offline không làm sập vòng lặp Agent | Ghi nhận lỗi và tiếp tục vòng lặp | **PASS** |

---

## 5. Kết luận Phân hệ Phase 3

1. **Điểm sáng:**
   - Linux Agent được lập trình hướng module hóa rất sạch sẽ, tách biệt độc lập giữa Collector, Client và Orchestrator.
   - Cơ chế bọc ngoại lệ trong `psutil` và `inspect_file` rất vững chắc: các tình huống tiến trình chết, tiến trình zombie, quyền truy cập bị từ chối hay file dung lượng lớn đều không gây crash Agent.
   - Client sử dụng thư viện tiêu chuẩn `urllib`, tự động tính toán Exponential Backoff và từ chối retry khi gặp lỗi 401 Unauthorized.
2. **Hạn chế then chốt cần khắc phục:**
   - **Mất sự kiện FIM vĩnh viễn** khi mạng gặp sự cố do cập nhật baseline trước khi gửi thành công ([`FINDING-PHASE03-01`](#finding-phase03-01)).
   - **Thiếu sót trường dòng lệnh `cmdline`** trong Process Collector, gây mâu thuẫn trực tiếp với tài liệu thiết kế và slide thuyết trình ([`FINDING-PHASE03-02`](#finding-phase03-02)).
   - **Cần bổ sung Stat Fast-Path** cho FIM để tránh băm lại toàn bộ file trên đĩa mỗi 30s ([`FINDING-PHASE03-03`](#finding-phase03-03)).

**Xếp loại phân hệ Phase 3:** **ĐẠT TIÊU CHUẨN CÓ ĐIỀU KIỆN (PARTIAL - CONDITIONAL PASS)**.
