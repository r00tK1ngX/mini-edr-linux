# BÁO CÁO KIỂM TOÁN PHÂN HỆ — PHASE 5: DETECTION ENGINE & CORRELATION AUDIT

**Dự án:** Mini Endpoint Detection and Response for Linux (`r00tK1ngX/mini-edr-linux`)  
**Phân hệ Kiểm toán:** Động cơ Phát hiện Mối nguy & Tương quan Đa nhân tố (`detection/rules.py`, `detection/engine.py`, `detection/correlation.py`)  
**Ngày thực hiện:** 06/11/2026 (04:52 EST)  
**Tình trạng Nghiệm thu:** **PARTIAL** (Kiến trúc hướng đối tượng cho Rule Registry và ma trận tương quan được xây dựng rất đẹp; tuy nhiên phát hiện 3 lỗi High nghiêm trọng gồm việc thiếu các luật cốt lõi đã cam kết trong tài liệu, lỗi luật "ma" khiến chuỗi tấn công FIM + Process bị vô hiệu hóa trong thực tế, và khả năng bị lẩn tránh dễ dàng; kèm 1 lỗi Medium và 1 lỗi Low)  

---

## 1. Tổng quan Động cơ Phát hiện & Tương quan An ninh

Phân hệ Detection Engine đóng vai trò "bộ não" phân tích an ninh của Mini EDR, chịu trách nhiệm chuyển hóa các dữ liệu thô (raw telemetry) từ máy trạm thành các sự kiện an ninh có ngữ cảnh và cảnh báo sự cố có thể hành động. Kiến trúc bao gồm:
1. **Rule Registry & Lớp cơ sở `BaseRule`** ([`detection/rules.py`](file:///home/kali/Projects/mini-edr-linux/detection/rules.py)):
   - Định nghĩa đối tượng kết quả phát hiện chuẩn tắc `DetectionResult` gồm `rule_id`, `severity`, `risk_score`, `evidence`, `fingerprint`, `event_type`.
   - Nạp các quy tắc phát hiện mặc định hoặc từ file cấu hình JSON bên ngoài.
2. **Động cơ Phân tích Thời gian thực `DetectionEngine`** ([`detection/engine.py`](file:///home/kali/Projects/mini-edr-linux/detection/engine.py)):
   - Đánh giá từng tiến trình trong snapshot với các luật tiến trình.
   - Truy vấn 20 sự kiện FIM gần nhất trên máy trạm để đưa vào tương quan.
   - Lưu vết các sự kiện phát hiện vào bảng `security_events` và lưu cảnh báo vào bảng `alerts`.
3. **Động cơ Tương quan & Tính điểm Rủi ro `CorrelationEngine`** ([`detection/correlation.py`](file:///home/kali/Projects/mini-edr-linux/detection/correlation.py)):
   - Gom cụm các phát hiện theo từng tiến trình (`PID`).
   - Tổng hợp các nhân tố đe dọa (Đường dẫn bất thường +50đ, File ẩn +40đ, CPU cao +30đ, RAM cao +30đ, Binary vừa được FIM phát hiện thả vào đĩa +50đ).
   - Quyết định mức độ nghiêm trọng: $\ge 85$ điểm $\rightarrow$ `CRITICAL`, ngược lại $\rightarrow$ `HIGH`.
   - Khử trùng lặp cảnh báo dựa trên `alert_key = <agent_id>:correlated:proc:<pid>:<proc_name>`.

---

## 2. Kết quả Trả lời Các Câu hỏi Kiểm toán Bắt buộc

### ❓ 1. Động cơ phát hiện có khớp đúng các luật như mô tả trong tài liệu không?
- **KHÔNG — SAI LỆCH NGHIÊM TRỌNG GIỮA TÀI LIỆU VÀ MÃ NGUỒN.**
  - Tài liệu `README.md` (dòng 289-291), `ARCHITECTURE.md` (dòng 184) và `TEST_PLAN.md` (dòng 122) đều khẳng định hệ thống có luật `RULE_SHELL_SPAWN` (phát hiện shell sinh từ web server/runtime) và `RULE_SUSPICIOUS_PROCESS` (phát hiện binary độc hại `nc`, `netcat`, `nmap`, `mimikatz`, `socat`).
  - Trong mã nguồn thực tế [`detection/rules.py`](file:///home/kali/Projects/mini-edr-linux/detection/rules.py), **chỉ có duy nhất 5 luật**:
    1. `rule-process-high-cpu` (CPU $\ge 85\%$)
    2. `rule-process-high-memory` (RAM $\ge 85\%$)
    3. `rule-process-suspicious-path` (Đường dẫn `/tmp`, `/var/tmp`, `/dev/shm`)
    4. `rule-process-hidden-binary` (Tên hoặc thư mục bắt đầu bằng dấu chấm `.`)
    5. `rule-fim-sensitive-tampered` (Can thiệp `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`...)
  - Cả `RULE_SHELL_SPAWN` và luật kiểm tra danh mục công cụ hack độc hại theo tên tiến trình đều **hoàn toàn chưa được lập trình** (*Chi tiết tại FINDING-PHASE05-01*).

### ❓ 2. Chuỗi tấn công kết hợp (FIM Dropped Binary + Execution) có hoạt động trong thực tế không?
- **KHÔNG — LỖI PHANTOM RULE (LUẬT "MA") TRONG PRODUCTION PIPELINE.**
  - `CorrelationEngine` có logic cộng 50 điểm nếu binary vừa được FIM phát hiện thả vào đĩa (`matching_fim`).
  - Unit test `test_correlation_complete_attack_chain_with_fim` vượt qua được là do người phát triển đã **tự tạo một `DetectionResult` giả lập với `rule_id="rule-fim-dropped-binary"`**.
  - Trong thực tế, luật `rule-fim-dropped-binary` **không hề tồn tại**! Khi Agent gửi sự kiện FIM cho file `/tmp/dropper.elf`, hàm `RuleRegistry.evaluate_fim_event()` chỉ chạy qua `FimSensitiveFileRule` (chỉ kiểm tra `/etc`). Do đó, file `/tmp/dropper.elf` bị trả về rỗng `[]`.
  - Kết quả: Nhân tố `"fim_dropped_and_executed"` **không bao giờ được kích hoạt** trong luồng vận hành thực tế (*Chi tiết tại FINDING-PHASE05-02*).

### ❓ 3. Thuật toán tính điểm rủi ro (Risk Scoring 0-100) có đáng tin cậy không?
- **CƠ BẢN ĐẠT MỤC TIÊU CỘNG DỒN, NHƯNG THIẾU KIỂM SOÁT NGƯỠNG.**
  - Thuật toán cộng dồn điểm số theo các trọng số cố định và chặn trần tại 100 điểm (`min(100, score)`).
  - Thuật toán giải quyết tốt việc ngăn chặn cảnh báo giả mạo đối với các tiến trình chỉ đơn thuần có CPU cao (CPU cao đơn lẻ chỉ có 30 điểm và mức `medium` nên không bị đẩy thành cảnh báo độc hại).
  - Tuy nhiên, tham số cấu hình `min_correlation_score` (mặc định 75) trong `CorrelationEngine.__init__()` là **tham số chết (Dead Parameter)**: mã nguồn chỉ kiểm tra `len(factors) >= 2` mà không hề kiểm tra điểm số có vượt qua ngưỡng này hay không (*Chi tiết tại FINDING-PHASE05-04*).

### ❓ 4. Kẻ tấn công có thể lẩn tránh (Evasion) Động cơ Phát hiện không?
- **CỰC KỲ DỄ DÀNG.**
  - Kẻ tấn công chỉ cần không chạy mã độc trong `/tmp`, `/var/tmp`, `/dev/shm` (ví dụ: copy `nc` vào `/opt/nc`, `/home/user/nc`, hoặc chạy trực tiếp `/usr/bin/nc -lvnp 4444`).
  - Kẻ tấn công sử dụng reverse shell bằng thông dịch viên: `python3 -c "import socket..."` hoặc `bash -i >& /dev/tcp/...`.
  - Kẻ tấn công chạy miner giới hạn CPU dưới $85\%$ (ví dụ $80\%$).
  - Trong tất cả các trường hợp trên, Mini EDR hoàn toàn **0 cảnh báo, 0 phát hiện** (*Chi tiết tại FINDING-PHASE05-03*).

### ❓ 5. Dữ liệu cảnh báo có được gắn nhãn kỹ thuật MITRE ATT&CK không?
- **KHÔNG CÓ TRONG CODE.**
  - Mặc dù tài liệu đề cập đến framework MITRE ATT&CK, cấu trúc dữ liệu `DetectionResult`, bảng `security_events` và bảng `alerts` trong cơ sở dữ liệu **hoàn toàn không có bất kỳ trường nào lưu trữ MITRE Tactic hay Technique ID** (như `T1059`, `T1036`) (*Chi tiết tại FINDING-PHASE05-05*).

---

## 3. Danh Sách Các Phát Hiện Kiểm Toán Chi Tiết (Findings)

---

### 🔴 FINDING-PHASE05-01: Thiếu hoàn toàn các quy tắc cốt lõi đã cam kết trong tài liệu (`RULE_SHELL_SPAWN` và `RULE_SUSPICIOUS_PROCESS`)
- **Mức độ nghiêm trọng:** **HIGH** (CVSS: 7.5 - High)
- **Phase ảnh hưởng:** Phase 5 (Detection Engine Rules) & Phase 9 (Documentation Consistency)
- **File / Vị trí:** [`detection/rules.py`](file:///home/kali/Projects/mini-edr-linux/detection/rules.py#L400-L476)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Trong toàn bộ các tài liệu nghiệm thu của đồ án:
  - `README.md` (dòng 289-290): Cam kết `RULE_SUSPICIOUS_PROCESS` phát hiện công cụ độc hại (`nc`, `netcat`, `nmap`, `mimikatz`, `socat`) và `RULE_SHELL_SPAWN` phát hiện shell tương tác (`bash`, `sh`, `zsh`) được sinh ra từ Web Server hoặc Scripting runtime.
  - `TEST_PLAN.md` (dòng 120-122): Khẳng định bài test `test_detect_netcat` và `test_detect_shell_spawn` đã chạy và đạt `PASS`.
  **Tuy nhiên, rà soát thực tế toàn bộ thư mục `detection/` và `tests/`:**
  - Không hề có bất kỳ class nào tên là `ProcessShellSpawnRule` hoặc rule nào kiểm tra quan hệ cha-con (PPID web server sinh ra PID shell).
  - Không hề có bất kỳ class nào kiểm tra danh mục binary độc hại theo tên (như `nmap`, `mimikatz`, `socat`, `nc`).
  - Các bài test `test_detect_shell_spawn` được ghi nhận trong `TEST_PLAN.md` **thực chất không hề tồn tại trong file test**.
- **Tác động (Impact):**
  1. Đồ án bị thiếu hụt nghiêm trọng các tính năng phát hiện an ninh cốt lõi đã báo cáo với Hội đồng.
  2. Kịch bản demo chạy reverse shell `nc` thực chất chỉ được phát hiện là nhờ nó tình cờ được đặt trong thư mục `/tmp` (kích hoạt `ProcessSuspiciousPathRule`), chứ hệ thống hoàn toàn không nhận biết được tiến trình đó là `nc` hay reverse shell.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  1. Triển khai class `ProcessShellSpawnRule`: kiểm tra nếu `process_name` nằm trong `("bash", "sh", "zsh", "dash")` và tiến trình cha (hoặc username) thuộc các dịch vụ mạng (`www-data`, `nginx`, `apache2`, `php`, `python`).
  2. Triển khai class `ProcessMaliciousToolRule`: kiểm tra `process_name` hoặc `exe_path` khớp với danh sách công cụ tấn công phổ biến (`nc`, `nmap`, `socat`, `tcpdump`, `chisel`).

---

### 🔴 FINDING-PHASE05-02: Lỗi luật "ma" (Phantom Rule): Chuỗi tấn công FIM Dropped Binary (`fim_dropped_and_executed`) không thể kích hoạt trong thực tế
- **Mức độ nghiêm trọng:** **HIGH** (CVSS: 7.2 - High)
- **Phase ảnh hưởng:** Phase 5 (Detection Engine & Correlation Pipeline)
- **File / Vị trí:** [`detection/rules.py`](file:///home/kali/Projects/mini-edr-linux/detection/rules.py#L491-L502), [`detection/engine.py`](file:///home/kali/Projects/mini-edr-linux/detection/engine.py#L88-L90), [`detection/correlation.py`](file:///home/kali/Projects/mini-edr-linux/detection/correlation.py#L116-L122)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  1. Trong [`detection/correlation.py`](file:///home/kali/Projects/mini-edr-linux/detection/correlation.py):
     Hàm `correlate_process_and_fim()` kiểm tra xem file thực thi `exe_path` có nằm trong danh sách các phát hiện FIM gần đây (`fim_detections`) hay không:
     ```python
     if matching_fim:
         score += 50
         factors.append({"factor": "fim_dropped_and_executed", ...})
     ```
  2. Trong [`detection/engine.py`](file:///home/kali/Projects/mini-edr-linux/detection/engine.py):
     `recent_fim_detections` được lấy bằng cách:
     ```python
     matches = self.rules.evaluate_fim_event(agent_id, ev)
     recent_fim_detections.extend(matches)
     ```
  3. Trong [`detection/rules.py`](file:///home/kali/Projects/mini-edr-linux/detection/rules.py):
     Hàm `evaluate_fim_event()` **chỉ chạy duy nhất một luật là `FimSensitiveFileRule`**. Mà `FimSensitiveFileRule` chỉ kiểm tra các file cấu hình nhạy cảm trong `/etc` (`/etc/shadow`, `/etc/passwd`...).
  4. Khi kẻ tấn công thả một file thực thi độc hại (ví dụ `/tmp/dropper.elf` hoặc `/tmp/nc`) và FIM gửi sự kiện `fim_file_created`, hàm `evaluate_fim_event()` thấy file này không thuộc `/etc` nên trả về danh sách rỗng `[]`.
  5. Vì vậy, `recent_fim_detections` không bao giờ chứa thông tin của file `/tmp/dropper.elf`. Khi snapshot tiến trình chạy `/tmp/dropper.elf` gửi lên, `matching_fim` luôn luôn là rỗng `[]`!
  6. Bài unit test `test_correlation_complete_attack_chain_with_fim` trong `tests/test_detection.py` vượt qua được là do nó tự khởi tạo một đối tượng giả mạo mang `rule_id="rule-fim-dropped-binary"`, một luật chưa từng được viết trong mã nguồn.
- **Tác động (Impact):**
  Tính năng tương quan đa nhân tố "Attack Chain" tự hào nhất của đồ án (kết hợp FIM phát hiện file thả vào đĩa + Process kích hoạt file) **hoàn toàn là mã chết (Dead Code)** trong luồng vận hành thực tế. Điểm số tương quan bị mất đi 50 điểm quan trọng và không phản ánh đúng kịch bản chuỗi tấn công.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  Xây dựng luật `FimDroppedBinaryRule(BaseRule)` trong `detection/rules.py`:
  - Khớp các sự kiện FIM `fim_file_created` có đường dẫn thuộc `/tmp`, `/var/tmp`, `/dev/shm` hoặc có cờ thực thi `file_mode & 0o111 != 0`.
  - Đăng ký luật này vào `RuleRegistry.evaluate_fim_event()` để đưa vào danh sách `fim_detections`.

---

### 🔴 FINDING-PHASE05-03: Điểm mù lẩn tránh (Trivial Evasion): Không thể phát hiện mã độc chạy ngoài thư mục tạm hoặc chạy qua thông dịch viên
- **Mức độ nghiêm trọng:** **HIGH** (CVSS: 7.4 - High)
- **Phase ảnh hưởng:** Phase 5 (Detection Coverage & Robustness)
- **File / Vị trí:** [`detection/rules.py`](file:///home/kali/Projects/mini-edr-linux/detection/rules.py#L222-L224)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Luật `ProcessSuspiciousPathRule` chỉ so sánh đường dẫn cứng:
  ```python
  DEFAULT_SUSPICIOUS_PATHS = ["/tmp", "/var/tmp", "/dev/shm"]
  ```
  Nếu kẻ tấn công:
  1. Thực thi tiện ích mạng nguy hiểm từ thư mục hợp pháp: `/usr/bin/nc -lvnp 4444` hoặc `/bin/nc 10.0.0.1 4444`.
  2. Tạo thư mục riêng trên máy trạm để chạy mã độc: `/home/kali/tools/malware` hoặc `/opt/app/backdoor`.
  3. Sử dụng kỹ thuật Living-off-the-Land (LotL) qua Python/Bash/Perl/PHP: `python3 -c "..."` (đường dẫn thực thi là `/usr/bin/python3`).
  Do Agent không thu thập dòng lệnh `cmdline` (đã chỉ ra ở `FINDING-PHASE03-02`) và Detection Engine chỉ nhìn vào `exe_path`, toàn bộ các hành vi tấn công trên **hoàn toàn vô hình** trước hệ thống Mini EDR.
- **Tác động (Impact):**
  Hiệu quả phát hiện thực tế của EDR bị giới hạn nghiêm trọng; bất kỳ kẻ tấn công nào có kiến thức cơ bản về Linux đều có thể né tránh toàn bộ các luật phát hiện mà không cần kỹ thuật bypass phức tạp.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  Bổ sung luật phát hiện dựa trên tên tiến trình nguy hiểm (Process Name Blacklist) độc lập với đường dẫn, và tích hợp phân tích tham số dòng lệnh `cmdline`.

---

### 🟡 FINDING-PHASE05-04: Tham số `min_correlation_score` trong `CorrelationEngine` là tham số chết (Dead Parameter)
- **Mức độ nghiêm trọng:** **MEDIUM** (CVSS: 4.3 - Medium)
- **Phase ảnh hưởng:** Phase 5 (Correlation Configuration)
- **File / Vị trí:** [`detection/correlation.py`](file:///home/kali/Projects/mini-edr-linux/detection/correlation.py#L38-L40), [`detection/correlation.py`](file:///home/kali/Projects/mini-edr-linux/detection/correlation.py#L128)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Trong hàm khởi tạo:
  ```python
  class CorrelationEngine:
      def __init__(self, min_correlation_score: int = 75):
          self.min_correlation_score = int(min_correlation_score)
  ```
  Tuy nhiên, trong toàn bộ phương thức `correlate_process_and_fim()`, biến `self.min_correlation_score` **không bao giờ được đem ra so sánh**. Điều kiện duy nhất để sinh cảnh báo tương quan là:
  ```python
  if len(factors) >= 2:
      severity = "critical" if total_score >= 85 else "high"
      ...
  ```
  Ngay cả khi người quản trị khởi tạo `CorrelationEngine(min_correlation_score=95)`, một tiến trình có 2 nhân tố với tổng điểm chỉ 60 điểm (ví dụ High CPU 30đ + High RAM 30đ) vẫn sẽ kích hoạt cảnh báo tương quan mức `HIGH`.
- **Tác động (Impact):**
  Cấu hình ngưỡng tương quan từ bên ngoài hoàn toàn không có tác dụng; logic nghiệp vụ không đúng với thiết kế API của class.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  Sửa điều kiện kiểm tra:
  ```python
  if len(factors) >= 2 and total_score >= self.min_correlation_score:
  ```

---

### 🔵 FINDING-PHASE05-05: Thiếu trường gắn nhãn định danh kỹ thuật MITRE ATT&CK trong cấu trúc dữ liệu và Database
- **Mức độ nghiêm trọng:** **LOW** (CVSS: 3.1 - Low)
- **Phase ảnh hưởng:** Phase 5 (Data Modeling) & Phase 7 (Dashboard Display)
- **File / Vị trí:** [`detection/rules.py`](file:///home/kali/Projects/mini-edr-linux/detection/rules.py#L31-L43), [`server/migrations/001_phase2_data_model.sql`](file:///home/kali/Projects/mini-edr-linux/server/migrations/001_phase2_data_model.sql#L274)
- **Căn nguyên Kỹ thuật (Technical Root Cause):**
  Cả dataclass `DetectionResult` lẫn bảng cơ sở dữ liệu `alerts` đều không có trường `mitre_attack_id` hay `mitre_tactic`. Trên giao diện Dashboard, các cảnh báo không hiển thị được mã kỹ thuật MITRE tương ứng để hỗ trợ chuyên viên SOC tra cứu Threat Intelligence nhanh.
- **Biện pháp Khắc phục Khuyến nghị (Remediation):**
  Thêm trường `mitre_attack_id: Optional[str] = None` vào `BaseRule` và `DetectionResult`, bổ sung cột `mitre_attack_id TEXT` vào bảng `alerts`.

---

## 4. Ma Trận Kiểm Thử Thực Nghiệm Phân Hệ Detection & Correlation

Auditor đã xây dựng kịch bản kiểm thử độc lập [`audit_phase5_detection.py`](file:///home/kali/.gemini/antigravity-cli/brain/2f030cf6-8c2b-476d-90bd-f71588442318/scratch/audit_phase5_detection.py) và thực thi trực tiếp trên môi trường ảo:

| STT | Hạng mục Kiểm thử | Kỳ vọng | Kết quả Thực tế | Trạng thái |
| :---: | :--- | :--- | :--- | :---: |
| 1 | **Rule Loading** | Nạp đủ các luật trong hệ thống | Nạp 5 luật cơ bản | **PASS** |
| 2 | **RULE_SHELL_SPAWN** | Tồn tại luật bắt shell sinh từ web/runtime | Luật KHÔNG tồn tại trong codebase | **FAILED (Lỗi High)** |
| 3 | **FIM Dropped Binary Rule** | Tồn tại luật bắt binary thả vào đĩa | Luật KHÔNG tồn tại (chỉ có trong mock test) | **FAILED (Lỗi High)** |
| 4 | **CPU Threshold (85%)** | Bắt CPU $\ge 85\%$, bỏ qua CPU $< 85\%$ | $86\%$ bắt, $84.9\%$ bỏ qua chuẩn xác | **PASS** |
| 5 | **Suspicious Path /tmp** | Bắt tiến trình chạy từ `/tmp` và `/dev/shm` | Nhận diện đúng cả `/tmp` và `/dev/shm` | **PASS** |
| 6 | **Standard Path /usr/bin/nc**| Bắt netcat khi chạy từ `/usr/bin/nc` | Bị bỏ sót hoàn toàn (Evasion 1) | **CONFIRMED (Lỗi High)** |
| 7 | **Hidden Binary Detection** | Bắt tên có dấu chấm hoặc thư mục ẩn | Nhận diện đúng `.hidden_service` | **PASS** |
| 8 | **FIM Sensitive /etc/shadow**| Sửa `/etc/shadow` sinh alert Critical | Sinh alert `critical` (80 điểm) | **PASS** |
| 9 | **FIM Dropped Binary in /tmp**| Sự kiện tạo file `/tmp/nc` được nạp | Bị `FimSensitiveFileRule` bỏ qua | **CONFIRMED (Lỗi High)** |
| 10 | **Attack Chain FIM Factor** | Alert chứa nhân tố `fim_dropped_and_executed` | Nhân tố KHÔNG xuất hiện trong alert thật | **CONFIRMED (Lỗi High)** |
| 11 | **Dead min_correlation_score**| Đặt ngưỡng 99đ phải chặn alert 80đ | Alert 80đ vẫn sinh (tham số bị bỏ qua) | **CONFIRMED (Lỗi Med)** |
| 12 | **Evasion: Python Reverse Shell**| Bắt python reverse shell từ `/usr/bin` | Bị bỏ sót hoàn toàn (Evasion 2) | **CONFIRMED (Lỗi High)** |
| 13 | **Evasion: Throttled Miner** | Bắt miner chạy tại `/opt` chiếm 80% CPU | Bị bỏ sót hoàn toàn (Evasion 3) | **CONFIRMED (Lỗi High)** |
| 14 | **Single CPU Spike Isolation** | CPU cao đơn lẻ không kết luận mã độc | Không sinh alert độc hại đơn lẻ | **PASS** |

---

## 5. Kết luận Phân hệ Phase 5

1. **Điểm sáng:**
   - Cấu trúc module hóa của `BaseRule`, `DetectionResult`, `RuleRegistry` và `CorrelationEngine` được thiết kế theo tư duy Clean Architecture, dễ đọc, dễ mở rộng.
   - Cơ chế gom cụm nhiều nhân tố (Multi-factor correlation) kết hợp trọng số là định hướng rất đúng đắn của các giải pháp SIEM / EDR hiện đại để giảm thiểu báo động giả (False Positives).
2. **Hạn chế then chốt cần khắc phục:**
   - **Bổ sung các luật cốt lõi bị thiếu**: Khẩn trương lập trình `ProcessShellSpawnRule` và `ProcessMaliciousToolRule` như đã cam kết trong tài liệu báo cáo ([`FINDING-PHASE05-01`](#finding-phase05-01)).
   - **Khắc phục lỗi Phantom Rule**: Viết luật `FimDroppedBinaryRule` để nối lại chuỗi tương quan tấn công bị đứt gãy giữa FIM và Process ([`FINDING-PHASE05-02`](#finding-phase05-02)).
   - **Kích hoạt tham số `min_correlation_score`** trong logic so sánh của `CorrelationEngine` ([`FINDING-PHASE05-04`](#finding-phase05-04)).

**Xếp loại phân hệ Phase 5:** **ĐẠT TIÊU CHUẨN CÓ ĐIỀU KIỆN (PARTIAL - CONDITIONAL PASS)**.
