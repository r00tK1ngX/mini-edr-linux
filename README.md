# Mini EDR for Linux (Endpoint Detection and Response)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/flask-3.x-green.svg)](https://flask.palletsprojects.com/)
[![SQLite](https://img.shields.io/badge/sqlite-WAL%20mode-lightgrey.svg)](https://www.sqlite.org/)
[![Tests](https://img.shields.io/badge/tests-230%20passed-brightgreen.svg)](tests/)
[![Dashboard](https://img.shields.io/badge/ui-cyberpunk%20hacker-00f0ff.svg)](templates/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)

An educational and modular **Mini Endpoint Detection and Response (EDR)** system built specifically for Linux environments (Ubuntu, Debian, Kali Linux). 

Mini EDR combines an independent host-level monitoring Agent, a secure centralized ingestion API, a real-time explainable Detection & Correlation Engine, and a modern **Cyberpunk Hacker / SOC Command Center Web Dashboard** for incident triage and investigation.

---

## 📑 Mục lục (Table of Contents)

1. [Tính năng Nổi bật (Key Features)](#tính-năng-nổi-bật-key-features)
2. [Kiến trúc Tổng quan (Architecture)](#kiến-trúc-tổng-quan-architecture)
3. [Công nghệ Sử dụng (Tech Stack)](#công-nghệ-sử-dụng-tech-stack)
4. [Cấu trúc Thư mục Dự án (Project Structure)](#cấu-trúc-thư-mục-dự-án-project-structure)
5. [Cài đặt & Khởi chạy Nhanh (Quickstart Guide)](#cài-đặt--khởi-chạy-nhanh-quickstart-guide)
   - [5.1. Yêu cầu môi trường](#51-yêu-cầu-môi-trường)
   - [5.2. Thiết lập môi trường ảo & cấu hình `.env`](#52-thiết-lập-môi-trường-ảo--cấu-hình-env)
   - [5.3. Khởi chạy Server & Web Dashboard](#53-khởi-chạy-server--web-dashboard)
   - [5.4. Nạp dữ liệu mẫu Demo (Demo Seeder)](#54-nạp-dữ-liệu-mẫu-demo-demo-seeder)
   - [5.5. Khởi chạy Linux Agent](#55-khởi-chạy-linux-agent)
6. [Giao diện Cyberpunk Web Dashboard](#giao-diện-cyberpunk-web-dashboard)
7. [Động cơ Phát hiện & Quy tắc An ninh (Detection Engine)](#động-cơ-phát-hiện--quy-tắc-an-ninh-detection-engine)
8. [Vòng đời Xử lý Sự cố (Incident Lifecycle)](#vòng-đời-xử-lý-sự-cố-incident-lifecycle)
9. [Bảo mật & Gia cố Hệ thống (Security Hardening)](#bảo-mật--gia-cố-hệ-thống-security-hardening)
10. [Kiểm thử Hệ thống (Testing & Verification)](#kiểm-thử-hệ-thống-testing--verification)
11. [Tài liệu Kỹ thuật Chi tiết (Documentation)](#tài-liệu-kỹ-thuật-chi-tiết-documentation)

---

## 1. Tính năng Nổi bật (Key Features)

- 🖥️ **Quản lý Hạm đội Máy trạm (Fleet Inventory):** Tự động phát hiện và quản lý trạng thái máy trạm `online`/`offline` theo chu kỳ Heartbeat thời gian thực.
- 📊 **Giám sát Tài nguyên & Tiến trình (Process & Resource Monitoring):** Thu thập CPU%, RAM%, Disk%, Uptime và chụp ảnh snapshot toàn diện bảng tiến trình `/proc` (PID, PPID, User, Path, Cmdline, RSS).
- 🛡️ **Giám sát Toàn vẹn Tệp tin (FIM - File Integrity Monitoring):** Theo dõi đệ quy các thư mục hệ thống nhạy cảm (`/etc`, `/bin`, `/sbin`) sử dụng mã băm mật mã học **SHA-256** để phát hiện tức thời hành vi thêm, sửa, xóa tệp.
- ⚡ **Động cơ Phát hiện Tương quan (Real-time Detection & Correlation Engine):** Khớp các quy tắc phát hiện mối nguy (Reverse shell, Netcat, Hack tools, Leo thang đặc quyền, Can thiệp `/etc/shadow`), tính điểm rủi ro $0 - 100$ và khử trùng cảnh báo bằng `alert_key`.
- 🚨 **Quản lý Sự cố Toàn diện (Incident Triage & Response):** Cung cấp luồng xử lý sự cố an ninh chuẩn SOC (`NEW` ➔ `ACKNOWLEDGED` ➔ `RESOLVED`), lưu vết thời gian và ghi chú giải quyết (`resolution_note`).
- 🌐 **Cyberpunk Hacker Web Dashboard:** Bảng điều khiển SOC Command Center với giao diện Dark Terminal, dải màu Neon, quét lưới Matrix CRT, xác thực phiên người dùng (`/login`), chống CSRF và XSS, đồ thị và modals trực quan hóa dữ liệu 100% độc lập không cần Internet (Air-gapped ready).
- 🔒 **Gia cố An toàn & Toàn vẹn Dữ liệu:** Xác thực Bearer Token ($\ge 32$ ký tự), bảo vệ CSRF (`X-CSRF-Token`), 100% Parameterized SQL ngăn SQLi, chống DOM XSS qua `escapeHtml()`, chống gửi lặp bằng UUIDv4, giới hạn payload 16 MiB (`EDR_MAX_CONTENT_LENGTH`), cam kết FIM hai pha (Two-phase commit) và ngăn hạ cấp mức độ nghiêm trọng của Alert.

---

## 2. Kiến trúc Tổng quan (Architecture)

Mini EDR hoạt động theo mô hình Client-Server phân tán:

```text
┌─────────────────────────────────┐                 ┌─────────────────────────────────┐
│       LINUX AGENT (Client)      │                 │    FLASK API SERVER (Backend)   │
│                                 │                 │                                 │
│  - System Metrics Collector     │  HTTP / JSON    │  - Bearer Token Auth Guard      │
│  - Process Table Collector      ├────────────────►│  - Payload Validation & Limits  │
│  - File Integrity Monitor (FIM) │  (Envelope 1.0) │  - Ingestion APIs               │
│  - Orchestrator Scheduling      │                 │  - Detection & Correlation      │
│  - Fail-soft HTTP Client        │                 │  - Repositories DAL (Param SQL) │
└─────────────────────────────────┘                 └────────────────┬────────────────┘
                                                                     │
                                                    ┌────────────────┴────────────────┐
                                                    │     SQLite3 Database (WAL)      │
                                                    │  (Endpoints, Metrics, Baseline, │
                                                    │   Processes, Events, Alerts)    │
                                                    └────────────────┬────────────────┘
                                                                     │
                                                    ┌────────────────┴────────────────┐
                                                    │     CYBERPUNK WEB DASHBOARD     │
                                                    │   (Overview, Fleet, Incidents,  │
                                                    │    Audit Logs, AJAX Actions)    │
                                                    └─────────────────────────────────┘
```

Xem sơ đồ chi tiết và các sequence diagrams tại [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 3. Công nghệ Sử dụng (Tech Stack)

| Thành phần | Công nghệ | Mục đích |
|---|---|---|
| **Ngôn ngữ** | Python 3.10+ | Toàn bộ Agent, Server, Detection Engine, DAL |
| **Backend Framework** | Flask 3.x | API Gateway, Web Routing, Jinja2 Templating |
| **Cơ sở dữ liệu** | SQLite 3 (WAL mode) | Cơ sở dữ liệu nhúng, khóa ngoại ON, hiệu năng cao |
| **Agent Collector** | `psutil` & Python Standard Lib | Thu thập tài nguyên phần cứng, tiến trình, mạng |
| **Cryptography** | `hashlib` (SHA-256), `secrets` | Băm tệp FIM, sinh token bảo mật |
| **Frontend UI** | HTML5, Modern CSS3, Vanilla ES6+ | Giao diện Cyberpunk Hacker, Modals, Toast (Offline) |
| **Testing Framework** | `pytest`, `pytest-cov` | 214 bài test tự động từ Unit đến E2E & Security |

---

## 4. Cấu trúc Thư mục Dự án (Project Structure)

```text
mini-edr-linux/
├── agent/                       # Phân hệ Linux Agent thu thập dữ liệu
│   ├── __main__.py              # Entrypoint thực thi `python -m agent`
│   ├── client.py                # HTTP client gửi bản tin chuẩn Envelope 1.0
│   ├── file_integrity.py        # Giám sát toàn vẹn tệp (FIM) bằng SHA-256 (Two-phase commit)
│   ├── main.py                  # Agent Orchestrator loop & vòng lặp quét
│   ├── orchestrator.py          # Bộ điều phối vòng lặp thu thập định kỳ
│   ├── process_collector.py     # Quét 9 thuộc tính tiến trình qua /proc
│   └── system_collector.py      # Thu thập thông số phần cứng CPU/RAM/Disk
├── detection/                   # Phân hệ Động cơ Phát hiện & Quy tắc An ninh
│   ├── correlation.py           # Động cơ phân tích tương quan & ngưỡng min_correlation_score
│   ├── engine.py                # Pipeline phát hiện & tính điểm rủi ro Risk Score
│   └── rules.py                 # Danh mục 7 quy tắc an ninh ánh xạ MITRE ATT&CK
├── server/                      # Phân hệ Flask API Server & Web Backend
│   ├── app.py                   # Flask Application Factory & Server entry point
│   ├── db.py                    # Khởi tạo kết nối SQLite, WAL mode & busy timeout
│   ├── routes.py                # Ingestion API Routes (/heartbeat, /telemetry/*, /alerts)
│   ├── web.py                   # Web Dashboard Blueprint, Session Auth & CSRF Guard
│   ├── migrations/              # Bộ quản lý Schema Migration tự động
│   │   ├── runner.py            # Migration runner kiểm tra Checksum SHA-256
│   │   └── sql/                 # Các script tạo cấu trúc bảng SQLite
│   └── repositories/            # Tầng Data Access Layer (DAL) cách ly SQL
│       ├── alert_repository.py  # Quản lý sự cố, Non-downgrade severity & Reopening
│       ├── base.py
│       ├── baseline_repository.py
│       ├── endpoint_repository.py
│       ├── event_repository.py
│       ├── process_repository.py
│       └── system_metrics_repository.py
├── static/                      # Tài nguyên giao diện tĩnh (Cyberpunk CSS & JS)
│   ├── style.css                # Bộ stylesheet Cyberpunk Theme hoàn chỉnh
│   └── dashboard.js             # Logic đồng hồ số, CSRF, DOM XSS Sanitizer & Modals
├── templates/                   # Giao diện Jinja2 HTML Templates
│   ├── base.html                # HUD Topbar, navigation & Modal container
│   ├── login.html               # Trang xác thực Operator Console Cyberpunk
│   ├── dashboard.html           # Trang 1: SOC Command Center Overview
│   ├── endpoints.html           # Trang 2: Endpoint Fleet & Inspection Modal
│   ├── alerts.html              # Trang 3: Incident Response & Triage Console
│   └── events.html              # Trang 4: Security Audit Logs & FIM Stream
├── scripts/                     # Scripts hỗ trợ và tiện ích
│   ├── seed_demo_data.py        # Sinh dữ liệu mẫu chân thực phục vụ demo
│   └── simulate_attack_scenario.py # Mô phỏng tấn công E2E 5 bước trực tiếp
├── tests/                       # Toàn bộ 230 ca kiểm thử tự động (100% Pass)
│   ├── test_agent_client.py
│   ├── test_agent_orchestrator.py
│   ├── test_alert_management.py
│   ├── test_api.py
│   ├── test_correlation.py
│   ├── test_detection.py
│   ├── test_file_integrity.py
│   ├── test_full_system_e2e.py  # Kiểm thử vòng đời hệ thống E2E
│   ├── test_security_reliability.py # 25 bài test bảo mật (SQLi, DOM XSS, CSRF, Token)
│   └── ...
├── docs/                        # Tài liệu đặc tả kỹ thuật chi tiết
│   ├── ARCHITECTURE.md          # Đặc tả kiến trúc, sơ đồ ERD & sequence
│   ├── DATA_CONTRACT.md         # Hợp đồng dữ liệu Envelope & 9 thuộc tính tiến trình
│   ├── API_SPECIFICATION.md     # Đặc tả API endpoints & Web routes
│   ├── TEST_PLAN.md             # Kế hoạch và ma trận 230 ca kiểm thử
│   ├── DEMO_SCENARIO.md         # Kịch bản diễn tập thuyết trình demo 5-7 phút
│   └── PRESENTATION_SLIDES_OUTLINE.md # Đề cương 13 slide bảo vệ đồ án trước Hội đồng
├── requirements.txt             # Danh sách thư viện Python
└── README.md                    # Hướng dẫn tổng quan dự án
```

---

## 5. Cài đặt & Khởi chạy Nhanh (Quickstart Guide)

### 5.1. Yêu cầu môi trường
- Hệ điều hành: Linux (Ubuntu 22.04+, Debian 12+, Kali Linux, v.v.).
- Python: Phiên bản 3.10 trở lên.

### 5.2. Thiết lập môi trường ảo & cấu hình `.env`

Từ thư mục gốc dự án:

```bash
# 1. Tạo và kích hoạt môi trường ảo Python
python3 -m venv .venv
source .venv/bin/activate

# 2. Cài đặt các thư viện phụ thuộc
pip install --upgrade pip
pip install -r requirements.txt

# 3. Tạo file cấu hình từ mẫu
cp .env.example .env
```

Tạo một API Token bảo mật ngẫu nhiên:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Mở `.env` và gán giá trị vừa sinh vào biến `EDR_API_TOKEN`:

```env
EDR_API_TOKEN=your_secure_generated_token_here
EDR_HOST=127.0.0.1
EDR_PORT=5000
EDR_DATABASE_PATH=data/mini_edr.db
EDR_OFFLINE_AFTER_SECONDS=15
```

### 5.3. Khởi chạy Server & Web Dashboard

```bash
python3 -m server.app
```

Khi server khởi động:
- Bộ migration tự động kiểm tra và tạo database SQLite tại `data/mini_edr.db`.
- Server lắng nghe tại `http://127.0.0.1:5000`.
- Kiểm tra trạng thái server:
  ```bash
  curl -i http://127.0.0.1:5000/health
  # Trả về: {"status": "ok"}
  ```

### 5.4. Nạp dữ liệu mẫu Demo (Demo Seeder)

Để phục vụ trình diễn và đánh giá đồ án trực quan mà không cần chờ chạy nhiều máy trạm trong thực tế, dự án tích hợp sẵn script nạp dữ liệu mẫu hoàn chỉnh:

```bash
python3 scripts/seed_demo_data.py
```

Script sẽ nạp:
- 3 máy trạm mẫu (`ubuntu-prod-01`, `kali-attacker-lab`, `debian-database-srv`) với trạng thái Online/Offline rõ ràng.
- Chuỗi đo lường CPU, RAM, Disk lịch sử.
- Danh mục Baseline giám sát FIM cho `/etc/shadow`, `/usr/bin/sudo`, v.v.
- Snapshot tiến trình chứa tiến trình độc hại `/tmp/nc -lvnp 4444`.
- 3 Sự kiện an ninh và 3 Cảnh báo an ninh tương ứng ở các trạng thái `NEW`, `ACKNOWLEDGED`, `RESOLVED`.

### 5.5. Khởi chạy Linux Agent

Mở một terminal mới (trong môi trường ảo):

```bash
# Khởi chạy qua entrypoint module:
python3 -m agent
# hoặc:
python3 -m agent.main
```

Agent sẽ lập tức:
1. Thu thập thông tin máy và gửi Heartbeat lên Server.
2. Quét bảng tiến trình `/proc` (9 thuộc tính cốt lõi) và gửi Process Snapshot.
3. Thiết lập baseline FIM ban đầu và theo dõi thay đổi tệp tin với cơ chế Two-phase commit.

### 5.6. Chạy kịch bản tấn công mô phỏng trực tiếp (Attack Simulator)

Hệ thống tích hợp tiện ích mô phỏng tấn công thời gian thực 5 bước phục vụ trình diễn và bảo vệ đồ án:

```bash
# Chế độ trình diễn tương tác từng bước (ấn ENTER để kích hoạt từng bước tấn công):
python3 scripts/simulate_attack_scenario.py

# Hoặc chế độ tự động hóa:
python3 scripts/simulate_attack_scenario.py --auto
```

Kịch bản thực hiện: Đăng ký Endpoint Heartbeat ➔ Tạo FIM Baseline ➔ Tấn công sửa đổi tệp `/tmp/mini_edr_demo/secure_config.conf` ➔ Thực thi tiện ích `/tmp/nc -lvnp 4444` ➔ Hiển thị báo cáo thống kê Alert trên Web Console.

---

## 6. Giao diện Cyberpunk Web Dashboard

Mở trình duyệt truy cập: **`http://127.0.0.1:5000/dashboard`**

Khi chưa đăng nhập, hệ thống tự động chuyển hướng đến màn hình xác thực Operator Console (`/login`). Nhập API Token đã cấu hình để tạo phiên làm việc an toàn.

Hệ thống cung cấp 4 phân hệ màn hình chuyên biệt:

1. **SOC Command Center Overview (`/dashboard`):**
   - 4 Cyber KPI Tiles: Tổng số thiết bị, Sự cố đang kích hoạt (New/Ack), Mối đe dọa mức độ nghiêm trọng (Critical/High), Số sự kiện an ninh tiếp nhận.
   - 3 Thanh đo tài nguyên mạng phát sáng Neon (CPU, RAM, Disk trung bình) tự động chuyển sang màu đỏ cảnh báo khi vượt 85%.
   - Ma trận phân bổ mức độ nghiêm trọng cảnh báo (Severity Matrix).
   - Luồng sự cố an ninh trực tiếp (Active Incidents Stream).
2. **Endpoint Fleet Matrix (`/endpoints`):**
   - Bảng quản lý máy trạm kèm bộ lọc trạng thái nhanh (`ALL`, `ONLINE`, `OFFLINE`) và ô tìm kiếm tức thời theo hostname/IP.
   - Nút **INSPECT**: Mở Cyber Modal nạp danh sách tiến trình đang chạy và số tệp FIM được giám sát qua AJAX.
3. **Incident Response & Triage Console (`/alerts`):**
   - Bảng điều khiển phân loại và xử lý sự cố an ninh được bảo vệ bằng CSRF Token.
   - Nút **EVIDENCE**: Mở Modal xem chi tiết JSON evidence và các security events liên quan (chống DOM XSS).
   - Thao tác trực tiếp không cần reload trang:
     - `ACK`: Tiếp nhận xử lý sự cố.
     - `RESOLVE`: Mở modal nhập kết luận khắc phục và đóng cảnh báo.
     - `DISMISS`: Bỏ qua cảnh báo dương tính giả.
4. **Security Audit Logs (`/events`):**
   - Nhật ký kiểm toán toàn bộ sự kiện an ninh và dữ liệu telemetry FIM.

---

## 7. Động cơ Phát hiện & Quy tắc An ninh (Detection Engine)

Detection Engine tích hợp sẵn 7 quy tắc phát hiện rõ ràng (explainable), ánh xạ đầy đủ theo khung ma trận tấn công **MITRE ATT&CK**:

| Mã Quy tắc | Tên Quy tắc | Hành vi Giám sát | Mức độ | MITRE ATT&CK |
|---|---|---|---|---|
| `rule-proc-suspicious-path` | `RULE_SUSPICIOUS_PROCESS` | Phát hiện binary độc hại (`nc`, `netcat`, `nmap`, `mimikatz`, `socat`) hoặc chạy từ thư mục bất thường (`/tmp`, `/dev/shm`, `/var/tmp`) | `CRITICAL` | T1059.004 |
| `rule-proc-shell-spawn` | `RULE_SHELL_SPAWN` | Phát hiện shell (`bash`, `sh`, `zsh`) được sinh ra dưới ngữ cảnh daemon/web service (`www-data`, `apache2`, `nginx`) | `HIGH` | T1059.004 |
| `rule-proc-high-cpu` | `RULE_HIGH_CPU_PROCESS` | Phát hiện tiến trình chiếm dụng $\ge 85.0\%$ CPU kéo dài (dấu hiệu đào tiền ảo / DoS) | `MEDIUM` | T1496 |
| `rule-fim-sensitive-file` | `RULE_FIM_SENSITIVE_FILE` | Phát hiện can thiệp tệp cấu hình bảo mật cốt lõi (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) | `HIGH` | T1003.008 |
| `rule-fim-dropped-binary` | `RULE_FIM_DROPPED_BINARY` | Phát hiện tệp thực thi ELF hoặc script mới được thả vào các thư mục tạm (`/tmp`, `/var/tmp`, `/dev/shm`) | `HIGH` | T1105 |
| `rule-fim-critical-deleted` | `RULE_FIM_CRITICAL_DELETED` | Phát hiện xóa tệp hệ thống hoặc tệp cấu hình an ninh trọng yếu | `HIGH` | T1070.004 |
| `rule-fim-service-tamper` | `RULE_FIM_SERVICE_TAMPER` | Phát hiện can thiệp hoặc thay đổi trái phép unit service (`systemd`) | `MEDIUM` | T1543.002 |

**Cơ chế Tính điểm Rủi ro (Correlation & Risk Scoring):**
- Động cơ phân tích tương quan (`detection/correlation.py`) phân tích đa sự kiện trong khung thời gian trượt (Sliding Time Window = 300s).
- Khi có ít nhất 2 yếu tố vi phạm và tổng điểm rủi ro đạt ngưỡng `min_correlation_score >= 60.0`, hệ thống sinh một cảnh báo tổng hợp (Correlated Alert) với mức độ nghiêm trọng tương xứng và bảng Evidence gom tụ đầy đủ.

---

## 8. Vòng đời Xử lý Sự cố (Incident Lifecycle)

Vòng đời cảnh báo tuân thủ nghiêm ngặt máy trạng thái hữu hạn với cơ chế bảo toàn mức độ nghiêm trọng (Non-downgrade severity):

```text
       ┌───────────┐
       │    NEW    │◄─── Sinh ra từ Detection Engine (hoặc mở lại khi có vi phạm mới)
       └─────┬─────┘
             │
      ┌──────┴──────┐
      │             │
      ▼             ▼
┌────────────┐┌────────────┐
│ACKNOWLEDGED││  RESOLVED  │◄─── Dismiss (False Positive)
└─────┬──────┘└────────────┘
      │             ▲
      └─────────────┘
      Resolve (Fix Applied)
```

- **Non-downgrade Severity:** Khi sự kiện tái diễn trên cùng alert key, mức độ nghiêm trọng chỉ được leo thang hoặc giữ nguyên theo thứ bậc: `info < low < medium < high < critical`.
- **Alert Reopening:** Nếu sự kiện vi phạm tiếp tục xuất hiện sau khi cảnh báo đã được đánh dấu `resolved`, trạng thái sẽ tự động được mở lại về `new` và xóa ghi chú giải quyết cũ.
- **Idempotency:** Các thao tác thừa nhận (`acknowledge`), giải quyết (`resolve`), bỏ qua (`dismiss`) đảm bảo tính lũy thừa, không ghi đè timestamp ban đầu.

---

## 9. Bảo mật & Gia cố Hệ thống (Security Hardening)

- **Authentication:** Mọi API `/api/v1/*` bắt buộc có Bearer Token ($\ge 32$ ký tự). Khi chạy môi trường production, Application Factory chặn khởi động nếu token yếu hoặc trùng chuỗi placeholder.
- **Web Console Session & CSRF:** Giao diện điều hành yêu cầu xác thực phiên (`/login`). Mọi thao tác thay đổi trạng thái Alert (`ACK`, `RESOLVE`, `DISMISS`) đều yêu cầu `X-CSRF-Token` bảo vệ chống tấn công CSRF.
- **Token Redaction:** Token được so khớp an toàn qua `hmac.compare_digest()` và ẩn giấu tự động trong toàn bộ hệ thống log nhằm tránh rò rỉ credential.
- **SQL Injection Defense:** 100% câu truy vấn sử dụng parameterized SQL trong tầng DAL Repositories. Đã vượt qua bộ probe SQL Injection nâng cao.
- **DOM XSS Defense:** Toàn bộ dữ liệu hiển thị trên Web Console đều được lọc qua hàm `escapeHtml()` ở Frontend và cơ chế autoescape của Jinja2. Các inline event attributes (`onclick`) được thay thế hoàn toàn bằng event delegation an toàn.
- **FIM Data Integrity & TOCTOU Protection:** Thuật toán FIM sử dụng `os.lstat()` và kiểm tra `stat.S_ISLNK()` ngăn chặn triệt để tấn công vượt quyền qua liên kết tượng trưng (Symlink Traversal), đồng thời áp dụng Two-phase commit (chỉ cập nhật baseline sau khi sự kiện gửi thành công) để chống mất mát dữ liệu khi đứt mạng.
- **Payload Bound:** Cấu hình `EDR_MAX_CONTENT_LENGTH = 16 MiB` mặc định cho phép tiếp nhận an toàn các snapshot tiến trình lớn mà không bị ngắt quãng.
- **Database Resilience:** SQLite chạy chế độ WAL mode, `PRAGMA foreign_keys = ON`, `busy_timeout = 10000ms`.

---

## 10. Kiểm thử Hệ thống (Testing & Verification)

Dự án sở hữu bộ kiểm thử tự động toàn diện gồm **230 ca kiểm thử** bao phủ toàn bộ các tầng kiến trúc:

```bash
# Kích hoạt môi trường và chạy toàn bộ kiểm thử
.venv/bin/pytest -v
```

Kết quả thực nghiệm:
```text
============================= 230 passed in 17.92s =============================
```

Chạy riêng từng bộ kiểm thử chuyên biệt:
```bash
# Kiểm thử Unit Agent (System, Process, FIM)
.venv/bin/pytest tests/test_system_collector.py tests/test_file_integrity.py tests/test_agent_orchestrator.py

# Kiểm thử Detection Rules & Correlation
.venv/bin/pytest tests/test_detection.py tests/test_correlation.py

# Kiểm thử Alert Management & Life-cycle
.venv/bin/pytest tests/test_alert_management.py

# Kiểm thử Tích hợp Chu trình E2E Toàn hệ thống
.venv/bin/pytest tests/test_full_system_e2e.py tests/test_phase4_e2e.py

# Kiểm thử An ninh & Độ tin cậy (SQLi, DOM XSS, CSRF, Token, Payload Bounds)
.venv/bin/pytest tests/test_security_reliability.py
```

---

## 11. Tài liệu Kỹ thuật Chi tiết (Documentation)

Dự án cung cấp bộ tài liệu kiến trúc và đặc tả chi tiết trong thư mục `docs/`:

- 📐 **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md):** Kiến trúc hệ thống toàn diện, sơ đồ ERD chi tiết, các sequence diagrams luồng dữ liệu, và phân tích thiết kế.
- 📜 **[docs/DATA_CONTRACT.md](docs/DATA_CONTRACT.md):** Đặc tả Common Telemetry Envelope 1.0, cấu trúc 9 thuộc tính tiến trình, cấu trúc FIM payload, timestamp ownership, và validator bounds.
- 📡 **[docs/API_SPECIFICATION.md](docs/API_SPECIFICATION.md):** Chi tiết toàn bộ REST APIs, Web Console Session Auth, CSRF Protection, HTTP status codes, và mã lỗi.
- 🧪 **[docs/TEST_PLAN.md](docs/TEST_PLAN.md):** Kế hoạch kiểm thử, phạm vi, kịch bản chi tiết và ma trận nghiệm thu 230 test cases.
- 🎬 **[docs/DEMO_SCENARIO.md](docs/DEMO_SCENARIO.md):** Kịch bản kịch tính 5 bước và lời thoại chi tiết diễn tập bảo vệ trước Hội đồng chấm thi (5–7 phút).
- 📊 **[docs/PRESENTATION_SLIDES_OUTLINE.md](docs/PRESENTATION_SLIDES_OUTLINE.md):** Đề cương 13 slide chuẩn học thuật tóm tắt toàn bộ nghiên cứu và công trình đồ án.
- 🗺️ **[Lo_trinh_trien_khai_Mini_EDR_Linux.md](Lo_trinh_trien_khai_Mini_EDR_Linux.md):** Lộ trình 10 giai đoạn phát triển và nghiệm thu đề tài.

---

## 12. Khóa Phạm vi Đề tài & Giới hạn Học thuật (Scope Lock & Academic Boundaries)

Nhằm đảm bảo tính tập trung, đúng đắn và khả thi cao nhất của một đồ án môn học Python / An toàn thông tin, dự án áp dụng nguyên tắc **Scope Lock**:

1. **Phát hiện Dựa trên Quy tắc (Rule-Based Detection):** Hệ thống ưu tiên tính minh bạch, giải thích được (Explainable AI / Detection logic), không đưa vào các mô hình Machine Learning hộp đen không thể kiểm chứng trong lab.
2. **Giới hạn Môi trường Linux:** Tập trung chuyên sâu vào giám sát kernel Linux qua `/proc`, POSIX file system (`os.lstat`), không phân tán nguồn lực sang Windows/macOS.
3. **Quy mô Môi trường Lab:** Được thiết kế tối ưu cho mô hình phòng thí nghiệm và hệ thống mạng nội bộ quy mô vừa và nhỏ; sử dụng xác thực Bearer Token dùng chung và SQLite ở chế độ WAL.
4. **Không Tự động Diệt Tiến trình (No Automatic Process Killing):** Để đảm bảo an toàn tuyệt đối cho hệ điều hành của người chấm thi trong buổi bảo vệ, hệ thống chỉ cảnh báo và đề xuất hành động cho quản trị viên (SOC Operator), không tự ý kill process hay cô lập tệp ngoài tầm kiểm soát.
5. **Không Mở rộng Enterprise Bloat:** Không tự ý bổ sung các thành phần phức tạp không cần thiết cho đồ án Python như Kubernetes, Celery, Redis, PostgreSQL, eBPF kernel drivers, hoặc Enterprise SIEM.
