# Mini EDR for Linux (Endpoint Detection and Response)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/flask-3.x-green.svg)](https://flask.palletsprojects.com/)
[![SQLite](https://img.shields.io/badge/sqlite-WAL%20mode-lightgrey.svg)](https://www.sqlite.org/)
[![Tests](https://img.shields.io/badge/tests-214%20passed-brightgreen.svg)](tests/)
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
- 🌐 **Cyberpunk Hacker Web Dashboard:** Bảng điều khiển SOC Command Center với giao diện Dark Terminal, dải màu Neon, quét lưới Matrix CRT, đồ thị và modals trực quan hóa dữ liệu 100% độc lập không cần Internet (Air-gapped ready).
- 🔒 **Gia cố An toàn Doanh nghiệp (Enterprise Hardening):** Xác thực Bearer Token, 100% Parameterized SQL ngăn SQLi, chống XSS trong Jinja2 & DOM, chống gửi lặp bằng UUIDv4, giới hạn payload 64KB ngăn DoS.

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
│   ├── client.py                # HTTP client gửi bản tin chuẩn Envelope 1.0
│   ├── file_integrity.py        # Giám sát toàn vẹn tệp (FIM) bằng SHA-256
│   ├── orchestrator.py          # Bộ điều phối vòng lặp thu thập định kỳ
│   ├── process_collector.py     # Quét danh sách tiến trình qua /proc
│   └── system_collector.py      # Thu thập thông số phần cứng CPU/RAM/Disk
├── server/                      # Phân hệ Flask API Server & Web Backend
│   ├── app.py                   # Flask Application Factory & Server entry point
│   ├── routes.py                # Ingestion API Routes (/heartbeat, /telemetry/*, /alerts)
│   ├── web.py                   # Web Dashboard Blueprint & Controllers
│   ├── detection/               # Phân hệ Detection Engine
│   │   ├── engine.py            # Động cơ phân tích tương quan & tính điểm rủi ro
│   │   └── rules.py             # Định nghĩa danh mục quy tắc phát hiện
│   ├── migrations/              # Bộ quản lý Schema Migration tự động
│   │   ├── runner.py            # Migration runner kiểm tra Checksum SHA-256
│   │   └── sql/                 # Các script tạo cấu trúc bảng SQLite
│   └── repositories/            # Tầng Data Access Layer (DAL) cách ly SQL
│       ├── alert_repository.py
│       ├── base.py
│       ├── baseline_repository.py
│       ├── endpoint_repository.py
│       ├── event_repository.py
│       ├── process_repository.py
│       └── system_metrics_repository.py
├── static/                      # Tài nguyên giao diện tĩnh (Cyberpunk CSS & JS)
│   ├── style.css                # Bộ stylesheet Cyberpunk Theme hoàn chỉnh
│   └── dashboard.js             # Logic đồng hồ số, AJAX Modals & Toast notifications
├── templates/                   # Giao diện Jinja2 HTML Templates
│   ├── base.html                # HUD Topbar, navigation & Modal container
│   ├── dashboard.html           # Trang 1: SOC Command Center Overview
│   ├── endpoints.html           # Trang 2: Endpoint Fleet & Inspection Modal
│   ├── alerts.html              # Trang 3: Incident Response & Triage Console
│   └── events.html              # Trang 4: Security Audit Logs & FIM Stream
├── scripts/                     # Scripts hỗ trợ và tiện ích
│   └── seed_demo_data.py        # Sinh dữ liệu mẫu chân thực phục vụ demo
├── tests/                       # Toàn bộ 214 ca kiểm thử tự động
│   ├── test_agent_client.py
│   ├── test_agent_orchestrator.py
│   ├── test_alert_management.py
│   ├── test_api.py
│   ├── test_dashboard.py
│   ├── test_database.py
│   ├── test_detection.py
│   ├── test_file_integrity.py
│   ├── test_full_system_e2e.py  # Kiểm thử vòng đời hệ thống E2E 8 bước
│   ├── test_security_reliability.py # 20 bài test bảo mật (SQLi, XSS, Replay)
│   └── ...
├── docs/                        # Tài liệu đặc tả kỹ thuật chi tiết
│   ├── ARCHITECTURE.md          # Đặc tả kiến trúc, sơ đồ ERD & sequence
│   ├── DATA_CONTRACT.md         # Hợp đồng dữ liệu Envelope & Payloads
│   ├── API_SPECIFICATION.md     # Đặc tả API endpoints & Web routes
│   └── TEST_PLAN.md             # Kế hoạch và ma trận 214 ca kiểm thử
├── Lo_trinh_trien_khai_Mini_EDR_Linux.md # Lộ trình triển khai chi tiết
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
python3 -m agent.orchestrator
```

Agent sẽ lập tức:
1. Thu thập thông tin máy và gửi Heartbeat lên Server.
2. Quét toàn bộ bảng tiến trình `/proc` và gửi Process Snapshot.
3. Thiết lập baseline FIM ban đầu và theo dõi thay đổi tệp tin.

### 5.6. Chạy Kịch bản Tấn công Demo Trực tiếp (Live Attack Simulation)

Để thực hiện kịch bản demo 5--7 phút phục vụ buổi bảo vệ đồ án:

```bash
python3 scripts/simulate_attack_scenario.py
```

Công cụ CLI tương tác sẽ dẫn dắt từng bước:
1. Đăng ký máy trạm demo (`demo-workstation-01`).
2. Thiết lập FIM baseline cho tệp cấu hình.
3. Kích hoạt tấn công sửa đổi tệp (FIM Tampering Attack) ➔ Kích hoạt Alert `HIGH`.
4. Kích hoạt tấn công Reverse Shell Netcat (`/tmp/nc -lvnp 4444`) ➔ Kích hoạt Alert `CRITICAL` (Risk Score 90).
5. Mở Web Dashboard `/alerts` để trình diễn quy trình SOC Triage (Evidence ➔ Acknowledge ➔ Resolve).

---

## 6. Giao diện Cyberpunk Web Dashboard

Mở trình duyệt truy cập: **`http://127.0.0.1:5000/dashboard`**

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
   - Bảng điều khiển phân loại và xử lý sự cố an ninh.
   - Nút **EVIDENCE**: Mở Modal xem chi tiết JSON evidence và các security events liên quan.
   - Thao tác trực tiếp không cần reload trang:
     - `ACK`: Tiếp nhận xử lý sự cố.
     - `RESOLVE`: Mở modal nhập kết luận khắc phục và đóng cảnh báo.
     - `DISMISS`: Bỏ qua cảnh báo dương tính giả.
4. **Security Audit Logs (`/events`):**
   - Nhật ký kiểm toán toàn bộ sự kiện an ninh và dữ liệu telemetry FIM.

---

## 7. Động cơ Phát hiện & Quy tắc An ninh (Detection Engine)

Detection Engine tích hợp sẵn các quy tắc phát hiện rõ ràng (explainable):

| Mã Quy tắc | Tên Quy tắc | Hành vi Giám sát | Mức độ |
|---|---|---|---|
| `RULE_SUSPICIOUS_PROCESS` | Reverse Shell / Hack Tools | Phát hiện binary độc hại (`nc`, `netcat`, `nmap`, `mimikatz`, `socat`) hoặc chạy từ `/tmp`, `/dev/shm` | `CRITICAL` |
| `RULE_SHELL_SPAWN` | Interactive Shell Spawning | Phát hiện shell (`bash`, `sh`, `zsh`) được sinh ra từ Web Server hoặc Scripting runtime | `HIGH` |
| `RULE_HIGH_CPU_PROCESS` | Anomalous CPU Usage | Phát hiện tiến trình chiếm dụng $> 85\%$ CPU kéo dài (dấu hiệu đào tiền ảo / DoS) | `MEDIUM` |
| `RULE_FIM_SENSITIVE_FILE` | Sensitive File Tampering | Phát hiện can thiệp tệp cấu hình bảo mật (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) | `HIGH` |

**Cơ chế Tính điểm Rủi ro (Correlation & Risk Scoring):**
Kết hợp đồng thời nhiều chỉ số vi phạm trên cùng endpoint để nâng mức độ cảnh báo (Ví dụ: Binary trong `/tmp` kết hợp sửa đổi `/etc/shadow` sẽ nâng điểm rủi ro lên $\ge 90$ - mức `CRITICAL`).

---

## 8. Vòng đời Xử lý Sự cố (Incident Lifecycle)

Vòng đời cảnh báo tuân thủ nghiêm ngặt máy trạng thái hữu hạn:

```text
       ┌───────────┐
       │    NEW    │◄─── Sinh ra từ Detection Engine
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

- **State Transition Guard:** Nghiêm cấm chuyển lùi từ `resolved` về `acknowledged` (Trả về HTTP 400/409).
- **Idempotency:** Bấm nhiều lần hành động không gây sai lệch dữ liệu lịch sử hoặc ghi đè timestamp ban đầu.

---

## 9. Bảo mật & Gia cố Hệ thống (Security Hardening)

- **Authentication:** Mọi API `/api/v1/*` bắt buộc có Bearer Token.
- **Token Redaction:** Token được ẩn giấu tự động trong toàn bộ hệ thống log nhằm tránh rò rỉ credential.
- **SQL Injection Defense:** 100% câu truy vấn sử dụng parameterized SQL trong tầng DAL. Đã vượt qua bộ probe SQL Injection nâng cao.
- **XSS Defense:** Toàn bộ dữ liệu hiển thị trên Web Console đều được escape HTML an toàn ở cả Frontend JS và Backend Jinja2.
- **Replay Attack Resistance:** Mỗi bản tin telemetry mang một UUIDv4 `message_id` duy nhất; chặn đứng hành vi gửi lặp dữ liệu độc hại.
- **DoS Prevention:** Cấu hình `MAX_CONTENT_LENGTH = 64KB` chặn payload quá tải bộ nhớ.
- **Database Resilience:** SQLite chạy chế độ WAL mode, `PRAGMA foreign_keys = ON`, `busy_timeout = 5000ms`.

---

## 10. Kiểm thử Hệ thống (Testing & Verification)

Dự án sở hữu bộ kiểm thử tự động toàn diện gồm **214 ca kiểm thử** bao phủ toàn bộ các tầng kiến trúc:

```bash
# Kích hoạt môi trường và chạy toàn bộ kiểm thử
.venv/bin/pytest -v
```

Kết quả thực nghiệm:
```text
============================= 214 passed in 12.54s =============================
```

Chạy riêng từng bộ kiểm thử chuyên biệt:
```bash
# Kiểm thử Unit Agent
.venv/bin/pytest tests/test_system_collector.py tests/test_process_collector.py tests/test_file_integrity.py

# Kiểm thử Detection & Alert
.venv/bin/pytest tests/test_detection.py tests/test_alert_management.py

# Kiểm thử Web Dashboard
.venv/bin/pytest tests/test_dashboard.py

# Kiểm thử Tích hợp Chu trình E2E Toàn hệ thống
.venv/bin/pytest tests/test_full_system_e2e.py

# Kiểm thử An ninh & Độ tin cậy (SQLi, XSS, Replay, Integrity)
.venv/bin/pytest tests/test_security_reliability.py
```

---

## 11. Tài liệu Kỹ thuật Chi tiết (Documentation)

Dự án cung cấp bộ tài liệu kiến trúc và đặc tả chi tiết trong thư mục `docs/`:

- 📐 **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md):** Kiến trúc hệ thống toàn diện, sơ đồ ERD chi tiết, các sequence diagrams luồng dữ liệu, và phân tích thiết kế.
- 📜 **[docs/DATA_CONTRACT.md](docs/DATA_CONTRACT.md):** Đặc tả Common Telemetry Envelope 1.0, cấu trúc payload từng loại telemetry, timestamp ownership, và validator bounds.
- 📡 **[docs/API_SPECIFICATION.md](docs/API_SPECIFICATION.md):** Chi tiết toàn bộ REST APIs, HTTP status codes, mã lỗi, và các route của Web Dashboard.
- 🧪 **[docs/TEST_PLAN.md](docs/TEST_PLAN.md):** Kế hoạch kiểm thử, phạm vi, kịch bản chi tiết và ma trận nghiệm thu 214 test cases.
- 📊 **[docs/PRESENTATION_SLIDES_OUTLINE.md](docs/PRESENTATION_SLIDES_OUTLINE.md):** Cấu trúc 18 slide thuyết trình bảo vệ đồ án chi tiết, kèm bố cục hình ảnh, lời thoại thuyết minh (speaker notes) và câu hỏi phản biện.
- 🎬 **[docs/DEMO_SCENARIO.md](docs/DEMO_SCENARIO.md):** Kịch bản trình diễn sản phẩm 5--7 phút cho buổi bảo vệ đồ án, checklist chuẩn bị và hướng dẫn video dự phòng.
- 🗺️ **[Lo_trinh_trien_khai_Mini_EDR_Linux.md](Lo_trinh_trien_khai_Mini_EDR_Linux.md):** Lộ trình 10 giai đoạn phát triển và nghiệm thu đề tài.

---

## 12. Giới hạn Phạm vi Đồ án & Hướng Phát triển

- **Môi trường phù hợp:** Hệ thống được thiết kế phục vụ mục đích nghiên cứu, học thuật và bảo vệ đồ án tốt nghiệp trong môi trường lab hoặc mạng nội bộ được ủy quyền.
- **An toàn Endpoint:** Phiên bản đồ án chủ động **không tự động gửi lệnh `kill` tiến trình** từ xa nhằm đảm bảo an toàn tối đa cho máy trạm thực tế trong buổi trình diễn demo.
- **Hướng mở rộng tương lai:**
  - Chuyển đổi từ quét `/proc` sang công nghệ **eBPF** ở tầng kernel Linux để bắt sự kiện syscalls theo thời gian thực với độ trễ tính bằng microsecond.
  - Hỗ trợ giao thức đẩy hai chiều gRPC / WebSockets để quản trị viên có thể gửi lệnh cách ly máy trạm (Host Isolation) ngay từ Web Console.
  - Hỗ trợ kiến trúc cơ sở dữ liệu phân tán (PostgreSQL/TimescaleDB) khi mở rộng quy mô lên hàng ngàn endpoints.
