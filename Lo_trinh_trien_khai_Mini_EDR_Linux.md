# Lộ trình triển khai và hoàn thiện Mini EDR for Linux

**Phiên bản:** 1.0\
**Ngày cập nhật:** 05/11/2026\
**Repository:** `r00tK1ngX/mini-edr-linux`\
**Môi trường phát triển:** Kali Linux trên VirtualBox, Python virtual
environment, Flask, SQLite, pytest\
**Phạm vi:** Đồ án môn Python --- hệ thống giám sát và phát hiện hành vi
đáng ngờ trên máy tính đầu cuối Linux.

------------------------------------------------------------------------

## 1. Mục tiêu và phạm vi đồ án

### 1.1. Mục tiêu tổng quát

Xây dựng một hệ thống Mini Endpoint Detection and Response (Mini EDR) có
khả năng:

-   Quản lý tập trung nhiều máy tính Linux (endpoints).
-   Thu thập thông tin hệ thống, tiến trình và trạng thái file được giám
    sát.
-   Gửi dữ liệu từ Linux Agent về Flask API Server.
-   Xác thực và kiểm tra dữ liệu đầu vào trước khi lưu.
-   Lưu lịch sử telemetry, process, file baseline, security events và
    alerts bằng SQLite.
-   Phát hiện dấu hiệu bất thường bằng các luật có thể giải thích
    (Rule-Based Detection).
-   Hiển thị endpoint và cảnh báo trên Web Dashboard.
-   Cho phép quản trị viên xác nhận và cập nhật trạng thái cảnh báo.
-   Có kiểm thử tự động, tài liệu kỹ thuật, slide và kịch bản demo.

### 1.2. Phạm vi và giới hạn

Đây là sản phẩm học thuật quy mô nhỏ, tập trung chứng minh luồng EDR
đầu-cuối (end-to-end), không phải EDR thương mại hoặc nền tảng SOC
production.

Trong phạm vi đồ án:

-   Chỉ giám sát các máy Linux do nhóm quản lý.
-   Chỉ giám sát các thư mục được cấu hình và được phép truy cập.
-   Detection ban đầu sử dụng rule-based, không tuyên bố phát hiện mọi
    malware.
-   Không tự động kill process, cách ly file hoặc thực hiện hành động
    phá hoại.
-   Không mở API trực tiếp ra Internet.
-   Token dùng chung hiện tại chỉ phù hợp lab; chưa phải mô hình định
    danh Agent production.
-   Dữ liệu nhạy cảm như process command line đầy đủ, environment
    variables, token và mật khẩu không được thu thập nếu không thật sự
    cần thiết.

### 1.3. Sản phẩm bàn giao

1.  Repository chạy được trên Linux.
2.  Flask API Server.
3.  Linux Agent và các collector.
4.  SQLite database với schema và migration.
5.  Detection Engine.
6.  Web Dashboard lấy dữ liệu thật.
7.  Automated tests.
8.  README, tài liệu kiến trúc, Data Contract và Test Plan.
9.  Slide thuyết trình.
10. Demo trực tiếp 5--7 phút và video dự phòng.

------------------------------------------------------------------------

## 2. Kiến trúc tổng thể

``` text
+------------------------------------------------------+
|                 Linux Endpoint(s)                    |
|                                                      |
|  +--------------- Linux Agent --------------------+  |
|  | System Collector | Process Collector | FIM      |  |
|  | Agent Client     | Local State        |         |  |
|  +------------------------+-------------------------+  |
+---------------------------|--------------------------+
                            |
                 HTTPS/HTTP trong lab
             Heartbeat / Telemetry / Events
                            |
                            v
+------------------------------------------------------+
|                  Flask API Server                    |
|                                                      |
|  Authentication | Validation | API Routing         |
|  Endpoint Service | Telemetry Service | Event Intake |
+---------------------------+--------------------------+
                            |
                            v
+------------------------------------------------------+
|                    SQLite Database                   |
|                                                      |
| Endpoints | System Metrics | Process Snapshots       |
| Process Observations | File Baselines                |
| Security Events | Alerts | Alert Events              |
| Schema Migrations                                    |
+---------------------------+--------------------------+
                            |
                            v
+------------------------------------------------------+
|                   Detection Engine                   |
|                                                      |
| Rule Evaluation | Event Correlation | Risk Scoring   |
+---------------------------+--------------------------+
                            |
                            v
+------------------------------------------------------+
|               Centralized Web Dashboard              |
|                                                      |
| Overview | Endpoints | Alerts | Incident Handling    |
+------------------------------------------------------+
```

### 2.1. Luồng xử lý chính

1.  Agent chạy trên Linux endpoint.
2.  Agent thu thập thông tin hệ thống, process và thay đổi file trong
    phạm vi cấu hình.
3.  Agent gửi heartbeat, telemetry và security events tới API.
4.  Server xác thực request và kiểm tra cấu trúc, kiểu, giới hạn dữ
    liệu.
5.  Server lưu dữ liệu vào SQLite.
6.  Detection Engine đánh giá sự kiện theo các rule.
7.  Hệ thống tạo hoặc cập nhật Alert khi có dấu hiệu đáng ngờ.
8.  Quản trị viên theo dõi endpoint, xem bằng chứng và xử lý cảnh báo
    trên Dashboard.

------------------------------------------------------------------------

## 3. Trạng thái dự án tại ngày 05/11/2026

> Trạng thái dưới đây được tổng hợp từ lịch sử triển khai và kết quả
> terminal đã cung cấp. Các mục "đã kiểm thử local" không đồng nghĩa với
> việc đã được triển khai production.

### 3.1. Phase 1 --- Backend Foundation

**Trạng thái: Đã merge vào `main`.**

-   PR #1 đã được merge.
-   Merge commit: `7eb673f` (`Merge pull request #1 ...`).
-   Flask application factory `create_app()`.
-   Health endpoint `GET /health`.
-   Bearer Token authentication cho `/api/v1/*`.
-   Heartbeat endpoint `POST /api/v1/heartbeat`.
-   Endpoint inventory `GET /api/v1/endpoints`.
-   SQLite connection management, foreign keys, busy timeout và WAL.
-   Validation cho identity, IP và system metrics.
-   API tests: 29 tests đã vượt qua trên môi trường local.
-   GitHub Actions CI đã chạy thành công theo kết quả đã kiểm tra.

**Các điểm còn cần theo dõi:**

-   Heartbeat hiện tại có thể ghi đè trường tùy chọn thành `NULL` nếu
    payload mới bỏ qua trường đó. Cần thống nhất rõ heartbeat là full
    update hay partial update; không để Agent gửi payload thiếu làm mất
    metrics mới nhất ngoài ý muốn.
-   API token hiện là token dùng chung. Cần xem đây là giới hạn của bản
    lab.
-   Validation độ mạnh token cần được áp dụng nhất quán cho mọi cách
    khởi chạy ứng dụng, không chỉ nhánh `__main__`.
-   Cần xác nhận thêm live test HTTP 401 và chuyển trạng thái
    Online/Offline theo thời gian nếu chưa thực hiện trực tiếp.

### 3.2. Phase 2 --- Database & Data Model

**Trạng thái: Đã hoàn thành 100% (Đạt toàn bộ tiêu chí nghiệm thu).**

**Đã hoàn thành:**

-   **Task 2.1 --- Migration Framework:** Đã tạo `server/migrations/runner.py`, `server/migrations/__init__.py`, `tests/test_migrations.py` (7 tests đạt: apply, idempotency, rollback, checksum SHA-256, phát hiện file bị sửa/xóa/rỗng).
-   **Task 2.2 --- Database Schema:** Đã hoàn thiện file migration chuẩn `server/migrations/001_phase2_data_model.sql` định nghĩa đầy đủ 7 bảng dữ liệu (`system_metrics`, `process_snapshots`, `process_observations`, `file_baselines`, `security_events`, `alerts`, `alert_events`) với đầy đủ check constraints, foreign keys và indexes. Tích hợp tự động vào `server/db.py` (`init_db`).
-   **Task 2.3 --- Data Access Layer (DAL):** Đã xây dựng hoàn chỉnh gói `server/repositories/` bao gồm:
    -   `base.py`: Quản lý kết nối SQLite và transaction an toàn.
    -   `endpoint_repository.py`: Quản lý vòng đời endpoint, trạng thái online/offline.
    -   `metrics_repository.py`: Lưu và tra cứu lịch sử tài nguyên hệ thống.
    -   `process_repository.py`: Ghi snapshot và quan sát tiến trình atomic.
    -   `baseline_repository.py`: Quản lý baseline tính toàn vẹn tệp (FIM), hash SHA-256.
    -   `event_repository.py`: Ghi nhận và tìm kiếm sự kiện bảo mật theo mức độ, fingerprint.
    -   `alert_repository.py`: Quản lý vòng đời cảnh báo (`new`, `acknowledged`, `resolved`), liên kết `alert_events`.
    -   Đã nối `server/db.py` sang dùng `EndpointRepository`.
-   **Task 2.4 & Task 2.5 --- Data Contract & API Specification:** Đã chuẩn hóa toàn bộ cấu trúc Standard Message Envelope (`schema_version`, `message_id`, `agent_id`, `collected_at`, `payload`), quy chuẩn ISO 8601 UTC và đặc tả chi tiết các payload trong `docs/DATA_CONTRACT.md`.
-   **Task 2.6 --- Database & DAL Tests:** Đã tạo `tests/test_database.py` (13 tests) và `tests/test_repositories.py` (10 tests).
-   **Task 2.7 --- Documentation & ERD:** Đã hoàn thiện tài liệu kiến trúc toàn diện và sơ đồ Mermaid ERD đầy đủ trong `docs/ARCHITECTURE.md`.
-   Tổng **59/59 tests** đã vượt qua: 29 API tests Phase 1 + 7 migration tests + 13 database tests + 10 repository tests. Toàn bộ tiêu chí nghiệm thu Phase 2 đã đạt. Sẵn sàng chuyển sang Phase 3 (Xây dựng Linux Agent).

### 3.3. Quy tắc Git hiện tại

-   `main` là nhánh ổn định.
-   Mỗi phase/feature được phát triển trên feature branch.
-   Phase 2 branch: `feature/phase-2-data-model`.
-   Nền tảng Phase 2 phải bắt đầu từ merge commit `7eb673f` trở lên.
-   Không commit file migration rỗng.
-   Chỉ merge qua Pull Request sau khi test và review đạt.

------------------------------------------------------------------------

# 4. Lộ trình triển khai A--Z

Mỗi giai đoạn phải có: mục tiêu, đầu việc, sản phẩm bàn giao và tiêu chí
nghiệm thu. Không chuyển giai đoạn chỉ vì đã tạo file; phải có chức năng
chạy được và kiểm thử phù hợp.

## Phase 1 --- Backend Foundation

**Trạng thái: Đã hoàn thành và merge.**

### Mục tiêu

Server có thể nhận heartbeat hợp lệ, xác thực request và quản lý danh
sách endpoint.

### Thành phần

  Công việc                     File / thành phần
  ----------------------------- ---------------------------------
  Cấu hình môi trường           `.env.example`, `server/app.py`
  Flask application factory     `server/app.py`
  Bearer Token authentication   `server/routes.py`
  SQLite database               `server/db.py`
  Heartbeat API                 `server/routes.py`
  Endpoint inventory API        `server/routes.py`
  Input validation              `server/routes.py`
  API tests                     `tests/test_api.py`
  CI                            `.github/workflows/ci.yml`

### Tiêu chí nghiệm thu

-   `GET /health` trả HTTP 200.
-   Heartbeat có token hợp lệ được lưu.
-   Token thiếu/sai bị từ chối HTTP 401.
-   Dữ liệu không hợp lệ bị từ chối.
-   Một `agent_id` không tạo nhiều endpoint trùng nhau.
-   Endpoint chuyển Offline khi heartbeat quá hạn và Online khi nhận
    heartbeat mới.
-   API tests và CI vượt qua.

------------------------------------------------------------------------

## Phase 2 --- Database Schema, Migration và Data Contract

**Trạng thái: Đã hoàn thành 100% (Đạt toàn bộ tiêu chí nghiệm thu Task 2.1 đến 2.7).**

### Mục tiêu

Thiết kế cấu trúc dữ liệu thống nhất, có quan hệ rõ ràng và có thể nâng
cấp an toàn từ database Phase 1.

### Task 2.1 --- Migration Framework

**Đã triển khai và có 7 migration tests vượt qua.**

Chức năng cần duy trì:

-   Phát hiện file migration theo thứ tự phiên bản.
-   Tạo bảng `schema_migrations`.
-   Lưu version, checksum SHA-256 và thời điểm áp dụng.
-   Không chạy lại migration đã áp dụng.
-   Rollback transaction nếu migration lỗi.
-   Phát hiện migration đã áp dụng bị sửa hoặc file bị xóa.
-   Từ chối migration rỗng hoặc tên file không hợp lệ.

**Lưu ý kỹ thuật:** migration phải chạy transactionally. Các migration
lịch sử đã áp dụng không được chỉnh sửa; nếu cần thay đổi schema, tạo
migration mới.

### Task 2.2 --- Thiết kế và triển khai Database Schema

**Đã hoàn thành và có 13 database tests vượt qua.**

Đầu việc đã thực hiện:

1.  Chốt thiết kế schema và quan hệ giữa các bảng (7 bảng mới + 1 bảng kế thừa Phase 1 + bảng migrations).
2.  Chốt primary key, foreign key, unique và check constraints (kiểm soát CPU/RAM/Disk 0-100%, uptime >= 0, SHA-256 hex 64 ký tự, trạng thái enum).
3.  Chốt quy tắc `ON DELETE` (`CASCADE` cho bảng quan sát con, `RESTRICT` cho endpoint/alert liên kết).
4.  Chốt index theo các truy vấn dự kiến (tra cứu theo agent, thời gian thu thập, fingerprint, v.v.).
5.  Viết migration file `001_phase2_data_model.sql`.
6.  Chạy migration và tích hợp vào `server/db.py` (`init_db`).
7.  Kiểm tra dữ liệu `endpoints` Phase 1 được bảo toàn nguyên vẹn.
8.  Kiểm tra foreign key và PRAGMA integrity trên database SQLite.

### Schema mục tiêu

  ------------------------------------------------------------------------
  Bảng                     Vai trò                 Khóa/quan hệ chính
  ------------------------ ----------------------- -----------------------
  `endpoints`              Danh sách endpoint      `agent_id` là khóa
                                                   chính; bảng đã có từ
                                                   Phase 1

  `system_metrics`         Lịch sử                 FK `agent_id` →
                           CPU/RAM/Disk/uptime     `endpoints`

  `process_snapshots`      Mỗi lần thu thập        FK `agent_id` →
                           process                 `endpoints`;
                                                   `message_id` duy nhất

  `process_observations`   Process thuộc một       FK `snapshot_id` →
                           snapshot                `process_snapshots`;
                                                   khóa ghép
                                                   `(snapshot_id, pid)`

  `file_baselines`         Trạng thái chuẩn của    FK `agent_id` →
                           file được giám sát      `endpoints`; định danh
                                                   theo agent và file path

  `security_events`        Sự kiện bảo mật         FK `agent_id` →
                                                   `endpoints`;
                                                   `message_id` duy nhất

  `alerts`                 Cảnh báo do Detection   FK tới endpoint;
                           Engine tạo              `alert_key` duy nhất

  `alert_events`           Liên kết Alert với các  FK tới `alerts` và
                           Event liên quan         `security_events`; khóa
                                                   ghép
  ------------------------------------------------------------------------

Bảng `schema_migrations` được Migration Framework quản lý.

### Nguyên tắc thiết kế từng nhóm dữ liệu

**`system_metrics`**

-   Lưu lịch sử, không chỉ lưu giá trị mới nhất.
-   Có `collected_at` do Agent cung cấp và `received_at` do Server tạo.
-   CPU, RAM, Disk nằm trong khoảng 0--100.
-   Uptime không âm.
-   Có index theo `(agent_id, collected_at)`.

**`process_snapshots` và `process_observations`**

-   Một snapshot đại diện cho một lần thu thập.
-   Một snapshot có nhiều process observations.
-   Dùng `(snapshot_id, pid)` để phân biệt process theo từng snapshot.
-   Lưu `process_started_at` nếu collector lấy được, hỗ trợ phân biệt
    PID bị tái sử dụng.
-   Không thu thập toàn bộ command line/environment variables nếu không
    cần thiết.

**`file_baselines`**

-   Lưu file path, SHA-256, size, mtime nanoseconds, file mode và thời
    điểm quan sát.
-   SHA-256 phải có 64 ký tự hexadecimal.
-   Cần biểu diễn rõ file đang tồn tại hay đã biến mất; ưu tiên giữ
    trạng thái `missing` để có thể truy vấn lịch sử trạng thái hiện tại.
-   Chỉ quét các thư mục được cấu hình.

**`security_events`**

-   Lưu event type, severity, source, title, description, evidence và
    thời gian.
-   Severity thống nhất: `info`, `low`, `medium`, `high`, `critical`.
-   Source phân biệt sự kiện từ Agent và sự kiện do Detection Engine
    tạo.
-   Evidence lưu JSON có giới hạn kích thước.

**`alerts` và `alert_events`**

-   Alert là kết quả đánh giá/correlation, không đồng nhất với Event.
-   Trạng thái: `new`, `acknowledged`, `resolved`.
-   Lưu `first_seen_at`, `last_seen_at`, `created_at`,
    `acknowledged_at`, `resolved_at` và resolution note khi phù hợp.
-   Một Alert có thể liên kết nhiều Security Events.

### Task 2.3 --- Data Access Layer (DAL)

**Đã hoàn thành và có 10 DAL tests vượt qua trong `tests/test_repositories.py`.**

Đã triển khai gói cấu trúc:

``` text
server/
├── repositories/
│   ├── __init__.py
│   ├── base.py
│   ├── endpoint_repository.py
│   ├── metrics_repository.py
│   ├── process_repository.py
│   ├── baseline_repository.py
│   ├── event_repository.py
│   └── alert_repository.py
```

Nguyên tắc đã tuân thủ:

-   Repository chịu trách nhiệm truy vấn và ghi dữ liệu có phân tách rõ ràng.
-   Dùng parameterized queries 100%, tuyệt đối không nối chuỗi SQL.
-   Transaction được quản lý an toàn qua context manager `BaseRepository._connection`.
-   Trả về kiểu dữ liệu dict nhất quán.
-   Không đặt business logic Detection vào repository.
-   Hàm nghiệp vụ `server/db.py` (`upsert_endpoint`, `list_endpoints`) đã được kết nối sử dụng `EndpointRepository`.

### Task 2.4 --- Data Contract

Chuẩn hóa envelope chung giữa Agent và Server. Ví dụ định hướng:

``` json
{
  "schema_version": "1.0",
  "message_id": "UUID",
  "agent_id": "lab-linux-01",
  "collected_at": "2026-11-05T08:00:00Z",
  "payload": {}
}
```

Quy ước:

-   `schema_version`: phiên bản hợp đồng dữ liệu.
-   `message_id`: UUID duy nhất để chống ghi trùng (idempotency).
-   `agent_id`: định danh endpoint.
-   `collected_at`: thời gian Agent thu thập dữ liệu, ISO 8601 UTC.
-   `received_at`: Server tự tạo, không tin timestamp do Agent khai báo.
-   Dữ liệu phải được validate trước khi ghi database.

Heartbeat hiện tại đã có payload riêng. Không thay đổi tùy tiện; cần
quyết định rõ duy trì heartbeat hiện tại hay chuyển dần sang envelope
chuẩn trong một thay đổi có kiểm thử.

### Task 2.5 --- API Specification

Các endpoint định hướng:

  Method   Endpoint                            Mục đích
  -------- ----------------------------------- ------------------------------
  GET      `/health`                           Health check
  POST     `/api/v1/heartbeat`                 Cập nhật trạng thái endpoint
  GET      `/api/v1/endpoints`                 Danh sách endpoint
  POST     `/api/v1/telemetry/system`          Gửi system metrics
  POST     `/api/v1/telemetry/processes`       Gửi process snapshot
  POST     `/api/v1/file-baselines`            Đồng bộ baseline
  POST     `/api/v1/events`                    Gửi security events
  GET      `/api/v1/alerts`                    Danh sách alerts
  GET      `/api/v1/alerts/<id>`               Chi tiết alert
  POST     `/api/v1/alerts/<id>/acknowledge`   Xác nhận alert
  POST     `/api/v1/alerts/<id>/resolve`       Đóng alert

Đây là thiết kế mục tiêu, không phải tuyên bố các endpoint này đã tồn
tại.

### Task 2.6 --- Database & DAL Tests

**Đã hoàn thành: 23 tests vượt qua (13 tests schema tại `tests/test_database.py` + 10 tests DAL tại `tests/test_repositories.py`).**

Kiểm thử đã đạt:

-   Migration tạo đủ bảng và index.
-   Migration chạy lại không thay đổi dữ liệu (idempotency).
-   Migration lỗi được rollback.
-   Dữ liệu `endpoints` cũ được bảo toàn.
-   Foreign key hợp lệ và từ chối bản ghi mồ côi.
-   Check constraints từ chối dữ liệu sai (CPU/RAM > 100%, SHA-256 sai định dạng, PID âm).
-   Unique `message_id` chống ghi trùng.
-   Quan hệ snapshot/process đúng, rollback atomic khi quan sát lỗi.
-   Quan hệ alert/event đúng, hỗ trợ correlation và liên kết event.
-   `PRAGMA integrity_check` trả `ok`.
-   `PRAGMA foreign_key_check` không trả lỗi.

### Task 2.7 --- Documentation và ERD

**Đã hoàn thành:**

-   `docs/DATA_CONTRACT.md`: Đặc tả chi tiết Standard Message Envelope, cấu trúc payload tất cả API, quy tắc validate và mã lỗi HTTP.
-   `docs/ARCHITECTURE.md`: Tài liệu kiến trúc toàn diện và sơ đồ Mermaid `erDiagram` biểu diễn quan hệ giữa 8 bảng dữ liệu.
-   Mô tả chi tiết từng bảng, kiểu dữ liệu cột, constraints (CHECK, FK, UNIQUE) và indexes tối ưu truy vấn.

### Điều kiện hoàn thành Phase 2

-   [x] Migration chạy được trên database Phase 1 mà không mất endpoint cũ.
-   [x] Schema đủ các bảng và quan hệ đã chốt (8 bảng + bảng migrations).
-   [x] DAL hoạt động và có test (`server/repositories/` + 10 unit tests).
-   [x] Data Contract/API specification nhất quán (`docs/DATA_CONTRACT.md`).
-   [x] Database tests và toàn bộ test suite vượt qua (59/59 tests PASSED).
-   [x] Tài liệu schema và ERD được cập nhật theo code thực tế (`docs/ARCHITECTURE.md`).

------------------------------------------------------------------------

## Phase 3 --- Xây dựng Linux Agent

**Trạng thái: Chưa triển khai theo roadmap.**

### Mục tiêu

Agent chạy trên Linux, thu thập dữ liệu thực tế và gửi về Server.

### Module 1 --- `agent/system_collector.py`

Thu thập:

-   Hostname.
-   IP address.
-   Operating System.
-   CPU usage.
-   RAM usage.
-   Disk usage.
-   Uptime.

Dùng `psutil`. Phải xử lý trường hợp permission error, interface không
có IP và giá trị không lấy được.

### Module 2 --- `agent/process_collector.py`

Thu thập:

-   PID.
-   PPID nếu lấy được.
-   Process name.
-   Username.
-   CPU percent.
-   Memory percent.
-   Executable path.
-   Process start time nếu lấy được.

Ví dụ dữ liệu:

``` json
{
  "pid": 1234,
  "name": "python3",
  "username": "root",
  "cpu_percent": 32.5,
  "memory_percent": 1.2,
  "exe": "/usr/bin/python3"
}
```

Phải xử lý `NoSuchProcess`, `AccessDenied`, `ZombieProcess` và không để
một process lỗi làm dừng toàn bộ collector.

### Module 3 --- `agent/file_integrity.py`

Triển khai File Integrity Monitoring (FIM):

-   Quét thư mục được cấu hình.
-   Tạo baseline ban đầu.
-   Tính SHA-256.
-   Phát hiện file mới, sửa đổi và xóa.
-   Có thể dùng mtime/size để lọc trước khi tính hash.
-   Không theo dõi toàn bộ filesystem mặc định.
-   Xử lý symlink, permission và file thay đổi trong lúc đọc.

Ví dụ event:

``` text
[FILE CREATED] /tmp/demo.txt
[FILE MODIFIED] /etc/example.conf
[FILE DELETED] /opt/app/old.conf
```

### Module 4 --- `agent/client.py`

Chịu trách nhiệm:

-   Gửi heartbeat.
-   Gửi system telemetry.
-   Gửi process snapshots.
-   Gửi security events.
-   Gửi Bearer Token.
-   Timeout.
-   Retry có giới hạn và backoff.
-   Không log token hoặc dữ liệu nhạy cảm.
-   Xử lý Server tạm thời không kết nối được.

### Module 5 --- `agent/main.py`

Agent Orchestrator điều phối collector và client.

``` text
START AGENT
    |
    v
COLLECT SYSTEM INFO
    |
    v
COLLECT PROCESS INFO
    |
    v
SCAN PROTECTED FILES
    |
    v
SEND DATA TO SERVER
    |
    v
WAIT / SLEEP
    |
    v
REPEAT
```

Ban đầu có thể dùng chu kỳ 5 giây để demo. Sau đó tách chu kỳ heartbeat,
process scan và FIM để tránh quét file quá thường xuyên.

### Điều kiện hoàn thành Phase 3

-   Agent chạy ổn định trên Linux.
-   Collector trả dữ liệu hợp lệ.
-   Lỗi permission/process không làm Agent crash.
-   Có unit tests.
-   Dữ liệu có thể serialize theo Data Contract.
-   Agent không làm lộ token hoặc dữ liệu nhạy cảm.

------------------------------------------------------------------------

## Phase 4 --- Kết nối Agent với Server (End-to-End)

**Trạng thái: Chưa triển khai theo roadmap.**

### Mục tiêu

Chứng minh nhiều Linux Agent có thể gửi dữ liệu và Server lưu đúng
endpoint.

### Công việc

1.  Chạy Server và Agent trên cùng VM.
2.  Gửi heartbeat.
3.  Gửi system telemetry.
4.  Gửi process snapshots.
5.  Gửi file events/security events.
6.  Kiểm tra dữ liệu trong SQLite.
7.  Chạy Agent thứ hai với `agent_id` khác.
8.  Tắt Agent để kiểm tra Offline.
9.  Khởi động lại Agent để kiểm tra Online.

### Cấu hình heartbeat tham khảo

-   Heartbeat mỗi 5 giây.
-   Offline nếu quá 15 giây không nhận heartbeat.
-   `last_seen` do Server tạo.
-   Không tin thời gian do Agent tự khai báo để quyết định trạng thái
    kết nối.

### Mạng lab

Server hiện bind `127.0.0.1`. Khi cần VM khác kết nối, cấu hình bind phù
hợp như `0.0.0.0`, nhưng phải giới hạn bằng mạng lab và firewall. Không
mở API trực tiếp ra Internet.

### Điều kiện hoàn thành Phase 4

-   Tối thiểu hai endpoint xuất hiện.
-   Không tạo endpoint trùng.
-   Metrics/process/events lưu đúng Agent.
-   Offline/Online hoạt động đúng.
-   Có integration test cho luồng Agent → API → Database.

------------------------------------------------------------------------

## Phase 5 --- Detection Engine

**Trạng thái: Chưa triển khai.**

### Mục tiêu

Chuyển telemetry và security events thành phát hiện có thể giải thích.

### File dự kiến

``` text
detection/
├── __init__.py
├── rules.py
├── engine.py
└── correlation.py

config/
└── rules.json
```

### Nhóm rule ban đầu

  Rule                     Điều kiện
  ------------------------ ---------------------------------------------
  High CPU                 Process có CPU cao kéo dài
  High Memory              Process sử dụng RAM vượt ngưỡng
  Suspicious Path          Executable chạy từ thư mục bất thường
  File Integrity           File được bảo vệ bị sửa/xóa
  Suspicious Combination   Nhiều dấu hiệu đáng ngờ xuất hiện cùng nhau

Ví dụ cấu hình định hướng:

``` json
{
  "thresholds": {
    "cpu_percent": 85,
    "memory_percent": 85
  },
  "suspicious_paths": [
    "/tmp",
    "/var/tmp",
    "/dev/shm"
  ]
}
```

Các ngưỡng trên chỉ là giá trị demo ban đầu, cần kiểm thử và điều chỉnh
theo môi trường.

### Correlation --- kết hợp dấu hiệu

Ví dụ:

1.  Một file mới xuất hiện trong `/tmp`.
2.  Một process chạy từ đường dẫn đó.
3.  Process có CPU bất thường kéo dài.

Một dấu hiệu đơn lẻ chưa đủ kết luận malware. Khi kết hợp, hệ thống có
cơ sở tăng severity hoặc risk score.

Có thể triển khai risk score 0--100 để minh họa, nhưng phải lưu được
rule và evidence giải thích điểm số.

### Điều kiện hoàn thành Phase 5

-   Rule chạy trên dữ liệu thực tế.
-   Có test cho từng rule.
-   Event được tạo với severity/evidence.
-   Correlation hoạt động với dữ liệu nhiều nguồn.
-   Không kết luận malware chỉ từ một ngưỡng CPU đơn lẻ.

------------------------------------------------------------------------

## Phase 6 --- Alert và Incident Management

**Trạng thái: Chưa triển khai.**

### Vòng đời Alert

``` text
NEW
 |
 v
ACKNOWLEDGED
 |
 v
RESOLVED
```

-   `NEW`: cảnh báo mới.
-   `ACKNOWLEDGED`: quản trị viên đã xác nhận.
-   `RESOLVED`: sự cố đã được xử lý.

### API dự kiến

``` http
GET  /api/v1/alerts
GET  /api/v1/alerts/<id>
POST /api/v1/alerts/<id>/acknowledge
POST /api/v1/alerts/<id>/resolve
```

### Dữ liệu cần lưu

-   Alert ID.
-   Rule ID.
-   Endpoint liên quan.
-   Severity.
-   Title/description.
-   Evidence hoặc các event liên quan.
-   First seen / last seen.
-   Created time.
-   Acknowledged time.
-   Resolved time.
-   Resolution note.

### Điều kiện hoàn thành Phase 6

-   Detection tạo được Alert.
-   Alert hiển thị qua API.
-   Có thể acknowledge và resolve.
-   Thời điểm xử lý được lưu.
-   Có test cho trạng thái hợp lệ và chuyển trạng thái không hợp lệ.

------------------------------------------------------------------------

## Phase 7 --- Web Dashboard

**Trạng thái: Chưa triển khai.**

### Công nghệ

Flask + Jinja2 + HTML + CSS + JavaScript. Với phạm vi đồ án, chưa cần
React.

### Cấu trúc giao diện

``` text
templates/
├── dashboard.html
├── endpoints.html
└── alerts.html

static/
└── style.css
```

### Trang 1 --- Overview

-   Tổng số endpoint.
-   Số Online/Offline.
-   Tổng số Alert đang mở.
-   Biểu đồ CPU/RAM.
-   Cảnh báo mới nhất.

### Trang 2 --- Endpoints

-   Hostname.
-   IP.
-   OS.
-   CPU/RAM/Disk.
-   Uptime.
-   Last Seen.
-   Trạng thái.

### Trang 3 --- Alerts

-   Alert ID.
-   Severity.
-   Event type.
-   Endpoint.
-   Thời gian phát hiện.
-   Evidence.
-   Nút Acknowledge/Resolve.

### Nguyên tắc

Dashboard phải lấy dữ liệu thật từ database/API, không dùng số liệu
hardcode để giả lập kết quả cuối cùng.

### Điều kiện hoàn thành Phase 7

-   Overview hiển thị số liệu thật.
-   Endpoint list cập nhật đúng.
-   Alert list và chi tiết có evidence.
-   Acknowledge/Resolve hoạt động.
-   Giao diện sử dụng được trên màn hình demo.

------------------------------------------------------------------------

## Phase 8 --- Testing, Security và Reliability

**Trạng thái: Thực hiện xuyên suốt; cần hoàn thiện kiểm thử toàn hệ
thống.**

### 8.1. Unit Tests

Kiểm tra từng module độc lập:

-   System collector.
-   Process collector.
-   FIM.
-   API validation.
-   Repository.
-   Detection rules.
-   Alert state transitions.
-   Migration.

### 8.2. Integration Tests

Kiểm tra luồng:

``` text
Agent
  |
  v
HTTP API
  |
  v
Validation
  |
  v
Database
  |
  v
Detection Engine
  |
  v
Alert
  |
  v
Dashboard
```

### 8.3. Test matrix

  Kiểm thử                          Kết quả mong đợi
  --------------------------------- ----------------------------------------
  Health check                      HTTP 200
  Heartbeat đúng token              HTTP 200
  Token sai/thiếu                   HTTP 401
  Thiếu trường bắt buộc             HTTP 400
  CPU vượt giới hạn                 HTTP 400
  Metrics sai kiểu                  HTTP 400
  Hai heartbeat cùng Agent ID       Cập nhật bản ghi cũ
  Agent ngừng hoạt động             Offline
  Agent kết nối lại                 Online
  Tạo file trong thư mục giám sát   FIM phát hiện
  Sửa file                          FIM phát hiện
  Xóa file                          FIM phát hiện
  Process đáng ngờ theo rule        Security Event/Alert được tạo
  Alert acknowledge                 Trạng thái được cập nhật
  Alert resolve                     Trạng thái và thời gian xử lý được lưu
  Duplicate message ID              Không ghi trùng
  Migration lỗi                     Rollback
  Database integrity                `ok`
  Foreign key check                 Không có lỗi

### 8.4. Security checklist

-   Không commit `.env`.
-   Không log API token.
-   Không nối chuỗi SQL với dữ liệu người dùng.
-   Validate kích thước và kiểu dữ liệu đầu vào.
-   Giới hạn thư mục FIM.
-   Xử lý permission errors.
-   Không tự động kill process trong phiên bản đồ án.
-   Chỉ chạy trong lab hoặc hệ thống được phép giám sát.
-   Không mở API ra Internet.
-   Backup database trước thay đổi schema quan trọng.

### Điều kiện hoàn thành Phase 8

Các test quan trọng đều có kết quả tái lập được; có unit và integration
tests; không có lỗi bảo mật cơ bản chưa xử lý.

------------------------------------------------------------------------

## Phase 9 --- Documentation và kiến trúc

**Trạng thái: Chưa hoàn thiện.**

### `docs/ARCHITECTURE.md`

Cần có:

-   Tổng quan hệ thống.
-   Sơ đồ kiến trúc.
-   Vai trò module.
-   Luồng giao tiếp.
-   Cấu trúc database và ERD.
-   Data Contract.
-   Luồng Detection.
-   Các giới hạn thiết kế.

### `docs/DATA_CONTRACT.md`

Cần có:

-   Envelope chung.
-   Heartbeat payload.
-   System telemetry payload.
-   Process snapshot payload.
-   FIM/event payload.
-   Kiểu dữ liệu, required/optional.
-   Timestamp/timezone.
-   Validation rules.
-   Idempotency và message ID.
-   API response/error format.

### `docs/TEST_PLAN.md`

Cần có:

-   Mục tiêu kiểm thử.
-   Môi trường.
-   Test cases.
-   Dữ liệu đầu vào.
-   Kết quả mong đợi.
-   Kết quả thực nghiệm thực tế.
-   Lệnh chạy test.

### README

Cập nhật theo code thực tế:

-   Giới thiệu.
-   Kiến trúc.
-   Yêu cầu môi trường.
-   Cài đặt.
-   Cấu hình `.env`.
-   Chạy Server.
-   Chạy Agent.
-   Chạy tests.
-   Demo.
-   Giới hạn và hướng phát triển.

### Điều kiện hoàn thành Phase 9

Tài liệu phải khớp với implementation hiện tại. Không mô tả endpoint,
bảng hoặc tính năng chưa tồn tại như thể đã hoàn thành.

------------------------------------------------------------------------

## Phase 10 --- Hoàn thiện sản phẩm, Slide và Demo

### Tiêu chí sản phẩm cuối

-   [ ] Repository chạy được trên Linux.
-   [ ] Agent thu thập system telemetry.
-   [ ] Agent thu thập process information.
-   [ ] FIM phát hiện file create/modify/delete.
-   [ ] Server nhận và lưu dữ liệu.
-   [ ] SQLite quản lý nhiều endpoint.
-   [ ] Detection Engine phát hiện dấu hiệu đáng ngờ.
-   [ ] Alert có evidence và severity.
-   [ ] Dashboard hiển thị dữ liệu thật.
-   [ ] Alert có thể acknowledge/resolve.
-   [ ] Unit và integration tests vượt qua.
-   [ ] README và tài liệu kỹ thuật đầy đủ.
-   [ ] Slide hoàn chỉnh.
-   [ ] Demo trực tiếp và video dự phòng.

### Kịch bản demo 5--7 phút

1.  Giới thiệu bài toán và kiến trúc Mini EDR.
2.  Khởi động Flask Server.
3.  Khởi động Agent trên Linux.
4.  Cho thấy endpoint xuất hiện trên Dashboard.
5.  Tạo file mới trong thư mục được giám sát.
6.  Chỉnh sửa hoặc xóa file để FIM phát hiện.
7.  Kích hoạt một tình huống process đáng ngờ an toàn trong lab.
8.  Quan sát Security Event/Alert và evidence.
9.  Acknowledge Alert trên Dashboard.
10. Kết thúc bằng kết quả kiểm thử và giới hạn của hệ thống.

Chuẩn bị video demo dự phòng để tránh sự cố mạng, VM hoặc môi trường
trong buổi báo cáo.

------------------------------------------------------------------------

# 5. Thứ tự triển khai kỹ thuật chi tiết từ trạng thái hiện tại

Đây là thứ tự khuyến nghị để tránh viết Agent/API khi database và data
contract còn thay đổi.

``` text
[ĐÃ HOÀN THÀNH]
Phase 1: Backend Foundation
        |
        v
[ĐÃ KIỂM THỬ LOCAL]
Phase 2.1: Migration Framework
        |
        v
[TIẾP THEO]
Phase 2.2: Database Schema
        |
        v
Phase 2.3: Data Access Layer
        |
        v
Phase 2.4: Data Contract
        |
        v
Phase 2.5: API Specification
        |
        v
Phase 2.6: Database Tests
        |
        v
Phase 2.7: ERD & Documentation
        |
        v
Phase 3: Linux Agent
        |
        v
Phase 4: End-to-End Integration
        |
        v
Phase 5: Detection Engine
        |
        v
Phase 6: Alert Management
        |
        v
Phase 7: Web Dashboard
        |
        v
Phase 8: Full Testing & Security
        |
        v
Phase 9: Documentation Finalization
        |
        v
Phase 10: Slides & Demo
```

Có thể thực hiện một số test và tài liệu song song, nhưng không nên bỏ
qua phụ thuộc: schema và data contract phải đủ ổn định trước khi Agent
gửi dữ liệu diện rộng.

------------------------------------------------------------------------

# 6. Quy trình Git áp dụng cho từng Task

Ví dụ với Phase 2:

``` bash
# 1. Về main và cập nhật
git switch main
git pull --ff-only origin main

# 2. Tạo/chuyển feature branch
git switch -C feature/phase-2-data-model main

# 3. Kiểm tra branch và trạng thái
git branch --show-current
git log -1 --oneline
git status

# 4. Chạy kiểm thử
python -m py_compile server/*.py
python -m pytest -v

# 5. Xem thay đổi
git diff
git status --short

# 6. Stage file đã hoàn thiện
git add <các-file-cụ-thể>

# 7. Commit
git commit -m "feat(database): implement phase 2 data model"

# 8. Push
git push -u origin feature/phase-2-data-model
```

Không dùng `git add .` một cách máy móc. Luôn kiểm tra `.env`, SQLite
database, backup, log và file tạm trước khi commit.

Sau khi CI thành công và review xong, tạo Pull Request để merge vào
`main`. Không merge code chưa kiểm thử.

------------------------------------------------------------------------

# 7. Definition of Done --- tiêu chuẩn hoàn thành toàn dự án

Đồ án chỉ được xem là hoàn thành khi chứng minh được luồng sau bằng dữ
liệu thực tế:

1.  Linux Agent khởi chạy và định danh endpoint.
2.  Agent thu thập system/process/file telemetry.
3.  Agent gửi dữ liệu về Flask Server.
4.  Server xác thực, validate và lưu dữ liệu.
5.  Database giữ được lịch sử và quan hệ dữ liệu.
6.  Detection Engine tạo Security Event/Alert từ rule có thể giải thích.
7.  Dashboard hiển thị endpoint, telemetry và alerts.
8.  Quản trị viên acknowledge/resolve alert.
9.  Hệ thống có unit/integration tests.
10. Demo có thể chạy lại và có bằng chứng kết quả.

**Nguyên tắc cuối cùng:** hoàn thành một chức năng nghĩa là code đã
triển khai, có kiểm thử phù hợp và có thể trình diễn; không chỉ là đã
tạo file hoặc viết xong kế hoạch.
