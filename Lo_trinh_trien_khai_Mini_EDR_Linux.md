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

**Trạng thái: Đã hoàn thành 100% (Đạt toàn bộ tiêu chí nghiệm thu Module 1 đến Module 5).**

### Mục tiêu

Agent chạy trên Linux, thu thập dữ liệu thực tế và gửi về Server.

### Module 1 --- `agent/system_collector.py`

**Đã hoàn thành và có 16 unit tests vượt qua (`tests/test_system_collector.py`).**

Chức năng đã xây dựng:

-   Thu thập `Hostname` qua socket/platform/`/etc/hostname`.
-   Thu thập `IP address` qua routing socket UDP & psutil interfaces (trả về `None` an toàn nếu không có mạng).
-   Thu thập `Operating System` qua `platform.freedesktop_os_release()`, `/etc/os-release` và platform fallback.
-   Thu thập `CPU usage` qua `psutil.cpu_percent` (ràng buộc chuẩn `0.0` đến `100.0%`).
-   Thu thập `RAM usage` qua `psutil.virtual_memory().percent` (`0.0` đến `100.0%`).
-   Thu thập `Disk usage` qua `psutil.disk_usage` (xử lý an toàn `PermissionError` và phân vùng).
-   Thu thập `Uptime` qua `psutil.boot_time()` và `/proc/uptime` (giây `>= 0.0`).
-   Cung cấp các hàm `collect_metrics()` (chuẩn hóa payload telemetry) và `collect_system_info()` (chuẩn hóa Heartbeat payload theo Data Contract).
-   Cung cấp lớp `SystemCollector` hướng đối tượng có khả năng cấu hình tham số đợt quét.

### Module 2 --- `agent/process_collector.py`

**Đã hoàn thành và có 13 unit tests vượt qua (`tests/test_process_collector.py`).**

Chức năng đã xây dựng:

-   Thu thập `PID` (kiểm tra `pid >= 0`).
-   Thu thập `PPID` (`ppid >= 0` hoặc `None`).
-   Thu thập `Process name` (chuẩn hóa tên không rỗng, fallback sang tên file binary thực thi `exe` hoặc `proc-<pid>`).
-   Thu thập `Username` sở hữu tiến trình.
-   Thu thập `CPU percent` (`>= 0.0%`).
-   Thu thập `Memory percent` (`0.0` đến `100.0%`).
-   Thu thập `RSS bytes` (bộ nhớ thực tế tiêu thụ).
-   Thu thập `Executable path` (`exe_path`).
-   Thu thập `Process start time` (chuẩn hóa `create_time` sang ISO 8601 UTC).
-   Bắt và xử lý an toàn các ngoại lệ `NoSuchProcess`, `AccessDenied`, `ZombieProcess` mà không làm crash collector.
-   Hàm `collect_process_snapshot()` đóng gói dữ liệu snapshot đầy đủ envelope theo chuẩn Data Contract và có thể lưu trực tiếp vào cơ sở dữ liệu qua `ProcessRepository`.
-   Hỗ trợ tra cứu tiến trình theo PID cụ thể qua `get_process_by_pid()`.
-   Cung cấp lớp hướng đối tượng `ProcessCollector`.

### Module 3 --- `agent/file_integrity.py`

**Đã hoàn thành và có 7 unit tests vượt qua (`tests/test_file_integrity.py`).**

Chức năng đã xây dựng:

-   Hàm `compute_sha256()` tính mã băm SHA-256 theo từng chunk 64KB, giới hạn kích thước file an toàn tránh treo bộ nhớ, kiểm tra file rỗng chuẩn `e3b0c442...`.
-   Hàm `inspect_file()` kiểm tra file thông thường, lấy kích thước byte, thời điểm sửa đổi `mtime_ns`, quyền hạn `file_mode` (mask `0o7777`) và hash SHA-256.
-   Hàm `scan_monitored_paths()` quét các tệp và thư mục được cấu hình, hỗ trợ quét đệ quy (recursive) hoặc 1 cấp, bỏ qua an toàn các symlink vòng lặp hoặc file thiếu quyền đọc.
-   Hàm `detect_file_changes()` so sánh quét hiện tại với baseline:
    -   Phát hiện file tạo mới (`change_type = 'created'`).
    -   Phát hiện file bị chỉnh sửa nội dung hoặc quyền (`change_type = 'modified'`).
    -   Phát hiện file bị xóa (`change_type = 'deleted'`), tự động cập nhật trạng thái `state = 'missing'` trong baseline nhưng vẫn bảo lưu hash cũ để phục vụ forensics.
-   Hàm `format_baseline_sync_payload()` chuẩn hóa payload đồng bộ baseline (`POST /api/v1/file-baselines`) theo đúng Data Contract.
-   Hàm `format_fim_security_event()` sinh sự kiện an ninh tương ứng (`fim_file_created`, `fim_file_modified`, `fim_file_deleted`) kèm fingerprint và evidence chi tiết.
-   Cung cấp lớp hướng đối tượng `FileIntegrityMonitor`.

### Module 4 --- `agent/client.py`

**Đã hoàn thành và có 10 unit tests vượt qua (`tests/test_agent_client.py`).**

Chức năng đã xây dựng:

-   Sử dụng thư viện chuẩn `urllib.request` thuần túy, zero-dependency, đảm bảo Agent siêu nhẹ và tương thích mọi bản phân phối Linux.
-   Gửi đầy đủ các loại payload lên API Server:
    -   `send_heartbeat()`: Gửi nhịp tim định kỳ (`POST /api/v1/heartbeat`).
    -   `send_system_telemetry()`: Gửi metrics tài nguyên (`POST /api/v1/telemetry/system`).
    -   `send_process_snapshot()`: Gửi toàn bộ snapshot tiến trình (`POST /api/v1/telemetry/processes`).
    -   `send_file_baselines()`: Đồng bộ trạng thái baseline tệp (`POST /api/v1/file-baselines`).
    -   `send_security_event()`: Gửi sự kiện an ninh (`POST /api/v1/events`).
-   Gửi header xác thực an toàn `Authorization: Bearer <token>`, tuyệt đối không log token hay thông tin nhạy cảm.
-   Cơ chế kiểm tra kết nối `check_health()` (`GET /health`).
-   Cơ chế Retry thông minh với Exponential Backoff:
    -   Tự động thử lại khi mất mạng, DNS timeout, hoặc server gặp sự cố 5xx.
    -   Tuyệt đối **không retry** khi gặp lỗi Client 401 (sai token) hoặc 400 (sai payload), mà trả ngay ngoại lệ `AgentAuthenticationError` / `AgentRequestError`.
    -   Ném ngoại lệ `AgentConnectionError` rõ ràng khi đã thử hết số lần retry tối đa.

### Module 5 --- `agent/main.py`

**Đã hoàn thành và có 6 unit tests vượt qua (`tests/test_agent_orchestrator.py`).**

Chức năng đã xây dựng:

-   Lớp `AgentConfig`: Quản lý cấu hình, tự động đọc biến môi trường và file `.env` (`EDR_AGENT_ID`, `EDR_SERVER_URL`, `EDR_API_TOKEN`, `EDR_HEARTBEAT_INTERVAL`, `EDR_PROCESS_SCAN_INTERVAL`, `EDR_FIM_SCAN_INTERVAL`, `EDR_MONITORED_PATHS`).
-   Lớp điều phối `AgentOrchestrator`:
    -   Điều phối độc lập 3 luồng chu kỳ (Heartbeat, Process Scan, FIM Scan).
    -   Khởi tạo và đồng bộ baseline FIM ở chu kỳ đầu, sau đó theo dõi phát hiện thay đổi và gửi security events.
    -   Hỗ trợ `run_single_cycle()` độc lập, hỗ trợ cờ `force_all` cho phép chạy đơn lẻ hoặc chạy lặp lại liên tục.
    -   Xử lý tín hiệu ngắt `SIGINT` (Ctrl+C) và `SIGTERM` đảm bảo Agent dừng an toàn mà không làm hỏng tài nguyên (Graceful shutdown).
    -   Bắt ngoại lệ cấp độ chu kỳ, đảm bảo một lỗi mạng tạm thời hoặc một task collector không làm sập tiến trình daemon của Agent.
-   CLI Entrypoint: Hỗ trợ các tham số dòng lệnh `--once` (chạy 1 chu kỳ rồi thoát), `--debug` (bật log chi tiết), `--server` và `--agent-id`.

### Điều kiện hoàn thành Phase 3

-   [x] Agent chạy ổn định trên Linux (môi trường Kali Linux).
-   [x] Collector trả dữ liệu hợp lệ (System, Process, FIM).
-   [x] Lỗi permission/process không làm Agent crash.
-   [x] Có unit tests đầy đủ (52 tests cho Agent, tổng toàn bộ dự án đạt 111 tests).
-   [x] Dữ liệu serialize chuẩn theo Data Contract.
-   [x] Agent không làm lộ token hoặc dữ liệu nhạy cảm trong logs.

------------------------------------------------------------------------

## Phase 4 --- Kết nối Agent với Server (End-to-End)

**Trạng thái: Đã hoàn thành 100% (Đạt toàn bộ tiêu chí nghiệm thu).**

### Mục tiêu

Chứng minh nhiều Linux Agent có thể gửi dữ liệu và Server lưu đúng
endpoint, hoạt động end-to-end từ thu thập mạng đến lưu trữ database.

### Các thành phần đã triển khai

1.  **Ingestion & Management API Endpoints (`server/routes.py`):**
    -   `POST /api/v1/telemetry/system`: Tiếp nhận telemetry metrics lịch sử, validate envelope, kiểm tra agent hợp lệ (HTTP 404 nếu chưa đăng ký), chống ghi trùng idempotency theo `message_id` (HTTP 200 duplicate / HTTP 409 conflict), lưu qua `MetricsRepository`.
    -   `POST /api/v1/telemetry/processes`: Tiếp nhận process snapshots, kiểm tra khớp `process_count`, từ chối PID trùng lặp trong snapshot, lưu atomic qua `ProcessRepository.create_snapshot()`.
    -   `POST /api/v1/file-baselines`: Đồng bộ baseline FIM, kiểm tra mã băm SHA-256 64 ký tự hex, đường dẫn tuyệt đối, trạng thái `present`/`missing`, tính toán số lượng `created`/`updated` và upsert hàng loạt an toàn qua `BaselineRepository`.
    -   `POST /api/v1/events`: Tiếp nhận security events từ Agent, ràng buộc nghiêm ngặt `source: "agent"`, validate severity chuẩn (`info`, `low`, `medium`, `high`, `critical`), lưu qua `EventRepository`.
    -   Alert API: Cung cấp `GET /api/v1/alerts` (hỗ trợ lọc theo `status`, `severity`, `agent_id`, phân trang `limit`/`offset`), `GET /api/v1/alerts/<id>` (kèm sự kiện liên kết), `POST /api/v1/alerts/<id>/acknowledge`, `POST /api/v1/alerts/<id>/resolve` (kèm resolution note).

2.  **Agent Integration Enhancement (`agent/main.py` & `agent/system_collector.py`):**
    -   Bổ sung phương thức `collect_telemetry_envelope()` vào `SystemCollector` để tự động đóng gói payload telemetry theo đúng chuẩn Data Contract 1.0.
    -   Cập nhật `AgentOrchestrator` trong chu kỳ thu thập tự động gửi cả Heartbeat và Telemetry metrics lên Server.
    -   Cập nhật `format_fim_security_event()` trong `agent/file_integrity.py` bổ sung trường bắt buộc `occurred_at`.

3.  **End-to-End Integration Test Suite (`tests/test_phase4_e2e.py`):**
    -   Khởi chạy Flask HTTP server thực tế trên cổng loopback ngẫu nhiên (`make_server`).
    -   `test_e2e_multiple_agents_registration_and_persistence`: Đăng ký 2 Agent độc lập (`lab-linux-01`, `lab-linux-02`), xác nhận không trùng lặp endpoint, kiểm tra toàn bộ dữ liệu (metrics, snapshots, observations, baselines) lưu chính xác vào SQLite.
    -   `test_e2e_fim_file_tampering_detects_and_creates_security_event`: Giả lập chỉnh sửa tệp giám sát, Agent phát hiện thay đổi và gửi security event lên Server, Server lưu vào bảng `security_events`.
    -   `test_e2e_offline_transition_and_online_reactivation`: Kiểm thử endpoint chuyển sang `offline` khi quá 15s không heartbeat và tự động phục hồi `online` khi nhận heartbeat mới.
    -   `test_e2e_agent_authentication_failure`: Kiểm thử từ chối kết nối khi sai token (HTTP 401), không retry sai mục đích và không lộ credential.

4.  **API Ingestion Tests (`tests/test_api.py`):**
    -   Bổ sung 9 unit tests cho các endpoint mới, kiểm thử xác thực, envelope validation, idempotency, duplicate retry, và alert lifecycle.

### Kết quả kiểm thử

-   Toàn bộ test suite: **124/124 tests PASSED** (52 agent tests, 38 API tests, 13 database tests, 10 repository tests, 7 migration tests, 4 E2E tests).

### Điều kiện hoàn thành Phase 4

-   [x] Tối thiểu hai endpoint xuất hiện (`lab-linux-01`, `lab-linux-02`).
-   [x] Không tạo endpoint trùng khi Agent gửi nhiều lần.
-   [x] Metrics/process/baselines/events lưu đúng Agent trong SQLite.
-   [x] Offline/Online hoạt động đúng theo ngưỡng thời gian.
-   [x] Có integration test hoàn chỉnh cho luồng Agent → API → Database.

------------------------------------------------------------------------

## Phase 5 --- Detection Engine

**Trạng thái: Đã hoàn thành 100% (Đạt toàn bộ tiêu chí nghiệm thu).**

### Mục tiêu

Chuyển telemetry và security events thành phát hiện có thể giải thích, kết hợp nhiều nguồn dữ liệu (tiến trình, FIM, tài nguyên) để đánh giá rủi ro chính xác và tạo cảnh báo an ninh.

### Các thành phần đã triển khai

1.  **Cấu hình tập trung (`config/rules.json`):**
    -   Thiết lập ngưỡng tài nguyên (`cpu_percent: 85.0`, `memory_percent: 85.0`).
    -   Định nghĩa danh sách thư mục thực thi đáng ngờ (`/tmp`, `/var/tmp`, `/dev/shm`).
    -   Định nghĩa danh sách tệp cấu hình/xác thực nhạy cảm cần bảo vệ nghiêm ngặt (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/etc/pam.d/`, v.v.).

2.  **Hệ thống Rule phát hiện (`detection/rules.py`):**
    -   `DetectionResult`: Cấu trúc chuẩn hóa kết quả phát hiện kèm `rule_id`, `severity`, `risk_score`, `evidence`, `fingerprint` và `event_type`.
    -   `ProcessHighCpuRule`: Phát hiện tiến trình chiếm dụng CPU vượt ngưỡng.
    -   `ProcessHighMemoryRule`: Phát hiện tiến trình chiếm dụng bộ nhớ RAM vượt ngưỡng.
    -   `ProcessSuspiciousPathRule`: Phát hiện binary thực thi từ thư mục tạm hoặc thế giới có quyền ghi (`/tmp`, `/var/tmp`, `/dev/shm`).
    -   `ProcessHiddenBinaryRule`: Phát hiện binary hoặc tiến trình ẩn (tên file hoặc thư mục cha bắt đầu bằng dấu chấm `.`).
    -   `FimSensitiveFileRule`: Phát hiện hành vi can thiệp, chỉnh sửa, xóa các tệp xác thực tối quan trọng của hệ điều hành.
    -   `RuleRegistry`: Nạp động các quy tắc từ cấu hình, quản lý và điều phối đánh giá đa dạng nguồn dữ liệu.

3.  **Hệ thống tương quan và chấm điểm rủi ro (`detection/correlation.py`):**
    -   `CorrelationEngine`: Kết hợp tín hiệu từ nhiều nguồn khác nhau trên cùng một endpoint.
    -   Mô hình chấm điểm rủi ro (Risk Score 0--100) minh bạch:
        -   Hiện tượng CPU cao đơn lẻ: Điểm rủi ro cơ sở (30 điểm), mức độ `medium` --- **Tuyệt đối không kết luận malware chỉ từ một ngưỡng CPU đơn lẻ**.
        -   Thực thi từ thư mục đáng ngờ (`/tmp`): Điểm rủi ro (50 điểm).
        -   Kết hợp thư mục đáng ngờ + CPU cao: Điểm rủi ro tăng vọt (80 điểm), mức độ `high`.
        -   Kết hợp FIM (tệp vừa được thả vào thư mục) + Tiến trình chạy từ tệp đó + CPU cao: Điểm rủi ro đạt tối đa (90--100 điểm), mức độ `critical` (chuỗi tấn công multi-stage malware execution).
    -   Mỗi phát hiện tương quan đều lưu đầy đủ bảng giải trình `factors` chi tiết, minh bạch lý do nâng mức độ cảnh báo.

4.  **Detection Orchestrator (`detection/engine.py`):**
    -   Tích hợp trực tiếp với Data Access Layer (`EventRepository`, `AlertRepository`, `ProcessRepository`).
    -   Khi phát hiện vi phạm quy tắc, tự động ghi nhận security event mới với `source = "detection"` vào bảng `security_events`.
    -   Tự động tổng hợp và tạo/cập nhật cảnh báo trong bảng `alerts` (trạng thái `new`) và liên kết các sự kiện vi phạm vào bảng `alert_events`.
    -   Được kích hoạt tự động theo thời gian thực (real-time) ngay khi Server nhận dữ liệu snapshot tiến trình hoặc security event tại `server/routes.py`.

5.  **Kiểm thử toàn diện (`tests/test_detection.py`):**
    -   22 test cases kiểm thử từng rule độc lập, kiểm thử nạp cấu hình JSON, kiểm thử logic tương quan đa nguồn, kiểm thử chống kết luận sai từ CPU đơn lẻ, kiểm thử tương tác database và kiểm thử kích hoạt real-time qua API.

### Kết quả kiểm thử

-   Toàn bộ test suite: **146/146 tests PASSED** (52 agent tests, 38 API tests, 22 detection tests, 13 database tests, 10 repository tests, 7 migration tests, 4 E2E tests).

### Điều kiện hoàn thành Phase 5

-   [x] Rule chạy trên dữ liệu thực tế (tiến trình, FIM, hệ thống).
-   [x] Có unit/integration test đầy đủ cho từng rule.
-   [x] Event được tạo với severity/evidence rõ ràng (`source = "detection"`).
-   [x] Correlation hoạt động tốt với dữ liệu nhiều nguồn kết hợp.
-   [x] Không kết luận malware chỉ từ một ngưỡng CPU đơn lẻ.

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
