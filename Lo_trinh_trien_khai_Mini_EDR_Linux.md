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

**Trạng thái: Đã hoàn thành 100% (Đạt toàn bộ tiêu chí nghiệm thu).**

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

-   `NEW`: cảnh báo mới được kích hoạt từ Detection Engine.
-   `ACKNOWLEDGED`: quản trị viên/SOC đã xác nhận sự cố, bắt đầu điều tra.
-   `RESOLVED`: sự cố đã được xử lý (mitigated hoặc dismissed do false positive).

### API hoàn thiện

``` http
GET  /api/v1/alerts
GET  /api/v1/alerts/<id>
GET  /api/v1/alerts/summary
GET  /api/v1/alerts/stats
POST /api/v1/alerts/<id>/acknowledge
POST /api/v1/alerts/<id>/resolve
POST /api/v1/alerts/<id>/dismiss
```

### Dữ liệu lưu trữ và quản lý

-   Alert ID (`id`).
-   Unique key phục vụ gom cụm (`alert_key`).
-   Mã luật phát hiện (`rule_id`).
-   Endpoint liên quan (`agent_id`).
-   Mức độ nghiêm trọng (`severity`: info, low, medium, high, critical).
-   Tiêu đề và mô tả sự cố (`title`, `description`).
-   Liên kết sự kiện bảo mật nguồn (`alert_events` liên kết sang `security_events`).
-   Thời điểm phát hiện: `first_seen_at`, `last_seen_at`.
-   Thời điểm quản lý: `created_at`, `updated_at`, `acknowledged_at`, `resolved_at`.
-   Ghi chú xử lý sự cố (`resolution_note`).

### Tiêu chí nghiệm thu đã đạt

-   [x] Detection Engine tạo và liên kết Alert tự động trong thời gian thực.
-   [x] API liệt kê và lọc linh hoạt theo `status`, `severity`, `agent_id`, `rule_id`, phân trang chuẩn với `limit` và `offset`.
-   [x] API chi tiết cảnh báo `GET /api/v1/alerts/<id>` hiển thị đầy đủ danh sách security events liên kết.
-   [x] API thống kê `GET /api/v1/alerts/summary` và alias `/stats` tổng hợp số lượng alert theo status và severity (hỗ trợ lọc theo agent).
-   [x] Thực hiện xác nhận (`POST /acknowledge`), đóng sự cố (`POST /resolve`), và bỏ qua cảnh báo (`POST /dismiss`).
-   [x] Lưu chính xác thời điểm xử lý `acknowledged_at`, `resolved_at` cùng `resolution_note`.
-   [x] State transition guard: chặn chuyển từ `resolved` về `acknowledged` với HTTP 400.
-   [x] Idempotency: gọi lại acknowledge, resolve hoặc dismiss trên cảnh báo đã ở trạng thái đích đều trả về HTTP 200 mà không ghi đè timestamp lịch sử.
-   [x] Toàn bộ 36 test cases trong `tests/test_alert_management.py` và 182 test cases toàn hệ thống đều PASS 100%.

------------------------------------------------------------------------

## Phase 7 --- Web Dashboard

**Trạng thái: Đã hoàn thành 100% (Đạt toàn bộ tiêu chí nghiệm thu).**

### Công nghệ & Phong cách Thiết kế

-   **Backend:** Flask Application Factory + Jinja2 Templates + Repositories DAL.
-   **Frontend:** HTML5 + Modern CSS3 + Vanilla ES6+ JavaScript (không phụ thuộc CDN bên ngoài, chạy mượt mà ngay cả trong môi trường offline/air-gapped).
-   **Phong cách Giao diện:** **Cyberpunk Hacker / SOC Command Center** hiện đại:
    -   Tông nền tối Deep Space / Dark Terminal (`#06090e`), hiệu ứng lưới ma trận Matrix Grid và lớp phủ CRT scanlines.
    -   Bảng màu Neon đặc trưng: Neon Cyan (`#00f0ff`), Matrix Neon Green (`#00ff9d`), Alert Neon Red (`#ff0055`), Amber Warning (`#ffb700`), Neon Purple (`#b026ff`).
    -   HUD Navigation Bar hiển thị nhịp xung thời gian thực `● GRID ACTIVE` và đồng hồ số UTC.
    -   Font Monospace kỹ thuật (`JetBrains Mono`, `Fira Code`, `Consolas`).
    -   Cắt góc vát công nghệ (Angular Tech Chamfers), thanh đo tài nguyên có dải chuyển màu neon.

### Cấu trúc giao diện

``` text
templates/
├── base.html          # Khung HUD Cyberpunk, modal deck & toast system
├── dashboard.html     # Trang 1: SOC Command Center Overview
├── endpoints.html     # Trang 2: Endpoint Matrix & Telemetry
├── alerts.html        # Trang 3: Incident Response & Triage Console
└── events.html        # Trang 4: Security Events Audit Log

static/
├── style.css          # Cyberpunk Theme Stylesheet hoàn chỉnh
└── dashboard.js       # Live clock, Async Modals & Instant Triage Actions
```

### Các trang chức năng đã hoàn thiện

-   **Trang 1 --- Overview (`/dashboard`):**
    -   4 Cyber KPI Tiles: Tổng số Endpoint (Online/Offline), Active Incidents (New/Acknowledged), Critical & High Threats, Ingested Security Events.
    -   Đo lường trung bình tài nguyên toàn mạng: CPU, Memory, Disk với thanh đo phát sáng neon.
    -   Ma trận phân bố mức độ nghiêm trọng cảnh báo (Severity Matrix).
    -   Dòng sự cố an ninh trực tiếp (Active Incidents Stream) và luồng nhật ký sự kiện bảo mật (Security Telemetry Stream).
-   **Trang 2 --- Endpoints (`/endpoints`):**
    -   Bảng danh sách máy tính đầu cuối: Hostname, Agent ID, IP, OS, thanh đo CPU/RAM/Disk, Uptime, Last Heartbeat, Badge trạng thái Online/Offline.
    -   Bộ lọc nhanh trạng thái (`ALL`, `ONLINE`, `OFFLINE`) và ô tìm kiếm tức thời theo hostname/IP/agent.
    -   Nút `INSPECT`: Mở Cyber Modal nạp danh sách tiến trình đang chạy (`process_snapshots` & `process_observations`) và số lượng tệp FIM được giám sát.
-   **Trang 3 --- Alerts & Incident Response (`/alerts`):**
    -   Bảng điều khiển xử lý sự cố an ninh: lọc theo `Status` (`ALL`, `NEW`, `ACKNOWLEDGED`, `RESOLVED`), `Severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), và lọc theo Endpoint.
    -   Xem chi tiết bằng chứng (`EVIDENCE`): Mở Modal hiển thị toàn bộ JSON evidence và các security events liên kết.
    -   Thực thi hành động ngay trên giao diện mà không cần reload trang:
        -   `ACK`: Xác nhận sự cố (chuyển sang `ACKNOWLEDGED`).
        -   `RESOLVE`: Mở modal nhập ghi chú khắc phục sự cố (chuyển sang `RESOLVED`).
        -   `DISMISS`: Đánh dấu bỏ qua cảnh báo là false positive.
-   **Trang 4 --- Audit Logs (`/events`):**
    -   Nhật ký kiểm toán sự kiện an ninh và FIM, lọc theo mức độ nghiêm trọng và loại sự kiện, hỗ trợ mở rộng xem bằng chứng JSON chi tiết.

### Tiêu chí nghiệm thu đã đạt

-   [x] Overview hiển thị 100% số liệu thật từ SQLite database, không dùng số liệu hardcode.
-   [x] Endpoint list cập nhật chính xác theo chu kỳ heartbeat và ngưỡng `OFFLINE_AFTER_SECONDS`.
-   [x] Modal kiểm tra Endpoint hiển thị danh sách tiến trình và trạng thái FIM.
-   [x] Alert list và modal Evidence hiển thị đầy đủ chi tiết bằng chứng và security events liên quan.
-   [x] Các nút Acknowledge, Resolve, Dismiss hoạt động mượt mà qua AJAX, có Toast notification phản hồi ngay lập tức.
-   [x] Toàn bộ 11 test cases trong `tests/test_dashboard.py` và 193 test cases toàn hệ thống đều PASS 100%.

------------------------------------------------------------------------

## Phase 8 --- Testing, Security và Reliability

**Trạng thái: Đã hoàn thành 100% (Đạt toàn bộ tiêu chí nghiệm thu kiểm thử & bảo mật).**

### 8.1. Unit Tests

Kiểm tra từng module độc lập:

-   [x] System collector (`tests/test_agent_system_collector.py`).
-   [x] Process collector (`tests/test_agent_process_collector.py`).
-   [x] FIM (`tests/test_agent_fim.py`).
-   [x] API validation (`tests/test_api_validation.py`).
-   [x] Repository DAL (`tests/test_repositories.py`).
-   [x] Detection rules (`tests/test_detection_engine.py`, `tests/test_rules.py`).
-   [x] Alert state transitions (`tests/test_alert_management.py`).
-   [x] Migration framework (`tests/test_migrations.py`).
-   [x] Web Dashboard UI routes & view models (`tests/test_dashboard.py`).

### 8.2. Integration Tests

Kiểm tra luồng E2E khép kín toàn hệ thống (`tests/test_full_system_e2e.py`):

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

-   [x] Kịch bản Full System Lifecycle E2E:
    1. Agent đăng ký heartbeat & lưu telemetry hệ thống ban đầu (CPU, RAM, Disk).
    2. Khởi tạo FIM baseline cho các tệp nhạy cảm (`/etc/shadow`, `/usr/bin/sudo`).
    3. Gửi process snapshot chứa tiến trình độc hại (`/tmp/nc -lvnp 4444`).
    4. Detection Engine kích hoạt theo thời gian thực: sinh security events và tạo Alert CRITICAL (`Reverse Shell via Netcat`).
    5. Gửi sự kiện FIM sửa đổi tệp `/etc/shadow`: sinh Alert HIGH (`Sensitive File Tampering`).
    6. Dashboard SOC Console truy vấn tổng quan, danh sách endpoints, danh sách alerts và security events.
    7. SOC Analyst xử lý sự cố: Acknowledge -> Resolve với ghi chú khắc phục. Kiểm tra state transition guard (chặn lùi trạng thái về acknowledge).
    8. Kiểm tra agent offline sau ngưỡng thời gian và khôi phục online khi có heartbeat mới.
    9. Xác minh toàn vẹn cơ sở dữ liệu (`PRAGMA integrity_check`, `PRAGMA foreign_key_check`).

### 8.3. Test matrix

  Kiểm thử                          Kết quả mong đợi                           Trạng thái
  --------------------------------- ------------------------------------------ ----------
  Health check                      HTTP 200                                   [x] PASS
  Heartbeat đúng token              HTTP 200                                   [x] PASS
  Token sai/thiếu                   HTTP 401                                   [x] PASS
  Thiếu trường bắt buộc             HTTP 400                                   [x] PASS
  CPU vượt giới hạn                 HTTP 400                                   [x] PASS
  Metrics sai kiểu                  HTTP 400                                   [x] PASS
  Hai heartbeat cùng Agent ID       Cập nhật bản ghi cũ                        [x] PASS
  Agent ngừng hoạt động             Offline                                    [x] PASS
  Agent kết nối lại                 Online                                     [x] PASS
  Tạo file trong thư mục giám sát   FIM phát hiện                              [x] PASS
  Sửa file                          FIM phát hiện                              [x] PASS
  Xóa file                          FIM phát hiện                              [x] PASS
  Process đáng ngờ theo rule        Security Event/Alert được tạo              [x] PASS
  Alert acknowledge                 Trạng thái được cập nhật                   [x] PASS
  Alert resolve                     Trạng thái và thời gian xử lý được lưu     [x] PASS
  Duplicate message ID              Không ghi trùng (HTTP 200 vs HTTP 409)     [x] PASS
  Migration lỗi                     Rollback                                   [x] PASS
  Database integrity                `ok`                                       [x] PASS
  Foreign key check                 Không có lỗi                               [x] PASS

### 8.4. Security checklist

-   [x] Không commit `.env` (thêm vào `.gitignore`, cung cấp file mẫu `.env.example`).
-   [x] Không log API token: Kiểm tra cơ chế sanitize/redact token trong logs (`tests/test_security_reliability.py`).
-   [x] Không nối chuỗi SQL với dữ liệu người dùng: 100% parameterized queries, kiểm thử với payload SQLi probe suite.
-   [x] Validate kích thước và kiểu dữ liệu đầu vào: Chặn payload vượt `MAX_CONTENT_LENGTH` 64KB (HTTP 413), kiểm tra range metrics 0-100%.
-   [x] Giới hạn thư mục FIM (`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/etc`).
-   [x] Xử lý permission errors: Bắt lỗi graceful, ghi log cảnh báo và tiếp tục vận hành.
-   [x] Không tự động kill process trong phiên bản đồ án (Đảm bảo an toàn cho host demo).
-   [x] Chỉ chạy trong lab hoặc hệ thống được phép giám sát.
-   [x] Không mở API ra Internet (Mặc định bind `127.0.0.1:5000`, xác thực Bearer Token).
-   [x] Backup database trước thay đổi schema quan trọng.
-   [x] XSS Hardening: Escape HTML an toàn trong `static/dashboard.js`, escape Jinja JS context trong templates.
-   [x] Message ID Idempotency: Kiểm tra chống replay attack, xử lý duplicate message_id đúng chuẩn (HTTP 200 replay vs HTTP 409 conflict).
-   [x] Database Reliability: Cơ chế kiểm tra toàn vẹn định kỳ `PRAGMA integrity_check` và `foreign_key_check`.
-   [x] Demo & Evaluation Seeder: Cung cấp kịch bản dữ liệu mẫu chuẩn (`scripts/seed_demo_data.py`) phục vụ bảo vệ đồ án và demo trực quan.

### Điều kiện hoàn thành Phase 8

Toàn bộ **214/214 test cases** (Unit, Integration, E2E, Security & Reliability) đều PASS 100% trong ~13.5s; không còn lỗ hổng bảo mật cơ bản hay vấn đề toàn vẹn dữ liệu nào chưa xử lý.

------------------------------------------------------------------------

## Phase 9 --- Documentation và kiến trúc

**Trạng thái: Đã hoàn thành 100% (Đạt toàn bộ tiêu chí nghiệm thu tài liệu và kiến trúc).**

### `docs/ARCHITECTURE.md` (Đã cập nhật Phiên bản 2.0 hoàn chỉnh)

-   [x] Tổng quan kiến trúc phân tán Client-Server (Agent, Flask Server, Detection Engine, Repositories DAL, SQLite WAL, Cyberpunk Web Dashboard).
-   [x] Sơ đồ khối kiến trúc toàn hệ thống.
-   [x] Vai trò chi tiết từng module (System Collector, Process Collector, FIM, Orchestrator, Ingestion API, Detection Engine, DAL, Web Console).
-   [x] Sơ đồ tuần tự (Sequence Diagrams) bằng Mermaid:
    -   Luồng thu thập Telemetry & Heartbeat.
    -   Luồng phát hiện tiến trình độc hại & kích hoạt cảnh báo an ninh.
    -   Luồng SOC Analyst thực hiện quy trình Triage sự cố trên Web Dashboard.
-   [x] Sơ đồ Thực thể Liên kết (ERD) bằng Mermaid chuẩn hóa 3NF và đặc tả chi tiết 8 bảng dữ liệu.
-   [x] Kiến trúc An toàn & Bảo mật (Token auth, Token redaction, Parameterized SQL, XSS escaping, Replay resistance, Payload limits).
-   [x] Giới hạn thiết kế và định hướng mở rộng tương lai (eBPF, gRPC/WebSockets, Distributed DB).

### `docs/DATA_CONTRACT.md` (Đã cập nhật Trạng thái Implemented & Verified)

-   [x] Cấu trúc Common Telemetry Envelope 1.0 (UUIDv4 `message_id`, ISO 8601 UTC timestamp).
-   [x] Chi tiết các cấu trúc payload: Heartbeat, System Metrics, Process Snapshots, File Baselines, Security Events.
-   [x] Ràng buộc kiểu dữ liệu, các trường bắt buộc/tùy chọn, quy tắc validator và ngưỡng chặn.
-   [x] Timestamp semantics và quyền sở hữu timestamp giữa Agent và Server.
-   [x] Cơ chế chống ghi trùng lặp (Idempotency) và chính sách retry.
-   [x] Chuẩn hóa mã phản hồi HTTP và error format.

### `docs/API_SPECIFICATION.md` (Đã cập nhật Phiên bản 2.0 hoàn chỉnh)

-   [x] Toàn bộ REST APIs: `/health`, `/heartbeat`, `/endpoints`, `/telemetry/system`, `/telemetry/processes`, `/file-baselines`, `/events`.
-   [x] Bộ APIs Quản lý Cảnh báo (Alert Management): `/alerts`, `/alerts/<id>`, `/alerts/summary`, `/alerts/stats`.
-   [x] Bộ APIs Triage Sự cố: `/acknowledge`, `/resolve`, `/dismiss` kèm kiểm soát chuyển dịch trạng thái.
-   [x] Bảng đặc tả các route Web Dashboard (`/dashboard`, `/endpoints`, `/alerts`, `/events`) và AJAX modal endpoints.
-   [x] Bảng mã trạng thái HTTP, yêu cầu vận hành bảo mật, và checklist nghiệm thu API 100% hoàn thành.

### `docs/TEST_PLAN.md` (Đã hoàn thiện Kế hoạch & Ma trận Kiểm thử)

-   [x] Mục tiêu kiểm thử và tiêu chuẩn nghiệm thu chất lượng hệ thống.
-   [x] Phạm vi kiểm thử 4 cấp độ: Unit Testing, Integration Testing, Full-System E2E Lifecycle, Security & Reliability.
-   [x] Ma trận ca kiểm thử (Test Matrix) chi tiết: phân nhóm theo module, mục đích, dữ liệu đầu vào, kết quả mong đợi, kết quả thực tế.
-   [x] Hướng dẫn thực thi kiểm thử và lệnh chạy riêng từng phân hệ chuyên biệt.
-   [x] Báo cáo nghiệm thu thực tế: **214/214 tests PASS 100%** trong ~12.5 giây.

### `README.md` (Đã viết lại toàn diện theo sản phẩm hoàn chỉnh)

-   [x] Giới thiệu dự án hiện đại, phong cách Cyberpunk EDR, đầy đủ badges trạng thái.
-   [x] Tính năng nổi bật của 6 trụ cột đồ án.
-   [x] Kiến trúc tổng quan và bảng công nghệ sử dụng (Tech Stack).
-   [x] Cấu trúc cây thư mục dự án hoàn chỉnh.
-   [x] Hướng dẫn cài đặt & Quickstart (Môi trường ảo, sinh API Token, chạy Server, chạy Agent, chạy Demo Seeder).
-   [x] Giới thiệu 4 phân hệ màn hình của Cyberpunk Web Dashboard.
-   [x] Danh mục quy tắc phát hiện và cơ chế tính điểm rủi ro của Detection Engine.
-   [x] Máy trạng thái vòng đời xử lý sự cố an ninh.
-   [x] Các biện pháp gia cố bảo mật (Security Hardening).
-   [x] Hướng dẫn kiểm thử và chạy 214 test cases.
-   [x] Liên kết đầy đủ đến các tài liệu đặc tả trong `docs/`.
-   [x] Giới hạn phạm vi đồ án và hướng phát triển mở rộng.

### Điều kiện hoàn thành Phase 9

100% tài liệu kỹ thuật khớp hoàn toàn với mã nguồn thực tế; không còn mô tả dạng "pending" hay thiếu sót tính năng; toàn bộ sơ đồ, hợp đồng dữ liệu, ma trận kiểm thử và hướng dẫn vận hành đều hoàn chỉnh và sẵn sàng cho buổi bảo vệ đồ án.

------------------------------------------------------------------------

## Phase 10 --- Hoàn thiện sản phẩm, Slide và Demo

**Trạng thái: Đã hoàn thành 100% (Hoàn tất toàn bộ mục tiêu đề tài từ Phase 1 đến Phase 10).**

### Tiêu chí sản phẩm cuối

-   [x] Repository chạy được trên Linux (Ubuntu, Debian, Kali Linux).
-   [x] Agent thu thập system telemetry (CPU%, RAM%, Disk%, Uptime).
-   [x] Agent thu thập process information (PID, PPID, User, Exe, Cmdline, RSS).
-   [x] FIM phát hiện file create/modify/delete sử dụng mã băm SHA-256.
-   [x] Server nhận và lưu dữ liệu theo chuẩn Common Telemetry Envelope 1.0.
-   [x] SQLite quản lý nhiều endpoint (trạng thái Online/Offline theo chu kỳ heartbeat).
-   [x] Detection Engine phát hiện dấu hiệu đáng ngờ (Reverse shell, Hack tools, Shell spawn, FIM tampering).
-   [x] Alert có evidence JSON, fingerprint và mức độ nghiêm trọng (Severity).
-   [x] Dashboard hiển thị 100% dữ liệu thật từ database với phong cách Cyberpunk Hacker.
-   [x] Alert có thể acknowledge/resolve/dismiss trực tiếp qua AJAX với State Transition Guards.
-   [x] Unit, Integration, E2E và Security tests vượt qua: **214/214 tests PASS 100%**.
-   [x] README và tài liệu kỹ thuật đầy đủ (`docs/ARCHITECTURE.md`, `docs/DATA_CONTRACT.md`, `docs/API_SPECIFICATION.md`, `docs/TEST_PLAN.md`).
-   [x] Slide hoàn chỉnh: Cấu trúc 18 slide chi tiết kèm lời thoại thuyết minh và bộ câu hỏi phản biện (`docs/PRESENTATION_SLIDES_OUTLINE.md`).
-   [x] Demo trực tiếp và kịch bản dự phòng: Script tự động hóa kịch bản tấn công (`scripts/simulate_attack_scenario.py`) và hướng dẫn demo 5--7 phút (`docs/DEMO_SCENARIO.md`).

### Kịch bản demo 5--7 phút (Đã đóng gói hoàn chỉnh)

1.  Giới thiệu bài toán và kiến trúc Mini EDR trên giao diện Cyberpunk SOC Command Center (`/dashboard`).
2.  Khởi động Flask Server và nạp dữ liệu nền sinh động (`scripts/seed_demo_data.py`).
3.  Khởi động Agent trên Linux, hiển thị endpoint liveness và kiểm tra tiến trình qua Modal Inspect (`/endpoints`).
4.  Kích hoạt kịch bản tấn công FIM: Sửa đổi tệp cấu hình, Agent phát hiện mã băm SHA-256 thay đổi và kích hoạt Alert `HIGH`.
5.  Kích hoạt kịch bản tiến trình độc hại: Chạy `/tmp/nc -lvnp 4444`, Detection Engine tính Risk Score $= 90$ và tạo Alert `CRITICAL`.
6.  SOC Triage Console: Xem bằng chứng Evidence JSON, thực thi Acknowledge và Resolve với ghi chú xử lý trên giao diện.
7.  Minh chứng độ tin cậy và an toàn: Chạy toàn bộ 214 test cases và xác minh toàn vẹn cơ sở dữ liệu (`PRAGMA integrity_check`).
8.  Chuẩn bị sẵn video demo dự phòng 1080p theo hướng dẫn trong `docs/DEMO_SCENARIO.md`.

------------------------------------------------------------------------

# 5. Thứ tự triển khai kỹ thuật chi tiết từ trạng thái hiện tại

Đây là thứ tự khuyến nghị để tránh viết Agent/API khi database và data
contract còn thay đổi.

``` text
[100% HOÀN THÀNH] Phase 1: Backend Foundation & API Gateway
        |
        v
[100% HOÀN THÀNH] Phase 2: Database Schema & Repositories DAL
        |
        v
[100% HOÀN THÀNH] Phase 3: Linux Agent (Collectors, FIM, Orchestrator)
        |
        v
[100% HOÀN THÀNH] Phase 4: End-to-End Agent-Server Ingestion
        |
        v
[100% HOÀN THÀNH] Phase 5: Detection Engine & Correlation Rules
        |
        v
[100% HOÀN THÀNH] Phase 6: Alert & Incident Management Lifecycle
        |
        v
[100% HOÀN THÀNH] Phase 7: Cyberpunk Hacker SOC Web Dashboard
        |
        v
[100% HOÀN THÀNH] Phase 8: Full Testing & Security Hardening (214/214 Tests)
        |
        v
[100% HOÀN THÀNH] Phase 9: Documentation, ERD & Architecture Finalization
        |
        v
[100% HOÀN THÀNH] Phase 10: Slides Master Outline & Live Demo Scenario
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
