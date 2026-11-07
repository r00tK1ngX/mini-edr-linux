# RULE REGISTRY & THREAT DETECTION SPECIFICATION
**Mini EDR for Linux — Academic Acceptance & Verified Remediation**

- **Module:** Detection Engine (`detection/`)
- **Version:** 1.1.0
- **Phase:** Phase 3 — Detection Correctness
- **Status:** **VERIFIED & OPERATIONAL**

---

## 1. DETECTION ARCHITECTURE & PHILOSOPHY

The Mini EDR Linux threat detection subsystem operates on structured telemetry streams ingested from Linux endpoints:
1. **Rule-Based Heuristic Evaluation:** Evaluates process execution metadata and file integrity events against deterministic, explainable security rules.
2. **Multi-Factor Event Correlation:** Correlates disparate telemetry signals (e.g., process execution anomalies combined with FIM dropper events) within a bounded time window (`time_window_seconds`, default 300s).
3. **PID Reuse Resilience:** Implements unique process identity (`pid:process_name:start_time`) to eliminate alert collisions caused by Linux kernel PID recycling.
4. **Deterministic Event Linking:** Persists detection security events and links alerts exclusively to contributing event IDs, eliminating ambiguous alert-to-event relationships.

> [!IMPORTANT]
> **Heuristic Boundary Statement (Academic Honesty):**
> Mini EDR Linux employs host-level heuristics and polling-based `/proc` telemetry. These rules are designed for educational demonstration and transparent threat auditing. **They do not claim or guarantee 100% detection of all Linux rootkits, kernel exploits, memory-only injections, or obfuscated reverse shells.** Advanced evasion techniques (such as process hollowing, eBPF probes evasion, or rootkit hooks) are outside the academic scope of this project.

---

## 2. STANDARD DETECTION RULES CATALOG

### 2.1 `rule-process-high-cpu` — High CPU Consumption

| Field | Specification |
| :--- | :--- |
| **Rule ID** | `rule-process-high-cpu` |
| **Name** | High CPU Consumption |
| **Purpose** | Detect sustained anomalous process CPU consumption potentially indicating unmanaged cryptominers, runaway computational loops, or denial-of-service behavior. |
| **Input Fields** | `cpu_percent`, `process_name`, `pid`, `username`, `exe_path`, `start_time` |
| **Trigger Conditions** | `cpu_percent >= threshold_percent` (default: 85.0%) |
| **Severity** | `medium` |
| **Base Risk Score** | 30 / 100 |
| **MITRE ATT&CK** | `T1496: Resource Hijacking` |
| **Evidence Structure** | `{"pid": int, "process_name": str, "exe_path": str, "cpu_percent": float, "threshold_percent": float, "mitre_attack": str, "start_time": Optional[str]}` |
| **Expected False Positives** | - Software compilation tools (`gcc`, `clang`, `make`, `cargo`)<br>- Video/media processing and transcoding (`ffmpeg`)<br>- Intensive database operations (`VACUUM`, bulk index rebuilds)<br>- Scientific modeling and distributed rendering tasks |
| **Unit Tests** | `tests/test_detection.py::test_process_high_cpu_rule_triggers`<br>`tests/test_detection_correctness_p3.py::test_rule_registry_catalog_completeness` |

---

### 2.2 `rule-process-high-memory` — High Memory Usage

| Field | Specification |
| :--- | :--- |
| **Rule ID** | `rule-process-high-memory` |
| **Name** | High Memory Usage |
| **Purpose** | Detect anomalous process RAM allocation that could lead to host instability, OOM-killer panics, or denial of service. |
| **Input Fields** | `memory_percent`, `process_name`, `pid`, `username`, `rss_bytes`, `exe_path`, `start_time` |
| **Trigger Conditions** | `memory_percent >= threshold_percent` (default: 85.0%) |
| **Severity** | `medium` |
| **Base Risk Score** | 30 / 100 |
| **MITRE ATT&CK** | `T1499: Endpoint Denial of Service` |
| **Evidence Structure** | `{"pid": int, "process_name": str, "exe_path": str, "memory_percent": float, "rss_bytes": int, "threshold_percent": float, "mitre_attack": str, "start_time": Optional[str]}` |
| **Expected False Positives** | - Large in-memory caching systems (`redis-server`, `memcached`)<br>- Database buffers (`mysqld`, `postgres`)<br>- Heavy multi-tab browser processes (`chrome`, `firefox`)<br>- Large JVM application containers (`java`) |
| **Unit Tests** | `tests/test_detection.py::test_process_high_memory_rule_triggers` |

---

### 2.3 `rule-process-suspicious-path` — Process in Suspicious Directory

| Field | Specification |
| :--- | :--- |
| **Rule ID** | `rule-process-suspicious-path` |
| **Name** | Process Running from Suspicious Directory |
| **Purpose** | Detect executable binaries executing directly from world-writable or temporary directories (`/tmp`, `/var/tmp`, `/dev/shm`), where adversaries typically stage payloads to bypass read-only root filesystems. |
| **Input Fields** | `exe_path`, `process_name`, `pid`, `username`, `start_time` |
| **Trigger Conditions** | `exe_path` resides in or starts with any path in `suspicious_paths` (`/tmp`, `/var/tmp`, `/dev/shm`) |
| **Severity** | `high` |
| **Base Risk Score** | 50 / 100 |
| **MITRE ATT&CK** | `T1036: Masquerading` |
| **Evidence Structure** | `{"pid": int, "process_name": str, "exe_path": str, "matched_suspicious_path": str, "username": str, "mitre_attack": str, "start_time": Optional[str]}` |
| **Expected False Positives** | - Legitimate developer scripts executed ad-hoc from `/tmp`<br>- Self-extracting setup installers and uncompress routines<br>- Ephemeral containerized workers utilizing `/dev/shm` IPC buffers |
| **Unit Tests** | `tests/test_detection.py::test_process_suspicious_path_rule_triggers`<br>`tests/test_detection_correctness_p3.py::test_detection_to_event_id_direct_mapping` |

---

### 2.4 `rule-process-hidden-binary` — Hidden Executable Execution

| Field | Specification |
| :--- | :--- |
| **Rule ID** | `rule-process-hidden-binary` |
| **Name** | Hidden Executable Execution |
| **Purpose** | Detect processes running from hidden files (filename starts with `.`) or hidden directory components, a classic Linux masquerading technique to conceal persistence. |
| **Input Fields** | `process_name`, `exe_path`, `pid`, `username`, `start_time` |
| **Trigger Conditions** | `process_name.startswith('.')` (excluding `.` and `..`) OR any path component of `exe_path` starts with `.` |
| **Severity** | `high` |
| **Base Risk Score** | 50 / 100 |
| **MITRE ATT&CK** | `T1564.001: Hidden Files and Directories` |
| **Evidence Structure** | `{"pid": int, "process_name": str, "exe_path": str, "detection_reason": str, "mitre_attack": str, "start_time": Optional[str]}` |
| **Expected False Positives** | - User-installed tooling in `~/.local/bin` or `~/.cargo/bin`<br>- Python virtual environments (`.venv/bin/python`)<br>- Tool version managers (`~/.nvm/versions/...`) |
| **Unit Tests** | `tests/test_detection.py::test_process_hidden_binary_rule_triggers`<br>`tests/test_detection_correctness_p3.py::test_correlated_alert_links_only_relevant_event_ids` |

---

### 2.5 `rule-proc-shell-spawn` — Interactive Shell in Daemon Context

| Field | Specification |
| :--- | :--- |
| **Rule ID** | `rule-proc-shell-spawn` |
| **Name** | Interactive Shell Spawned Under Daemon Context |
| **Purpose** | Detect interactive Linux command interpreters (`sh`, `bash`, `zsh`, `dash`) executed under web servers, daemons, or unprivileged service accounts (`www-data`, `nginx`, `apache`, `nobody`), indicating potential web shell execution or reverse shell breakouts. |
| **Input Fields** | `process_name`, `exe_path`, `username`, `parent_name`, `ppid`, `pid`, `start_time` |
| **Trigger Conditions** | Process is a shell (`sh`, `bash`, `dash`, `zsh`) AND (`username` in `["www-data", "apache", "nginx", "nobody", "daemon"]` OR `parent_name` in `["nginx", "apache2", "httpd", "python", "python3", "php", "node"]` OR `context.get("suspicious_spawn") == True`) |
| **Severity** | `high` |
| **Base Risk Score** | 60 / 100 |
| **MITRE ATT&CK** | `T1059.004: Unix Shell` |
| **Evidence Structure** | `{"pid": int, "ppid": int, "process_name": str, "exe_path": str, "username": str, "parent_name": str, "mitre_attack": str, "start_time": Optional[str]}` |
| **Expected False Positives** | - Legitimate administrative scripts executed by deployment daemons<br>- CI/CD build agents executing shell steps under service accounts<br>- Scheduled cron scripts invoked under system accounts |
| **Unit Tests** | `tests/test_detection_correctness_p3.py::test_shell_spawn_parent_process_resolution`<br>`tests/test_detection.py::test_rule_registry_default_loading` |

---

### 2.6 `rule-fim-sensitive-tampered` — Critical System File Tampering

| Field | Specification |
| :--- | :--- |
| **Rule ID** | `rule-fim-sensitive-tampered` |
| **Name** | Critical System File Tampering |
| **Purpose** | Detect modification or deletion of sensitive system configuration, authentication, or scheduling files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/etc/pam.d/*`, `/etc/crontab`). |
| **Input Fields** | `file_path`, `event_type`, `sha256`, `evidence` |
| **Trigger Conditions** | Monitored file matches critical list AND `event_type` in `("fim_file_modified", "fim_file_deleted", "file.modified", "file.deleted")` |
| **Severity** | `critical` (for `/etc/shadow` or `/etc/sudoers`) or `high` |
| **Base Risk Score** | 60 (high) or 80 (critical) |
| **MITRE ATT&CK** | `T1565.001: Stored Data Manipulation / T1098: Account Manipulation` |
| **Evidence Structure** | `{"file_path": str, "event_type": str, "action": str, "evidence": dict, "mitre_attack": str}` |
| **Expected False Positives** | - Authorized sysadmin user creation or password modification (`passwd`, `useradd`)<br>- Security package upgrades altering default PAM or SSH configurations<br>- Automatic cron scheduling updates by package managers |
| **Unit Tests** | `tests/test_detection.py::test_fim_sensitive_file_tampering_triggers_alert`<br>`tests/test_detection.py::test_detection_engine_evaluates_fim_event_and_generates_alert` |

---

### 2.7 `rule-fim-dropped-binary` — Dropped Binary in Temporary Directory

| Field | Specification |
| :--- | :--- |
| **Rule ID** | `rule-fim-dropped-binary` |
| **Name** | Dropped Binary in Temporary Directory |
| **Purpose** | Detect newly created files in temporary directories (`/tmp`, `/var/tmp`, `/dev/shm`), identifying potential stage-1 malware drop events. |
| **Input Fields** | `file_path`, `event_type`, `evidence` |
| **Trigger Conditions** | File created in any path matching `suspicious_paths` AND `event_type` in `("fim_file_created", "file.created")` |
| **Severity** | `medium` |
| **Base Risk Score** | 40 / 100 |
| **MITRE ATT&CK** | `T1105: Ingress Tool Transfer` |
| **Evidence Structure** | `{"file_path": str, "event_type": str, "action": "created", "evidence": dict, "mitre_attack": str}` |
| **Expected False Positives** | - Ephemeral application temporary files and session sockets<br>- Text editor swap files (`.swp`, `nano.*`)<br>- IPC files created by desktop environments in `/dev/shm` |
| **Unit Tests** | `tests/test_detection.py::test_fim_dropped_binary_rule_triggers`<br>`tests/test_detection.py::test_fim_dropped_binary_and_process_exec_correlation_e2e` |

---

### 2.8 `rule-correlated-multistage` — Multi-Stage Correlated Threat

| Field | Specification |
| :--- | :--- |
| **Rule ID** | `rule-correlated-multistage` |
| **Name** | Multi-Stage Attack Correlation |
| **Purpose** | Correlate multi-source indicators across process anomalies and file integrity changes within `time_window_seconds`. Escalates low/medium noise into High or Critical actionable incidents when multiple stages converge on the same executable identity. |
| **Input Fields** | `process_detections`, `fim_detections`, `time_window_seconds`, `snapshot_time` |
| **Trigger Conditions** | Distinct contributing factors >= 2 AND Total calculated risk score >= `min_correlation_score` (default: 75) within `time_window_seconds` (default: 300s). |
| **Severity** | `critical` (Score >= 85) or `high` (Score 75-84) |
| **Total Risk Score** | Sum of contributing factor scores (clamped at 100) |
| **MITRE ATT&CK** | Aggregated composite MITRE tags (e.g., `T1059 / T1105 / T1496`) |
| **Contributing Factors** | - `suspicious_execution_path` (+50)<br>- `hidden_executable` (+40)<br>- `suspicious_shell_spawn` (+50)<br>- `fim_dropped_and_executed` (+50)<br>- `high_cpu_utilization` (+30)<br>- `high_memory_utilization` (+30) |
| **Evidence Structure** | `{"pid": int, "process_name": str, "exe_path": str, "process_identity": str, "start_time": str, "factors": list, "total_risk_score": int, "mitre_attack": str}` |
| **Expected False Positives** | - Self-compiled benchmark suites running inside `/tmp` that execute immediately after extraction and consume 90%+ CPU. |
| **Unit Tests** | `tests/test_detection.py::test_correlation_complete_attack_chain_with_fim`<br>`tests/test_detection_correctness_p3.py::test_correlation_time_window_recent_event_matches`<br>`tests/test_detection_correctness_p3.py::test_correlation_time_window_stale_event_rejected` |

---

## 3. SUMMARY DISPOSITION OF PHASE 3 FINDINGS

| Audit Finding ID | Finding Description | Technical Resolution | Verification Test |
| :--- | :--- | :--- | :--- |
| **`FINDING-NEW-10`** | Unsafe `index()` lookup and indiscriminate event ID linkage | Implemented direct `DetectionResult.event_id` assignment; correlated alerts link strictly contributing event IDs | `test_detection_to_event_id_direct_mapping`<br>`test_correlated_alert_links_only_relevant_event_ids` |
| **`FINDING-NEW-11`** | `parent_name` never resolved for shell spawn detection | Implemented in-snapshot PID->PPID hierarchy resolution in both `ProcessCollector` and `DetectionEngine` | `test_shell_spawn_parent_process_resolution`<br>`test_process_collector_enriches_parent_name` |
| **`FINDING-PHASE05-03`** | PID reuse and correlation time window boundaries | Implemented `_is_within_time_window` (300s limit) and start_time process identity separation | `test_correlation_time_window_recent_event_matches`<br>`test_correlation_time_window_stale_event_rejected`<br>`test_pid_reuse_distinct_process_identity` |
