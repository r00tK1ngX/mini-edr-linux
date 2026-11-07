"""Detection rules module for Mini EDR Linux.

Defines modular detection rules for analyzing system metrics, process snapshots,
and file integrity monitoring (FIM) events. Rules evaluate untrusted telemetry
and produce structured, explainable DetectionResults with risk scores and evidence.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_SUSPICIOUS_PATHS = ["/tmp", "/var/tmp", "/dev/shm"]
DEFAULT_SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/pam.d/common-auth",
    "/etc/pam.d/sshd",
    "/etc/crontab",
]


@dataclass
class DetectionResult:
    """Standardized result produced when a detection rule triggers."""

    rule_id: str
    rule_name: str
    title: str
    description: str
    severity: str  # "info", "low", "medium", "high", "critical"
    risk_score: int  # 0 to 100
    evidence: Dict[str, Any] = field(default_factory=dict)
    fingerprint: Optional[str] = None
    event_type: str = "security.detection"
    mitre_attack: Optional[str] = None
    event_id: Optional[int] = None


class BaseRule(ABC):
    """Abstract base class for all detection rules."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: str = "medium",
        base_score: int = 30,
        enabled: bool = True,
        mitre_attack: Optional[str] = None,
        purpose: Optional[str] = None,
        input_fields: Optional[List[str]] = None,
        expected_false_positives: Optional[List[str]] = None,
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity
        self.base_score = max(0, min(100, int(base_score)))
        self.enabled = enabled
        self.mitre_attack = mitre_attack
        self.purpose = purpose or description
        self.input_fields = list(input_fields or [])
        self.expected_false_positives = list(expected_false_positives or [])

    def to_dict(self) -> Dict[str, Any]:
        """Serialize rule metadata and documentation contract."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "purpose": self.purpose,
            "severity": self.severity,
            "base_score": self.base_score,
            "enabled": self.enabled,
            "mitre_attack": self.mitre_attack,
            "input_fields": self.input_fields,
            "expected_false_positives": self.expected_false_positives,
        }

    @abstractmethod
    def evaluate(self, context: Dict[str, Any]) -> Optional[DetectionResult]:
        """Evaluate contextual telemetry.

        Returns DetectionResult if matched, or None if no condition met.
        """
        raise NotImplementedError


class ProcessHighCpuRule(BaseRule):
    """Detects processes with CPU usage exceeding configured threshold."""

    def __init__(
        self,
        rule_id: str = "rule-process-high-cpu",
        name: str = "High CPU Consumption",
        threshold_percent: float = 85.0,
        severity: str = "medium",
        base_score: int = 30,
        enabled: bool = True,
        mitre_attack: str = "T1496: Resource Hijacking",
        purpose: str = "Detect sustained anomalous CPU utilization potentially indicating cryptomining or denial of service",
        input_fields: Optional[List[str]] = None,
        expected_false_positives: Optional[List[str]] = None,
    ):
        super().__init__(
            rule_id=rule_id,
            name=name,
            description="Process CPU consumption exceeded threshold",
            severity=severity,
            base_score=base_score,
            enabled=enabled,
            mitre_attack=mitre_attack,
            purpose=purpose,
            input_fields=input_fields or ["cpu_percent", "process_name", "pid", "username"],
            expected_false_positives=expected_false_positives or [
                "Software compilation (gcc, make)",
                "Video or media encoding (ffmpeg)",
                "Scientific computation or batch rendering",
                "Database maintenance routines (VACUUM, indexing)",
            ],
        )
        self.threshold_percent = float(threshold_percent)

    def evaluate(self, context: Dict[str, Any]) -> Optional[DetectionResult]:
        if not self.enabled:
            return None

        cpu_percent = context.get("cpu_percent")
        if cpu_percent is None or not isinstance(cpu_percent, (int, float)):
            return None

        if cpu_percent >= self.threshold_percent:
            agent_id = context.get("agent_id", "unknown")
            pid = context.get("pid", 0)
            proc_name = context.get("process_name", "unknown")
            exe_path = context.get("exe_path")
            start_time = context.get("start_time") or context.get("process_started_at")

            evidence = {
                "pid": pid,
                "process_name": proc_name,
                "exe_path": exe_path,
                "cpu_percent": round(float(cpu_percent), 2),
                "threshold_percent": self.threshold_percent,
                "mitre_attack": self.mitre_attack,
            }
            if start_time:
                evidence["start_time"] = start_time

            fp_suffix = f":{start_time}" if start_time else ""
            fingerprint = f"proc:high_cpu:{agent_id}:{pid}:{proc_name}{fp_suffix}"
            return DetectionResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                title=f"High CPU consumption by process '{proc_name}' (PID: {pid})",
                description=f"Process '{proc_name}' used {cpu_percent:.1f}% CPU, exceeding threshold of {self.threshold_percent}%.",
                severity=self.severity,
                risk_score=self.base_score,
                evidence=evidence,
                fingerprint=fingerprint,
                event_type="process.anomaly.high_cpu",
                mitre_attack=self.mitre_attack,
            )
        return None


class ProcessHighMemoryRule(BaseRule):
    """Detects processes with memory consumption exceeding configured threshold."""

    def __init__(
        self,
        rule_id: str = "rule-process-high-memory",
        name: str = "High Memory Usage",
        threshold_percent: float = 85.0,
        severity: str = "medium",
        base_score: int = 30,
        enabled: bool = True,
        mitre_attack: str = "T1499: Endpoint Denial of Service",
        purpose: str = "Detect excessive process memory utilization potentially indicating memory leaks or resource exhaustion",
        input_fields: Optional[List[str]] = None,
        expected_false_positives: Optional[List[str]] = None,
    ):
        super().__init__(
            rule_id=rule_id,
            name=name,
            description="Process RAM consumption exceeded threshold",
            severity=severity,
            base_score=base_score,
            enabled=enabled,
            mitre_attack=mitre_attack,
            purpose=purpose,
            input_fields=input_fields or ["memory_percent", "process_name", "pid", "username", "rss_bytes"],
            expected_false_positives=expected_false_positives or [
                "Heavy in-memory databases (redis-server, mysqld)",
                "Modern multi-process web browsers (chrome, firefox)",
                "JVM application servers or garbage collection pauses",
            ],
        )
        self.threshold_percent = float(threshold_percent)

    def evaluate(self, context: Dict[str, Any]) -> Optional[DetectionResult]:
        if not self.enabled:
            return None

        mem_percent = context.get("memory_percent")
        if mem_percent is None or not isinstance(mem_percent, (int, float)):
            return None

        if mem_percent >= self.threshold_percent:
            agent_id = context.get("agent_id", "unknown")
            pid = context.get("pid", 0)
            proc_name = context.get("process_name", "unknown")
            rss_bytes = context.get("rss_bytes")
            start_time = context.get("start_time") or context.get("process_started_at")

            evidence = {
                "pid": pid,
                "process_name": proc_name,
                "exe_path": context.get("exe_path"),
                "memory_percent": round(float(mem_percent), 2),
                "rss_bytes": rss_bytes,
                "threshold_percent": self.threshold_percent,
                "mitre_attack": self.mitre_attack,
            }
            if start_time:
                evidence["start_time"] = start_time

            fp_suffix = f":{start_time}" if start_time else ""
            fingerprint = f"proc:high_mem:{agent_id}:{pid}:{proc_name}{fp_suffix}"
            return DetectionResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                title=f"High memory usage by process '{proc_name}' (PID: {pid})",
                description=f"Process '{proc_name}' consumed {mem_percent:.1f}% RAM, exceeding threshold of {self.threshold_percent}%.",
                severity=self.severity,
                risk_score=self.base_score,
                evidence=evidence,
                fingerprint=fingerprint,
                event_type="process.anomaly.high_memory",
                mitre_attack=self.mitre_attack,
            )
        return None


class ProcessSuspiciousPathRule(BaseRule):
    """Detects executables running from temporary, shared memory, or world-writable directories."""

    def __init__(
        self,
        rule_id: str = "rule-process-suspicious-path",
        name: str = "Process Running from Suspicious Directory",
        suspicious_paths: Optional[List[str]] = None,
        severity: str = "high",
        base_score: int = 50,
        enabled: bool = True,
        mitre_attack: str = "T1036: Masquerading",
        purpose: str = "Detect binaries executing from writable temporary directories where malware commonly stages payloads",
        input_fields: Optional[List[str]] = None,
        expected_false_positives: Optional[List[str]] = None,
    ):
        super().__init__(
            rule_id=rule_id,
            name=name,
            description="Process binary executing from a temporary or world-writable directory",
            severity=severity,
            base_score=base_score,
            enabled=enabled,
            mitre_attack=mitre_attack,
            purpose=purpose,
            input_fields=input_fields or ["exe_path", "process_name", "pid", "username"],
            expected_false_positives=expected_false_positives or [
                "Legitimate administrative or benchmark scripts executed from /tmp",
                "Self-extracting software installers and unpackers",
                "Ephemeral worker binaries executed inside container /dev/shm",
            ],
        )
        self.suspicious_paths = [p.rstrip("/") for p in (suspicious_paths or DEFAULT_SUSPICIOUS_PATHS)]

    def evaluate(self, context: Dict[str, Any]) -> Optional[DetectionResult]:
        if not self.enabled:
            return None

        exe_path = context.get("exe_path")
        if not exe_path or not isinstance(exe_path, str):
            return None

        norm_path = os.path.normpath(exe_path.strip())

        for sp in self.suspicious_paths:
            # Check exact directory or subpath
            if norm_path == sp or norm_path.startswith(sp + "/"):
                agent_id = context.get("agent_id", "unknown")
                pid = context.get("pid", 0)
                proc_name = context.get("process_name", "unknown")
                start_time = context.get("start_time") or context.get("process_started_at")

                evidence = {
                    "pid": pid,
                    "process_name": proc_name,
                    "exe_path": norm_path,
                    "matched_suspicious_path": sp,
                    "username": context.get("username"),
                    "mitre_attack": self.mitre_attack,
                }
                if start_time:
                    evidence["start_time"] = start_time

                fp_suffix = f":{start_time}" if start_time else ""
                fingerprint = f"proc:suspicious_path:{agent_id}:{pid}:{norm_path}{fp_suffix}"
                return DetectionResult(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    title=f"Suspicious execution path '{norm_path}' (PID: {pid})",
                    description=f"Process '{proc_name}' is executing from suspicious directory '{sp}'.",
                    severity=self.severity,
                    risk_score=self.base_score,
                    evidence=evidence,
                    fingerprint=fingerprint,
                    event_type="process.suspicious.execution_path",
                    mitre_attack=self.mitre_attack,
                )
        return None


class ProcessHiddenBinaryRule(BaseRule):
    """Detects executables whose binary name or parent folder starts with a dot (hidden file)."""

    def __init__(
        self,
        rule_id: str = "rule-process-hidden-binary",
        name: str = "Hidden Executable Execution",
        severity: str = "high",
        base_score: int = 50,
        enabled: bool = True,
        mitre_attack: str = "T1564.001: Hidden Files and Directories",
        purpose: str = "Detect execution of hidden files or executables located inside hidden directory structures",
        input_fields: Optional[List[str]] = None,
        expected_false_positives: Optional[List[str]] = None,
    ):
        super().__init__(
            rule_id=rule_id,
            name=name,
            description="Process is executing from a hidden file or hidden directory",
            severity=severity,
            base_score=base_score,
            enabled=enabled,
            mitre_attack=mitre_attack,
            purpose=purpose,
            input_fields=input_fields or ["process_name", "exe_path", "pid", "username"],
            expected_false_positives=expected_false_positives or [
                "User binaries in ~/.local/bin or ~/.cargo/bin",
                "Virtual environment binaries in hidden directories (.venv/bin)",
                "System dotfile runners (~/.config or ~/.nvm)",
            ],
        )

    def evaluate(self, context: Dict[str, Any]) -> Optional[DetectionResult]:
        if not self.enabled:
            return None

        exe_path = context.get("exe_path")
        proc_name = context.get("process_name", "")

        is_hidden = False
        reason = ""

        if proc_name and proc_name.startswith(".") and proc_name not in (".", ".."):
            is_hidden = True
            reason = f"Process name '{proc_name}' starts with dot"

        if exe_path and isinstance(exe_path, str):
            parts = Path(exe_path).parts
            for part in parts:
                if part.startswith(".") and part not in (".", "..", "/"):
                    is_hidden = True
                    reason = f"Path component '{part}' is hidden in '{exe_path}'"
                    break

        if is_hidden:
            agent_id = context.get("agent_id", "unknown")
            pid = context.get("pid", 0)
            start_time = context.get("start_time") or context.get("process_started_at")
            evidence = {
                "pid": pid,
                "process_name": proc_name,
                "exe_path": exe_path,
                "detection_reason": reason,
                "mitre_attack": self.mitre_attack,
            }
            if start_time:
                evidence["start_time"] = start_time

            fp_suffix = f":{start_time}" if start_time else ""
            fingerprint = f"proc:hidden_bin:{agent_id}:{pid}:{proc_name}{fp_suffix}"
            return DetectionResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                title=f"Hidden executable executed: '{proc_name}' (PID: {pid})",
                description=f"Detected execution of hidden binary: {reason}.",
                severity=self.severity,
                risk_score=self.base_score,
                evidence=evidence,
                fingerprint=fingerprint,
                event_type="process.suspicious.hidden_binary",
                mitre_attack=self.mitre_attack,
            )
        return None


class ProcessShellSpawnRule(BaseRule):
    """Detects command shells (bash, sh, zsh, dash) spawned under daemon or web service contexts."""

    def __init__(
        self,
        rule_id: str = "rule-proc-shell-spawn",
        name: str = "Interactive Shell Spawned Under Daemon Context",
        target_shells: Optional[List[str]] = None,
        suspicious_users: Optional[List[str]] = None,
        severity: str = "high",
        base_score: int = 60,
        enabled: bool = True,
        mitre_attack: str = "T1059.004: Unix Shell",
        purpose: str = "Detect command shells executed by web server processes or unprivileged service accounts (potential web shell or reverse shell)",
        input_fields: Optional[List[str]] = None,
        expected_false_positives: Optional[List[str]] = None,
    ):
        super().__init__(
            rule_id=rule_id,
            name=name,
            description="Command shell executed in unprivileged web or daemon context",
            severity=severity,
            base_score=base_score,
            enabled=enabled,
            mitre_attack=mitre_attack,
            purpose=purpose,
            input_fields=input_fields or ["process_name", "exe_path", "username", "parent_name", "ppid", "pid"],
            expected_false_positives=expected_false_positives or [
                "Legitimate maintenance or deployment scripts invoked by web workers",
                "Automated CI/CD runner executing shell tasks under dedicated service account",
                "Cron jobs running shell wrappers under daemon accounts",
            ],
        )
        self.target_shells = set(target_shells or ["sh", "bash", "dash", "zsh"])
        self.suspicious_users = set(suspicious_users or ["www-data", "apache", "nginx", "nobody", "daemon"])

    def evaluate(self, context: Dict[str, Any]) -> Optional[DetectionResult]:
        if not self.enabled:
            return None

        proc_name = context.get("process_name", "")
        exe_path = context.get("exe_path", "")
        username = context.get("username", "")
        parent_name = context.get("parent_name", "")

        is_shell = proc_name in self.target_shells or any(
            exe_path.endswith(f"/{sh}") for sh in self.target_shells
        )

        if not is_shell:
            return None

        # Check suspicious conditions: daemon user, web parent, or explicit suspicious flag
        is_suspicious_user = username in self.suspicious_users
        is_suspicious_parent = parent_name in ("nginx", "apache2", "httpd", "python", "python3", "php", "node")
        explicit_suspicious = bool(context.get("suspicious_spawn", False))

        if is_suspicious_user or is_suspicious_parent or explicit_suspicious:
            agent_id = context.get("agent_id", "unknown")
            pid = context.get("pid", 0)
            start_time = context.get("start_time") or context.get("process_started_at")
            evidence = {
                "pid": pid,
                "ppid": context.get("ppid"),
                "process_name": proc_name,
                "exe_path": exe_path,
                "username": username,
                "parent_name": parent_name,
                "mitre_attack": self.mitre_attack,
            }
            if start_time:
                evidence["start_time"] = start_time

            fp_suffix = f":{start_time}" if start_time else ""
            fingerprint = f"proc:shell_spawn:{agent_id}:{pid}:{proc_name}{fp_suffix}"
            return DetectionResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                title=f"Suspicious shell spawned: '{proc_name}' (PID: {pid}, User: {username or 'unknown'})",
                description=f"Command interpreter '{proc_name}' spawned in daemon context (User: {username}, Parent: {parent_name}). Potential reverse shell.",
                severity=self.severity,
                risk_score=self.base_score,
                evidence=evidence,
                fingerprint=fingerprint,
                event_type="process.suspicious.shell_spawn",
                mitre_attack=self.mitre_attack,
            )
        return None


class FimSensitiveFileRule(BaseRule):
    """Detects tampering, deletion, or modification of critical OS security files."""

    def __init__(
        self,
        rule_id: str = "rule-fim-sensitive-tampered",
        name: str = "Critical System File Tampering",
        sensitive_files: Optional[List[str]] = None,
        severity: str = "high",
        base_score: int = 60,
        enabled: bool = True,
        mitre_attack: str = "T1565.001: Stored Data Manipulation / T1098: Account Manipulation",
        purpose: str = "Detect unauthorized tampering, deletion, or modification of critical OS security and authentication files",
        input_fields: Optional[List[str]] = None,
        expected_false_positives: Optional[List[str]] = None,
    ):
        super().__init__(
            rule_id=rule_id,
            name=name,
            description="Critical system configuration or authentication file altered or deleted",
            severity=severity,
            base_score=base_score,
            enabled=enabled,
            mitre_attack=mitre_attack,
            purpose=purpose,
            input_fields=input_fields or ["file_path", "event_type", "sha256"],
            expected_false_positives=expected_false_positives or [
                "Authorized administrator user creation or password rotation (passwd, useradd)",
                "System updates altering pam configuration or /etc/crontab",
                "Package manager maintenance updates to sshd_config",
            ],
        )
        self.sensitive_files = set(sensitive_files or DEFAULT_SENSITIVE_FILES)

    def evaluate(self, context: Dict[str, Any]) -> Optional[DetectionResult]:
        if not self.enabled:
            return None

        event_type = context.get("event_type", "")
        # Context can be a security event from FIM (dict payload or database row)
        raw_evidence = context.get("evidence") or context.get("evidence_json") or {}
        if isinstance(raw_evidence, str):
            try:
                evidence = json.loads(raw_evidence)
            except Exception:
                evidence = {}
        elif isinstance(raw_evidence, dict):
            evidence = raw_evidence
        else:
            evidence = {}

        file_path = evidence.get("file_path") or context.get("file_path")
        if not file_path or not isinstance(file_path, str):
            return None

        norm_path = os.path.normpath(file_path.strip())

        # Check if file is in sensitive list or sensitive prefix (e.g. /etc/ssh/, /etc/pam.d/)
        is_sensitive = norm_path in self.sensitive_files or any(
            norm_path.startswith(sp) for sp in ("/etc/ssh/", "/etc/pam.d/", "/etc/sudoers.d/")
        )

        if is_sensitive and event_type in ("fim_file_modified", "fim_file_deleted", "file.modified", "file.deleted"):
            agent_id = context.get("agent_id", "unknown")
            action = "deleted" if "deleted" in event_type else "modified"
            severity = "critical" if norm_path in ("/etc/shadow", "/etc/sudoers") else self.severity

            score = self.base_score
            if severity == "critical":
                score = min(100, score + 20)

            evidence_data = {
                "file_path": norm_path,
                "event_type": event_type,
                "action": action,
                "evidence": evidence,
                "mitre_attack": self.mitre_attack,
            }
            fingerprint = f"fim:sensitive:{agent_id}:{norm_path}:{action}"
            return DetectionResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                title=f"Critical system file {action}: '{norm_path}'",
                description=f"Protected file '{norm_path}' was {action}. Potential security compromise or persistence attempt.",
                severity=severity,
                risk_score=score,
                evidence=evidence_data,
                fingerprint=fingerprint,
                event_type="fim.critical_file_tampered",
                mitre_attack=self.mitre_attack,
            )
        return None


class FimDroppedBinaryRule(BaseRule):
    """Detects creation of executable files or binaries in temporary / world-writable paths."""

    def __init__(
        self,
        rule_id: str = "rule-fim-dropped-binary",
        name: str = "Dropped Binary in Temporary Directory",
        suspicious_paths: Optional[List[str]] = None,
        severity: str = "medium",
        base_score: int = 40,
        enabled: bool = True,
        mitre_attack: str = "T1105: Ingress Tool Transfer",
        purpose: str = "Detect creation of newly dropped files in world-writable or temporary directories",
        input_fields: Optional[List[str]] = None,
        expected_false_positives: Optional[List[str]] = None,
    ):
        super().__init__(
            rule_id=rule_id,
            name=name,
            description="New file or binary created in temporary or shared-memory directory",
            severity=severity,
            base_score=base_score,
            enabled=enabled,
            mitre_attack=mitre_attack,
            purpose=purpose,
            input_fields=input_fields or ["file_path", "event_type"],
            expected_false_positives=expected_false_positives or [
                "Temporary application cache or lock files created in /tmp",
                "Text editor swap files (.swp, nano temp files)",
                "Inter-process shared memory buffers in /dev/shm",
            ],
        )
        self.suspicious_paths = [p.rstrip("/") for p in (suspicious_paths or DEFAULT_SUSPICIOUS_PATHS)]

    def evaluate(self, context: Dict[str, Any]) -> Optional[DetectionResult]:
        if not self.enabled:
            return None

        event_type = context.get("event_type", "")
        # Only evaluate file creation events
        if not (event_type in ("fim_file_created", "file.created") or "created" in event_type):
            return None

        raw_evidence = context.get("evidence") or context.get("evidence_json") or {}
        if isinstance(raw_evidence, str):
            try:
                evidence = json.loads(raw_evidence)
            except Exception:
                evidence = {}
        elif isinstance(raw_evidence, dict):
            evidence = raw_evidence
        else:
            evidence = {}

        file_path = evidence.get("file_path") or context.get("file_path")
        if not file_path or not isinstance(file_path, str):
            return None

        norm_path = os.path.normpath(file_path.strip())
        is_dropped = any(norm_path == sp or norm_path.startswith(sp + "/") for sp in self.suspicious_paths)

        if is_dropped:
            agent_id = context.get("agent_id", "unknown")
            evidence_data = {
                "file_path": norm_path,
                "event_type": event_type,
                "action": "created",
                "evidence": evidence,
                "mitre_attack": self.mitre_attack,
            }
            fingerprint = f"fim:dropped:{agent_id}:{norm_path}"
            return DetectionResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                title=f"Dropped file detected in temporary path: '{norm_path}'",
                description=f"File '{norm_path}' was created in suspicious directory. Potential stage-1 dropper.",
                severity=self.severity,
                risk_score=self.base_score,
                evidence=evidence_data,
                fingerprint=fingerprint,
                event_type="fim.dropped_binary",
                mitre_attack=self.mitre_attack,
            )
        return None


class RuleRegistry:
    """Manages loaded detection rules and provides unified evaluation."""

    def __init__(self, config_path: Optional[str] = None):
        self.rules: List[BaseRule] = []
        self._load_rules(config_path)

    def _load_rules(self, config_path: Optional[str] = None) -> None:
        """Load rules from JSON config file or instantiate default rules."""
        config_data = {}
        if config_path and os.path.isfile(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    config_data = json.load(f)
            except Exception as exc:
                logger.warning("Failed to load rules configuration from '%s': %s", config_path, exc)

        cfg_rules = config_data.get("rules", {})
        thresholds = config_data.get("thresholds", {})
        suspicious_paths = config_data.get("suspicious_paths", DEFAULT_SUSPICIOUS_PATHS)
        sensitive_files = config_data.get("sensitive_files", DEFAULT_SENSITIVE_FILES)

        # 1. High CPU Rule
        cpu_cfg = cfg_rules.get("rule-process-high-cpu", {})
        self.rules.append(
            ProcessHighCpuRule(
                rule_id="rule-process-high-cpu",
                threshold_percent=cpu_cfg.get("threshold_percent", thresholds.get("cpu_percent", 85.0)),
                severity=cpu_cfg.get("severity", "medium"),
                base_score=cpu_cfg.get("base_score", 30),
                enabled=cpu_cfg.get("enabled", True),
            )
        )

        # 2. High Memory Rule
        mem_cfg = cfg_rules.get("rule-process-high-memory", {})
        self.rules.append(
            ProcessHighMemoryRule(
                rule_id="rule-process-high-memory",
                threshold_percent=mem_cfg.get("threshold_percent", thresholds.get("memory_percent", 85.0)),
                severity=mem_cfg.get("severity", "medium"),
                base_score=mem_cfg.get("base_score", 30),
                enabled=mem_cfg.get("enabled", True),
            )
        )

        # 3. Suspicious Path Rule
        path_cfg = cfg_rules.get("rule-process-suspicious-path", {})
        self.rules.append(
            ProcessSuspiciousPathRule(
                rule_id="rule-process-suspicious-path",
                suspicious_paths=path_cfg.get("suspicious_paths", suspicious_paths),
                severity=path_cfg.get("severity", "high"),
                base_score=path_cfg.get("base_score", 50),
                enabled=path_cfg.get("enabled", True),
            )
        )

        # 4. Hidden Binary Rule
        hidden_cfg = cfg_rules.get("rule-process-hidden-binary", {})
        self.rules.append(
            ProcessHiddenBinaryRule(
                rule_id="rule-process-hidden-binary",
                severity=hidden_cfg.get("severity", "high"),
                base_score=hidden_cfg.get("base_score", 50),
                enabled=hidden_cfg.get("enabled", True),
            )
        )

        # 5. Shell Spawn Rule
        shell_cfg = cfg_rules.get("rule-proc-shell-spawn", {})
        self.rules.append(
            ProcessShellSpawnRule(
                rule_id="rule-proc-shell-spawn",
                target_shells=shell_cfg.get("target_shells"),
                suspicious_users=shell_cfg.get("suspicious_users"),
                severity=shell_cfg.get("severity", "high"),
                base_score=shell_cfg.get("base_score", 60),
                enabled=shell_cfg.get("enabled", True),
            )
        )

        # 6. FIM Sensitive File Rule
        fim_cfg = cfg_rules.get("rule-fim-sensitive-tampered", {})
        self.rules.append(
            FimSensitiveFileRule(
                rule_id="rule-fim-sensitive-tampered",
                sensitive_files=sensitive_files,
                severity=fim_cfg.get("severity", "high"),
                base_score=fim_cfg.get("base_score", 60),
                enabled=fim_cfg.get("enabled", True),
            )
        )

        # 7. FIM Dropped Binary Rule
        drop_cfg = cfg_rules.get("rule-fim-dropped-binary", {})
        self.rules.append(
            FimDroppedBinaryRule(
                rule_id="rule-fim-dropped-binary",
                suspicious_paths=drop_cfg.get("suspicious_paths", suspicious_paths),
                severity=drop_cfg.get("severity", "medium"),
                base_score=drop_cfg.get("base_score", 40),
                enabled=drop_cfg.get("enabled", True),
            )
        )

    def evaluate_process(self, agent_id: str, proc: Dict[str, Any]) -> List[DetectionResult]:
        """Evaluate a single process observation across all applicable process rules."""
        context = dict(proc)
        context["agent_id"] = agent_id

        results = []
        for rule in self.rules:
            if isinstance(rule, (ProcessHighCpuRule, ProcessHighMemoryRule, ProcessSuspiciousPathRule, ProcessHiddenBinaryRule, ProcessShellSpawnRule)):
                res = rule.evaluate(context)
                if res:
                    results.append(res)
        return results

    def evaluate_fim_event(self, agent_id: str, event: Dict[str, Any]) -> List[DetectionResult]:
        """Evaluate a security event across FIM rules."""
        context = dict(event)
        context["agent_id"] = agent_id

        results = []
        for rule in self.rules:
            if isinstance(rule, (FimSensitiveFileRule, FimDroppedBinaryRule)):
                res = rule.evaluate(context)
                if res:
                    results.append(res)
        return results

    def get_rule_catalog(self) -> List[Dict[str, Any]]:
        """Return catalog of all configured detection rules with full metadata."""
        return [rule.to_dict() for rule in self.rules]

    def get_rule_by_id(self, rule_id: str) -> Optional[BaseRule]:
        """Lookup a registered rule instance by its identifier."""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None
