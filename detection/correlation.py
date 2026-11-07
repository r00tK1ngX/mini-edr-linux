"""Correlation module for Mini EDR Linux.

Correlates telemetry signals and security events across multiple collectors (process observations,
file integrity monitor, and system metrics) on an endpoint. Implements multi-factor risk scoring
(0-100) with explainable evidence, ensuring that single threshold spikes (e.g. CPU alone) do not
falsely trigger critical malware alerts, while multi-stage indicators escalate appropriately.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
import os
from typing import Any, Dict, List, Optional, Set

from detection.rules import DetectionResult

logger = logging.getLogger(__name__)


@dataclass
class CorrelatedFinding:
    """The outcome of a correlation evaluation combining multiple threat signals."""

    alert_key: str
    rule_id: str
    title: str
    description: str
    severity: str  # "info", "low", "medium", "high", "critical"
    total_risk_score: int  # 0 to 100
    matched_rules: List[str]
    factors: List[Dict[str, Any]]
    evidence: Dict[str, Any]
    event_ids: List[int] = field(default_factory=list)


class CorrelationEngine:
    """Evaluates multi-source signals and correlates them into actionable security alerts."""

    def __init__(self, min_correlation_score: int = 75, time_window_seconds: int = 300):
        self.min_correlation_score = int(min_correlation_score)
        self.time_window_seconds = max(10, int(time_window_seconds))

    def _is_within_time_window(
        self,
        fim_detection: DetectionResult,
        proc_detection: DetectionResult,
        reference_time: Optional[str] = None,
    ) -> bool:
        """Verify that FIM activity occurred within time_window_seconds of process activity."""
        fim_time_str = fim_detection.evidence.get("occurred_at") or fim_detection.evidence.get("received_at")
        proc_time_str = (
            proc_detection.evidence.get("start_time")
            or proc_detection.evidence.get("process_started_at")
            or reference_time
        )

        if not fim_time_str or not proc_time_str:
            # If timestamps are not provided, assume within window for compatibility
            return True

        try:
            fim_dt = datetime.fromisoformat(str(fim_time_str).replace("Z", "+00:00"))
            proc_dt = datetime.fromisoformat(str(proc_time_str).replace("Z", "+00:00"))
            diff_seconds = abs((proc_dt - fim_dt).total_seconds())
            return diff_seconds <= self.time_window_seconds
        except Exception as exc:
            logger.debug("Failed to calculate correlation time difference: %s", exc)
            return True

    def correlate_process_and_fim(
        self,
        agent_id: str,
        process_detections: List[DetectionResult],
        fim_detections: List[DetectionResult],
        associated_event_ids: Optional[List[int]] = None,
        snapshot_time: Optional[str] = None,
    ) -> List[CorrelatedFinding]:
        """Correlate process anomalies with file integrity events on the same endpoint."""
        findings: List[CorrelatedFinding] = []
        event_ids = associated_event_ids or []

        # Group process detections by PID
        proc_by_pid: Dict[int, List[DetectionResult]] = {}
        for d in process_detections:
            pid = d.evidence.get("pid")
            if pid is not None:
                proc_by_pid.setdefault(pid, []).append(d)

        # 1. Evaluate per-process combinations (e.g. Suspicious Path + High CPU + Hidden Binary)
        for pid, detections in proc_by_pid.items():
            rule_ids = {d.rule_id for d in detections}
            proc_name = detections[0].evidence.get("process_name", "unknown")
            exe_path = detections[0].evidence.get("exe_path", "")
            start_time = (
                detections[0].evidence.get("start_time")
                or detections[0].evidence.get("process_started_at")
                or ""
            )

            factors: List[Dict[str, Any]] = []
            score = 0

            has_suspicious_path = "rule-process-suspicious-path" in rule_ids
            has_high_cpu = "rule-process-high-cpu" in rule_ids
            has_high_mem = "rule-process-high-memory" in rule_ids
            has_hidden = "rule-process-hidden-binary" in rule_ids
            has_shell_spawn = "rule-proc-shell-spawn" in rule_ids

            if has_suspicious_path:
                score += 50
                factors.append({
                    "factor": "suspicious_execution_path",
                    "score": 50,
                    "description": f"Executable located in temporary or writable directory: {exe_path}",
                })

            if has_hidden:
                score += 40
                factors.append({
                    "factor": "hidden_executable",
                    "score": 40,
                    "description": f"Process '{proc_name}' or its binary is hidden",
                })

            if has_shell_spawn:
                score += 50
                factors.append({
                    "factor": "suspicious_shell_spawn",
                    "score": 50,
                    "description": f"Process '{proc_name}' is an interactive shell spawned in daemon context",
                })

            if has_high_cpu:
                score += 30
                cpu_val = next((d.evidence.get("cpu_percent") for d in detections if d.rule_id == "rule-process-high-cpu"), 0)
                factors.append({
                    "factor": "high_cpu_utilization",
                    "score": 30,
                    "description": f"Process consuming high CPU ({cpu_val}%)",
                })

            if has_high_mem:
                score += 30
                mem_val = next((d.evidence.get("memory_percent") for d in detections if d.rule_id == "rule-process-high-memory"), 0)
                factors.append({
                    "factor": "high_memory_utilization",
                    "score": 30,
                    "description": f"Process consuming high memory ({mem_val}%)",
                })

            # Check if this executable path was recently created or modified in FIM within time window
            matching_fim = []
            if exe_path:
                norm_exe = os.path.normpath(exe_path)
                for fd in fim_detections:
                    fim_file = fd.evidence.get("file_path")
                    if fim_file and os.path.normpath(fim_file) == norm_exe:
                        if self._is_within_time_window(fd, detections[0], snapshot_time):
                            matching_fim.append(fd)

            if matching_fim:
                score += 50
                factors.append({
                    "factor": "fim_dropped_and_executed",
                    "score": 50,
                    "description": f"Binary was detected by FIM being created/tampered right before execution: {exe_path}",
                })

            total_score = min(100, score)

            # Correlation decision:
            # Multi-stage detection: requires at least 2 distinct factors and reaches min_correlation_score
            if len(factors) >= 2 and total_score >= self.min_correlation_score:
                severity = "critical" if total_score >= 85 else "high"

                # Incorporate start_time / process identity to avoid alert collision on PID reuse
                proc_identity = f"{pid}:{proc_name}" + (f":{start_time}" if start_time else "")
                alert_key = f"{agent_id}:correlated:proc:{proc_identity}"

                mitre_tags = set()
                for d in detections:
                    if getattr(d, "mitre_attack", None):
                        mitre_tags.add(d.mitre_attack)
                for fd in matching_fim:
                    if getattr(fd, "mitre_attack", None):
                        mitre_tags.add(fd.mitre_attack)
                mitre_str = " / ".join(sorted(mitre_tags)) if mitre_tags else "T1059 / T1105 / T1496"

                # Collect event_ids specifically related to this process and matching FIM detections
                proc_event_ids = [d.event_id for d in detections if getattr(d, "event_id", None) is not None]
                fim_event_ids = [fd.event_id for fd in matching_fim if getattr(fd, "event_id", None) is not None]
                correlated_event_ids = list(dict.fromkeys(proc_event_ids + fim_event_ids))
                if not correlated_event_ids and associated_event_ids:
                    correlated_event_ids = associated_event_ids

                finding = CorrelatedFinding(
                    alert_key=alert_key,
                    rule_id="rule-correlated-multistage",
                    title=f"Multi-stage threat detected on process '{proc_name}' (PID: {pid})",
                    description=(
                        f"Process '{proc_name}' (PID: {pid}) exhibited multiple correlated threat indicators: "
                        + ", ".join(f["factor"] for f in factors)
                    ),
                    severity=severity,
                    total_risk_score=total_score,
                    matched_rules=list(rule_ids),
                    factors=factors,
                    evidence={
                        "pid": pid,
                        "process_name": proc_name,
                        "exe_path": exe_path,
                        "process_identity": proc_identity,
                        "start_time": start_time,
                        "factors": factors,
                        "total_risk_score": total_score,
                        "mitre_attack": mitre_str,
                    },
                    event_ids=correlated_event_ids,
                )
                findings.append(finding)

        return findings

    def calculate_single_rule_alert(
        self,
        agent_id: str,
        detection: DetectionResult,
        event_id: Optional[int] = None,
    ) -> CorrelatedFinding:
        """Create a single-source alert finding for an individual high/critical detection."""
        pid = detection.evidence.get("pid")
        proc_name = detection.evidence.get("process_name")
        start_time = detection.evidence.get("start_time") or detection.evidence.get("process_started_at")

        if pid is not None and proc_name:
            proc_identity = f"{pid}:{proc_name}" + (f":{start_time}" if start_time else "")
            alert_key = f"{agent_id}:{detection.rule_id}:{proc_identity}"
        else:
            alert_key = f"{agent_id}:{detection.rule_id}:{detection.fingerprint or detection.title}"

        factors = [{
            "factor": detection.rule_id,
            "score": detection.risk_score,
            "description": detection.description,
        }]

        return CorrelatedFinding(
            alert_key=alert_key,
            rule_id=detection.rule_id,
            title=detection.title,
            description=detection.description,
            severity=detection.severity,
            total_risk_score=detection.risk_score,
            matched_rules=[detection.rule_id],
            factors=factors,
            evidence={
                **detection.evidence,
                "risk_score": detection.risk_score,
                "factors": factors,
            },
            event_ids=[event_id] if event_id is not None else [],
        )
