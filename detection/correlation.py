"""Correlation module for Mini EDR Linux.

Correlates telemetry signals and security events across multiple collectors (process observations,
file integrity monitor, and system metrics) on an endpoint. Implements multi-factor risk scoring
(0-100) with explainable evidence, ensuring that single threshold spikes (e.g. CPU alone) do not
falsely trigger critical malware alerts, while multi-stage indicators escalate appropriately.
"""

from dataclasses import dataclass, field
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

    def __init__(self, min_correlation_score: int = 75):
        self.min_correlation_score = int(min_correlation_score)

    def correlate_process_and_fim(
        self,
        agent_id: str,
        process_detections: List[DetectionResult],
        fim_detections: List[DetectionResult],
        associated_event_ids: Optional[List[int]] = None,
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

            factors: List[Dict[str, Any]] = []
            score = 0

            has_suspicious_path = "rule-process-suspicious-path" in rule_ids
            has_high_cpu = "rule-process-high-cpu" in rule_ids
            has_high_mem = "rule-process-high-memory" in rule_ids
            has_hidden = "rule-process-hidden-binary" in rule_ids

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

            # Check if this executable path was recently created or modified in FIM
            matching_fim = []
            if exe_path:
                norm_exe = os.path.normpath(exe_path)
                for fd in fim_detections:
                    fim_file = fd.evidence.get("file_path")
                    if fim_file and os.path.normpath(fim_file) == norm_exe:
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
            # Multi-stage detection: requires at least 2 distinct factors (e.g. suspicious path + resource spike or FIM drop)
            if len(factors) >= 2:
                severity = "critical" if total_score >= 85 else "high"
                alert_key = f"{agent_id}:correlated:proc:{pid}:{proc_name}"

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
                        "factors": factors,
                        "total_risk_score": total_score,
                    },
                    event_ids=event_ids,
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
