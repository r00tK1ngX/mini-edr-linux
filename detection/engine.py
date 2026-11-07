"""Detection Engine module for Mini EDR Linux.

Orchestrates rule evaluation, correlates multi-source signals, records detection security events,
and generates actionable alerts in the database.
"""

from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Dict, List, Optional
import uuid

from detection.correlation import CorrelatedFinding, CorrelationEngine
from detection.rules import DetectionResult, RuleRegistry
from server.repositories.alert_repository import AlertRepository
from server.repositories.event_repository import EventRepository
from server.repositories.process_repository import ProcessRepository

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DetectionEngine:
    """Core Detection Engine for analyzing endpoint telemetry and generating alerts."""

    def __init__(
        self,
        database_path: Optional[str] = None,
        config_path: Optional[str] = None,
        rule_registry: Optional[RuleRegistry] = None,
        correlation_engine: Optional[CorrelationEngine] = None,
    ):
        self.database_path = database_path
        self.rules = rule_registry or RuleRegistry(config_path)
        self.correlation = correlation_engine or CorrelationEngine()

        self.event_repo = EventRepository(database_path)
        self.alert_repo = AlertRepository(database_path)
        self.proc_repo = ProcessRepository(database_path)

    def evaluate_process_snapshot(
        self,
        agent_id: str,
        snapshot_id: int,
        observations: List[Dict[str, Any]],
        snapshot_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Evaluate a full process observation snapshot against all detection rules and correlation."""
        now = _utc_now()
        eval_time = snapshot_time or now
        raw_detections: List[DetectionResult] = []
        created_event_ids: List[int] = []

        # 0. Build PID -> process mapping and enrich parent_name if missing
        pid_map: Dict[int, Dict[str, Any]] = {}
        for p in observations:
            p_pid = p.get("pid")
            if p_pid is not None:
                pid_map[p_pid] = p

        for proc in observations:
            if not proc.get("parent_name"):
                ppid = proc.get("ppid")
                parent = pid_map.get(ppid)
                if parent:
                    pname = parent.get("process_name") or parent.get("name")
                    if pname:
                        proc["parent_name"] = pname

        # 1. Rule evaluation on each process
        for proc in observations:
            matches = self.rules.evaluate_process(agent_id, proc)
            for match in matches:
                raw_detections.append(match)

                # Persist detection security event
                msg_id = str(uuid.uuid4())
                event_record = {
                    "message_id": msg_id,
                    "schema_version": "1.0",
                    "agent_id": agent_id,
                    "event_type": match.event_type,
                    "severity": match.severity,
                    "source": "detection",
                    "title": match.title,
                    "description": match.description,
                    "evidence_json": match.evidence,
                    "occurred_at": eval_time,
                    "received_at": now,
                    "fingerprint": match.fingerprint,
                }
                try:
                    saved_event = self.event_repo.record(event_record)
                    match.event_id = saved_event["id"]
                    created_event_ids.append(saved_event["id"])
                except Exception as exc:
                    logger.warning("Failed to save detection event for '%s': %s", match.rule_id, exc)

        # 2. Query recent FIM events on this endpoint for correlation
        recent_events = self.event_repo.list_by_agent(agent_id, limit=20)
        recent_fim_detections: List[DetectionResult] = []
        for ev in recent_events:
            if ev.get("source") == "agent" and "fim" in ev.get("event_type", ""):
                matches = self.rules.evaluate_fim_event(agent_id, ev)
                for m in matches:
                    m.event_id = ev.get("id")
                    if "occurred_at" not in m.evidence:
                        m.evidence["occurred_at"] = ev.get("occurred_at")
                recent_fim_detections.extend(matches)

        # 3. Correlation evaluation
        correlated_findings = self.correlation.correlate_process_and_fim(
            agent_id=agent_id,
            process_detections=raw_detections,
            fim_detections=recent_fim_detections,
            associated_event_ids=created_event_ids,
            snapshot_time=snapshot_time,
        )

        saved_alerts: List[Dict[str, Any]] = []

        # If multi-factor correlation matched, save correlated alerts
        correlated_pids = set()
        for finding in correlated_findings:
            correlated_pids.add(finding.evidence.get("pid"))
            alert_dict = {
                "alert_key": finding.alert_key,
                "agent_id": agent_id,
                "rule_id": finding.rule_id,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "status": "new",
            }
            try:
                saved = self.alert_repo.create_or_update(alert_dict, event_ids=finding.event_ids)
                saved_alerts.append(saved)
                logger.warning("Correlated alert generated [%s]: %s (Score: %d)", finding.severity.upper(), finding.title, finding.total_risk_score)
            except Exception as exc:
                logger.error("Failed to persist correlated alert: %s", exc)

        # For remaining high/critical process detections that were not part of a correlated alert:
        # Create individual alerts if severity is high or critical (e.g. suspicious path alone)
        for d in raw_detections:
            pid = d.evidence.get("pid")
            if pid not in correlated_pids and d.severity in ("high", "critical"):
                single_finding = self.correlation.calculate_single_rule_alert(
                    agent_id=agent_id,
                    detection=d,
                    event_id=d.event_id,
                )
                alert_dict = {
                    "alert_key": single_finding.alert_key,
                    "agent_id": agent_id,
                    "rule_id": single_finding.rule_id,
                    "title": single_finding.title,
                    "description": single_finding.description,
                    "severity": single_finding.severity,
                    "status": "new",
                }
                try:
                    saved = self.alert_repo.create_or_update(alert_dict, event_ids=single_finding.event_ids)
                    saved_alerts.append(saved)
                except Exception as exc:
                    logger.error("Failed to persist single detection alert: %s", exc)

        return {
            "agent_id": agent_id,
            "observations_evaluated": len(observations),
            "detections_count": len(raw_detections),
            "events_created": len(created_event_ids),
            "alerts_created": len(saved_alerts),
            "alerts": saved_alerts,
        }

    def evaluate_security_event(
        self,
        agent_id: str,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Evaluate an incoming security event from an Agent (e.g. FIM event) and trigger alerts."""
        now = _utc_now()
        matches = self.rules.evaluate_fim_event(agent_id, event)
        saved_alerts: List[Dict[str, Any]] = []

        event_id = event.get("id")
        valid_event_ids = []
        if event_id is not None:
            if self.event_repo.get_by_id(event_id) is not None:
                valid_event_ids.append(event_id)

        for match in matches:
            match.event_id = event_id
            # Create or correlate Alert for sensitive file tampering
            alert_key = f"{agent_id}:{match.rule_id}:{match.fingerprint or match.title}"
            alert_dict = {
                "alert_key": alert_key,
                "agent_id": agent_id,
                "rule_id": match.rule_id,
                "title": match.title,
                "description": match.description,
                "severity": match.severity,
                "status": "new",
            }
            try:
                saved = self.alert_repo.create_or_update(
                    alert_dict,
                    event_ids=valid_event_ids,
                )
                saved_alerts.append(saved)
                logger.warning("FIM sensitive file alert generated [%s]: %s", match.severity.upper(), match.title)
            except Exception as exc:
                logger.error("Failed to save FIM alert: %s", exc)

        return {
            "agent_id": agent_id,
            "matches_count": len(matches),
            "alerts_created": len(saved_alerts),
            "alerts": saved_alerts,
        }
