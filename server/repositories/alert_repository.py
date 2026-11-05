from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import sqlite3

from server.repositories.base import BaseRepository


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AlertRepository(BaseRepository):
    """Repository handling persistence and lifecycle management for security alerts."""

    def create_or_update(
        self,
        alert: Dict[str, Any],
        event_ids: Optional[List[int]] = None,
        connection: Optional[sqlite3.Connection] = None,
    ) -> Dict[str, Any]:
        """Insert or correlate/update an alert by its unique alert_key."""
        now = _utc_now()
        sql = """
            INSERT INTO alerts (
                alert_key,
                agent_id,
                rule_id,
                title,
                description,
                severity,
                status,
                first_seen_at,
                last_seen_at,
                created_at,
                updated_at,
                acknowledged_at,
                resolved_at,
                resolution_note
            )
            VALUES (
                :alert_key,
                :agent_id,
                :rule_id,
                :title,
                :description,
                :severity,
                :status,
                :first_seen_at,
                :last_seen_at,
                :created_at,
                :updated_at,
                :acknowledged_at,
                :resolved_at,
                :resolution_note
            )
            ON CONFLICT(alert_key) DO UPDATE SET
                title = excluded.title,
                description = excluded.description,
                severity = excluded.severity,
                last_seen_at = excluded.last_seen_at,
                updated_at = excluded.updated_at
            RETURNING *;
        """
        status = alert.get("status", "new")
        params = {
            "alert_key": alert["alert_key"],
            "agent_id": alert["agent_id"],
            "rule_id": alert["rule_id"],
            "title": alert["title"],
            "description": alert.get("description"),
            "severity": alert["severity"],
            "status": status,
            "first_seen_at": alert.get("first_seen_at", now),
            "last_seen_at": alert.get("last_seen_at", now),
            "created_at": alert.get("created_at", now),
            "updated_at": alert.get("updated_at", now),
            "acknowledged_at": alert.get("acknowledged_at"),
            "resolved_at": alert.get("resolved_at"),
            "resolution_note": alert.get("resolution_note"),
        }

        with self._connection(connection) as conn:
            cursor = conn.execute(sql, params)
            row = cursor.fetchone()
            if row:
                saved_alert = dict(row)
            else:
                sel = conn.execute(
                    "SELECT * FROM alerts WHERE alert_key = ?",
                    (alert["alert_key"],),
                )
                saved_alert = dict(sel.fetchone())

            if event_ids:
                link_sql = """
                    INSERT OR IGNORE INTO alert_events (alert_id, event_id, linked_at)
                    VALUES (?, ?, ?);
                """
                conn.executemany(
                    link_sql,
                    [(saved_alert["id"], eid, now) for eid in event_ids],
                )

            return saved_alert

    def get_by_id(
        self,
        alert_id: int,
        connection: Optional[sqlite3.Connection] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve alert by primary key ID."""
        sql = "SELECT * FROM alerts WHERE id = ?"
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (alert_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_by_key(
        self,
        alert_key: str,
        connection: Optional[sqlite3.Connection] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve alert by unique alert_key."""
        sql = "SELECT * FROM alerts WHERE alert_key = ?"
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (alert_key,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        agent_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        connection: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        """List alerts with optional status, severity, agent, rule filters, limit, and offset."""
        conditions = []
        params = []
        if status:
            conditions.append("status = ?")
            params.append(status)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if agent_id:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if rule_id:
            conditions.append("rule_id = ?")
            params.append(rule_id)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"""
            SELECT * FROM alerts
            {where_clause}
            ORDER BY last_seen_at DESC, id DESC
            LIMIT ? OFFSET ?
        """
        params.extend([max(1, int(limit)), max(0, int(offset))])

        with self._connection(connection) as conn:
            cursor = conn.execute(sql, tuple(params))
            return [dict(row) for row in cursor.fetchall()]

    def acknowledge(
        self,
        alert_id: int,
        acknowledged_at: Optional[str] = None,
        note: Optional[str] = None,
        connection: Optional[sqlite3.Connection] = None,
    ) -> Optional[Dict[str, Any]]:
        """Transition alert to 'acknowledged' status with timestamp and optional note."""
        now = acknowledged_at or _utc_now()
        sql = """
            UPDATE alerts
            SET status = 'acknowledged',
                acknowledged_at = ?,
                updated_at = ?,
                resolution_note = COALESCE(?, resolution_note)
            WHERE id = ?
            RETURNING *;
        """
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (now, now, note, alert_id))
            row = cursor.fetchone()
            return dict(row) if row else None

    def resolve(
        self,
        alert_id: int,
        resolved_at: Optional[str] = None,
        note: Optional[str] = None,
        connection: Optional[sqlite3.Connection] = None,
    ) -> Optional[Dict[str, Any]]:
        """Transition alert to 'resolved' status with timestamp and optional resolution note."""
        now = resolved_at or _utc_now()
        sql = """
            UPDATE alerts
            SET status = 'resolved',
                resolved_at = ?,
                updated_at = ?,
                resolution_note = COALESCE(?, resolution_note)
            WHERE id = ?
            RETURNING *;
        """
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (now, now, note, alert_id))
            row = cursor.fetchone()
            return dict(row) if row else None

    def dismiss(
        self,
        alert_id: int,
        dismissed_at: Optional[str] = None,
        note: Optional[str] = None,
        connection: Optional[sqlite3.Connection] = None,
    ) -> Optional[Dict[str, Any]]:
        """Dismiss an alert by marking it resolved with a dismissal / false positive note."""
        dismiss_note = note or "Dismissed by operator (false positive / ignored)"
        return self.resolve(alert_id, resolved_at=dismissed_at, note=dismiss_note, connection=connection)

    def get_summary(
        self,
        agent_id: Optional[str] = None,
        connection: Optional[sqlite3.Connection] = None,
    ) -> Dict[str, Any]:
        """Aggregate alert statistics grouped by status and severity."""
        with self._connection(connection) as conn:
            status_params = [agent_id] if agent_id else []
            agent_filter = "WHERE agent_id = ?" if agent_id else ""

            status_rows = conn.execute(
                f"SELECT status, COUNT(*) as cnt FROM alerts {agent_filter} GROUP BY status",
                tuple(status_params),
            ).fetchall()
            by_status = {r["status"]: r["cnt"] for r in status_rows}
            for s in ("new", "acknowledged", "resolved"):
                by_status.setdefault(s, 0)

            sev_rows = conn.execute(
                f"SELECT severity, COUNT(*) as cnt FROM alerts {agent_filter} GROUP BY severity",
                tuple(status_params),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}
            for sev in ("info", "low", "medium", "high", "critical"):
                by_severity.setdefault(sev, 0)

            total = sum(by_status.values())
            open_count = by_status["new"] + by_status["acknowledged"]

            return {
                "total_alerts": total,
                "open_alerts": open_count,
                "resolved_alerts": by_status["resolved"],
                "critical_and_high_alerts": by_severity["critical"] + by_severity["high"],
                "by_status": by_status,
                "by_severity": by_severity,
            }

    def link_events(
        self,
        alert_id: int,
        event_ids: List[int],
        linked_at: Optional[str] = None,
        connection: Optional[sqlite3.Connection] = None,
    ) -> int:
        """Associate security events with this alert."""
        if not event_ids:
            return 0
        now = linked_at or _utc_now()
        sql = """
            INSERT OR IGNORE INTO alert_events (alert_id, event_id, linked_at)
            VALUES (?, ?, ?);
        """
        params = [(alert_id, eid, now) for eid in event_ids]
        with self._connection(connection) as conn:
            cursor = conn.executemany(sql, params)
            return cursor.rowcount

    def get_linked_events(
        self,
        alert_id: int,
        connection: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve all security events associated with an alert."""
        sql = """
            SELECT e.*, ae.linked_at
            FROM security_events e
            JOIN alert_events ae ON e.id = ae.event_id
            WHERE ae.alert_id = ?
            ORDER BY e.occurred_at DESC
        """
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (alert_id,))
            return [dict(row) for row in cursor.fetchall()]

    def count(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        agent_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        connection: Optional[sqlite3.Connection] = None,
    ) -> int:
        """Count alerts based on status, severity, agent, or rule filters."""
        conditions = []
        params = []
        if status:
            conditions.append("status = ?")
            params.append(status)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if agent_id:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if rule_id:
            conditions.append("rule_id = ?")
            params.append(rule_id)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT COUNT(*) FROM alerts {where_clause}"

        with self._connection(connection) as conn:
            cursor = conn.execute(sql, tuple(params))
            return cursor.fetchone()[0]
