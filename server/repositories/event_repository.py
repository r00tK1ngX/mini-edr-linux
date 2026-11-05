import json
from typing import Any, Dict, List, Optional
import sqlite3

from server.repositories.base import BaseRepository


class EventRepository(BaseRepository):
    """Repository handling persistence for security events."""

    def record(
        self,
        event: Dict[str, Any],
        connection: Optional[sqlite3.Connection] = None,
    ) -> Dict[str, Any]:
        """Insert a security event."""
        evidence = event.get("evidence_json", "{}")
        if isinstance(evidence, (dict, list)):
            evidence = json.dumps(evidence)

        sql = """
            INSERT INTO security_events (
                message_id,
                schema_version,
                agent_id,
                event_type,
                severity,
                source,
                title,
                description,
                evidence_json,
                occurred_at,
                received_at,
                fingerprint
            )
            VALUES (
                :message_id,
                :schema_version,
                :agent_id,
                :event_type,
                :severity,
                :source,
                :title,
                :description,
                :evidence_json,
                :occurred_at,
                :received_at,
                :fingerprint
            )
            RETURNING *;
        """
        params = {
            "message_id": event["message_id"],
            "schema_version": event.get("schema_version", "1.0"),
            "agent_id": event["agent_id"],
            "event_type": event["event_type"],
            "severity": event.get("severity", "info"),
            "source": event.get("source", "agent"),
            "title": event["title"],
            "description": event.get("description"),
            "evidence_json": evidence,
            "occurred_at": event["occurred_at"],
            "received_at": event["received_at"],
            "fingerprint": event.get("fingerprint"),
        }

        with self._connection(connection) as conn:
            cursor = conn.execute(sql, params)
            row = cursor.fetchone()
            if row:
                return dict(row)
            sel = conn.execute(
                "SELECT * FROM security_events WHERE message_id = ?",
                (event["message_id"],),
            )
            return dict(sel.fetchone())

    def get_by_id(
        self,
        event_id: int,
        connection: Optional[sqlite3.Connection] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve security event by ID."""
        sql = "SELECT * FROM security_events WHERE id = ?"
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (event_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_by_message_id(
        self,
        message_id: str,
        connection: Optional[sqlite3.Connection] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve security event by unique message_id."""
        sql = "SELECT * FROM security_events WHERE message_id = ?"
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (message_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_by_agent(
        self,
        agent_id: str,
        limit: int = 100,
        severity: Optional[str] = None,
        connection: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        """List security events for an agent ordered by occurred_at descending."""
        if severity:
            sql = """
                SELECT * FROM security_events
                WHERE agent_id = ? AND severity = ?
                ORDER BY occurred_at DESC, id DESC
                LIMIT ?
            """
            params = (agent_id, severity, limit)
        else:
            sql = """
                SELECT * FROM security_events
                WHERE agent_id = ?
                ORDER BY occurred_at DESC, id DESC
                LIMIT ?
            """
            params = (agent_id, limit)

        with self._connection(connection) as conn:
            cursor = conn.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]

    def list_recent(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        connection: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        """List recent security events across all endpoints."""
        conditions = []
        params = []
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"""
            SELECT * FROM security_events
            {where_clause}
            ORDER BY occurred_at DESC, id DESC
            LIMIT ?
        """
        params.append(limit)

        with self._connection(connection) as conn:
            cursor = conn.execute(sql, tuple(params))
            return [dict(row) for row in cursor.fetchall()]

    def find_by_fingerprint(
        self,
        fingerprint: str,
        limit: int = 20,
        connection: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        """Search security events with identical fingerprint."""
        sql = """
            SELECT * FROM security_events
            WHERE fingerprint = ?
            ORDER BY occurred_at DESC, id DESC
            LIMIT ?
        """
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (fingerprint, limit))
            return [dict(row) for row in cursor.fetchall()]

    def count(
        self,
        agent_id: Optional[str] = None,
        severity: Optional[str] = None,
        connection: Optional[sqlite3.Connection] = None,
    ) -> int:
        """Count security events with optional agent and severity filters."""
        conditions = []
        params = []
        if agent_id:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT COUNT(*) FROM security_events {where_clause}"

        with self._connection(connection) as conn:
            cursor = conn.execute(sql, tuple(params))
            return cursor.fetchone()[0]
