from typing import Any, Dict, List, Optional
import sqlite3

from server.repositories.base import BaseRepository


class MetricsRepository(BaseRepository):
    """Repository handling persistence for endpoint system metrics telemetry."""

    def record(
        self,
        metric: Dict[str, Any],
        connection: Optional[sqlite3.Connection] = None,
    ) -> Dict[str, Any]:
        """Insert a system metrics record."""
        sql = """
            INSERT INTO system_metrics (
                message_id,
                schema_version,
                agent_id,
                cpu_percent,
                memory_percent,
                disk_percent,
                uptime_seconds,
                collected_at,
                received_at
            )
            VALUES (
                :message_id,
                :schema_version,
                :agent_id,
                :cpu_percent,
                :memory_percent,
                :disk_percent,
                :uptime_seconds,
                :collected_at,
                :received_at
            )
            RETURNING *;
        """
        params = {
            "message_id": metric["message_id"],
            "schema_version": metric.get("schema_version", "1.0"),
            "agent_id": metric["agent_id"],
            "cpu_percent": metric["cpu_percent"],
            "memory_percent": metric["memory_percent"],
            "disk_percent": metric["disk_percent"],
            "uptime_seconds": metric["uptime_seconds"],
            "collected_at": metric["collected_at"],
            "received_at": metric["received_at"],
        }
        with self._connection(connection) as conn:
            with conn:
                cursor = conn.execute(sql, params)
                row = cursor.fetchone()
                if row:
                    return dict(row)
                select_cur = conn.execute(
                    "SELECT * FROM system_metrics WHERE message_id = ?",
                    (metric["message_id"],),
                )
                return dict(select_cur.fetchone())

    def get_by_id(
        self,
        metric_id: int,
        connection: Optional[sqlite3.Connection] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve metric record by its primary key ID."""
        sql = "SELECT * FROM system_metrics WHERE id = ?"
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (metric_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_by_message_id(
        self,
        message_id: str,
        connection: Optional[sqlite3.Connection] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve metric record by unique message_id."""
        sql = "SELECT * FROM system_metrics WHERE message_id = ?"
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (message_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_latest(
        self,
        agent_id: str,
        connection: Optional[sqlite3.Connection] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve the latest metric telemetry record for an agent."""
        sql = """
            SELECT * FROM system_metrics
            WHERE agent_id = ?
            ORDER BY collected_at DESC, id DESC
            LIMIT 1
        """
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (agent_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_by_agent(
        self,
        agent_id: str,
        limit: int = 100,
        connection: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        """List historical system metrics for an agent ordered by collected_at descending."""
        sql = """
            SELECT * FROM system_metrics
            WHERE agent_id = ?
            ORDER BY collected_at DESC, id DESC
            LIMIT ?
        """
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (agent_id, limit))
            return [dict(row) for row in cursor.fetchall()]

    def count_by_agent(
        self,
        agent_id: str,
        connection: Optional[sqlite3.Connection] = None,
    ) -> int:
        """Count total metric samples collected for an agent."""
        sql = "SELECT COUNT(*) FROM system_metrics WHERE agent_id = ?"
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (agent_id,))
            return cursor.fetchone()[0]
