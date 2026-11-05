from typing import Any, Dict, List, Optional
import sqlite3

from server.repositories.base import BaseRepository


class EndpointRepository(BaseRepository):
    """Repository handling persistence for registered endpoints."""

    def upsert(
        self,
        endpoint: Dict[str, Any],
        connection: Optional[sqlite3.Connection] = None,
    ) -> Dict[str, Any]:
        """Insert or update an endpoint record."""
        sql = """
            INSERT INTO endpoints (
                agent_id,
                hostname,
                ip_address,
                os,
                agent_version,
                status,
                cpu_percent,
                memory_percent,
                disk_percent,
                uptime_seconds,
                last_seen
            )
            VALUES (
                :agent_id,
                :hostname,
                :ip_address,
                :os,
                :agent_version,
                'online',
                :cpu_percent,
                :memory_percent,
                :disk_percent,
                :uptime_seconds,
                :last_seen
            )
            ON CONFLICT(agent_id) DO UPDATE SET
                hostname = excluded.hostname,
                ip_address = excluded.ip_address,
                os = excluded.os,
                agent_version = excluded.agent_version,
                status = 'online',
                cpu_percent = excluded.cpu_percent,
                memory_percent = excluded.memory_percent,
                disk_percent = excluded.disk_percent,
                uptime_seconds = excluded.uptime_seconds,
                last_seen = excluded.last_seen
            RETURNING *;
        """
        params = {
            "agent_id": endpoint["agent_id"],
            "hostname": endpoint["hostname"],
            "ip_address": endpoint.get("ip_address"),
            "os": endpoint["os"],
            "agent_version": endpoint.get("agent_version"),
            "cpu_percent": endpoint.get("cpu_percent"),
            "memory_percent": endpoint.get("memory_percent"),
            "disk_percent": endpoint.get("disk_percent"),
            "uptime_seconds": endpoint.get("uptime_seconds"),
            "last_seen": endpoint["last_seen"],
        }
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, params)
            row = cursor.fetchone()
            if row:
                return dict(row)
            # Fallback if RETURNING not supported or empty
            select_cur = conn.execute(
                "SELECT * FROM endpoints WHERE agent_id = ?",
                (endpoint["agent_id"],),
            )
            return dict(select_cur.fetchone())

    def get_by_id(
        self,
        agent_id: str,
        connection: Optional[sqlite3.Connection] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a single endpoint by agent_id."""
        sql = "SELECT * FROM endpoints WHERE agent_id = ?"
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (agent_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_all(
        self,
        offline_after_seconds: float = 15,
        connection: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        """Mark stale endpoints offline and return all registered endpoints."""
        update_sql = """
            UPDATE endpoints
            SET status = CASE
                WHEN (julianday('now') - julianday(last_seen)) * 86400.0 > ?
                THEN 'offline'
                ELSE 'online'
            END
        """
        select_sql = """
            SELECT
                agent_id,
                hostname,
                ip_address,
                os,
                agent_version,
                status,
                cpu_percent,
                memory_percent,
                disk_percent,
                uptime_seconds,
                last_seen
            FROM endpoints
            ORDER BY hostname COLLATE NOCASE, agent_id
        """
        with self._connection(connection) as conn:
            conn.execute(update_sql, (offline_after_seconds,))
            cursor = conn.execute(select_sql)
            return [dict(row) for row in cursor.fetchall()]

    def update_status(
        self,
        agent_id: str,
        status: str,
        connection: Optional[sqlite3.Connection] = None,
    ) -> bool:
        """Manually update the status of an endpoint ('online' or 'offline')."""
        sql = "UPDATE endpoints SET status = ? WHERE agent_id = ?"
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (status, agent_id))
            return cursor.rowcount > 0

    def count(self, connection: Optional[sqlite3.Connection] = None) -> int:
        """Count total registered endpoints."""
        sql = "SELECT COUNT(*) FROM endpoints"
        with self._connection(connection) as conn:
            cursor = conn.execute(sql)
            return cursor.fetchone()[0]
