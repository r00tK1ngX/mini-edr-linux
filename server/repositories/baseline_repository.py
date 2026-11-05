from typing import Any, Dict, List, Optional
import sqlite3

from server.repositories.base import BaseRepository


class BaselineRepository(BaseRepository):
    """Repository handling file baseline integrity state for endpoints."""

    def upsert(
        self,
        baseline: Dict[str, Any],
        connection: Optional[sqlite3.Connection] = None,
    ) -> Dict[str, Any]:
        """Insert or update a single file baseline record."""
        sql = """
            INSERT INTO file_baselines (
                agent_id,
                file_path,
                sha256,
                file_size_bytes,
                mtime_ns,
                file_mode,
                state,
                first_seen_at,
                last_seen_at,
                last_checked_at
            )
            VALUES (
                :agent_id,
                :file_path,
                :sha256,
                :file_size_bytes,
                :mtime_ns,
                :file_mode,
                :state,
                :first_seen_at,
                :last_seen_at,
                :last_checked_at
            )
            ON CONFLICT(agent_id, file_path) DO UPDATE SET
                sha256 = excluded.sha256,
                file_size_bytes = excluded.file_size_bytes,
                mtime_ns = excluded.mtime_ns,
                file_mode = excluded.file_mode,
                state = excluded.state,
                last_seen_at = excluded.last_seen_at,
                last_checked_at = excluded.last_checked_at
            RETURNING *;
        """
        params = {
            "agent_id": baseline["agent_id"],
            "file_path": baseline["file_path"],
            "sha256": baseline["sha256"].lower(),
            "file_size_bytes": baseline["file_size_bytes"],
            "mtime_ns": baseline["mtime_ns"],
            "file_mode": baseline["file_mode"],
            "state": baseline.get("state", "present"),
            "first_seen_at": baseline["first_seen_at"],
            "last_seen_at": baseline["last_seen_at"],
            "last_checked_at": baseline["last_checked_at"],
        }
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, params)
            row = cursor.fetchone()
            if row:
                return dict(row)
            sel = conn.execute(
                "SELECT * FROM file_baselines WHERE agent_id = ? AND file_path = ?",
                (baseline["agent_id"], baseline["file_path"]),
            )
            return dict(sel.fetchone())

    def bulk_upsert(
        self,
        agent_id: str,
        baselines: List[Dict[str, Any]],
        connection: Optional[sqlite3.Connection] = None,
    ) -> int:
        """Batch upsert multiple file baseline records for an agent."""
        if not baselines:
            return 0

        sql = """
            INSERT INTO file_baselines (
                agent_id,
                file_path,
                sha256,
                file_size_bytes,
                mtime_ns,
                file_mode,
                state,
                first_seen_at,
                last_seen_at,
                last_checked_at
            )
            VALUES (
                :agent_id,
                :file_path,
                :sha256,
                :file_size_bytes,
                :mtime_ns,
                :file_mode,
                :state,
                :first_seen_at,
                :last_seen_at,
                :last_checked_at
            )
            ON CONFLICT(agent_id, file_path) DO UPDATE SET
                sha256 = excluded.sha256,
                file_size_bytes = excluded.file_size_bytes,
                mtime_ns = excluded.mtime_ns,
                file_mode = excluded.file_mode,
                state = excluded.state,
                last_seen_at = excluded.last_seen_at,
                last_checked_at = excluded.last_checked_at;
        """
        formatted = [
            {
                "agent_id": agent_id,
                "file_path": b["file_path"],
                "sha256": b["sha256"].lower(),
                "file_size_bytes": b["file_size_bytes"],
                "mtime_ns": b["mtime_ns"],
                "file_mode": b["file_mode"],
                "state": b.get("state", "present"),
                "first_seen_at": b["first_seen_at"],
                "last_seen_at": b["last_seen_at"],
                "last_checked_at": b["last_checked_at"],
            }
            for b in baselines
        ]
        with self._connection(connection) as conn:
            conn.executemany(sql, formatted)
            return len(formatted)

    def get_by_path(
        self,
        agent_id: str,
        file_path: str,
        connection: Optional[sqlite3.Connection] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve baseline entry for a specific file on an endpoint."""
        sql = "SELECT * FROM file_baselines WHERE agent_id = ? AND file_path = ?"
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (agent_id, file_path))
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_by_agent(
        self,
        agent_id: str,
        state: Optional[str] = None,
        connection: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        """List baseline records for an agent, optionally filtering by state."""
        if state:
            sql = """
                SELECT * FROM file_baselines
                WHERE agent_id = ? AND state = ?
                ORDER BY file_path ASC
            """
            params = (agent_id, state)
        else:
            sql = """
                SELECT * FROM file_baselines
                WHERE agent_id = ?
                ORDER BY file_path ASC
            """
            params = (agent_id,)

        with self._connection(connection) as conn:
            cursor = conn.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]

    def mark_missing(
        self,
        agent_id: str,
        file_path: str,
        checked_at: str,
        connection: Optional[sqlite3.Connection] = None,
    ) -> bool:
        """Mark a monitored file as missing while keeping its last known hash."""
        sql = """
            UPDATE file_baselines
            SET state = 'missing', last_checked_at = ?
            WHERE agent_id = ? AND file_path = ?
        """
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (checked_at, agent_id, file_path))
            return cursor.rowcount > 0

    def count_by_agent(
        self,
        agent_id: str,
        state: Optional[str] = None,
        connection: Optional[sqlite3.Connection] = None,
    ) -> int:
        """Count monitored baseline entries for an agent."""
        if state:
            sql = "SELECT COUNT(*) FROM file_baselines WHERE agent_id = ? AND state = ?"
            params = (agent_id, state)
        else:
            sql = "SELECT COUNT(*) FROM file_baselines WHERE agent_id = ?"
            params = (agent_id,)

        with self._connection(connection) as conn:
            cursor = conn.execute(sql, params)
            return cursor.fetchone()[0]
