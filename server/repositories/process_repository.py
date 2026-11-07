from typing import Any, Dict, List, Optional
import sqlite3

from server.repositories.base import BaseRepository


class ProcessRepository(BaseRepository):
    """Repository handling persistence for process snapshots and observations."""

    def create_snapshot(
        self,
        snapshot: Dict[str, Any],
        observations: List[Dict[str, Any]],
        connection: Optional[sqlite3.Connection] = None,
    ) -> Dict[str, Any]:
        """Atomically create a snapshot and all its observed processes."""
        snapshot_sql = """
            INSERT INTO process_snapshots (
                message_id,
                schema_version,
                agent_id,
                process_count,
                collected_at,
                received_at,
                payload_hash
            )
            VALUES (
                :message_id,
                :schema_version,
                :agent_id,
                :process_count,
                :collected_at,
                :received_at,
                :payload_hash
            )
            RETURNING *;
        """
        snapshot_sql_fallback = """
            INSERT INTO process_snapshots (
                message_id,
                schema_version,
                agent_id,
                process_count,
                collected_at,
                received_at
            )
            VALUES (
                :message_id,
                :schema_version,
                :agent_id,
                :process_count,
                :collected_at,
                :received_at
            )
            RETURNING *;
        """
        observation_sql = """
            INSERT INTO process_observations (
                snapshot_id,
                pid,
                ppid,
                process_name,
                username,
                exe_path,
                cpu_percent,
                memory_percent,
                rss_bytes,
                process_started_at
            )
            VALUES (
                :snapshot_id,
                :pid,
                :ppid,
                :process_name,
                :username,
                :exe_path,
                :cpu_percent,
                :memory_percent,
                :rss_bytes,
                :process_started_at
            );
        """
        snapshot_params = {
            "message_id": snapshot["message_id"],
            "schema_version": snapshot.get("schema_version", "1.0"),
            "agent_id": snapshot["agent_id"],
            "process_count": snapshot.get("process_count", len(observations)),
            "collected_at": snapshot["collected_at"],
            "received_at": snapshot["received_at"],
            "payload_hash": snapshot.get("payload_hash"),
        }

        with self._connection(connection) as conn:
            with conn:
                try:
                    snap_cur = conn.execute(snapshot_sql, snapshot_params)
                except sqlite3.OperationalError:
                    fallback_params = dict(snapshot_params)
                    fallback_params.pop("payload_hash", None)
                    snap_cur = conn.execute(snapshot_sql_fallback, fallback_params)

                snap_row = snap_cur.fetchone()
                if snap_row:
                    created_snapshot = dict(snap_row)
                else:
                    sel_cur = conn.execute(
                        "SELECT * FROM process_snapshots WHERE message_id = ?",
                        (snapshot["message_id"],),
                    )
                    created_snapshot = dict(sel_cur.fetchone())

                snapshot_id = created_snapshot["id"]

                if observations:
                    formatted_obs = [
                        {
                            "snapshot_id": snapshot_id,
                            "pid": obs["pid"],
                            "ppid": obs.get("ppid"),
                            "process_name": obs["process_name"],
                            "username": obs.get("username"),
                            "exe_path": obs.get("exe_path"),
                            "cpu_percent": obs.get("cpu_percent"),
                            "memory_percent": obs.get("memory_percent"),
                            "rss_bytes": obs.get("rss_bytes"),
                            "process_started_at": obs.get("process_started_at"),
                        }
                        for obs in observations
                    ]
                    conn.executemany(observation_sql, formatted_obs)

                return created_snapshot

    def get_snapshot_by_id(
        self,
        snapshot_id: int,
        connection: Optional[sqlite3.Connection] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve snapshot metadata by ID."""
        sql = "SELECT * FROM process_snapshots WHERE id = ?"
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (snapshot_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_snapshot_by_message_id(
        self,
        message_id: str,
        connection: Optional[sqlite3.Connection] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve snapshot metadata by unique message_id."""
        sql = "SELECT * FROM process_snapshots WHERE message_id = ?"
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (message_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_latest_snapshot(
        self,
        agent_id: str,
        connection: Optional[sqlite3.Connection] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve the latest snapshot for an agent."""
        sql = """
            SELECT * FROM process_snapshots
            WHERE agent_id = ?
            ORDER BY collected_at DESC, id DESC
            LIMIT 1
        """
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (agent_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_snapshots_by_agent(
        self,
        agent_id: str,
        limit: int = 20,
        connection: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        """List snapshots for an agent ordered by collected_at descending."""
        sql = """
            SELECT * FROM process_snapshots
            WHERE agent_id = ?
            ORDER BY collected_at DESC, id DESC
            LIMIT ?
        """
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (agent_id, limit))
            return [dict(row) for row in cursor.fetchall()]

    def list_observations(
        self,
        snapshot_id: int,
        connection: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        """List all process observations recorded within a given snapshot."""
        sql = """
            SELECT * FROM process_observations
            WHERE snapshot_id = ?
            ORDER BY pid ASC
        """
        with self._connection(connection) as conn:
            cursor = conn.execute(sql, (snapshot_id,))
            return [dict(row) for row in cursor.fetchall()]

    def find_observations_by_name(
        self,
        process_name: str,
        agent_id: Optional[str] = None,
        limit: int = 50,
        connection: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        """Search process observations matching process_name across snapshots."""
        if agent_id:
            sql = """
                SELECT o.*, s.agent_id, s.collected_at
                FROM process_observations o
                JOIN process_snapshots s ON o.snapshot_id = s.id
                WHERE o.process_name = ? AND s.agent_id = ?
                ORDER BY s.collected_at DESC
                LIMIT ?
            """
            params = (process_name, agent_id, limit)
        else:
            sql = """
                SELECT o.*, s.agent_id, s.collected_at
                FROM process_observations o
                JOIN process_snapshots s ON o.snapshot_id = s.id
                WHERE o.process_name = ?
                ORDER BY s.collected_at DESC
                LIMIT ?
            """
            params = (process_name, limit)

        with self._connection(connection) as conn:
            cursor = conn.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]
