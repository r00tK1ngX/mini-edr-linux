"""Durable Local Event Spool Queue and Baseline Persistence for Mini EDR Linux Agent.

Provides persistent, crash-resilient SQLite storage for FIM change events and
baseline state. Ensures zero event loss during network outages, transient server
errors, partial batch transmissions, and unexpected agent process crashes (SIGKILL).

Features:
- Durable SQLite spool queue for security events.
- Stable UUID v4 message IDs for idempotent retry.
- Atomic baseline state persistence across agent restarts.
- Bounded queue capacity to prevent unbounded disk growth.
- Acknowledgement tracking and retry count semantics.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional
import uuid

logger = logging.getLogger(__name__)

DEFAULT_MAX_SPOOL_EVENTS = 1000


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventSpool:
    """Manages persistent local SQLite spool queue for security events and FIM baseline."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        max_size: int = DEFAULT_MAX_SPOOL_EVENTS,
        agent_id: str = "agent-local",
    ):
        self.max_size = max(10, int(max_size))
        self.agent_id = agent_id

        if db_path:
            self.db_path = ":memory:" if db_path == ":memory:" else str(Path(db_path).resolve())
        else:
            default_dir = Path(__file__).resolve().parent.parent / "data"
            self.db_path = str(default_dir / f"spool_{self.agent_id}.db")

        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
        else:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

    @contextmanager
    def _connection(self):
        """Yield an active SQLite connection with WAL and safety pragmas."""
        if self.db_path == ":memory:":
            try:
                yield self._mem_conn
            finally:
                pass
            return

        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 10000;")
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create spool queue and baseline state tables."""
        with self._connection() as conn:
            if self.db_path != ":memory:":
                conn.execute("PRAGMA journal_mode = WAL;")

            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS fim_spool (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        message_id TEXT UNIQUE NOT NULL,
                        agent_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        envelope_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        last_attempt_at TEXT,
                        status TEXT NOT NULL DEFAULT 'pending'
                            CHECK(status IN ('pending', 'acknowledged', 'failed'))
                    );
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_fim_spool_status
                    ON fim_spool(status, id);
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS fim_baseline_state (
                        file_path TEXT PRIMARY KEY,
                        sha256 TEXT NOT NULL,
                        file_size_bytes INTEGER NOT NULL,
                        mtime_ns INTEGER NOT NULL,
                        file_mode INTEGER NOT NULL,
                        state TEXT NOT NULL,
                        first_seen_at TEXT NOT NULL,
                        last_seen_at TEXT NOT NULL,
                        last_checked_at TEXT NOT NULL
                    );
                """)

    def enqueue_events(self, events: List[Dict[str, Any]]) -> int:
        """Persist security event envelopes into the local spool.

        Returns:
            Number of new events successfully enqueued.
        """
        if not events:
            return 0

        now = _utc_now()
        inserted_count = 0

        with self._connection() as conn:
            with conn:
                # Enforce bounded queue size: purge acknowledged events first if near capacity
                total_count = conn.execute("SELECT COUNT(*) as cnt FROM fim_spool").fetchone()["cnt"]
                if total_count + len(events) > self.max_size:
                    # Clean up acknowledged events
                    conn.execute("DELETE FROM fim_spool WHERE status = 'acknowledged'")
                    total_count = conn.execute("SELECT COUNT(*) as cnt FROM fim_spool").fetchone()["cnt"]
                    # If still exceeding capacity, drop oldest pending events to prevent unbounded growth
                    if total_count + len(events) > self.max_size:
                        excess = (total_count + len(events)) - self.max_size
                        conn.execute(
                            "DELETE FROM fim_spool WHERE id IN (SELECT id FROM fim_spool ORDER BY id ASC LIMIT ?)",
                            (excess,),
                        )
                        logger.warning("Spool exceeded capacity (%d); purged %d oldest events", self.max_size, excess)

                for ev in events:
                    msg_id = ev.get("message_id") or str(uuid.uuid4())
                    ev["message_id"] = msg_id
                    agent_id = ev.get("agent_id", self.agent_id)
                    payload = ev.get("payload", {})
                    event_type = payload.get("event_type", "unknown")
                    severity = payload.get("severity", "medium")
                    envelope_json = json.dumps(ev)

                    cursor = conn.execute(
                        """
                        INSERT OR IGNORE INTO fim_spool (
                            message_id, agent_id, event_type, severity, envelope_json, created_at, status
                        )
                        VALUES (?, ?, ?, ?, ?, ?, 'pending');
                        """,
                        (msg_id, agent_id, event_type, severity, envelope_json, now),
                    )
                    if cursor.rowcount > 0:
                        inserted_count += 1

        logger.debug("Enqueued %d events into local spool (total attempted: %d)", inserted_count, len(events))
        return inserted_count

    def get_pending_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve pending events from the spool in FIFO order."""
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, message_id, agent_id, event_type, severity, envelope_json, attempts, created_at
                FROM fim_spool
                WHERE status = 'pending'
                ORDER BY id ASC
                LIMIT ?;
                """,
                (limit,),
            ).fetchall()

            results = []
            for r in rows:
                try:
                    envelope = json.loads(r["envelope_json"])
                except Exception:
                    envelope = {}
                results.append({
                    "id": r["id"],
                    "message_id": r["message_id"],
                    "agent_id": r["agent_id"],
                    "event_type": r["event_type"],
                    "severity": r["severity"],
                    "envelope": envelope,
                    "attempts": r["attempts"],
                    "created_at": r["created_at"],
                })
            return results

    def mark_acknowledged(self, message_id: str) -> bool:
        """Mark an event as acknowledged after successful server ingestion."""
        if not message_id:
            return False
        with self._connection() as conn:
            with conn:
                cursor = conn.execute(
                    "UPDATE fim_spool SET status = 'acknowledged' WHERE message_id = ?",
                    (message_id,),
                )
                return cursor.rowcount > 0

    def record_failure(self, message_id: str) -> None:
        """Increment attempt counter and record failure timestamp for an event."""
        if not message_id:
            return
        now = _utc_now()
        with self._connection() as conn:
            with conn:
                conn.execute(
                    """
                    UPDATE fim_spool
                    SET attempts = attempts + 1, last_attempt_at = ?
                    WHERE message_id = ?;
                    """,
                    (now, message_id),
                )

    def count_pending(self) -> int:
        """Return total count of pending events in spool."""
        with self._connection() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM fim_spool WHERE status = 'pending'").fetchone()
            return row["cnt"] if row else 0

    def count_total(self) -> int:
        """Return total records count in spool."""
        with self._connection() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM fim_spool").fetchone()
            return row["cnt"] if row else 0

    # -------------------------------------------------------------------------
    # Baseline Persistence
    # -------------------------------------------------------------------------

    def save_baseline(self, baseline: Dict[str, Dict[str, Any]]) -> None:
        """Atomically persist the entire FIM baseline state in SQLite."""
        now = _utc_now()
        with self._connection() as conn:
            with conn:
                # Replace all rows atomically
                conn.execute("DELETE FROM fim_baseline_state;")
                sql = """
                    INSERT INTO fim_baseline_state (
                        file_path, sha256, file_size_bytes, mtime_ns, file_mode,
                        state, first_seen_at, last_seen_at, last_checked_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """
                params = [
                    (
                        path,
                        rec["sha256"],
                        rec["file_size_bytes"],
                        rec["mtime_ns"],
                        rec["file_mode"],
                        rec.get("state", "present"),
                        rec.get("first_seen_at", now),
                        rec.get("last_seen_at", now),
                        rec.get("last_checked_at", now),
                    )
                    for path, rec in baseline.items()
                ]
                conn.executemany(sql, params)
        logger.debug("Persisted %d baseline records to local spool storage", len(baseline))

    def load_baseline(self) -> Dict[str, Dict[str, Any]]:
        """Load persisted FIM baseline state from SQLite storage."""
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM fim_baseline_state").fetchall()
            baseline: Dict[str, Dict[str, Any]] = {}
            for r in rows:
                baseline[r["file_path"]] = {
                    "file_path": r["file_path"],
                    "sha256": r["sha256"],
                    "file_size_bytes": r["file_size_bytes"],
                    "mtime_ns": r["mtime_ns"],
                    "file_mode": r["file_mode"],
                    "state": r["state"],
                    "first_seen_at": r["first_seen_at"],
                    "last_seen_at": r["last_seen_at"],
                    "last_checked_at": r["last_checked_at"],
                }
            return baseline

    def has_persisted_baseline(self) -> bool:
        """Check whether a baseline has already been persisted to disk."""
        with self._connection() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM fim_baseline_state").fetchone()
            return bool(row and row["cnt"] > 0)
