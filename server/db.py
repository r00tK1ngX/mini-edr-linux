
import sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_PATH = PROJECT_ROOT / "data" / "mini_edr.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS endpoints (
                agent_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                ip_address TEXT,
                os TEXT NOT NULL,
                agent_version TEXT,
                status TEXT NOT NULL DEFAULT 'online',
                cpu_percent REAL,
                memory_percent REAL,
                disk_percent REAL,
                uptime_seconds REAL,
                last_seen TEXT NOT NULL
            )
        """)


def upsert_endpoint(endpoint):
    """Insert a new endpoint or update an existing endpoint."""
    with get_connection() as connection:
        connection.execute("""
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
        """)

        row = connection.execute(
            "SELECT * FROM endpoints WHERE agent_id = ?",
            (endpoint["agent_id"],)
        ).fetchone()

        return dict(row)

