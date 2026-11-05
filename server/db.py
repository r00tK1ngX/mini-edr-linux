import sqlite3
from contextlib import closing
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "data" / "mini_edr.db"
SQLITE_TIMEOUT_SECONDS = 5.0


def get_connection(database_path=None):
    """Open a configured SQLite connection.

    The caller owns the returned connection and must close it. WAL improves
    reader/writer coexistence for the dashboard and periodic Agent updates.
    """
    path = Path(database_path) if database_path else DEFAULT_DATABASE_PATH
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        str(path),
        timeout=SQLITE_TIMEOUT_SECONDS,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def init_db(database_path=None):
    """Create the Phase 1 endpoint table if it does not already exist."""
    with closing(get_connection(database_path)) as connection:
        with connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS endpoints (
                    agent_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    ip_address TEXT,
                    os TEXT NOT NULL,
                    agent_version TEXT,
                    status TEXT NOT NULL DEFAULT 'online'
                        CHECK (status IN ('online', 'offline')),
                    cpu_percent REAL,
                    memory_percent REAL,
                    disk_percent REAL,
                    uptime_seconds REAL,
                    last_seen TEXT NOT NULL
                )
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen
                ON endpoints(last_seen)
            """)


def upsert_endpoint(endpoint, database_path=None):
    """Insert an endpoint or refresh its existing record by agent_id."""
    with closing(get_connection(database_path)) as connection:
        with connection:
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
            """, endpoint)

            row = connection.execute(
                "SELECT * FROM endpoints WHERE agent_id = ?",
                (endpoint["agent_id"],),
            ).fetchone()
            return dict(row)


def list_endpoints(database_path=None, offline_after_seconds=15):
    """Return endpoints and derive Online/Offline from the last heartbeat."""
    with closing(get_connection(database_path)) as connection:
        with connection:
            connection.execute("""
                UPDATE endpoints
                SET status = CASE
                    WHEN (julianday('now') - julianday(last_seen)) * 86400.0 > ?
                    THEN 'offline'
                    ELSE 'online'
                END
            """, (offline_after_seconds,))

            rows = connection.execute("""
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
            """).fetchall()
            return [dict(row) for row in rows]
