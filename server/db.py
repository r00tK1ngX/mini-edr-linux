import os
import sqlite3
from contextlib import closing
from pathlib import Path
from server.migrations import apply_migrations

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "data" / "mini_edr.db"
SQLITE_TIMEOUT_SECONDS = float(os.getenv("SQLITE_TIMEOUT_SECONDS", "10.0"))


def get_connection(database_path=None):
    """Open a configured SQLite connection.

    The caller owns the returned connection and must close it. WAL is enabled
    once by init_db(); each connection applies its own safety pragmas.
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
    connection.execute(f"PRAGMA busy_timeout = {int(SQLITE_TIMEOUT_SECONDS * 1000)}")
    return connection



def init_db(database_path=None):
    """
    Initialize the legacy Phase 1 schema and apply all pending
    versioned database migrations.

    Phase 1's endpoints table is preserved.
    Phase 2 schema is managed by Migration Runner.
    """

    database_path = (
        str(database_path)
        if database_path is not None
        else str(DEFAULT_DATABASE_PATH)
    )

    if database_path == ":memory:":
        raise ValueError(
            "File-backed SQLite database is required "
            "because migrations use separate connections."
        )

    # Step 1: Initialize the Phase 1 schema.
    with closing(get_connection(database_path)) as connection:

        # WAL must be configured outside an active transaction.
        connection.execute("PRAGMA journal_mode = WAL")

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

    # Step 2: Apply Phase 2 and subsequent migrations.
    # This happens only after the endpoints table is available.
    applied = apply_migrations(database_path)

    return applied


def upsert_endpoint(endpoint, database_path=None):
    """Insert an endpoint or refresh its existing record by agent_id."""
    from server.repositories.endpoint_repository import EndpointRepository

    repo = EndpointRepository(database_path)
    return repo.upsert(endpoint)


def list_endpoints(database_path=None, offline_after_seconds=15):
    """Return endpoints and derive Online/Offline from the last heartbeat."""
    from server.repositories.endpoint_repository import EndpointRepository

    repo = EndpointRepository(database_path)
    return repo.list_all(offline_after_seconds=offline_after_seconds)
