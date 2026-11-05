
import sqlite3
from contextlib import closing

import pytest

from server.db import init_db


@pytest.fixture()
def database_path(tmp_path):
    path = tmp_path / "mini_edr_schema_test.db"
    init_db(path)
    return path


def test_phase2_tables_are_created(database_path):
    expected_tables = {
        "endpoints",
        "system_metrics",
        "process_snapshots",
        "process_observations",
        "file_baselines",
        "security_events",
        "alerts",
        "alert_events",
        "schema_migrations",
    }

    with closing(sqlite3.connect(database_path)) as connection:
        rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            """
        ).fetchall()

    actual_tables = {row[0] for row in rows}

    assert expected_tables.issubset(actual_tables)


def test_phase1_endpoint_data_is_preserved(tmp_path):
    path = tmp_path / "legacy_edr.db"

    # Simulate the existing Phase 1 database.
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("""
            CREATE TABLE endpoints (
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
            INSERT INTO endpoints (
                agent_id,
                hostname,
                os,
                status,
                last_seen
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            "lab-linux-01",
            "ubuntu-lab-01",
            "Ubuntu 24.04",
            "online",
            "2026-11-05T08:00:00+00:00",
        ))

        connection.commit()

    # Apply Phase 2 migrations to the existing database.
    init_db(path)

    with closing(sqlite3.connect(path)) as connection:
        row = connection.execute(
            """
            SELECT agent_id, hostname, os
            FROM endpoints
            WHERE agent_id = ?
            """,
            ("lab-linux-01",),
        ).fetchone()

    assert row == (
        "lab-linux-01",
        "ubuntu-lab-01",
        "Ubuntu 24.04",
    )


def test_system_metrics_requires_existing_endpoint(database_path):
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("""
                INSERT INTO system_metrics (
                    message_id,
                    agent_id,
                    cpu_percent,
                    memory_percent,
                    disk_percent,
                    uptime_seconds,
                    collected_at,
                    received_at
                )
                VALUES (
                    'msg-001',
                    'unknown-agent',
                    20,
                    30,
                    40,
                    1000,
                    '2026-11-05T08:00:00Z',
                    '2026-11-05T08:00:01Z'
                )
            """)


def test_system_metrics_rejects_invalid_cpu(database_path):
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        connection.execute("""
            INSERT INTO endpoints (
                agent_id,
                hostname,
                os,
                last_seen
            )
            VALUES (
                'lab-linux-01',
                'ubuntu-lab-01',
                'Ubuntu 24.04',
                '2026-11-05T08:00:00Z'
            )
        """)

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("""
                INSERT INTO system_metrics (
                    message_id,
                    agent_id,
                    cpu_percent,
                    memory_percent,
                    disk_percent,
                    uptime_seconds,
                    collected_at,
                    received_at
                )
                VALUES (
                    'msg-002',
                    'lab-linux-01',
                    150,
                    30,
                    40,
                    1000,
                    '2026-11-05T08:00:00Z',
                    '2026-11-05T08:00:01Z'
                )
            """)


def test_system_metrics_rejects_duplicate_message_id(database_path):
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        connection.execute("""
            INSERT INTO endpoints (
                agent_id,
                hostname,
                os,
                last_seen
            )
            VALUES (
                'lab-linux-01',
                'ubuntu-lab-01',
                'Ubuntu 24.04',
                '2026-11-05T08:00:00Z'
            )
        """)

        payload = """
            INSERT INTO system_metrics (
                message_id,
                agent_id,
                cpu_percent,
                memory_percent,
                disk_percent,
                uptime_seconds,
                collected_at,
                received_at
            )
            VALUES (
                'same-message-id',
                'lab-linux-01',
                20,
                30,
                40,
                1000,
                '2026-11-05T08:00:00Z',
                '2026-11-05T08:00:01Z'
            )
        """

        connection.execute(payload)

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(payload)


def test_process_observation_requires_existing_snapshot(database_path):
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("""
                INSERT INTO process_observations (
                    snapshot_id,
                    pid,
                    process_name
                )
                VALUES (
                    9999,
                    1234,
                    'python'
                )
            """)


def test_process_snapshot_and_observation_relationship(database_path):
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        connection.execute("""
            INSERT INTO endpoints (
                agent_id,
                hostname,
                os,
                last_seen
            )
            VALUES (
                'lab-linux-01',
                'ubuntu-lab-01',
                'Ubuntu 24.04',
                '2026-11-05T08:00:00Z'
            )
        """)

        cursor = connection.execute("""
            INSERT INTO process_snapshots (
                message_id,
                agent_id,
                process_count,
                collected_at,
                received_at
            )
            VALUES (
                'snapshot-001',
                'lab-linux-01',
                1,
                '2026-11-05T08:00:00Z',
                '2026-11-05T08:00:01Z'
            )
        """)

        snapshot_id = cursor.lastrowid

        connection.execute("""
            INSERT INTO process_observations (
                snapshot_id,
                pid,
                ppid,
                process_name,
                username,
                exe_path,
                cpu_percent,
                memory_percent,
                rss_bytes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            snapshot_id,
            1234,
            1000,
            "python",
            "kali",
            "/usr/bin/python3",
            5.5,
            1.2,
            1024 * 1024,
        ))

        count = connection.execute("""
            SELECT COUNT(*)
            FROM process_observations
            WHERE snapshot_id = ?
        """, (snapshot_id,)).fetchone()[0]

    assert count == 1


def test_file_baseline_rejects_invalid_sha256(database_path):
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        connection.execute("""
            INSERT INTO endpoints (
                agent_id,
                hostname,
                os,
                last_seen
            )
            VALUES (
                'lab-linux-01',
                'ubuntu-lab-01',
                'Ubuntu 24.04',
                '2026-11-05T08:00:00Z'
            )
        """)

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("""
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
                    'lab-linux-01',
                    '/etc/passwd',
                    'not-a-valid-hash',
                    1000,
                    123456,
                    420,
                    'present',
                    '2026-11-05T08:00:00Z',
                    '2026-11-05T08:00:00Z',
                    '2026-11-05T08:00:00Z'
                )
            """)


def test_security_event_rejects_invalid_severity(database_path):
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        connection.execute("""
            INSERT INTO endpoints (
                agent_id,
                hostname,
                os,
                last_seen
            )
            VALUES (
                'lab-linux-01',
                'ubuntu-lab-01',
                'Ubuntu 24.04',
                '2026-11-05T08:00:00Z'
            )
        """)

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("""
                INSERT INTO security_events (
                    message_id,
                    agent_id,
                    event_type,
                    severity,
                    source,
                    title,
                    occurred_at,
                    received_at
                )
                VALUES (
                    'event-001',
                    'lab-linux-01',
                    'process.suspicious',
                    'extreme',
                    'agent',
                    'Suspicious process detected',
                    '2026-11-05T08:00:00Z',
                    '2026-11-05T08:00:01Z'
                )
            """)


def test_alert_rejects_invalid_status(database_path):
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        connection.execute("""
            INSERT INTO endpoints (
                agent_id,
                hostname,
                os,
                last_seen
            )
            VALUES (
                'lab-linux-01',
                'ubuntu-lab-01',
                'Ubuntu 24.04',
                '2026-11-05T08:00:00Z'
            )
        """)

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("""
                INSERT INTO alerts (
                    alert_key,
                    agent_id,
                    rule_id,
                    title,
                    severity,
                    status,
                    first_seen_at,
                    last_seen_at,
                    created_at,
                    updated_at
                )
                VALUES (
                    'alert-001',
                    'lab-linux-01',
                    'RULE-001',
                    'Test alert',
                    'high',
                    'investigating',
                    '2026-11-05T08:00:00Z',
                    '2026-11-05T08:00:00Z',
                    '2026-11-05T08:00:00Z',
                    '2026-11-05T08:00:00Z'
                )
            """)


def test_endpoint_cannot_be_deleted_while_history_exists(database_path):
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        connection.execute("""
            INSERT INTO endpoints (
                agent_id,
                hostname,
                os,
                last_seen
            )
            VALUES (
                'lab-linux-01',
                'ubuntu-lab-01',
                'Ubuntu 24.04',
                '2026-11-05T08:00:00Z'
            )
        """)

        connection.execute("""
            INSERT INTO system_metrics (
                message_id,
                agent_id,
                cpu_percent,
                memory_percent,
                disk_percent,
                uptime_seconds,
                collected_at,
                received_at
            )
            VALUES (
                'msg-preserve',
                'lab-linux-01',
                20,
                30,
                40,
                1000,
                '2026-11-05T08:00:00Z',
                '2026-11-05T08:00:01Z'
            )
        """)

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("""
                DELETE FROM endpoints
                WHERE agent_id = 'lab-linux-01'
            """)


def test_migration_is_recorded_once(database_path):
    with closing(sqlite3.connect(database_path)) as connection:
        rows = connection.execute("""
            SELECT version, checksum_sha256, applied_at
            FROM schema_migrations
        """).fetchall()

    assert len(rows) == 1
    assert rows[0][0] == "001_phase2_data_model"
    assert len(rows[0][1]) == 64
    assert rows[0][2]


def test_database_integrity_and_foreign_keys(database_path):
    with closing(sqlite3.connect(database_path)) as connection:
        integrity = connection.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]

        foreign_key_errors = connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()

    assert integrity == "ok"
    assert foreign_key_errors == []

