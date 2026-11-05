
import sqlite3

import pytest

from server.migrations import (
    MigrationError,
    apply_migrations,
)


@pytest.fixture()
def migration_dir(tmp_path):
    directory = tmp_path / "migrations"
    directory.mkdir()
    return directory


@pytest.fixture()
def database_path(tmp_path):
    return tmp_path / "test_edr.db"


def write_migration(directory, name, content):
    path = directory / name
    path.write_text(content, encoding="utf-8")
    return path


def test_applies_new_migration(
    migration_dir,
    database_path,
):
    write_migration(
        migration_dir,
        "001_create_assets.sql",
        """
        CREATE TABLE assets (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        );
        """,
    )

    applied = apply_migrations(
        database_path,
        migration_dir,
    )

    assert applied == ["001_create_assets"]

    with sqlite3.connect(database_path) as connection:
        table = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'assets'
            """
        ).fetchone()

        migration = connection.execute(
            """
            SELECT version, checksum_sha256, applied_at
            FROM schema_migrations
            """
        ).fetchone()

    assert table is not None
    assert migration[0] == "001_create_assets"
    assert len(migration[1]) == 64
    assert migration[2]


def test_migration_is_idempotent(
    migration_dir,
    database_path,
):
    write_migration(
        migration_dir,
        "001_create_assets.sql",
        """
        CREATE TABLE assets (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        );
        """,
    )

    first_run = apply_migrations(
        database_path,
        migration_dir,
    )

    second_run = apply_migrations(
        database_path,
        migration_dir,
    )

    assert first_run == ["001_create_assets"]
    assert second_run == []

    with sqlite3.connect(database_path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM schema_migrations"
        ).fetchone()[0]

    assert count == 1


def test_failed_migration_rolls_back(
    migration_dir,
    database_path,
):
    write_migration(
        migration_dir,
        "001_broken_migration.sql",
        """
        CREATE TABLE temporary_table (
            id INTEGER PRIMARY KEY
        );

        THIS IS NOT VALID SQL;
        """,
    )

    with pytest.raises(MigrationError):
        apply_migrations(
            database_path,
            migration_dir,
        )

    with sqlite3.connect(database_path) as connection:
        table = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'temporary_table'
            """
        ).fetchone()

        count = connection.execute(
            "SELECT COUNT(*) FROM schema_migrations"
        ).fetchone()[0]

    assert table is None
    assert count == 0


def test_detects_modified_applied_migration(
    migration_dir,
    database_path,
):
    migration = write_migration(
        migration_dir,
        "001_create_assets.sql",
        """
        CREATE TABLE assets (
            id INTEGER PRIMARY KEY
        );
        """,
    )

    apply_migrations(database_path, migration_dir)

    # Simulate someone modifying an already-applied migration.
    migration.write_text(
        """
        CREATE TABLE assets (
            id INTEGER PRIMARY KEY,
            name TEXT
        );
        """,
        encoding="utf-8",
    )

    with pytest.raises(
        MigrationError,
        match="modified after application",
    ):
        apply_migrations(database_path, migration_dir)


def test_detects_missing_applied_migration(
    migration_dir,
    database_path,
):
    migration = write_migration(
        migration_dir,
        "001_create_assets.sql",
        """
        CREATE TABLE assets (
            id INTEGER PRIMARY KEY
        );
        """,
    )

    apply_migrations(database_path, migration_dir)

    migration.unlink()

    with pytest.raises(
        MigrationError,
        match="migration files are missing",
    ):
        apply_migrations(database_path, migration_dir)


def test_rejects_empty_migration(
    migration_dir,
    database_path,
):
    write_migration(
        migration_dir,
        "001_empty_migration.sql",
        "",
    )

    with pytest.raises(
        MigrationError,
        match="Migration is empty",
    ):
        apply_migrations(database_path, migration_dir)


def test_rejects_invalid_migration_filename(
    migration_dir,
    database_path,
):
    write_migration(
        migration_dir,
        "create_assets.sql",
        """
        CREATE TABLE assets (
            id INTEGER PRIMARY KEY
        );
        """,
    )

    with pytest.raises(
        MigrationError,
        match="Invalid migration filename",
    ):
        apply_migrations(database_path, migration_dir)

