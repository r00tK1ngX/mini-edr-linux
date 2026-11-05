
from __future__ import annotations

import hashlib
import re
import sqlite3

from datetime import datetime, timezone
from pathlib import Path


MIGRATIONS_DIR = Path(__file__).resolve().parent

SQLITE_TIMEOUT_SECONDS = 5.0

MIGRATION_FILENAME_PATTERN = re.compile(
    r"^\d{3,}_[a-z0-9][a-z0-9_]*\.sql$"
)


class MigrationError(RuntimeError):
    """Raised when a database migration cannot be applied safely."""


def _discover_migrations(migrations_dir: Path) -> list[Path]:
    """Find and validate migration files in filename order."""

    if not migrations_dir.is_dir():
        raise MigrationError(
            f"Migration directory does not exist: {migrations_dir}"
        )

    migration_files = sorted(migrations_dir.glob("*.sql"))

    for migration_file in migration_files:
        if not MIGRATION_FILENAME_PATTERN.fullmatch(
            migration_file.name
        ):
            raise MigrationError(
                f"Invalid migration filename: {migration_file.name}"
            )

    return migration_files


def _split_sql_statements(sql_content: str) -> list[str]:
    """
    Split SQL safely using SQLite's own statement completeness checker.

    This supports semicolons inside quoted strings and multi-line
    SQL statements better than a simple string.split(';').
    """

    statements = []
    buffer = ""

    for line in sql_content.splitlines(keepends=True):
        buffer += line

        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            buffer = ""

            if statement:
                statements.append(statement)

    if buffer.strip():
        raise MigrationError(
            "Migration contains an incomplete SQL statement."
        )

    return statements


def _ensure_migration_table(connection: sqlite3.Connection) -> None:
    """Create the migration history table if it does not exist."""

    connection.execute("BEGIN IMMEDIATE")

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                checksum_sha256 TEXT NOT NULL
                    CHECK(length(checksum_sha256) = 64),
                applied_at TEXT NOT NULL
            )
        """)

        connection.commit()

    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise


def _apply_one_migration(
    connection: sqlite3.Connection,
    version: str,
    checksum: str,
    statements: list[str],
) -> bool:
    """
    Apply one migration atomically.

    Return True if a new migration was applied.
    Return False if it had already been applied.
    """

    connection.execute("BEGIN IMMEDIATE")

    try:
        existing = connection.execute(
            """
            SELECT checksum_sha256
            FROM schema_migrations
            WHERE version = ?
            """,
            (version,),
        ).fetchone()

        if existing is not None:
            if existing["checksum_sha256"] != checksum:
                raise MigrationError(
                    f"Migration {version} was modified after application."
                )

            connection.commit()
            return False

        for statement in statements:
            connection.execute(statement)

        applied_at = datetime.now(timezone.utc).isoformat()

        connection.execute(
            """
            INSERT INTO schema_migrations (
                version,
                checksum_sha256,
                applied_at
            )
            VALUES (?, ?, ?)
            """,
            (version, checksum, applied_at),
        )

        connection.commit()
        return True

    except Exception as exc:
        if connection.in_transaction:
            connection.rollback()

        if isinstance(exc, MigrationError):
            raise

        raise MigrationError(
            f"Failed to apply migration {version}: {exc}"
        ) from exc


def apply_migrations(
    database_path: str | Path,
    migrations_dir: str | Path | None = None,
) -> list[str]:
    """
    Apply all pending migrations in ascending filename order.

    Returns a list containing the versions applied in this execution.

    Historical migration files must remain available and unchanged.
    """

    database_path = str(database_path)

    if database_path != ":memory:":
        database_file = Path(database_path).expanduser()
        database_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        database_path = str(database_file)

    directory = (
        Path(migrations_dir)
        if migrations_dir is not None
        else MIGRATIONS_DIR
    )

    migration_files = _discover_migrations(directory)

    connection = sqlite3.connect(
        database_path,
        timeout=SQLITE_TIMEOUT_SECONDS,
        isolation_level=None,
    )

    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")

    applied_versions = []

    try:
        _ensure_migration_table(connection)

        # An applied migration must never disappear from the repository.
        applied_rows = connection.execute(
            "SELECT version FROM schema_migrations"
        ).fetchall()

        applied_in_database = {
            row["version"] for row in applied_rows
        }

        available_versions = {
            migration.stem for migration in migration_files
        }

        missing_files = applied_in_database - available_versions

        if missing_files:
            missing = ", ".join(sorted(missing_files))
            raise MigrationError(
                f"Applied migration files are missing: {missing}"
            )

        for migration_file in migration_files:
            raw_content = migration_file.read_bytes()

            checksum = hashlib.sha256(
                raw_content
            ).hexdigest()

            try:
                sql_content = raw_content.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise MigrationError(
                    f"Migration is not valid UTF-8: {migration_file.name}"
                ) from exc

            statements = _split_sql_statements(sql_content)

            if not statements:
                raise MigrationError(
                    f"Migration is empty: {migration_file.name}"
                )

            version = migration_file.stem

            was_applied = _apply_one_migration(
                connection,
                version,
                checksum,
                statements,
            )

            if was_applied:
                applied_versions.append(version)

        return applied_versions

    finally:
        connection.close()

