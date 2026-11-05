from contextlib import contextmanager
from typing import Optional
import sqlite3

from server.db import get_connection


class BaseRepository:
    """Base class for repositories providing connection and transaction handling."""

    def __init__(self, database_path: Optional[str] = None):
        self.database_path = database_path

    @contextmanager
    def _connection(self, connection: Optional[sqlite3.Connection] = None):
        """Yield an active connection.

        If a connection is provided, it is reused and not closed here.
        If no connection is provided, a new connection is created and committed/closed
        automatically within a transaction block.
        """
        if connection is not None:
            yield connection
        else:
            conn = get_connection(self.database_path)
            try:
                with conn:
                    yield conn
            finally:
                conn.close()
