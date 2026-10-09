"""
SQLite connection management for Secure Wave Analyzer.

Provides a single thread-safe entry point (:class:`Database`) that all
repositories use. Creates the database and schema automatically on first
launch and never crashes if the database file is missing beforehand.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from config.settings import settings
from utils.logger import get_logger

logger = get_logger(__name__)


class Database:
    """Thin wrapper around a SQLite connection with schema bootstrapping."""

    _lock = threading.Lock()

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or settings.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._initialize_schema()

    # -- connection handling -------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        """Return a thread-local connection (SQLite connections aren't shared)."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            self._local.conn = conn
        return conn

    def _initialize_schema(self) -> None:
        schema_path = Path(__file__).parent / "schema.sql"
        try:
            with self._lock:
                conn = self._connect()
                if schema_path.exists():
                    conn.executescript(schema_path.read_text(encoding="utf-8"))
                    conn.commit()
                    logger.info("Database schema ready at %s", self.db_path)
                else:
                    logger.error("Schema file missing: %s", schema_path)
        except sqlite3.Error as exc:
            logger.error("Failed to initialize database schema: %s", exc)

    # -- query helpers ---------------------------------------------------------
    def execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """Run a write/DDL query and commit. Raises sqlite3.Error on failure."""
        with self._lock:
            conn = self._connect()
            try:
                cursor = conn.execute(query, params)
                conn.commit()
                return cursor
            except sqlite3.Error as exc:
                logger.error("Query failed: %s | %s", query, exc)
                raise

    def executemany(self, query: str, seq_of_params: list[tuple]) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executemany(query, seq_of_params)
                conn.commit()
            except sqlite3.Error as exc:
                logger.error("Batch query failed: %s | %s", query, exc)
                raise

    def fetch_all(self, query: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            conn = self._connect()
            try:
                return conn.execute(query, params).fetchall()
            except sqlite3.Error as exc:
                logger.error("Fetch failed: %s | %s", query, exc)
                return []

    def fetch_one(self, query: str, params: tuple = ()) -> sqlite3.Row | None:
        with self._lock:
            conn = self._connect()
            try:
                return conn.execute(query, params).fetchone()
            except sqlite3.Error as exc:
                logger.error("Fetch failed: %s | %s", query, exc)
                return None

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None


# Module-level singleton used throughout the app.
_db_instance: Database | None = None


def get_database() -> Database:
    """Return the shared Database singleton, creating it on first call."""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance