# SPDX-License-Identifier: AGPL-3.0-only
"""Local file-backed SQLite. Never creates schema or identity implicitly."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import URL, Engine, create_engine, event, text
from sqlalchemy.orm import Session

from journeon.contracts import DomainError

SCHEMA_REVISION = "0001_foundation"


def require_compatible_schema(session: Session) -> None:
    # Existing tables alone do not prove safe compatibility with a newer writer.
    revisions = session.scalars(text("SELECT version_num FROM alembic_version")).all()
    if revisions != [SCHEMA_REVISION]:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "The operation schema is incompatible")


def create_database(path: Path, *, busy_timeout_ms: int = 5000) -> Engine:
    if not path.is_absolute() or path.name in {":memory:", ""}:
        raise ValueError("Use an absolute path to a local SQLite database")
    if not 1 <= busy_timeout_ms <= 60000:
        raise ValueError("busy_timeout_ms must be between 1 and 60000")
    engine = create_engine(
        URL.create("sqlite+pysqlite", database=str(path)),
        connect_args={"check_same_thread": False, "timeout": busy_timeout_ms / 1000},
        pool_pre_ping=True,
    )

    @event.listens_for(engine, "connect")
    def configure(connection: sqlite3.Connection, _record: Any) -> None:
        connection.isolation_level = None
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
        if not mode or mode[0].lower() != "wal":
            raise RuntimeError("SQLite WAL is required")
        connection.execute("PRAGMA synchronous = FULL")

    @event.listens_for(engine, "begin")
    def begin(connection: Any) -> None:
        # Serialize current authorization with the accepted mutation/receipt.
        connection.exec_driver_sql("BEGIN IMMEDIATE")

    return engine


@contextmanager
def transaction(engine: Engine) -> Iterator[Session]:
    with Session(engine, expire_on_commit=False) as session, session.begin():
        yield session
