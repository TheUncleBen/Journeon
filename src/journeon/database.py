# SPDX-License-Identifier: AGPL-3.0-only
"""Local file-backed SQLite. Never creates schema or identity implicitly."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import URL, Connection, Engine, create_engine, event, text
from sqlalchemy.orm import Session

from journeon.contracts import DomainError
from journeon.maintenance import RestoreWriteIdentity

SCHEMA_REVISION = "0013_task_dispatch"


def require_compatible_schema(session: Session) -> None:
    # Existing tables alone do not prove safe compatibility with a newer writer.
    revisions = session.scalars(text("SELECT version_num FROM alembic_version")).all()
    if revisions != [SCHEMA_REVISION]:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "The operation schema is incompatible")


def create_database(
    path: Path,
    *,
    busy_timeout_ms: int = 5000,
    restore_write: RestoreWriteIdentity | None = None,
) -> Engine:
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
        from journeon.maintenance import acquire

        if Path(str(path) + ".successor.json").exists():
            raise RuntimeError("The store has a restored successor")
        descriptor = acquire(path)
        try:
            if connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='store_identity'"
            ).fetchone():
                from journeon.restore import startup_admission

                startup_admission(path, connection, staging=restore_write)
            connection.isolation_level = None
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if not mode or mode[0].lower() != "wal":
                raise RuntimeError("SQLite WAL is required")
            connection.execute("PRAGMA synchronous = FULL")
        except BaseException:
            import os

            os.close(descriptor)
            raise
        _record.info["maintenance_descriptor"] = descriptor

    @event.listens_for(engine, "begin")
    def begin(connection: Any) -> None:
        # Serialize current authorization with the accepted mutation/receipt.
        connection.exec_driver_sql("BEGIN IMMEDIATE")

    @event.listens_for(engine, "close")
    def unlock(_connection: Any, record: Any) -> None:
        import os

        descriptor = record.info.pop("maintenance_descriptor", None)
        if descriptor is not None:
            os.close(descriptor)

    return engine


def _persist_session_clock(connection: Connection | Session, observations: dict[str, int]) -> None:
    for session_id, observed in observations.items():
        connection.execute(
            text(
                "UPDATE browser_sessions SET last_observed = "
                "max(last_observed, :observed) WHERE id = :session_id"
            ),
            {"observed": observed, "session_id": session_id},
        )


@contextmanager
def transaction(engine: Engine) -> Iterator[Session]:
    observations: dict[str, int] = {}
    failure: BaseException | None = None
    with engine.connect() as connection, connection.begin():
        try:
            with (
                Session(
                    bind=connection,
                    expire_on_commit=False,
                    join_transaction_mode="create_savepoint",
                ) as session,
                session.begin(),
            ):
                session.info["session_clock_observations"] = observations
                yield session
                session.flush()
        except BaseException as exc:
            failure = exc
        # Domain rollback preserves the outer writer lock until security time is committed.
        _persist_session_clock(connection, observations)
    if failure is not None:
        raise failure
