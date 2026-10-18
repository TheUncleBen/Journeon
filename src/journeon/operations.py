# SPDX-License-Identifier: AGPL-3.0-only
"""Local database diagnostics, snapshots and explicit offline migrations.

Stop the application before migration. Snapshots contain only the SQLite database,
not external files or recovery credentials, and are not a complete deployment backup.
Failed operations preserve partial output for inspection; they never restore automatically.
Live WAL diagnostics require an explicit snapshot and do not certify service readiness.
"""

import argparse
import hashlib
import json
import os
import sqlite3
import stat
import time
from contextlib import closing
from pathlib import Path
from typing import Any

from alembic import command
from alembic.script import ScriptDirectory
from alembic.util.exc import CommandError
from sqlalchemy.exc import SQLAlchemyError

from journeon.database import SCHEMA_REVISION, create_database
from journeon.migrate import configuration
from journeon.models import Base


def _regular(path: Path) -> None:
    if not path.is_absolute() or not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("An absolute regular database file is required")


def _connect(path: Path) -> sqlite3.Connection:
    _regular(path)
    return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)


def _metadata(connection: sqlite3.Connection) -> dict[str, Any]:
    if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise ValueError("Database integrity validation failed")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise ValueError("Database relationship validation failed")
    revisions = connection.execute("SELECT version_num FROM alembic_version").fetchall()
    if len(revisions) != 1 or not isinstance(revisions[0][0], str):
        raise ValueError("Database schema revision is unavailable")
    tables = sorted(
        row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    )
    return {"schema": revisions[0][0], "tables": tables}


def doctor(path: Path) -> dict[str, str]:
    """Inspect without opening WAL databases or changing database journal settings."""
    try:
        _regular(path)
        with path.open("rb") as stream:
            header = stream.read(100)
        if len(header) != 100 or header[:16] != b"SQLite format 3\x00":
            raise ValueError("Invalid database header")
        if header[18:20] != b"\x01\x01":
            return {
                "status": "WARN",
                "schema": "NOT_ASSESSED",
                "detail": "WAL database requires an explicit coherent snapshot for validation",
            }
        # Refuse a live rollback journal rather than attempting recovery during diagnosis.
        if Path(str(path) + "-journal").exists():
            return {
                "status": "WARN",
                "schema": "NOT_ASSESSED",
                "detail": "Database journal requires operational recovery assessment",
            }
        with closing(_connect(path)) as connection:
            connection.execute("BEGIN")
            metadata = _metadata(connection)
        current = metadata["schema"] == SCHEMA_REVISION and set(Base.metadata.tables) <= set(
            metadata["tables"]
        )
        return {
            "status": "PASS" if current else "FAIL",
            "schema": "CURRENT" if current else "INCOMPATIBLE",
            "detail": "Database integrity and schema checked; authentication is not assessed",
        }
    except (OSError, ValueError, sqlite3.Error):
        return {
            "status": "FAIL",
            "schema": "UNKNOWN",
            "detail": "Database is missing, inaccessible or invalid",
        }


def validate_snapshot(directory: Path) -> dict[str, Any]:
    """Validate database bytes and metadata; this is not signature or restore approval."""
    path = directory / "database.sqlite"
    _regular(path)
    _regular(directory / "manifest.json")
    manifest = json.loads((directory / "manifest.json").read_text())
    if not isinstance(manifest, dict) or set(manifest) != {
        "format",
        "sha256",
        "bytes",
        "schema",
        "tables",
    }:
        raise ValueError("Snapshot manifest is invalid")
    if manifest["format"] != 1 or manifest["bytes"] != path.stat().st_size:
        raise ValueError("Snapshot format or size is invalid")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if manifest["sha256"] != digest:
        raise ValueError("Snapshot checksum does not match")
    with path.open("rb") as stream:
        header = stream.read(20)
    if header[18:20] != b"\x01\x01" or any(
        Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")
    ):
        raise ValueError("Snapshot must be a standalone database")
    with closing(_connect(path)) as connection:
        metadata = _metadata(connection)
    if any(manifest[key] != value for key, value in metadata.items()):
        raise ValueError("Snapshot metadata does not match database contents")
    return manifest


def snapshot_database(path: Path, destination: Path) -> dict[str, Any]:
    """Create a new private coherent database snapshot; leave failed outputs unapproved."""
    if not destination.is_absolute():
        raise ValueError("An absolute new snapshot directory is required")
    with closing(_connect(path)) as source:
        destination.mkdir(mode=0o700)
        target = destination / "database.sqlite"
        descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        deadline = time.monotonic() + 30

        def progress(_status: int, _remaining: int, _total: int) -> None:
            if time.monotonic() >= deadline:
                raise TimeoutError("Snapshot did not finish within the operation deadline")

        with closing(sqlite3.connect(target)) as saved:
            source.backup(saved, pages=256, progress=progress, sleep=0.05)
            saved.execute("PRAGMA journal_mode=DELETE")
            metadata = _metadata(saved)
        with target.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
            os.fsync(stream.fileno())
        manifest = {
            "format": 1,
            "sha256": digest,
            "bytes": target.stat().st_size,
            **metadata,
        }
        manifest_path = destination / "manifest.json"
        descriptor = os.open(manifest_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w") as writer:
            json.dump(manifest, writer, sort_keys=True)
            writer.write("\n")
            writer.flush()
            os.fsync(writer.fileno())
        for directory in (destination, destination.parent):
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    return validate_snapshot(destination)


def migrate_database(path: Path, snapshot: Path) -> dict[str, str]:
    """Snapshot and migrate an existing supported database; never auto-restore on failure."""
    config = configuration()
    supported = {
        revision.revision for revision in ScriptDirectory.from_config(config).walk_revisions()
    }
    with closing(_connect(path)) as connection:
        if _metadata(connection)["schema"] not in supported:
            raise ValueError("Database schema is not supported for migration")
    engine = create_database(path)
    try:
        with engine.begin() as connection:
            # The existing BEGIN IMMEDIATE hook excludes other writers through snapshot and upgrade.
            previous = snapshot_database(path, snapshot)
            if previous["schema"] not in supported:
                raise ValueError("Database schema changed before migration")
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
            revisions = connection.exec_driver_sql("SELECT version_num FROM alembic_version").all()
            tables: set[str] = set(
                connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).scalars()
            )
            if revisions != [(SCHEMA_REVISION,)] or not set(Base.metadata.tables) <= tables:
                raise ValueError("Migration did not reach the expected schema")
            if connection.exec_driver_sql("PRAGMA integrity_check").all() != [("ok",)]:
                raise ValueError("Migrated database integrity validation failed")
            if connection.exec_driver_sql("PRAGMA foreign_key_check").first() is not None:
                raise ValueError("Migrated database relationship validation failed")
    finally:
        engine.dispose()
    return {"status": "PASS", "schema": SCHEMA_REVISION}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("doctor", "snapshot", "validate", "migrate"))
    parser.add_argument("path", type=Path)
    parser.add_argument("destination", type=Path, nargs="?")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result: dict[str, Any]
        if args.operation == "doctor":
            result = doctor(args.path)
        elif args.operation == "validate":
            result = validate_snapshot(args.path)
        elif args.destination is None:
            raise ValueError("A destination is required")
        elif args.operation == "snapshot":
            result = snapshot_database(args.path, args.destination)
        else:
            result = migrate_database(args.path, args.destination)
    except (OSError, ValueError, sqlite3.Error, SQLAlchemyError, CommandError):
        result = {
            "status": "FAIL",
            "detail": "Operation failed; preserve existing state and any partial snapshot",
        }
    print(
        json.dumps(result, sort_keys=True)
        if args.json
        else "\n".join(f"{k}: {v}" for k, v in result.items())
    )
    return 0 if result.get("status", "PASS") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
