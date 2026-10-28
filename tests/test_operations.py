# SPDX-License-Identifier: AGPL-3.0-only
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from alembic import command

from journeon.database import create_database
from journeon.migrate import configuration
from journeon.operations import doctor, migrate_database, snapshot_database, validate_snapshot


def tree_bytes(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize("kind", ["absent", "corrupt", "wal", "readonly", "incompatible"])
def test_doctor_does_not_change_files(tmp_path, kind):
    path = tmp_path / "db.sqlite"
    connection = None
    if kind == "corrupt":
        path.write_bytes(b"not a database")
    elif kind in ("wal", "readonly", "incompatible"):
        connection = sqlite3.connect(path)
        connection.execute("CREATE TABLE alembic_version (version_num TEXT)")
        connection.execute("INSERT INTO alembic_version VALUES ('future')")
        connection.commit()
        if kind == "wal":
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("INSERT INTO alembic_version VALUES ('pending')")
            connection.commit()
        if kind == "readonly":
            path.chmod(0o400)
    before = tree_bytes(tmp_path)
    report = doctor(path)
    assert report["status"] in ("FAIL", "WARN")
    assert report["schema"] != "CURRENT"
    assert tree_bytes(tmp_path) == before
    if connection:
        connection.close()


def test_snapshot_includes_committed_wal_and_validates(database, tmp_path):
    engine, path = database
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
        destination = tmp_path / "snapshot"
        report = snapshot_database(path, destination)
        assert report == validate_snapshot(destination)
        assert report["schema"] == "0017_notification_presentation"
        assert (destination.stat().st_mode & 0o777) == 0o700
        assert (destination / "database.sqlite").stat().st_mode & 0o777 == 0o600
        with sqlite3.connect(destination / "database.sqlite") as saved:
            assert saved.execute("SELECT count(*) FROM principals").fetchone()[0] == 2
            assert saved.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert doctor(destination / "database.sqlite")["schema"] == "CURRENT"


def test_snapshot_never_replaces_existing_destination(database, tmp_path):
    destination = tmp_path / "existing"
    destination.mkdir()
    sentinel = destination / "keep"
    sentinel.write_bytes(b"preserve")
    with pytest.raises(FileExistsError):
        snapshot_database(database[1], destination)
    assert sentinel.read_bytes() == b"preserve"


def test_snapshot_corruption_and_metadata_tampering_rejected(database, tmp_path):
    destination = tmp_path / "snapshot"
    snapshot_database(database[1], destination)
    manifest = destination / "manifest.json"
    original = manifest.read_bytes()
    content = json.loads(original)
    content["schema"] = "future"
    manifest.write_text(json.dumps(content))
    with pytest.raises(ValueError):
        validate_snapshot(destination)
    manifest.write_bytes(original)
    with (destination / "database.sqlite").open("ab") as stream:
        stream.write(b"corrupt")
    with pytest.raises(ValueError):
        validate_snapshot(destination)


def test_migration_snapshots_old_schema_and_preserves_rows(tmp_path):
    path = tmp_path / "old.sqlite"
    engine = create_database(path)
    config = configuration()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "0001_foundation")
        connection.exec_driver_sql("INSERT INTO principals VALUES ('preserved', 'OWNER', 1, 1)")
    engine.dispose()
    result = migrate_database(path, tmp_path / "before")
    assert result["schema"] == "0017_notification_presentation"
    assert validate_snapshot(tmp_path / "before")["schema"] == "0001_foundation"
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT id FROM principals").fetchall() == [("preserved",)]


def test_migration_rejects_missing_or_unknown_without_creation(tmp_path):
    path = tmp_path / "missing.sqlite"
    with pytest.raises((ValueError, FileNotFoundError)):
        migrate_database(path, tmp_path / "backup")
    assert not path.exists()
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE alembic_version (version_num TEXT)")
        connection.execute("INSERT INTO alembic_version VALUES ('future')")
    before = path.read_bytes()
    with pytest.raises(ValueError):
        migrate_database(path, tmp_path / "backup")
    assert path.read_bytes() == before
    assert not (tmp_path / "backup").exists()


def test_cli_reports_failure_without_raw_path_or_traceback(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "journeon.operations",
            "doctor",
            str(tmp_path / "private-missing"),
            "--json",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert json.loads(result.stdout)["status"] == "FAIL"
    assert "private-missing" not in result.stdout + result.stderr


def test_migration_failure_rolls_back_and_keeps_valid_snapshot(tmp_path, monkeypatch):
    path = tmp_path / "old.sqlite"
    engine = create_database(path)
    config = configuration()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "0001_foundation")
    engine.dispose()

    def fail_upgrade(config, revision):
        config.attributes["connection"].exec_driver_sql("CREATE TABLE interrupted (id INTEGER)")
        raise RuntimeError("injected migration failure")

    monkeypatch.setattr(command, "upgrade", fail_upgrade)
    with pytest.raises(RuntimeError, match="injected"):
        migrate_database(path, tmp_path / "backup")
    assert validate_snapshot(tmp_path / "backup")["schema"] == "0001_foundation"
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchall() == [
            ("0001_foundation",)
        ]
        assert (
            connection.execute("SELECT name FROM sqlite_master WHERE name='interrupted'").fetchall()
            == []
        )


def test_invalid_source_leaves_no_approved_snapshot(tmp_path):
    path = tmp_path / "invalid.sqlite"
    path.write_bytes(b"invalid")
    with pytest.raises(sqlite3.Error):
        snapshot_database(path, tmp_path / "backup")
    assert not (tmp_path / "backup" / "manifest.json").exists()
    assert path.read_bytes() == b"invalid"


def test_closed_wal_doctor_does_not_create_sidecars(database, tmp_path):
    engine, path = database
    engine.dispose()
    assert not Path(str(path) + "-wal").exists()
    before = tree_bytes(tmp_path)
    assert doctor(path)["schema"] == "NOT_ASSESSED"
    assert tree_bytes(tmp_path) == before


def test_cli_snapshot_validate_and_human_doctor(database, tmp_path):
    root = Path(__file__).resolve().parents[1]
    destination = tmp_path / "backup"
    for arguments in [
        ["snapshot", str(database[1]), str(destination), "--json"],
        ["validate", str(destination), "--json"],
        ["doctor", str(destination / "database.sqlite")],
    ]:
        result = subprocess.run(
            [sys.executable, "-m", "journeon.operations", *arguments],
            cwd=root,
            env={"PYTHONPATH": str(root / "src")},
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout


def test_cli_migration_error_is_redacted(tmp_path, monkeypatch, capsys):
    from sqlalchemy.exc import OperationalError

    from journeon import operations

    def fail(*args):
        raise OperationalError("private SQL", {}, Exception("private path"))

    monkeypatch.setattr(operations, "migrate_database", fail)
    monkeypatch.setattr(
        sys,
        "argv",
        ["operations", "migrate", str(tmp_path / "db"), str(tmp_path / "backup"), "--json"],
    )
    assert operations.main() == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out)["status"] == "FAIL"
    assert "private" not in captured.out + captured.err


def test_migration_rejects_false_revision_without_current_tables(tmp_path, monkeypatch):
    path = tmp_path / "old.sqlite"
    engine = create_database(path)
    config = configuration()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "0001_foundation")
    engine.dispose()

    def incomplete_upgrade(config, revision):
        config.attributes["connection"].exec_driver_sql(
            "UPDATE alembic_version SET version_num='0007_identity_instructions'"
        )

    monkeypatch.setattr(command, "upgrade", incomplete_upgrade)
    with pytest.raises(ValueError):
        migrate_database(path, tmp_path / "backup")
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
            == "0001_foundation"
        )


def test_snapshot_syncs_new_directory_entry_before_success(database, tmp_path, monkeypatch):
    import os

    synced = set()
    original = os.fsync

    def observe(fd):
        info = os.fstat(fd)
        synced.add((info.st_dev, info.st_ino))
        original(fd)

    monkeypatch.setattr(os, "fsync", observe)
    destination = tmp_path / "backup"
    snapshot_database(database[1], destination)
    for path in (
        tmp_path,
        destination,
        destination / "database.sqlite",
        destination / "manifest.json",
    ):
        info = path.stat()
        assert (info.st_dev, info.st_ino) in synced


def test_doctor_journal_transition_never_opens_source_with_sqlite(tmp_path, monkeypatch):
    from journeon import operations

    path = tmp_path / "source.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE alembic_version (version_num TEXT)")
        connection.execute("INSERT INTO alembic_version VALUES ('old')")
    original = operations._connect
    opened = []

    def transition(target):
        connection = sqlite3.connect(path)
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        connection.close()
        opened.append(target)
        return original(target)

    monkeypatch.setattr(operations, "_connect", transition)
    result = doctor(path)
    assert path not in opened
    assert not Path(str(path) + "-wal").exists()
    assert not Path(str(path) + "-shm").exists()
    assert result["status"] != "PASS"


def test_doctor_success_is_observation_not_live_health(database, tmp_path):
    destination = tmp_path / "snapshot"
    snapshot_database(database[1], destination)
    result = doctor(destination / "database.sqlite")
    assert result["status"] == "INFO"
    assert result["scope"] == "COPIED_BYTES_ONLY"
    assert result["schema"] == "CURRENT"


@pytest.mark.parametrize("failure", ["copy", "sqlite"])
def test_doctor_private_copy_is_cleaned_and_errors_redacted(tmp_path, monkeypatch, failure):
    import shutil
    import tempfile

    from journeon import operations

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    path = tmp_path / "source.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE sample (id INTEGER)")
    before = path.read_bytes()

    def fail(*args, **kwargs):
        raise OSError("private diagnostic value")

    monkeypatch.setattr(shutil, "copyfileobj", fail) if failure == "copy" else monkeypatch.setattr(
        operations, "_metadata", fail
    )
    result = doctor(path)
    assert result["status"] == "FAIL"
    assert "private diagnostic value" not in str(result)
    assert list(scratch.iterdir()) == []
    assert path.read_bytes() == before


def test_doctor_detects_source_replacement_during_copy(tmp_path, monkeypatch):
    import shutil

    path = tmp_path / "source.sqlite"
    replacement = tmp_path / "replacement.sqlite"
    for target in (path, replacement):
        with sqlite3.connect(target) as connection:
            connection.execute("CREATE TABLE sample (id INTEGER)")
    original = shutil.copyfileobj

    def replace(source, target, *args, **kwargs):
        original(source, target, *args, **kwargs)
        replacement.replace(path)

    monkeypatch.setattr(shutil, "copyfileobj", replace)
    result = doctor(path)
    assert result["status"] == "WARN"
    assert result["schema"] == "NOT_ASSESSED"


def test_doctor_rejects_symlink_without_opening_target(tmp_path, monkeypatch):
    from journeon import operations

    target = tmp_path / "target"
    target.write_bytes(b"private bytes")
    path = tmp_path / "alias"
    path.symlink_to(target)

    def forbidden(*args):
        pytest.fail("Doctor must not open the original path with SQLite")

    monkeypatch.setattr(operations, "_connect", forbidden)
    before = tree_bytes(tmp_path)
    assert doctor(path)["status"] == "FAIL"
    assert tree_bytes(tmp_path) == before


def test_doctor_source_disappears_during_copy_cleans_temporary_files(tmp_path, monkeypatch):
    import shutil
    import tempfile

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    path = tmp_path / "source.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE sample (id INTEGER)")
    original = shutil.copyfileobj

    def remove(source, target, *args, **kwargs):
        original(source, target, *args, **kwargs)
        path.unlink()

    monkeypatch.setattr(shutil, "copyfileobj", remove)
    assert doctor(path)["status"] == "FAIL"
    assert list(scratch.iterdir()) == []
    assert not path.exists()
