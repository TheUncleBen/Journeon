# SPDX-License-Identifier: AGPL-3.0-only
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.exc import OperationalError

from journeon.contracts import DomainError
from journeon.database import create_database, transaction
from journeon.models import OutboxEvent, Project, Receipt
from journeon.projects import ProjectService

ROOT = Path(__file__).resolve().parents[1]


def record_counts(engine):
    with transaction(engine) as session:
        return tuple(
            session.scalar(select(func.count()).select_from(model))
            for model in (Project, Receipt, OutboxEvent)
        )


@pytest.mark.parametrize("stage", ["project", "receipt", "outbox", "before_commit", "after_commit"])
def test_process_crash_reopens_atomically_and_reconciles(database, actor, command, stage):
    original, path = database
    original.dispose()
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests/crash_worker.py"), str(path), stage],
        env={"PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == (78 if stage == "after_commit" else 77), result.stderr
    reopened = create_database(path)
    try:
        committed = stage == "after_commit"
        assert record_counts(reopened) == ((1, 1, 1) if committed else (0, 0, 0))
        with transaction(reopened) as session:
            original_receipt = session.scalar(select(Receipt))
            accepted = None if original_receipt is None else original_receipt.result
        reconciled = ProjectService(reopened).create(actor, command)
        assert record_counts(reopened) == (1, 1, 1)
        if committed:
            assert reconciled.model_dump(mode="json") == accepted
        with reopened.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA integrity_check").scalar() == "ok"
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    finally:
        reopened.dispose()


def test_outbox_storage_failure_rolls_back_without_success(database, actor, command):
    engine, _ = database

    def fail_outbox(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO outbox_events"):
            raise OperationalError(
                "synthetic test statement", {}, Exception("synthetic storage error")
            )

    event.listen(engine, "before_cursor_execute", fail_outbox)
    try:
        with pytest.raises(DomainError) as error:
            ProjectService(engine).create(actor, command)
        assert error.value.code == "DEPENDENCY_UNAVAILABLE"
    finally:
        event.remove(engine, "before_cursor_execute", fail_outbox)
    assert record_counts(engine) == (0, 0, 0)
    assert ProjectService(engine).create(actor, command).outcome == "CANONICAL_COMMITTED"
