# SPDX-License-Identifier: AGPL-3.0-only
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import inspect, text
from test_operation_migration import legacy_store  # noqa: F401

from journeon.contracts import DomainError, PasskeyMutationReceipt, PasskeySummary
from journeon.database import transaction
from journeon.migrate import configuration, upgrade
from journeon.permissions import AuthenticatedContext
from journeon.receipts import OperationService


@pytest.fixture
def populated_0005(request):
    engine, path, project_receipt, now = request.getfixturevalue("legacy_store")
    result = PasskeyMutationReceipt(
        operation_id="old-label",
        committed_at=project_receipt.committed_at,
        passkey=PasskeySummary(
            passkey_id="old-key",
            principal_id="owner",
            revision=2,
            label="Retained label",
            revoked=False,
        ),
    )
    with engine.begin() as db:
        config = configuration()
        config.attributes["connection"] = db
        command.upgrade(config, "0005_protected_operations")
        db.execute(text("UPDATE passkeys SET revision=2,label='Retained label'"))
        db.execute(
            text(
                "INSERT INTO operation_receipts VALUES ('old-label','owner','passkey.label.v1',"
                "'label-key',:hash,NULL,'old-session',:result,'identity','passkey','old-key')"
            ),
            {"hash": "a" * 64, "result": result.model_dump_json()},
        )
        db.execute(
            text(
                "INSERT INTO outbox_events VALUES (43,'label-event','old-label',"
                "'passkey.labelled',1,'owner',NULL,'identity','passkey','old-key',:time)"
            ),
            {"time": result.committed_at},
        )
        db.execute(text("UPDATE sqlite_sequence SET seq=100 WHERE name='outbox_events'"))
        snapshot = {
            name: db.execute(text(f"SELECT * FROM {name}")).all()
            for name in inspect(db).get_table_names()
            if name not in ("outbox_events", "tasks", "alembic_version")
        }
    return engine, path, project_receipt, result, snapshot


def test_populated_0005_preserves_all_rows_and_pruned_allocation_ceiling(populated_0005):
    engine, _, project, label, snapshot = populated_0005
    upgrade(engine)
    upgrade(engine)
    with engine.begin() as db:
        for name, rows in snapshot.items():
            assert db.execute(text(f"SELECT * FROM {name}")).all() == rows
        rows = db.execute(
            text(
                "SELECT sequence,event_id,target_revision,payload "
                "FROM outbox_events ORDER BY sequence"
            )
        ).all()
        assert [(r[0], r[1], r[2]) for r in rows] == [(42, "old-event", 1), (43, "label-event", 2)]
        assert [json.loads(r[3]) for r in rows] == [project.model_dump(), label.model_dump()]
        assert db.scalar(text("SELECT seq FROM sqlite_sequence WHERE name='outbox_events'")) == 100
        db.execute(text("DELETE FROM outbox_events WHERE sequence=43"))
        db.execute(
            text(
                "INSERT INTO outbox_events(event_id,operation_id,event_type,schema_version,"
                "principal_id,project_id,owner,target_kind,target_id,"
                "committed_at,target_revision,payload) "
                "VALUES ('replacement-event','old-label','passkey.labelled',1,"
                "'owner',NULL,'identity',"
                "'passkey','old-key',:time,2,:payload)"
            ),
            {"time": label.committed_at, "payload": label.model_dump_json()},
        )
        assert (
            db.scalar(text("SELECT sequence FROM outbox_events WHERE event_id='replacement-event'"))
            == 101
        )


def test_0005_receipts_authorize_after_upgrade(populated_0005):
    engine, _, project, label, _ = populated_0005
    upgrade(engine)
    actor = AuthenticatedContext("owner", 7, "old-session")
    assert OperationService(engine).receipt(actor, project.operation_id) == project
    assert OperationService(engine).receipt(actor, label.operation_id) == label
    with transaction(engine) as db:
        assert db.execute(text("PRAGMA foreign_key_check")).all() == []
    with pytest.raises(DomainError):
        OperationService(engine).receipt(
            AuthenticatedContext("owner", 7, "revoked-session"), label.operation_id
        )


@pytest.mark.parametrize(
    "boundary", ("DROP TABLE operation_receipts", "INSERT INTO outbox_events", "CREATE TABLE tasks")
)
def test_process_interruption_0006_is_atomic_and_retryable(populated_0005, boundary):
    engine, path, project, label, _ = populated_0005
    script = """
import os, sys
from pathlib import Path
from sqlalchemy import event
from journeon.database import create_database
from journeon.migrate import upgrade
engine = create_database(Path(sys.argv[1]))
def crash(conn,cursor,statement,parameters,context,many):
    if sys.argv[2] in statement:
        os._exit(79)
event.listen(engine,'after_cursor_execute',crash)
upgrade(engine)
"""
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-c", script, str(path), boundary],
        env={**os.environ, "PYTHONPATH": str(root / "src")},
        timeout=30,
    )
    assert result.returncode == 79
    with engine.begin() as db:
        assert (
            db.scalar(text("SELECT version_num FROM alembic_version"))
            == "0005_protected_operations"
        )
        assert db.scalar(text("SELECT seq FROM sqlite_sequence WHERE name='outbox_events'")) == 100
        assert db.scalar(text("SELECT count(*) FROM operation_receipts")) == 2
    upgrade(engine)
    actor = AuthenticatedContext("owner", 7, "old-session")
    assert OperationService(engine).receipt(actor, project.operation_id) == project
    assert OperationService(engine).receipt(actor, label.operation_id) == label
