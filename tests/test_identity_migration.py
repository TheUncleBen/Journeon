# SPDX-License-Identifier: AGPL-3.0-only
import os
import subprocess
import sys
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import inspect, text
from test_operation_migration import legacy_store  # noqa: F401
from test_work_migration import populated_0005  # noqa: F401

from journeon.contracts import TaskCreate
from journeon.database import transaction
from journeon.migrate import configuration, upgrade
from journeon.models import AccessGrant
from journeon.permissions import AuthenticatedContext
from journeon.receipts import OperationService
from journeon.work import WorkService


@pytest.fixture
def populated_0006(request, monkeypatch):
    engine, path, project, label, _ = request.getfixturevalue("populated_0005")
    with engine.begin() as db:
        config = configuration()
        config.attributes["connection"] = db
        command.upgrade(config, "0006_work")
    with transaction(engine) as db:
        for action in ["create", "read", "receipt.read"]:
            db.add(
                AccessGrant(
                    id="work-" + action,
                    principal_id="owner",
                    capability="task." + action,
                    resource_kind="project",
                    resource_id=project.project.project_id,
                    enabled=True,
                    revision=1,
                    provenance="fixture",
                )
            )
    with monkeypatch.context() as patch:
        patch.setattr("journeon.database.SCHEMA_REVISION", "0006_work")
        task = WorkService(engine).create(
            AuthenticatedContext("owner", 7, "old-session"),
            TaskCreate(
                schema_version=1,
                idempotency_key="task",
                project_id=project.project.project_id,
                expected_project_revision=1,
                objective="Preserve Work history",
                responsibility="HUMAN",
            ),
        )
    with engine.begin() as db:
        db.execute(text("UPDATE sqlite_sequence SET seq=250 WHERE name='outbox_events'"))
        snapshot = {
            name: db.execute(text(f"SELECT * FROM {name}")).all()
            for name in inspect(db).get_table_names()
            if name != "alembic_version"
        }
    return engine, path, [project, label, task], snapshot


def test_populated_0006_preservation_and_restart(populated_0006):
    from journeon.database import create_database

    engine, path, receipts, snapshot = populated_0006
    upgrade(engine)
    engine.dispose()
    engine = create_database(path)
    upgrade(engine)
    with engine.begin() as db:
        for name, rows in snapshot.items():
            assert db.execute(text(f"SELECT * FROM {name}")).all() == rows
        assert db.execute(text("PRAGMA foreign_key_check")).all() == []
        assert db.scalar(text("SELECT seq FROM sqlite_sequence WHERE name='outbox_events'")) == 250
    actor = AuthenticatedContext("owner", 7, "old-session")
    for receipt in receipts:
        assert OperationService(engine).receipt(actor, receipt.operation_id) == receipt
    from test_agents import profile_command

    from journeon.agents import AgentService

    AgentService(engine).create_profile(actor, profile_command())
    with engine.begin() as db:
        assert db.scalar(text("SELECT max(sequence) FROM outbox_events")) == 251
    engine.dispose()


@pytest.mark.parametrize(
    "boundary",
    [
        "DROP TABLE operation_receipts",
        "CREATE TABLE instruction_bundles",
        "CREATE TRIGGER immutable_instruction_bundles_delete",
    ],
)
def test_interrupted_0007_transaction_and_retry(populated_0006, boundary):
    engine, path, receipts, snapshot = populated_0006
    script = """
import os,sys
from pathlib import Path
from sqlalchemy import event
from journeon.database import create_database
from journeon.migrate import upgrade
engine=create_database(Path(sys.argv[1]))
def crash(conn,cursor,statement,parameters,context,many):
    if sys.argv[2] in statement:os._exit(79)
event.listen(engine,"after_cursor_execute",crash)
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
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "0006_work"
        for name, rows in snapshot.items():
            assert db.execute(text(f"SELECT * FROM {name}")).all() == rows
    upgrade(engine)
    actor = AuthenticatedContext("owner", 7, "old-session")
    for receipt in receipts:
        assert OperationService(engine).receipt(actor, receipt.operation_id) == receipt
