# SPDX-License-Identifier: AGPL-3.0-only
import os
import subprocess
import sys
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import inspect, text
from test_identity_migration import populated_0006  # noqa: F401
from test_operation_migration import legacy_store  # noqa: F401
from test_work_migration import populated_0005  # noqa: F401

from journeon.database import create_database, transaction
from journeon.migrate import configuration, upgrade
from journeon.permissions import AuthenticatedContext


@pytest.fixture
def populated_0007(request, monkeypatch):
    from test_agents import setup_agents

    from journeon.contracts import BundleOrigin, BundleView, ComponentRef
    from journeon.models import InstructionBundle

    engine, path, receipts, _ = request.getfixturevalue("populated_0006")
    with engine.begin() as db:
        config = configuration()
        config.attributes["connection"] = db
        command.upgrade(config, "0007_identity_instructions")
    actor = AuthenticatedContext("owner", 7, "old-session")
    with monkeypatch.context() as patch:
        patch.setattr("journeon.database.SCHEMA_REVISION", "0007_identity_instructions")
        _, profile, bot, _ = setup_agents((engine, path), actor)
    project_id = receipts[0].project.project_id
    view = BundleView(
        bundle_id="retained-bundle",
        initiating_principal_id=actor.principal_id,
        profile_id=profile.profile_id,
        profile_revision=1,
        project_id=project_id,
        project_revision=1,
        origin=BundleOrigin(
            kind="NAMED_BOT",
            source_kind="CHAT",
            source_id="chat",
            bot_id=bot.bot_id,
            bot_revision=1,
        ),
        components=[
            ComponentRef(
                asset_id=profile.baseline_asset_id, revision=1, content_hash=profile.baseline_hash
            )
        ],
        content_digest="a" * 64,
        byte_count=17,
    )
    with transaction(engine) as db:
        db.add(
            InstructionBundle(
                id=view.bundle_id,
                principal_id=actor.principal_id,
                profile_id=profile.profile_id,
                bot_id=bot.bot_id,
                project_id=project_id,
                task_id=None,
                snapshot=view.model_dump(mode="json"),
            )
        )
    with engine.begin() as db:
        db.execute(text("UPDATE sqlite_sequence SET seq=400 WHERE name='outbox_events'"))
        snapshot = {
            name: db.execute(text(f"SELECT * FROM {name}")).all()
            for name in inspect(db).get_table_names()
            if name != "alembic_version"
        }
    return engine, path, receipts, snapshot


@pytest.mark.parametrize(
    "boundary",
    [
        None,
        "CREATE TABLE instruction_roots",
        "CREATE TABLE project_instruction_bindings",
        "CREATE TABLE instruction_request_scopes",
    ],
)
def test_populated_0007_upgrade_crash_restart_preserves_every_row(populated_0007, boundary):
    engine, path, receipts, snapshot = populated_0007
    if boundary:
        script = """
import os,sys
from pathlib import Path
from sqlalchemy import event
from journeon.database import create_database
from journeon.migrate import upgrade
engine=create_database(Path(sys.argv[1]))
def crash(conn,cursor,statement,parameters,context,many):
    if sys.argv[2] in statement:os._exit(79)
event.listen(engine,'after_cursor_execute',crash)
upgrade(engine)
"""
        result = subprocess.run(
            [sys.executable, "-c", script, str(path), boundary],
            env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
            timeout=30,
        )
        assert result.returncode == 79
        with engine.begin() as db:
            assert (
                db.scalar(text("SELECT version_num FROM alembic_version"))
                == "0007_identity_instructions"
            )
            for name, rows in snapshot.items():
                assert db.execute(text(f"SELECT * FROM {name}")).all() == rows
    upgrade(engine)
    engine.dispose()
    reopened = create_database(path)
    upgrade(reopened)
    with reopened.begin() as db:
        for name, rows in snapshot.items():
            assert db.execute(text(f"SELECT * FROM {name}")).all() == rows
        assert db.execute(text("PRAGMA foreign_key_check")).all() == []
        assert db.scalar(text("SELECT seq FROM sqlite_sequence WHERE name='outbox_events'")) == 400
        assert db.scalar(text("SELECT count(*) FROM instruction_roots")) == 0
        assert db.scalar(text("SELECT count(*) FROM project_instruction_bindings")) == 0
    from journeon.receipts import OperationService

    for receipt in receipts:
        assert (
            OperationService(reopened).receipt(
                AuthenticatedContext("owner", 7, "old-session"), receipt.operation_id
            )
            == receipt
        )
    reopened.dispose()


def test_populated_0008_successor_preserves_rows_and_sequence(populated_0007):
    engine, path, receipts, previous = populated_0007
    with engine.begin() as db:
        config = configuration()
        config.attributes["connection"] = db
        command.upgrade(config, "0008_project_instructions")
        snapshot = {
            name: db.execute(text(f"SELECT * FROM {name}")).all()
            for name in inspect(db).get_table_names()
            if name != "alembic_version"
        }
    upgrade(engine)
    with engine.begin() as db:
        for name, rows in snapshot.items():
            assert db.execute(text(f"SELECT * FROM {name}")).all() == rows
        assert db.scalar(text("SELECT seq FROM sqlite_sequence WHERE name='outbox_events'")) == 400
        assert (
            db.scalar(text("SELECT version_num FROM alembic_version")) == "0012_attempt_execution"
        )
        assert db.execute(text("PRAGMA foreign_key_check")).all() == []
        for name in ("operation_receipts", "outbox_events"):
            ddl = db.scalar(text("SELECT sql FROM sqlite_master WHERE name=:name"), {"name": name})
            assert "target_kind = 'project_instructions' AND project_id IS NOT NULL" in ddl
