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

from journeon.migrate import configuration, upgrade


@pytest.fixture
def populated_0009(request):
    engine, path, receipts, _ = request.getfixturevalue("populated_0006")
    with engine.begin() as db:
        config = configuration()
        config.attributes["connection"] = db
        command.upgrade(config, "0009_instruction_scope")
        db.exec_driver_sql("UPDATE sqlite_sequence SET seq=900 WHERE name='outbox_events'")
        retained = {
            name: db.exec_driver_sql(f'SELECT * FROM "{name}"').all()
            for name in inspect(db).get_table_names()
            if name != "alembic_version"
        }
    return engine, path, receipts, retained


@pytest.mark.parametrize("boundary", [None, "CREATE TABLE jobs", "INSERT INTO operation_receipts"])
def test_populated_0009_upgrade_and_crash_preserve_canonical_rows(populated_0009, boundary):
    engine, path, receipts, retained = populated_0009
    if boundary is not None:
        script = """import os,sys
from pathlib import Path
from sqlalchemy import event
from journeon.database import create_database
from journeon.migrate import upgrade
engine=create_database(Path(sys.argv[1]))
def interrupt(conn,cursor,statement,parameters,context,many):
    if sys.argv[2] in statement: os._exit(79)
event.listen(engine,'after_cursor_execute',interrupt)
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
                == "0009_instruction_scope"
            )
            for name, rows in retained.items():
                assert db.exec_driver_sql(f'SELECT * FROM "{name}"').all() == rows
    upgrade(engine)
    upgrade(engine)
    with engine.begin() as db:
        for name, rows in retained.items():
            assert db.exec_driver_sql(f'SELECT * FROM "{name}"').all() == rows
        assert db.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert (
            db.exec_driver_sql(
                "SELECT seq FROM sqlite_sequence WHERE name='outbox_events'"
            ).scalar()
            == 900
        )
        assert db.exec_driver_sql("SELECT count(*) FROM jobs").scalar() == 0
    from journeon.permissions import AuthenticatedContext
    from journeon.receipts import OperationService

    for receipt in receipts:
        assert (
            OperationService(engine).receipt(
                AuthenticatedContext("owner", 7, "old-session"), receipt.operation_id
            )
            == receipt
        )


def test_all_pruned_event_sequence_ceiling_is_preserved(populated_0009):
    engine, _, _, _ = populated_0009
    with engine.begin() as db:
        db.exec_driver_sql("DELETE FROM outbox_events")
    upgrade(engine)
    with engine.begin() as db:
        assert (
            db.exec_driver_sql(
                "SELECT seq FROM sqlite_sequence WHERE name='outbox_events'"
            ).scalar()
            == 900
        )
