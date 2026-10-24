# SPDX-License-Identifier: AGPL-3.0-only
import os
import subprocess
import sys
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import inspect
from test_execution_migration import populated_0009  # noqa: F401
from test_identity_migration import populated_0006  # noqa: F401
from test_operation_migration import legacy_store  # noqa: F401
from test_work_migration import populated_0005  # noqa: F401

from journeon.migrate import configuration, upgrade


@pytest.mark.parametrize("crash", [False, True])
def test_populated_task_dispatch_upgrade_preserves_legacy_origins_and_sequence(
    populated_0009,  # noqa: F811
    crash,
):
    engine, path, _, _ = populated_0009
    with engine.begin() as db:
        config = configuration()
        config.attributes["connection"] = db
        command.upgrade(config, "0012_attempt_execution")
        db.exec_driver_sql(
            "INSERT INTO instruction_candidates VALUES "
            "('candidate','old-project','owner','candidate-key','hash','{}')"
        )
        db.exec_driver_sql(
            "INSERT INTO jobs VALUES ('job','INSTRUCTION_NAVIGATION','old-project','candidate',"
            "'hash',1,1,'owner',7,'old-session',1,'QUEUED',0,NULL,'incarnation',NULL,0,0,0,"
            "NULL,'NONE',NULL,'admission',NULL,1)"
        )
        db.exec_driver_sql(
            "INSERT INTO attention VALUES "
            "('attention','job','old-project','RETAINED',1,'OPEN','[]')"
        )
        db.exec_driver_sql("UPDATE sqlite_sequence SET seq=901 WHERE name='outbox_events'")
        retained = {
            name: db.exec_driver_sql(f'SELECT * FROM "{name}"').mappings().all()
            for name in inspect(db).get_table_names()
            if name != "alembic_version"
        }
        columns = {
            name: [item["name"] for item in inspect(db).get_columns(name)] for name in retained
        }
    if crash:
        script = """import os,sys
from pathlib import Path
from sqlalchemy import event
from journeon.database import create_database
from journeon.migrate import upgrade
engine=create_database(Path(sys.argv[1]))
def interrupt(conn,cursor,statement,parameters,context,many):
    if 'CREATE TABLE task_verification_jobs' in statement: os._exit(79)
event.listen(engine,'after_cursor_execute',interrupt)
upgrade(engine)
"""
        result = subprocess.run(
            [sys.executable, "-c", script, str(path)],
            env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
            timeout=30,
        )
        assert result.returncode == 79
        with engine.begin() as db:
            assert (
                db.exec_driver_sql("SELECT version_num FROM alembic_version").scalar()
                == "0012_attempt_execution"
            )
            for name, rows in retained.items():
                assert db.exec_driver_sql(f'SELECT * FROM "{name}"').mappings().all() == rows
    upgrade(engine)
    upgrade(engine)
    with engine.begin() as db:
        for name, rows in retained.items():
            selected = ",".join(f'"{column}"' for column in columns[name])
            assert db.exec_driver_sql(f'SELECT {selected} FROM "{name}"').mappings().all() == rows
        assert db.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert (
            db.exec_driver_sql(
                "SELECT seq FROM sqlite_sequence WHERE name='outbox_events'"
            ).scalar()
            == 901
        )
        assert db.exec_driver_sql("SELECT candidate_id,task_id FROM jobs").one() == (
            "candidate",
            None,
        )
        assert db.exec_driver_sql("SELECT count(*) FROM task_verification_jobs").scalar() == 0
