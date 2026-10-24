# SPDX-License-Identifier: AGPL-3.0-only
import os
import subprocess
import sys
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import inspect, select
from test_execution_migration import populated_0009  # noqa: F401
from test_identity_migration import populated_0006  # noqa: F401
from test_operation_migration import legacy_store  # noqa: F401
from test_work_migration import populated_0005  # noqa: F401

from journeon.migrate import configuration, upgrade
from journeon.models import (
    Attempt,
    AttemptManifest,
    Execution,
    InstructionRoot,
    Job,
    Task,
    TaskVerificationEvidence,
    TaskVerificationJob,
)


@pytest.mark.parametrize(
    "boundary", [None, "CREATE TABLE review_policy_revisions", "CREATE TABLE review_targets"]
)
def test_populated_review_upgrade_and_interrupted_ddl_preserve_all_evidence(
    populated_0009,  # noqa: F811
    boundary,
):
    engine, path, _, _ = populated_0009
    with engine.begin() as db:
        config = configuration()
        config.attributes["connection"] = db
        command.upgrade(config, "0013_task_dispatch")
        task = db.execute(select(Task.__table__)).mappings().first()
        assert task is not None
        db.execute(
            InstructionRoot.__table__.insert().values(
                id="retained-root",
                root_key="retained-root",
                revision=1,
                config_revision=1,
                project_id=task["project_id"],
                role="PROJECT",
                device=1,
                inode=2,
                git_identity="retained",
                enabled=True,
            )
        )
        db.execute(
            Attempt.__table__.insert().values(
                id="retained-attempt",
                project_id=task["project_id"],
                task_id=task["id"],
                root_id="retained-root",
                root_revision=1,
                workspace_key="retained-workspace",
                workspace_revision=1,
                configuration_revision=1,
                principal_id="owner",
                authentication_ref="old-session",
                principal_epoch=7,
                idempotency_key="retained-attempt",
                payload_hash="a" * 64,
                revision=1,
                snapshot={"retained": "attempt"},
                inputs={"retained": "input"},
            )
        )
        db.execute(
            AttemptManifest.__table__.insert().values(
                id="retained-manifest",
                attempt_id="retained-attempt",
                content_hash="b" * 64,
                snapshot={"retained": "manifest"},
            )
        )
        db.execute(
            Job.__table__.insert().values(
                id="retained-task-job",
                kind="TASK_VERIFICATION",
                project_id=task["project_id"],
                task_id=task["id"],
                candidate_id=None,
                input_hash="c" * 64,
                binding_revision=1,
                policy_revision=1,
                principal_id="owner",
                principal_epoch=7,
                session_id="old-session",
                revision=3,
                state="SUCCEEDED",
                fence=1,
                claim_owner="retained-worker",
                incarnation="retained",
                lease_deadline=1,
                due_at=0,
                attempts=1,
                cancel_requested=False,
                reason=None,
                effect="COMMITTED",
                operation_id=None,
                admission_id="retained-admission",
                evidence_id="retained-evidence",
                byte_count=1,
            )
        )
        db.execute(
            Execution.__table__.insert().values(
                id="retained-execution",
                job_id="retained-task-job",
                root_id="retained-root",
                root_revision=1,
                project_id=task["project_id"],
                principal_id="owner",
                authentication_ref="old-session",
                principal_epoch=7,
                idempotency_key="retained-execution",
                payload_hash="d" * 64,
                revision=3,
                state="COMPLETED",
                drained=True,
                memory_bytes=1,
                storage_bytes=1,
                snapshot={"retained": "completion"},
                inputs={"retained": "execution input"},
            )
        )
        db.execute(
            TaskVerificationJob.__table__.insert().values(
                job_id="retained-task-job",
                attempt_id="retained-attempt",
                manifest_id="retained-manifest",
                principal_id="owner",
                idempotency_key="retained-dispatch",
                step_id="verify",
                route_digest="e" * 64,
                configuration_revision=1,
                inputs={"retained": "dispatch"},
                execution_id="retained-execution",
                claim_fence=1,
                claim_owner="retained-worker",
                claim_incarnation="retained",
            )
        )
        db.execute(
            TaskVerificationEvidence.__table__.insert().values(
                id="retained-evidence",
                job_id="retained-task-job",
                execution_id="retained-execution",
                manifest_id="retained-manifest",
                content_hash="f" * 64,
                snapshot={"retained": "evidence"},
            )
        )
        db.exec_driver_sql("UPDATE sqlite_sequence SET seq=901 WHERE name='outbox_events'")
        retained = {
            name: db.exec_driver_sql(f'SELECT * FROM "{name}"').all()
            for name in inspect(db).get_table_names()
            if name != "alembic_version"
        }
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
                db.exec_driver_sql("SELECT version_num FROM alembic_version").scalar()
                == "0013_task_dispatch"
            )
            for name, rows in retained.items():
                assert db.exec_driver_sql(f'SELECT * FROM "{name}"').all() == rows
    upgrade(engine)
    upgrade(engine)
    with engine.begin() as db:
        assert (
            db.exec_driver_sql("SELECT version_num FROM alembic_version").scalar()
            == "0014_review_completion"
        )
        assert db.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        for name, rows in retained.items():
            assert db.exec_driver_sql(f'SELECT * FROM "{name}"').all() == rows
        assert (
            db.exec_driver_sql(
                "SELECT seq FROM sqlite_sequence WHERE name='outbox_events'"
            ).scalar()
            == 901
        )
