# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from alembic import command
from sqlalchemy import event, inspect
from test_operation_migration import legacy_store  # noqa: F401

from journeon.migrate import configuration, upgrade
from journeon.models import (
    Attempt,
    AttemptManifest,
    InstructionRequestScope,
    InstructionRoot,
    ProtectedRequest,
    RestoreRequestScope,
    ReviewPolicyRevision,
    ReviewTargetRecord,
    Task,
    TaskRevision,
)


def retain_reference_graph(db):
    # Relational preservation fixture, not evidence of production authority provisioning.
    db.execute(
        Task.__table__.insert().values(
            id="retained-task",
            project_id="old-project",
            initiating_principal_id="owner",
            revision=1,
            snapshot={"retained": "task"},
        )
    )
    db.execute(
        TaskRevision.__table__.insert().values(
            task_id="retained-task",
            revision=1,
            snapshot={"retained": "revision"},
            operation_id="old-operation",
        )
    )
    db.execute(
        InstructionRoot.__table__.insert().values(
            id="retained-root",
            root_key="retained-root",
            revision=1,
            config_revision=1,
            project_id="old-project",
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
            project_id="old-project",
            task_id="retained-task",
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
            inputs={},
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
        ReviewPolicyRevision.__table__.insert().values(
            project_id="old-project",
            revision=1,
            snapshot={"retained": "policy"},
            content_hash="c" * 64,
        )
    )
    db.execute(
        ReviewTargetRecord.__table__.insert().values(
            id="retained-review",
            project_id="old-project",
            task_id="retained-task",
            task_revision=1,
            attempt_id="retained-attempt",
            manifest_id="retained-manifest",
            review_policy_revision=1,
            principal_id="owner",
            operation_id="old-operation",
            snapshot={"retained": "target"},
            content_hash="d" * 64,
        )
    )
    for identity, kind in (
        ("retained-instruction", "project.root.revoke.v1"),
        ("retained-restore", "lifecycle.restore.authorize.v1"),
    ):
        db.execute(
            ProtectedRequest.__table__.insert().values(
                id=identity,
                operation_id=identity,
                principal_id="owner",
                principal_epoch=7,
                session_id="old-session",
                idempotency_key=identity,
                command=kind,
                payload={},
                payload_hash="e" * 64,
                credential_revision=1,
                policy_hash="f" * 64,
                issued_at=1,
                deadline=2,
                state="EXPIRED",
            )
        )
    db.execute(
        InstructionRequestScope.__table__.insert().values(
            request_id="retained-instruction",
            project_id="old-project",
            projection=False,
        )
    )
    db.execute(
        RestoreRequestScope.__table__.insert().values(
            request_id="retained-restore",
            project_id="old-project",
        )
    )


@pytest.mark.parametrize(
    "boundary", [None, "operation_receipts", "outbox_events", "protected_requests"]
)
def test_workspace_upgrade_preserves_rows_triggers_and_sequence(legacy_store, boundary):  # noqa: F811
    engine, _, _, _ = legacy_store
    with engine.begin() as db:
        config = configuration()
        config.attributes["connection"] = db
        command.upgrade(config, "0014_review_completion")
        retain_reference_graph(db)
        db.exec_driver_sql("UPDATE sqlite_sequence SET seq=901 WHERE name='outbox_events'")
        db.exec_driver_sql(
            "CREATE TRIGGER retained_receipt_guard BEFORE UPDATE ON operation_receipts "
            "BEGIN SELECT RAISE(ABORT, 'Retained receipt guard'); END"
        )
        retained = {
            name: db.exec_driver_sql(f'SELECT * FROM "{name}"').all()
            for name in inspect(db).get_table_names()
            if name != "alembic_version"
        }
        triggers = db.exec_driver_sql(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' ORDER BY name"
        ).all()
    if boundary is not None:

        def interrupt(connection, cursor, statement, parameters, context, many):
            if f"DROP TABLE {boundary}" in statement or f'DROP TABLE "{boundary}"' in statement:
                raise RuntimeError("Interrupted migration fixture")

        event.listen(engine, "after_cursor_execute", interrupt)
        try:
            with pytest.raises(RuntimeError, match="Interrupted migration fixture"):
                upgrade(engine)
        finally:
            event.remove(engine, "after_cursor_execute", interrupt)
        with engine.begin() as db:
            assert (
                db.exec_driver_sql("SELECT version_num FROM alembic_version").scalar()
                == "0014_review_completion"
            )
            for name, rows in retained.items():
                assert db.exec_driver_sql(f'SELECT * FROM "{name}"').all() == rows
    upgrade(engine)
    upgrade(engine)
    with engine.begin() as db:
        assert (
            db.exec_driver_sql("SELECT version_num FROM alembic_version").scalar()
            == "0015_workspace_read_models"
        )
        assert db.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        for name, rows in retained.items():
            assert db.exec_driver_sql(f'SELECT * FROM "{name}"').all() == rows
        assert (
            db.exec_driver_sql(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' ORDER BY name"
            ).all()
            == triggers
        )
        assert (
            db.exec_driver_sql(
                "SELECT seq FROM sqlite_sequence WHERE name='outbox_events'"
            ).scalar()
            == 901
        )
