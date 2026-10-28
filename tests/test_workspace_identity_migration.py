# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from alembic import command
from sqlalchemy import event, inspect
from test_operation_migration import legacy_store  # noqa: F401
from test_workspace_administration_migration import retain_reference_graph

from journeon.migrate import configuration


def upgrade_to(engine, revision):
    with engine.begin() as db:
        config = configuration()
        config.attributes["connection"] = db
        command.upgrade(config, revision)


@pytest.mark.parametrize("base", ["0014_review_completion", "0015_workspace_read_models"])
@pytest.mark.parametrize(
    "boundary", [None, "operation_receipts", "outbox_events", "protected_requests"]
)
def test_identity_migration_preserves_prior_graph_and_bounds(legacy_store, base, boundary):  # noqa: F811
    # Raw rows qualify migration preservation only, never human or permission provisioning.
    engine, _, _, _ = legacy_store
    upgrade_to(engine, base)
    with engine.begin() as db:
        retain_reference_graph(db)
        if base == "0015_workspace_read_models":
            db.exec_driver_sql(
                "INSERT INTO access_grants VALUES ('retained-p0-grant','owner','project.create',"
                "'deployment','deployment',1,1,NULL,'retained-provenance')"
            )
            db.exec_driver_sql(
                "INSERT INTO deployment_policy VALUES (1,1,'retained-approval','owner','[]',NULL)"
            )
            db.exec_driver_sql(
                "INSERT INTO protected_requests (id,operation_id,principal_id,principal_epoch,"
                "session_id,idempotency_key,command,payload,payload_hash,credential_revision,"
                "policy_hash,issued_at,deadline,state,approved_at,approval_deadline,"
                "strong_authenticated_at,nonce_hash,nonce_deadline) "
                "SELECT 'retained-p0-consent','retained-p0-operation',"
                "principal_id,principal_epoch,session_id,'retained-p0-key','permission.grant.set.v1',"
                "payload,payload_hash,credential_revision,policy_hash,issued_at,deadline,state,"
                "approved_at,approval_deadline,strong_authenticated_at,nonce_hash,nonce_deadline "
                "FROM protected_requests WHERE id='retained-instruction'"
            )
        db.exec_driver_sql("UPDATE sqlite_sequence SET seq=1701 WHERE name='outbox_events'")
        db.exec_driver_sql(
            "CREATE TRIGGER retained_identity_receipt_guard BEFORE UPDATE ON operation_receipts "
            "BEGIN SELECT RAISE(ABORT, 'Retained identity receipt guard'); END"
        )
        rows = {
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
                raise RuntimeError("Interrupted identity migration fixture")

        event.listen(engine, "after_cursor_execute", interrupt)
        try:
            with pytest.raises(RuntimeError, match="Interrupted identity migration fixture"):
                upgrade_to(engine, "0016_identity_sessions")
        finally:
            event.remove(engine, "after_cursor_execute", interrupt)
        with engine.begin() as db:
            assert db.exec_driver_sql("SELECT version_num FROM alembic_version").scalar() == base
            for name, prior in rows.items():
                assert db.exec_driver_sql(f'SELECT * FROM "{name}"').all() == prior
    upgrade_to(engine, "0016_identity_sessions")
    upgrade_to(engine, "0016_identity_sessions")
    with engine.begin() as db:
        assert (
            db.exec_driver_sql("SELECT version_num FROM alembic_version").scalar()
            == "0016_identity_sessions"
        )
        assert db.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        for name, prior in rows.items():
            assert db.exec_driver_sql(f'SELECT * FROM "{name}"').all() == prior
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
            == 1701
        )
