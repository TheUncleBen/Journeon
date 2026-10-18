# SPDX-License-Identifier: AGPL-3.0-only
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import event, text

from journeon.contracts import OperationReceipt, ProjectCreated, ProviderSnapshot
from journeon.database import create_database, transaction
from journeon.migrate import configuration, upgrade
from journeon.models import BrowserSession, Passkey, Principal
from journeon.permissions import AuthenticatedContext
from journeon.receipts import OperationService
from journeon.sessions import current_session, utc_seconds


@pytest.fixture
def legacy_store(tmp_path):
    path = tmp_path / "legacy.db"
    engine = create_database(path)
    now = utc_seconds()
    receipt = OperationReceipt(
        operation_id="old-operation",
        committed_at="2026-01-01T00:00:00+00:00",
        project=ProjectCreated(
            project_id="old-project",
            revision=1,
            name="Retained",
            description="",
            instruction_authority_ref="environment:project:old-project",
            provider_allowance_at_creation=ProviderSnapshot(
                mode="LOCAL_ONLY", policy_revision=1, approval_id=None, providers=[]
            ),
            verification_policy_ref=None,
            resource_refs=[],
        ),
    )
    with engine.begin() as db:
        config = configuration()
        config.attributes["connection"] = db
        command.upgrade(config, "0003_passkeys")
        db.execute(text("INSERT INTO principals VALUES ('owner','OWNER',1,7)"))
        db.execute(
            text(
                "INSERT INTO access_grants VALUES ('read','owner','project.receipt.read',"
                "'deployment','deployment',1,1,NULL,'fixture')"
            )
        )
        db.execute(
            text(
                "INSERT INTO projects VALUES ('old-project',1,'Retained','','owner',"
                "'ENVIRONMENT','environment:project:old-project',:snapshot,NULL,'[]',:time)"
            ),
            {
                "snapshot": json.dumps(receipt.project.provider_allowance_at_creation.model_dump()),
                "time": receipt.committed_at,
            },
        )
        db.execute(
            text(
                "INSERT INTO operation_receipts VALUES ('old-operation','owner',"
                "'project.create.v1','old-key',:hash,'old-project','old-session',:result)"
            ),
            {"hash": "a" * 64, "result": receipt.model_dump_json()},
        )
        db.execute(
            text(
                "INSERT INTO outbox_events VALUES (42,'old-event','old-operation',"
                "'project.created',1,'owner','old-project',:time)"
            ),
            {"time": receipt.committed_at},
        )
        for name, revoked in (("old-session", 0), ("revoked-session", 1)):
            db.execute(
                text(
                    "INSERT INTO browser_sessions VALUES (:id,:token,:csrf,'owner',7,"
                    "'fixture','Official browser',:now,:now,:now,:end,43200,:now,300,:revoked)"
                ),
                {
                    "id": name,
                    "token": name * 3,
                    "csrf": "b" * 64,
                    "now": now,
                    "end": now + 604800,
                    "revoked": revoked,
                },
            )
        db.execute(
            text(
                "INSERT INTO passkeys VALUES ('old-key','credential','data','owner',"
                "'Existing',9,0,0,0)"
            )
        )
        db.execute(
            text("UPDATE identity_state SET owner_id='owner',last_observed=:now"), {"now": now}
        )
    yield engine, path, receipt, now
    engine.dispose()


def verify_preserved(engine, receipt, now):
    actor = AuthenticatedContext("owner", 7, "old-session")
    assert OperationService(engine).receipt(actor, receipt.operation_id) == receipt
    with transaction(engine) as db:
        assert current_session(db, "old-session").audience == "unknown"
        assert db.get(BrowserSession, "revoked-session").revoked
        assert db.get(BrowserSession, "old-session").last_observed >= now
        assert db.get(Principal, "owner").authorization_epoch == 7
        assert db.get(Principal, "owner").credential_revision == 1
        assert db.get(Passkey, "old-key").revision == 1
        assert db.get(Passkey, "old-key").sign_count == 9
        row = db.execute(text("SELECT sequence,event_id,target_id FROM outbox_events")).one()
        assert tuple(row) == (42, "old-event", "old-project")
        assert db.execute(text("PRAGMA foreign_key_check")).all() == []


def test_populated_0003_0004_0005_and_repeat_startup(legacy_store):
    engine, _, receipt, now = legacy_store
    with engine.begin() as db:
        config = configuration()
        config.attributes["connection"] = db
        command.upgrade(config, "0004_auth_rate_events")
    upgrade(engine)
    upgrade(engine)
    verify_preserved(engine, receipt, now)


def test_interrupted_upgrade_rolls_back_and_restarts(legacy_store):
    engine, _, receipt, now = legacy_store

    def interrupt(_conn, _cursor, statement, _parameters, _context, _many):
        if "DROP TABLE operation_receipts" in statement:
            raise RuntimeError("synthetic migration interruption")

    event.listen(engine, "before_cursor_execute", interrupt)
    with pytest.raises(RuntimeError, match="synthetic migration interruption"):
        upgrade(engine)
    event.remove(engine, "before_cursor_execute", interrupt)
    with engine.connect() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "0003_passkeys"
        assert db.scalar(text("SELECT event_id FROM outbox_events")) == "old-event"
    upgrade(engine)
    verify_preserved(engine, receipt, now)


def test_process_crash_mid_upgrade_preserves_old_records(legacy_store):
    engine, path, receipt, now = legacy_store
    script = """
import os, sys
from pathlib import Path
from sqlalchemy import event
from journeon.database import create_database
from journeon.migrate import upgrade
engine = create_database(Path(sys.argv[1]))
def crash(conn, cursor, statement, parameters, context, many):
    if "DROP TABLE operation_receipts" in statement:
        os._exit(79)
event.listen(engine, "before_cursor_execute", crash)
upgrade(engine)
"""
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-c", script, str(path)],
        cwd=root,
        env={**os.environ, "PYTHONPATH": str(root / "src")},
        timeout=30,
    )
    assert result.returncode == 79
    with engine.connect() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "0003_passkeys"
        assert db.scalar(text("SELECT event_id FROM outbox_events")) == "old-event"
    upgrade(engine)
    verify_preserved(engine, receipt, now)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE principals SET credential_revision=0",
        "UPDATE passkeys SET revision=0",
        "UPDATE browser_sessions SET audience='caller-asserted'",
    ],
)
def test_new_identity_domains_are_database_constrained(legacy_store, statement):
    from sqlalchemy.exc import IntegrityError

    engine = legacy_store[0]
    upgrade(engine)
    with pytest.raises(IntegrityError), engine.begin() as db:
        db.execute(text(statement))


def test_explicit_snapshot_migration_preserves_populated_identity_and_receipts(
    legacy_store, tmp_path
):
    from journeon.operations import migrate_database, validate_snapshot

    engine, path, receipt, now = legacy_store
    snapshot = tmp_path / "before-upgrade"
    result = migrate_database(path, snapshot)
    assert result == {"status": "PASS", "schema": "0007_identity_instructions"}
    assert validate_snapshot(snapshot)["schema"] == "0003_passkeys"
    verify_preserved(engine, receipt, now)
