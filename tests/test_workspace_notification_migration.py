# SPDX-License-Identifier: AGPL-3.0-only
import json
import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, inspect, text
from test_execution_migration import populated_0009 as populated_0009
from test_identity_migration import populated_0006 as populated_0006
from test_operation_migration import legacy_store as legacy_store
from test_production_instructions import official_effect
from test_work_migration import populated_0005 as populated_0005
from test_workspace_discovery_pages import grant
from test_workspace_discovery_work import dispatch
from test_workspace_identity_migration import upgrade_to
from test_workspace_search_attention import attention_page, dismiss, search
from test_workspace_search_attention import failed_work as failed_work
from workspace_durable_helpers import enrolled_owner as enrolled_owner
from workspace_durable_helpers import genuine_durable_work as genuine_durable_work
from workspace_durable_helpers import genuine_instruction_scope as genuine_instruction_scope
from workspace_durable_helpers import genuine_project_task as genuine_project_task

from journeon.api import create_app
from journeon.database import create_database, transaction
from journeon.instructions import digest
from journeon.models import Attention
from journeon.operations import snapshot_database
from journeon.restore_contracts import RestoreConfiguration


@pytest.mark.parametrize("interrupt", [False, True])
def test_presentation_upgrade_preserves_every_prior_row_and_legacy_disposition(
    populated_0009, interrupt
):
    engine = populated_0009[0]
    upgrade_to(engine, "0016_identity_sessions")
    with engine.begin() as db:
        db.exec_driver_sql(
            "INSERT INTO instruction_candidates VALUES "
            "('candidate','old-project','owner','candidate-key','hash','{}')"
        )
        db.exec_driver_sql(
            "INSERT INTO jobs VALUES "
            "('job','INSTRUCTION_NAVIGATION','old-project','candidate','hash',1,1,'owner',7,"
            "'old-session',1,'FAILED',0,NULL,'incarnation',NULL,0,0,0,NULL,'NONE',NULL,"
            "'admission',NULL,1,NULL)"
        )
        for index, disposition in enumerate(("OPEN", "DISMISSED", "RESOLVED")):
            db.exec_driver_sql(
                "INSERT INTO attention VALUES (?,?,?, ?,1,?,?)",
                (
                    f"attention-{index}",
                    "job",
                    "old-project",
                    f"RETAINED-{index}",
                    disposition,
                    '[{"retained":"unchanged"}]',
                ),
            )
        db.exec_driver_sql("UPDATE sqlite_sequence SET seq=1901 WHERE name='outbox_events'")
        retained = {
            name: db.exec_driver_sql(f'SELECT * FROM "{name}"').all()
            for name in inspect(db).get_table_names()
            if name != "alembic_version"
        }
        triggers = db.exec_driver_sql(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' ORDER BY name"
        ).all()
    if interrupt:

        def interrupted(connection, cursor, statement, parameters, context, many):
            if "CREATE TABLE notification_presentations" in statement:
                raise RuntimeError("Interrupted presentation migration")

        event.listen(engine, "after_cursor_execute", interrupted)
        try:
            with pytest.raises(RuntimeError, match="Interrupted presentation migration"):
                upgrade_to(engine, "0017_notification_presentation")
        finally:
            event.remove(engine, "after_cursor_execute", interrupted)
        with engine.begin() as db:
            assert (
                db.exec_driver_sql("SELECT version_num FROM alembic_version").scalar()
                == "0016_identity_sessions"
            )
    upgrade_to(engine, "0017_notification_presentation")
    with engine.begin() as db:
        for name, rows in retained.items():
            assert db.exec_driver_sql(f'SELECT * FROM "{name}"').all() == rows
        current_triggers = db.exec_driver_sql(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' ORDER BY name"
        ).all()
        assert all(row in current_triggers for row in triggers)
        assert len(current_triggers) == len(triggers) + 2
        assert db.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert (
            db.exec_driver_sql(
                "SELECT seq FROM sqlite_sequence WHERE name='outbox_events'"
            ).scalar()
            == 1901
        )
        assert db.exec_driver_sql("SELECT count(*) FROM notification_presentations").scalar() == 0


def test_real_backup_restore_retains_presentations_receipts_and_invalidates_old_cursor(
    failed_work, tmp_path
):
    fixture, _ = failed_work
    owner, config, prepare, _, _ = fixture
    project = prepare["project_id"]
    for capability, scope in (
        ("lifecycle.restore", None),
        ("project.instruction.restore", project),
    ):
        grant(owner, capability, scope, "restore-" + capability)
    first = attention_page(owner)["items"][0]
    command, accepted = dismiss(owner, first)
    assert accepted.status_code == 200
    second_command, second = dismiss(
        owner, attention_page(owner)["items"][0], key="restore-second-presentation"
    )
    assert second.status_code == 200
    another = owner.client.post(
        "/api/v1/projects",
        headers=owner.headers,
        json={
            "schema_version": 1,
            "idempotency_key": "restore-paging-project",
            "name": "Restore project",
            "expected_policy_revision": 1,
            "provider_mode": "LOCAL_ONLY",
        },
    )
    assert another.status_code == 200
    grant(owner, "project.read", another.json()["project"]["project_id"], "restore-other-read")
    cursor_page = search(owner, "project", ("PROJECT",), limit=1).json()
    assert cursor_page["has_more"]
    pending = dispatch(fixture, "restore-pending-source")
    assert pending["state"] == "QUEUED"
    snapshots, destinations = tmp_path / "snapshots", tmp_path / "destinations"
    snapshots.mkdir()
    destinations.mkdir()
    config = config.model_copy(
        update={
            "restore": RestoreConfiguration(
                snapshot_root=str(snapshots), destination_root=str(destinations)
            )
        }
    )
    with TestClient(
        create_app(
            owner.engine, browser_auth=owner.client.app.state.browser_auth, instructions=config
        ),
        base_url="https://example.test",
        cookies=owner.client.cookies,
    ) as client:
        current_owner = replace(owner, client=client)
        snapshot_database(Path(str(owner.engine.url.database)), snapshots / "before")
        planned = client.post(
            "/api/v1/lifecycle/restore-preview",
            headers=owner.headers,
            json={
                "idempotency_key": "restore-presentation-history",
                "snapshot": "before",
                "destination": "restored",
                "data_class": "PROJECT_INSTRUCTION_HISTORY",
                "selection": [{"project_id": project, "revisions": [1]}],
            },
        )
        assert planned.status_code == 200, planned.text
        plan = planned.json()
        authorized = official_effect(client, owner.headers, plan)
        before = attention_page(current_owner)["items"][0]
        with transaction(owner.engine) as db:
            rows = db.execute(
                text("SELECT * FROM notification_presentations ORDER BY revision")
            ).all()
        plan_file, config_file = tmp_path / "restore-plan.json", tmp_path / "restore-config.json"
        plan_file.write_text(json.dumps(plan))
        config_file.write_text(config.model_dump_json())
        owner.engine.dispose()
        executed = subprocess.run(
            [
                sys.executable,
                "-m",
                "journeon.operations",
                "restore",
                str(owner.engine.url.database),
                plan["destination_path"],
                "--authorization",
                authorized["request_id"],
                "--plan",
                str(plan_file),
                "--instruction-config",
                str(config_file),
                "--json",
            ],
            env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert executed.returncode == 0, executed.stdout + executed.stderr
        result = json.loads(executed.stdout)
        assert result["status"] == "RESTORED_INACTIVE"
    with closing(sqlite3.connect(result["database"])) as db:
        assert db.execute(
            "SELECT * FROM notification_presentations ORDER BY revision"
        ).fetchall() == [tuple(row) for row in rows]
    engine = create_database(Path(result["database"]))
    try:
        with TestClient(
            create_app(
                engine, browser_auth=owner.client.app.state.browser_auth, instructions=config
            ),
            base_url="https://example.test",
            cookies=owner.client.cookies,
        ) as client:
            restored = replace(owner, engine=engine, client=client)
            items = attention_page(restored)["items"]
            assert (
                next(item for item in items if item["attention_id"] == before["attention_id"])
                == before
            )
            invalidated = next(
                item for item in items if item["source"]["job_id"] == pending["job_id"]
            )
            assert invalidated["reason"] == "RESTORE_REAUTHORIZATION_REQUIRED"
            assert invalidated["source_revision"] > pending["revision"]
            assert invalidated["canonical_disposition"] == "OPEN"
            with transaction(engine) as db:
                assert (
                    db.get(Attention, invalidated["attention_id"]).history[-1]["revision"]
                    == invalidated["source_revision"]
                )
            assert (
                search(
                    restored, "project", ("PROJECT",), limit=1, cursor=cursor_page["next_cursor"]
                ).status_code
                == 409
            )
            for original, receipt in ((command, accepted.json()), (second_command, second.json())):
                assert client.get(f"/api/v1/operations/{receipt['operation_id']}").json() == receipt
                query = {
                    "schema_version": 1,
                    "command": "notification.dismiss.v1",
                    "idempotency_key": original["idempotency_key"],
                    "payload_digest": digest(
                        {key: value for key, value in original.items() if key != "idempotency_key"}
                    ),
                    "scope": {"attention_id": receipt["attention_id"]},
                    "store_incarnation": cursor_page["store_incarnation"],
                }
                assert (
                    client.post(
                        "/api/v1/operations/resolve", headers=owner.headers, json=query
                    ).json()["status"]
                    == "RECONCILIATION_REQUIRED"
                )
                query["store_incarnation"] = attention_page(restored)["store_incarnation"]
                resolved = client.post(
                    "/api/v1/operations/resolve", headers=owner.headers, json=query
                )
                assert resolved.status_code == 200, resolved.text
                assert resolved.json()["receipt"] == receipt
    finally:
        engine.dispose()
