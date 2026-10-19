# SPDX-License-Identifier: AGPL-3.0-only
import subprocess
import sys
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import func, inspect, select
from sqlalchemy.exc import IntegrityError

from journeon.api import create_app
from journeon.database import create_database, transaction
from journeon.health import schema_and_database
from journeon.migrate import upgrade
from journeon.models import Base, Principal
from journeon.registry import COMMANDS, MODULES

ROOT = Path(__file__).resolve().parents[1]


def test_migration_matches_models_and_is_repeatable(database):
    engine, _ = database
    upgrade(engine)
    with engine.connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []
        assert connection.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
        assert connection.exec_driver_sql("PRAGMA synchronous").scalar() == 2
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
    assert schema_and_database(engine).schema_state == "CURRENT"
    assert schema_and_database(engine).operational_authentication == "NOT_ASSESSED"


def test_migration_never_bootstraps_principals_or_policy(tmp_path):
    engine = create_database(tmp_path / "empty.db")
    try:
        assert schema_and_database(engine).schema_state == "MISSING_OR_INCOMPATIBLE"
        upgrade(engine)
        with transaction(engine) as session:
            for table in Base.metadata.tables.values():
                expected = 1 if table.name == "store_identity" else 0
                assert session.scalar(select(func.count()).select_from(table)) == expected
            from uuid import UUID

            from journeon.models import StoreIdentity

            identity = session.get(StoreIdentity, 1)
            assert str(UUID(identity.store_id)) == identity.store_id
            assert str(UUID(identity.incarnation)) == identity.incarnation
            assert identity.restore_operation is None
            assert identity.destination == str(engine.url.database)
            assert identity.security_reconciled is True
    finally:
        engine.dispose()


def test_database_constraint_disallows_second_enabled_owner(database):
    with pytest.raises(IntegrityError), transaction(database[0]) as session:
        session.add(
            Principal(id="another-owner", role="OWNER", enabled=True, authorization_epoch=1)
        )


def test_database_rejects_memory_or_relative_location():
    for path in (Path(":memory:"), Path("relative.db")):
        with pytest.raises(ValueError):
            create_database(path)


def test_registry_owns_every_canonical_table_and_api(database):
    owners = [name for module in MODULES.values() for name in module["tables"]]
    assert len(owners) == len(set(owners))
    assert set(owners) == set(Base.metadata.tables)
    assert set(inspect(database[0]).get_table_names()) == set(owners) | {"alembic_version"}
    for module in MODULES.values():
        assert module["backup_class"] in {"R0", "R1", "R2", "R3"}
        assert module["health"] == schema_and_database.__name__
        assert module["migration"] == (
            "0012_attempt_execution"
            if set(module["tables"]) & {"attempts", "executions"}
            else "0011_task_admission"
            if set(module["tables"]) & {"tasks", "verification_policy_revisions"}
            else "0010_work_execution"
            if set(module["tables"])
            & {
                "jobs",
                "attention",
                "store_identity",
                "restore_request_scopes",
                "operation_receipts",
                "outbox_events",
                "protected_requests",
            }
            else "0009_instruction_scope"
            if set(module["tables"])
            & {
                "projects",
                "browser_sessions",
                "operation_receipts",
                "instruction_assets",
                "instruction_roots",
            }
            else "0007_identity_instructions"
            if set(module["tables"])
            & {"agent_profiles", "instruction_assets", "access_grants", "operation_receipts"}
            else "0006_work"
            if "tasks" in module["tables"]
            else "0005_protected_operations"
            if set(module["tables"]) & {"browser_sessions", "operation_receipts"}
            else "0001_foundation"
        )
        assert module["settings"] == ()  # No module-level mutable settings implemented.
    for methods in create_app(database[0]).openapi()["paths"].values():
        for operation in methods.values():
            assert operation["x-journeon-owner"] in MODULES
            if command_name := operation.get("x-journeon-command"):
                command = COMMANDS[command_name]
                assert command.owner == operation["x-journeon-owner"]
                assert command.external_effects == (
                    ("Attempt workspace and snapshot storage",)
                    if operation["operationId"] == "prepareAttempt"
                    else ("CONFIGURED_RELEASE_BACKUP",)
                    if operation["operationId"] == "verifyInstalledRelease"
                    else ("ADMITTED_LOCAL_FILESYSTEM",)
                    if operation["operationId"]
                    in {
                        "bindProjectInstructions",
                        "proposeProjectInstructions",
                        "acceptProjectInstructions",
                        "projectInstructionProjection",
                        "confirmInstructionEffect",
                    }
                    else ()
                )
                assert command.stability == "INTERNAL"


def test_generated_contracts_are_current():
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools/generate_contracts.py"), "--check"],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
