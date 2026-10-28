# SPDX-License-Identifier: AGPL-3.0-only
import json
import os
import platform
import sqlite3
from contextlib import closing
from pathlib import Path
from uuid import uuid4

from sqlalchemy import Engine, select
from sqlalchemy.orm import defer

from journeon.contracts import DomainError
from journeon.database import SCHEMA_REVISION, create_database, transaction
from journeon.instruction_config import InstructionConfiguration
from journeon.instructions import digest
from journeon.maintenance import RestoreWriteIdentity, acquire
from journeon.models import InstructionPublication, Job, ProtectedRequest, StoreIdentity
from journeon.operations import doctor, snapshot_database, validate_snapshot
from journeon.permissions import AuthenticatedContext, current_owner, require_grant
from journeon.restore_contracts import RestoreAuthorization, RestorePlan, RestorePreview


def locations(config: InstructionConfiguration, command: RestorePreview) -> tuple[Path, Path]:
    if config.restore is None:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Explicit restore locations are required")
    snapshot = Path(config.restore.snapshot_root) / command.snapshot
    destination = Path(config.restore.destination_root) / command.destination
    for path in (snapshot, destination):
        if (
            not path.is_absolute()
            or any(p.is_symlink() for p in (path, *path.parents))
            or ".." in path.parts
        ):
            raise DomainError(
                "PERMISSION_DENIED", "Restore paths must remain inside configured roots"
            )
    if snapshot.parent != Path(config.restore.snapshot_root) or destination.parent != Path(
        config.restore.destination_root
    ):
        raise DomainError("PERMISSION_DENIED", "Restore path selection is invalid")
    return snapshot, destination


def canonical_hash(db: sqlite3.Connection) -> str:
    excluded = {
        "browser_sessions",
        "auth_ceremonies",
        "auth_rates",
        "auth_rate_events",
        "protected_requests",
        "instruction_request_scopes",
        "restore_request_scopes",
        "sqlite_sequence",
    }
    tables = sorted(
        row[0]
        for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        if row[0] not in excluded and not row[0].startswith("sqlite_")
    )
    return digest(
        {
            name: sorted(db.execute('SELECT * FROM "' + name + '"').fetchall(), key=repr)
            for name in tables
        }
    )


def preview(
    engine: Engine,
    config: InstructionConfiguration,
    actor: AuthenticatedContext,
    command: RestorePreview,
) -> RestorePlan:
    from journeon.project_instructions import ProjectInstructionService

    service = ProjectInstructionService(engine, config)
    with transaction(engine) as db:
        current_owner(db, actor)
        require_grant(db, actor, "lifecycle.restore")
        for selected in command.selection:
            service.binding(db, actor, selected.project_id)
            require_grant(
                db,
                actor,
                "project.instruction.restore",
                resource_kind="project",
                resource_id=selected.project_id,
            )
        store = db.get(StoreIdentity, 1)
        if store is None or not store.security_reconciled:
            raise DomainError("PERMISSION_DENIED", "Current store security evidence is required")
        store_id, incarnation = store.store_id, store.incarnation
        if db.scalar(select(Job.id).where(Job.state == "RUNNING").limit(1)) or db.scalar(
            select(InstructionPublication.id)
            .where(InstructionPublication.status.not_in(("CANONICAL_COMMITTED", "ABANDONED")))
            .limit(1)
        ):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE",
                "Pending effects require owning reconciliation before restore",
            )
    snapshot, destination = locations(config, command)
    if destination.exists():
        raise DomainError("REVISION_CONFLICT", "Restore destination already exists")
    manifest = validate_snapshot(snapshot)
    if manifest["schema"] != SCHEMA_REVISION:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Restore snapshot schema is incompatible")
    dependencies = {}
    for selected in command.selection:
        current = service.read(actor, selected.project_id)
        dependencies[selected.project_id] = current.model_dump(mode="json")
    with closing(sqlite3.connect(snapshot / "database.sqlite")) as source:
        identity = source.execute("SELECT store_id FROM store_identity WHERE id=1").fetchone()
        if identity != (store_id,):
            raise DomainError("PERMISSION_DENIED", "Snapshot belongs to a different store")
        for selected in command.selection:
            service.validate_restore_history(source, selected)
    path = Path(str(engine.url.database))
    with closing(sqlite3.connect(path)) as current_db:
        versions = canonical_hash(current_db)
    return RestorePlan(
        **command.model_dump(),
        snapshot_hash=manifest["sha256"],
        store_id=store_id,
        incarnation=incarnation,
        current_versions_hash=versions,
        dependencies_hash=digest(dependencies),
        platform=platform.system() + ":" + platform.machine(),
        schema_revision=SCHEMA_REVISION,
        source_path=str(path),
        destination_path=str(destination),
    )


def authorization(row: ProtectedRequest) -> RestoreAuthorization:
    return RestoreAuthorization(
        operation_id=row.operation_id, request_id=row.id, plan_hash=row.payload_hash
    )


def restore(
    engine: Engine, config: InstructionConfiguration, request_id: str, plan: RestorePlan
) -> dict[str, str]:
    from journeon.instruction_protected import InstructionConfirmation

    service = InstructionConfirmation(engine, config)
    with transaction(engine) as db:
        row = db.get(ProtectedRequest, request_id, options=[defer(ProtectedRequest.payload)])
        if row is None:
            raise DomainError("PERMISSION_DENIED", "Restore authorization is unavailable")
        actor = AuthenticatedContext(row.principal_id, row.principal_epoch, row.session_id)
        row = service._request(db, actor, request_id)
        effect = service._bound(db, actor, row)
        if row.state != "APPROVED" or not isinstance(effect, RestorePlan) or effect != plan:
            raise DomainError(
                "PERMISSION_DENIED", "Exact current restore authorization is required"
            )
        operation = row.operation_id
    command = RestorePreview.model_validate(
        plan.model_dump(include=set(RestorePreview.model_fields))
    )
    if preview(engine, config, actor, command) != plan:
        raise DomainError("REVISION_CONFLICT", "Restore plan changed")
    with transaction(engine) as db:
        row = service._request(db, actor, request_id)
        service._bound(db, actor, row)
        if row.state != "APPROVED":
            raise DomainError("PERMISSION_DENIED", "Restore authorization was consumed")
        from journeon.protected import official_session

        current = official_session(db, actor)
        assert row.approval_deadline is not None and current.strong_authenticated_at is not None
        deadline = min(
            row.deadline,
            row.approval_deadline,
            current.absolute_deadline,
            current.last_activity + current.inactivity_seconds,
            current.strong_authenticated_at + current.strong_freshness_seconds,
        )
        row.state = "COMMITTED"
        row.nonce_hash = None
    source = Path(str(engine.url.database))
    with closing(sqlite3.connect(source)) as current_db:
        security = security_hash(current_db)
    engine.dispose()
    lock = acquire(source, exclusive=True)
    snapshot, destination = locations(config, command)
    try:
        with closing(sqlite3.connect(source)) as current_db:
            if security_hash(current_db) != security:
                raise DomainError("PERMISSION_DENIED", "Security state changed before restore")
            if canonical_hash(current_db) != plan.current_versions_hash:
                raise DomainError("REVISION_CONFLICT", "Canonical state changed before restore")
        destination.mkdir(mode=0o700)
        pre = destination / "surviving-store"
        staged = destination / "staged"
        path = staged / "database.sqlite"
        incarnation = str(uuid4())
        pending = Path(str(staged) + ".pending.json")
        staging = RestoreWriteIdentity(operation, incarnation, str(path))
        write_admission(
            pending,
            {
                "operation": operation,
                "incarnation": incarnation,
                "destination": str(path),
            },
        )
        snapshot_database(source, pre)
        snapshot_database(source, staged)
        if validate_snapshot(snapshot)["sha256"] != plan.snapshot_hash:
            raise DomainError("REVISION_CONFLICT", "Snapshot changed before restore")
        from journeon.project_instructions import ProjectInstructionService

        with (
            closing(sqlite3.connect(snapshot / "database.sqlite")) as backup,
            closing(sqlite3.connect(path)) as target,
        ):
            target.execute("PRAGMA foreign_keys=ON")
            restored_count = 0
            for selected in plan.selection:
                restored_count += ProjectInstructionService.restore_history(
                    backup, target, selected
                )
            target.execute(
                (
                    "UPDATE store_identity SET incarnation=?,restore_operation=?,desti"
                    "nation=?,security_reconciled=1 WHERE id=1"
                ),
                (incarnation, operation, str(path)),
            )
            target.execute(
                "UPDATE protected_requests SET state='INVALIDATED', nonce_hash=NUL"
                "L, nonce_deadline=NULL WHERE state IN ('PENDING','APPROVED')"
            )
            target.commit()
            if (
                target.execute("PRAGMA integrity_check").fetchall() != [("ok",)]
                or target.execute("PRAGMA foreign_key_check").fetchone()
            ):
                raise ValueError("Restored integrity validation failed")
        if doctor(path)["status"] != "INFO":
            raise ValueError("Restored store diagnostics failed")
        with path.open("rb") as stream:
            os.fsync(stream.fileno())
        from datetime import UTC, datetime

        from journeon.contracts import RestoreReceipt
        from journeon.models import OutboxEvent, Receipt
        from journeon.protected import official_session
        from journeon.sessions import utc_seconds

        staged_engine = create_database(path, restore_write=staging)
        try:
            with transaction(staged_engine) as db:
                current_owner(db, actor)
                official_session(db, actor)
                require_grant(db, actor, "lifecycle.restore")
                if utc_seconds() >= deadline:
                    raise DomainError(
                        "PERMISSION_DENIED", "Restore consent expired before admission"
                    )
            owner = ProjectInstructionService(staged_engine, config)
            dependencies = {}
            for selected in plan.selection:
                with transaction(staged_engine) as db:
                    require_grant(
                        db,
                        actor,
                        "project.instruction.restore",
                        resource_kind="project",
                        resource_id=selected.project_id,
                    )
                dependencies[selected.project_id] = owner.read(
                    actor, selected.project_id
                ).model_dump(mode="json")
            if digest(dependencies) != plan.dependencies_hash:
                raise DomainError("REVISION_CONFLICT", "External restore dependencies changed")
            with transaction(staged_engine) as db:
                official_session(db, actor)
                if utc_seconds() >= deadline:
                    raise DomainError(
                        "PERMISSION_DENIED", "Restore consent expired before admission"
                    )
                from journeon.jobs import attention, record

                for job in db.scalars(
                    select(Job).where(Job.state.in_(("QUEUED", "RUNNING", "RETRY_WAIT")))
                ):
                    job.state = "FAILED"
                    job.reason = "RESTORE_REAUTHORIZATION_REQUIRED"
                    job.fence += 1
                    job.revision += 1
                    attention(db, job, job.reason)
                    record(db, job)
                result = RestoreReceipt(
                    operation_id=operation,
                    target_id=plan.store_id,
                    incarnation=incarnation,
                    plan_hash=digest(plan.model_dump(mode="json")),
                    restored_history_count=restored_count,
                    committed_at=datetime.now(UTC).isoformat(),
                )
                db.add(
                    Receipt(
                        id=operation,
                        principal_id=actor.principal_id,
                        command=result.command,
                        idempotency_key=operation,
                        payload_hash=result.plan_hash,
                        project_id=None,
                        owner="lifecycle",
                        target_kind="store",
                        target_id=plan.store_id,
                        authentication_ref=actor.authentication_ref,
                        result=result.model_dump(mode="json"),
                    )
                )
                db.flush()
                db.add(
                    OutboxEvent(
                        event_id=str(uuid4()),
                        operation_id=operation,
                        event_type="lifecycle.history.restored",
                        schema_version=1,
                        principal_id=actor.principal_id,
                        project_id=None,
                        owner="lifecycle",
                        target_kind="store",
                        target_id=plan.store_id,
                        target_revision=1,
                        committed_at=result.committed_at,
                        payload=result.model_dump(mode="json"),
                    )
                )
        finally:
            staged_engine.dispose()
        with closing(sqlite3.connect(path)) as completed:
            completed.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            completed.execute("PRAGMA journal_mode=DELETE")
        with path.open("rb") as stream:
            os.fsync(stream.fileno())
        if doctor(path)["status"] != "INFO":
            raise ValueError("Restored final diagnostics failed")
        admission = {
            "operation": operation,
            "source": str(source),
            "source_incarnation": plan.incarnation,
            "store_id": plan.store_id,
            "incarnation": incarnation,
            "destination": str(path),
            "security_reconciled": True,
            "status": "COMPLETE",
            "plan_hash": digest(plan.model_dump(mode="json")),
        }
        write_admission(Path(str(source) + ".successor.json"), admission)
        write_admission(Path(str(path) + ".admission.json"), admission)
        pending.unlink()
        descriptor = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return {"status": "RESTORED_INACTIVE", "database": str(path), "incarnation": incarnation}
    finally:
        os.close(lock)


def write_admission(path: Path, data: dict[str, object]) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(data, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def startup_admission(
    path: Path, db: sqlite3.Connection, *, staging: RestoreWriteIdentity | None = None
) -> None:
    if Path(str(path) + ".successor.json").exists():
        raise ValueError("Store has a restored successor awaiting explicit activation")
    row = db.execute(
        "SELECT store_id,incarnation,restore_operation,destination,securit"
        "y_reconciled FROM store_identity WHERE id=1"
    ).fetchone()
    if row is None or row[4] != 1 or row[3] != str(path):
        raise ValueError("Store admission or destination binding is unavailable")
    pending = Path(str(path.parent) + ".pending.json")
    if staging is not None:
        expected = {
            "operation": staging.operation,
            "incarnation": staging.incarnation,
            "destination": staging.destination,
        }
        if (row[2], row[1], str(path)) != (
            staging.operation,
            staging.incarnation,
            staging.destination,
        ) or json.loads(pending.read_bytes()) != expected:
            raise ValueError("Staged writer identity does not match")
        return
    if pending.exists():
        raise ValueError("Restored staging is incomplete")
    admission = Path(str(path) + ".admission.json")
    if row[2] is not None or admission.exists():
        data = json.loads(admission.read_bytes())
        if not isinstance(data, dict) or set(data) != {
            "operation",
            "source",
            "source_incarnation",
            "store_id",
            "incarnation",
            "destination",
            "security_reconciled",
            "status",
            "plan_hash",
        }:
            raise ValueError("Restored admission metadata is incomplete")
        source = Path(data["source"])
        if (
            not source.is_absolute()
            or source == path
            or any(item.is_symlink() for item in (source, *source.parents))
        ):
            raise ValueError("Restored source identity is unavailable")
        if json.loads(Path(str(source) + ".successor.json").read_bytes()) != data:
            raise ValueError("Restored source completion fence does not match")
        with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as original:
            previous = original.execute(
                "SELECT store_id,incarnation FROM store_identity WHERE id=1"
            ).fetchone()
            if previous != (data["store_id"], data["source_incarnation"]):
                raise ValueError("Restored source incarnation changed")
        if (
            data.get("store_id"),
            data.get("incarnation"),
            data.get("operation"),
            data.get("destination"),
            data.get("security_reconciled"),
            data.get("status"),
        ) != (row[0], row[1], row[2], str(path), True, "COMPLETE") or row[3] != str(path):
            raise ValueError("Restored store admission does not match")


def security_hash(db: sqlite3.Connection) -> str:
    tables = (
        "principals",
        "access_grants",
        "browser_sessions",
        "passkeys",
        "identity_state",
        "protected_requests",
    )
    return digest(
        {
            name: sorted(db.execute('SELECT * FROM "' + name + '"').fetchall(), key=repr)
            for name in tables
        }
    )
