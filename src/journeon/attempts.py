# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical preparation of deterministic Task Attempts and retained workspace evidence."""

import fcntl
import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

if TYPE_CHECKING:
    from journeon.job_contracts import TaskDispatch

from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session, defer

from journeon.attempt_contracts import (
    AttemptPrepare,
    AttemptReceipt,
    AttemptView,
    DeterministicInstructionBundle,
    RunManifest,
)
from journeon.attempt_snapshots import (
    CapturedSnapshot,
    capture_snapshot,
    materialize_directory,
    materialize_worktree,
    snapshot_digest,
)
from journeon.contracts import (
    DomainError,
    RuntimeConfigurationUnavailable,
    TaskView,
    VerificationPolicy,
)
from journeon.database import transaction
from journeon.instruction_config import InstructionConfiguration, git_identity, open_directory
from journeon.instructions import InstructionService, digest
from journeon.models import (
    Attempt,
    AttemptEffect,
    AttemptManifest,
    InstructionRoot,
    OutboxEvent,
    Receipt,
    WorkspaceLease,
)
from journeon.permissions import AuthenticatedContext, require_grant
from journeon.project_instructions import ProjectInstructionService
from journeon.verification import current_policy
from journeon.work import WorkService, require_settled_task, task_row, task_view, work_transaction


def workspace_root(db: Session, project_id: str, root_id: str, revision: int) -> InstructionRoot:
    root = db.get(InstructionRoot, root_id, populate_existing=True)
    if (
        root is None
        or not root.enabled
        or root.role != "PROJECT"
        or root.project_id != project_id
        or root.revision != revision
    ):
        raise DomainError(
            "PERMISSION_DENIED", "Workspace requires a current admitted root for this exact Project"
        )
    return root


def authorized_attempt(
    db: Session, actor: AuthenticatedContext, identity: str, action: str = "read"
) -> Attempt:
    row = db.get(Attempt, identity, options=[defer(Attempt.snapshot), defer(Attempt.inputs)])
    if row is None:
        raise DomainError("NOT_FOUND", "Attempt is unavailable")
    require_grant(db, actor, "attempt." + action, project_id=row.project_id)
    require_grant(db, actor, "task.read", project_id=row.project_id)
    require_grant(
        db, actor, "project.instruction.read", resource_kind="project", resource_id=row.project_id
    )
    workspace_root(db, row.project_id, row.root_id, row.root_revision)
    if row.principal_id != actor.principal_id:
        raise DomainError("NOT_FOUND", "Attempt is unavailable")
    return row


def validate_attempt_view(db: Session, row: Attempt, view: AttemptView) -> None:
    if (
        view.attempt_id != row.id
        or view.project_id != row.project_id
        or view.origin.kind != "TASK"
        or view.origin.task_id != row.task_id
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored Attempt scope requires repair")
    manifest = view.manifest
    if (view.state == "PREPARED") != (manifest is not None):
        raise DomainError(
            "DEPENDENCY_UNAVAILABLE", "Stored Attempt manifest binding requires repair"
        )
    if manifest is None:
        return
    accepted = db.get(AttemptManifest, manifest.manifest_id)
    bundle = manifest.instruction_bundle
    if (
        accepted is None
        or accepted.attempt_id != row.id
        or accepted.snapshot != manifest.model_dump(mode="json")
        or accepted.content_hash != manifest.content_digest
        or digest(manifest.model_dump(mode="json", exclude={"content_digest"}))
        != manifest.content_digest
        or (manifest.attempt_id, manifest.project_id, manifest.root_id, manifest.root_revision)
        != (row.id, row.project_id, row.root_id, row.root_revision)
        or manifest.task.task_id != row.task_id
        or manifest.origin != view.origin
        or (bundle.project_id, bundle.task_id, bundle.task_revision)
        != (row.project_id, row.task_id, manifest.task.revision)
        or hashlib.sha256(bundle.rendering.encode()).hexdigest() != bundle.content_digest
        or len(bundle.rendering.encode()) != bundle.byte_count
        or snapshot_digest(manifest.snapshot.model_dump(mode="json", exclude={"snapshot_hash"}))
        != manifest.snapshot.snapshot_hash
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored Attempt evidence requires repair")


def authorized_attempt_receipt(
    db: Session, actor: AuthenticatedContext, receipt: Receipt
) -> AttemptReceipt:
    row = authorized_attempt(db, actor, receipt.target_id)
    require_grant(db, actor, "attempt.receipt.read", project_id=row.project_id)
    if (
        receipt.principal_id != actor.principal_id
        or receipt.project_id != row.project_id
        or receipt.target_kind != "attempt"
    ):
        raise DomainError("PERMISSION_DENIED", "Attempt receipt scope is unavailable")
    result = AttemptReceipt.model_validate(receipt.result)
    if result.operation_id != receipt.id or result.attempt.attempt_id != row.id:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Attempt receipt requires repair")
    validate_attempt_view(db, row, result.attempt)
    return result


def snapshot_storage_bytes(captured: CapturedSnapshot, *, metadata_only: bool = False) -> int:
    payload_bytes = (
        0
        if metadata_only
        else (
            sum(len(blob) for blob in captured.blobs.values())
            + sum(entry.byte_count for entry in captured.snapshot.working)
        )
    )
    return (
        len(captured.snapshot.model_dump_json().encode())
        + payload_bytes
        + sum(
            snapshot_storage_bytes(child, metadata_only=metadata_only)
            for child in captured.submodules.values()
        )
    )


def write_snapshot(directory: Path, captured: CapturedSnapshot) -> None:
    directory.mkdir(mode=0o700)
    blobs = directory / "blobs"
    blobs.mkdir(mode=0o700)
    for identity, content in captured.blobs.items():
        with (blobs / identity).open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    for index, (_, module) in enumerate(sorted(captured.submodules.items())):
        write_snapshot(directory / f"module-{index}", module)
    with (directory / "snapshot.json").open("xb") as stream:
        stream.write(captured.snapshot.model_dump_json().encode())
        stream.flush()
        os.fsync(stream.fileno())
    for path in (blobs, directory):
        descriptor = open_directory(path)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def verify_snapshot_evidence(directory: Path, captured: CapturedSnapshot) -> None:
    descriptor = open_directory(directory)
    try:
        metadata = os.open("snapshot.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        with os.fdopen(metadata, "rb") as stream:
            expected = captured.snapshot.model_dump_json().encode()
            if stream.read(len(expected) + 1) != expected:
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE", "Interrupted snapshot metadata requires repair"
                )
    finally:
        os.close(descriptor)
    blob_directory = open_directory(directory / "blobs")
    try:
        for identity, content in captured.blobs.items():
            descriptor = os.open(identity, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=blob_directory)
            with os.fdopen(descriptor, "rb") as stream:
                if stream.read(len(content) + 1) != content:
                    raise DomainError(
                        "DEPENDENCY_UNAVAILABLE", "Interrupted snapshot bytes require repair"
                    )
    finally:
        os.close(blob_directory)
    for index, (_, module) in enumerate(sorted(captured.submodules.items())):
        verify_snapshot_evidence(directory / f"module-{index}", module)


class AttemptService:
    def __init__(self, engine: Engine, configuration: InstructionConfiguration | None) -> None:
        self.engine = engine
        self.configuration = configuration

    def read(self, actor: AuthenticatedContext, identity: str) -> AttemptView:
        with work_transaction(self.engine, actor) as db:
            row = authorized_attempt(db, actor, identity)
            self.check_configuration(db, row)
            result = AttemptView.model_validate(row.snapshot)
            if (
                result.attempt_id != row.id
                or result.project_id != row.project_id
                or result.revision != row.revision
            ):
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored Attempt requires repair")
            validate_attempt_view(db, row, result)
            return result

    def check_configuration(self, db: Session, row: Attempt) -> None:
        if self.configuration is None or self.configuration.attempts is None:
            raise RuntimeConfigurationUnavailable("Attempt preparation is not configured")
        config = self.configuration.attempts
        root = workspace_root(db, row.project_id, row.root_id, row.root_revision)
        root_config = next(
            (item for item in self.configuration.roots if item.key == root.root_key), None
        )
        if root_config is None or (
            root_config.role,
            root_config.project_id,
            root_config.revision,
        ) != (root.role, root.project_id, root.config_revision):
            raise DomainError(
                "PERMISSION_DENIED", "Current workspace root configuration is unavailable"
            )
        workspace = next(
            (item for item in config.workspaces if item.key == row.workspace_key), None
        )
        if (
            config.revision != row.configuration_revision
            or workspace is None
            or (
                workspace.revision,
                workspace.project_id,
                workspace.root_key,
                workspace.root_revision,
            )
            != (row.workspace_revision, row.project_id, row.root_id, row.root_revision)
        ):
            raise DomainError(
                "PERMISSION_DENIED", "Current Attempt workspace configuration is unavailable"
            )

    def inputs(
        self, db: Session, actor: AuthenticatedContext, command: AttemptPrepare
    ) -> tuple[TaskView, VerificationPolicy]:
        for action in ("attempt.prepare", "attempt.read", "attempt.receipt.read"):
            require_grant(db, actor, action, project_id=command.project_id)
        if command.origin.kind != "TASK":
            require_grant(db, actor, "job.read", project_id=command.project_id)
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "This Job owner has no Attempt preparation producer"
            )
        task = task_view(task_row(db, actor, command.origin.task_id, "task.read"))
        if task.project_id != command.project_id:
            raise DomainError("PERMISSION_DENIED", "Task origin is outside this Project")
        require_settled_task(task)
        policy = current_policy(db, actor, task.project_id)
        if (
            task.revision != command.origin.task_revision
            or policy is None
            or policy.revision != command.expected_policy_revision
        ):
            raise DomainError("REVISION_CONFLICT", "Attempt input revisions changed")
        admission = WorkService(self.engine)._admission(
            db, actor, task, policy, datetime.now(UTC).isoformat()
        )
        if admission.decision != "ADMIT":
            raise DomainError(
                "PERMISSION_DENIED", "Current Task admission does not permit preparation"
            )
        if command.previous_attempt_id:
            previous = authorized_attempt(db, actor, command.previous_attempt_id)
            if previous.task_id != task.task_id:
                raise DomainError("PERMISSION_DENIED", "Previous Attempt belongs to another Task")
        return task, policy

    def prepare(
        self,
        actor: AuthenticatedContext,
        command: AttemptPrepare,
        *,
        dispatch: "TaskDispatch | None" = None,
    ) -> AttemptReceipt:
        try:
            return self._prepare(actor, command, dispatch=dispatch)
        except (OSError, ValueError, KeyError):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Attempt preparation dependencies require repair"
            ) from None

    def _prepare(
        self,
        actor: AuthenticatedContext,
        command: AttemptPrepare,
        *,
        dispatch: "TaskDispatch | None" = None,
    ) -> AttemptReceipt:
        command_payload = command.model_dump(mode="json", exclude={"idempotency_key"})
        if dispatch is not None:
            command_payload["dispatch"] = dispatch.model_dump(
                mode="json", exclude={"idempotency_key"}
            )
        command_hash = digest(command_payload)
        with work_transaction(self.engine, actor) as db:
            # Current grants precede replay decoding and configuration disclosure.
            for action in ("attempt.prepare", "attempt.read", "attempt.receipt.read"):
                require_grant(db, actor, action, project_id=command.project_id)
            prior = db.scalar(
                select(Attempt)
                .options(defer(Attempt.snapshot), defer(Attempt.inputs))
                .where(
                    Attempt.principal_id == actor.principal_id,
                    Attempt.idempotency_key == command.idempotency_key,
                )
            )
            if prior is not None:
                authorized_attempt(db, actor, prior.id, "prepare")
                self.check_configuration(db, prior)
                if prior.payload_hash != command_hash:
                    raise DomainError(
                        "IDEMPOTENCY_CONFLICT", "Attempt identity has different input"
                    )
                old = AttemptView.model_validate(prior.snapshot)
                receipt = db.get(Receipt, old.preparation_operation_id)
                if receipt is not None:
                    return authorized_attempt_receipt(db, actor, receipt)
                if (prior.authentication_ref, prior.principal_epoch) != (
                    actor.authentication_ref,
                    actor.principal_epoch,
                ):
                    raise DomainError(
                        "PERMISSION_DENIED",
                        "Interrupted preparation remains bound to its original "
                        "authenticated session",
                    )
                _ = prior.inputs

            self.inputs(db, actor, command)
        if self.configuration is None or self.configuration.attempts is None:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Attempt preparation is not configured")
        config = self.configuration.attempts
        workspace = next(
            (item for item in config.workspaces if item.key == command.workspace_key), None
        )
        if (
            workspace is None
            or workspace.project_id != command.project_id
            or workspace.revision != command.workspace_revision
        ):
            raise DomainError("REVISION_CONFLICT", "Attempt workspace configuration changed")
        owner = ProjectInstructionService(self.engine, self.configuration)
        observed = owner.read(actor, command.project_id)
        with work_transaction(self.engine, actor) as db:
            root = workspace_root(
                db, command.project_id, workspace.root_key, workspace.root_revision
            )
            root_config = next(
                (item for item in self.configuration.roots if item.key == root.root_key), None
            )
            if root_config is None or (
                root_config.role,
                root_config.project_id,
                root_config.revision,
            ) != (root.role, root.project_id, root.config_revision):
                raise DomainError(
                    "PERMISSION_DENIED", "Current workspace root configuration is unavailable"
                )
            source = Path(root_config.path)
            root_identity = (root.device, root.inode, root.git_identity)

        def observe_source() -> None:
            source_descriptor = open_directory(source)
            try:
                observed_source = os.fstat(source_descriptor)
            finally:
                os.close(source_descriptor)
            if (
                observed_source.st_dev,
                observed_source.st_ino,
                git_identity(source),
            ) != root_identity:
                raise DomainError("PERMISSION_DENIED", "Admitted workspace root identity changed")

        observe_source()
        storage = Path(config.storage_path)
        descriptor = open_directory(storage)
        lock = None
        identity: str | None = None
        effect_started = False
        try:
            lock = os.open(
                "workspace-" + hashlib.sha256(workspace.root_key.encode()).hexdigest() + ".lock",
                os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                0o600,
                dir_fd=descriptor,
            )
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise DomainError(
                    "REVISION_CONFLICT", "Workspace has an active preparation writer"
                ) from None
            identity = prior.id if prior else str(uuid4())
            operation = old.preparation_operation_id if prior else str(uuid4())
            effect_id = str(uuid4())
            now = datetime.now(UTC)
            with work_transaction(self.engine, actor) as db:
                task, policy = self.inputs(db, actor, command)
                count = db.scalar(select(func.count()).select_from(Attempt)) or 0
                if prior is None and count >= config.pending_count:
                    raise DomainError(
                        "DEPENDENCY_UNAVAILABLE", "Attempt storage count limit reached"
                    )
                bundle = InstructionService(self.engine, self.configuration).deterministic_bundle(
                    db, actor, task, observed
                )
                if prior is None:
                    view = AttemptView(
                        attempt_id=identity,
                        project_id=command.project_id,
                        origin=command.origin,
                        revision=1,
                        state="PREPARING",
                        preparation_operation_id=operation,
                        manifest=None,
                        created_at=now.isoformat(),
                    )
                    db.add(
                        Attempt(
                            id=identity,
                            project_id=command.project_id,
                            task_id=task.task_id,
                            root_id=workspace.root_key,
                            root_revision=workspace.root_revision,
                            workspace_key=workspace.key,
                            workspace_revision=workspace.revision,
                            configuration_revision=config.revision,
                            principal_id=actor.principal_id,
                            authentication_ref=actor.authentication_ref,
                            principal_epoch=actor.principal_epoch,
                            idempotency_key=command.idempotency_key,
                            payload_hash=command_hash,
                            revision=1,
                            snapshot=view.model_dump(mode="json"),
                            inputs={
                                "command": command.model_dump(mode="json"),
                                **(
                                    {"dispatch": dispatch.model_dump(mode="json")}
                                    if dispatch is not None
                                    else {}
                                ),
                                "task": task.model_dump(mode="json"),
                                "policy": policy.model_dump(mode="json"),
                                "bundle": bundle.model_dump(mode="json"),
                            },
                        )
                    )
                    db.flush()
                else:
                    existing = authorized_attempt(db, actor, identity, "prepare")
                    self.check_configuration(db, existing)
                    retained_bundle = DeterministicInstructionBundle.model_validate(
                        existing.inputs["bundle"]
                    )
                    if (retained_bundle.content_digest, retained_bundle.production) != (
                        bundle.content_digest,
                        bundle.production,
                    ):
                        raise DomainError(
                            "REVISION_CONFLICT", "Interrupted instruction bindings changed"
                        )
                    bundle = retained_bundle
                    view = AttemptView.model_validate(existing.snapshot)
                    retained_effect = db.scalar(
                        select(AttemptEffect).where(AttemptEffect.attempt_id == identity)
                    )
                    if retained_effect is None:
                        raise DomainError(
                            "DEPENDENCY_UNAVAILABLE",
                            "Interrupted preparation journal is unavailable",
                        )
                    effect_id = retained_effect.id
                lease = db.get(WorkspaceLease, workspace.root_key)
                if (
                    lease is not None
                    and lease.attempt_id != identity
                    and datetime.fromisoformat(lease.deadline) > now
                ):
                    raise DomainError("REVISION_CONFLICT", "Workspace preparation lease is active")
                fence = lease.fence + 1 if lease else 1
                if lease is None:
                    lease = WorkspaceLease(
                        root_id=workspace.root_key,
                        attempt_id=identity,
                        fence=fence,
                        deadline=(now + timedelta(seconds=config.lease_seconds)).isoformat(),
                    )
                    db.add(lease)
                else:
                    lease.attempt_id, lease.fence, lease.deadline = (
                        identity,
                        fence,
                        (now + timedelta(seconds=config.lease_seconds)).isoformat(),
                    )
                if prior is None:
                    db.add(
                        AttemptEffect(
                            id=effect_id,
                            attempt_id=identity,
                            fence=fence,
                            kind="WORKSPACE_PREPARATION",
                            state="PREPARED",
                            snapshot={
                                "root_id": workspace.root_key,
                                "configuration_revision": config.revision,
                            },
                        )
                    )
                else:
                    assert retained_effect is not None
                    retained_effect.fence = fence
            captured = capture_snapshot(
                source, max_bytes=config.snapshot_bytes, max_files=config.snapshot_files
            )
            if captured.snapshot.byte_count > config.pending_bytes:
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Attempt storage byte limit reached")
            directory = storage / identity
            target = directory / "workspace"
            with work_transaction(self.engine, actor) as db:
                self.inputs(db, actor, command)
                authorized_attempt(db, actor, identity, "prepare")
                journal = db.get(AttemptEffect, effect_id)
                if journal is None or journal.fence != fence:
                    raise DomainError("REVISION_CONFLICT", "Preparation effect fence changed")
                accepted_snapshot = journal.snapshot.get("source_snapshot")
                if (
                    accepted_snapshot is not None
                    and accepted_snapshot != captured.snapshot.model_dump(mode="json")
                ):
                    raise DomainError("REVISION_CONFLICT", "Interrupted source snapshot changed")
                reservation = snapshot_storage_bytes(captured)
                retained_bytes = 0
                for retained_journal in db.scalars(
                    select(AttemptEffect).where(AttemptEffect.attempt_id != identity)
                ):
                    if "source_snapshot" in retained_journal.snapshot:
                        reserved = retained_journal.snapshot.get("storage_bytes")
                        if type(reserved) is not int or reserved < 0:
                            raise DomainError(
                                "DEPENDENCY_UNAVAILABLE",
                                "Attempt storage accounting requires repair",
                            )
                        retained_bytes += reserved
                if retained_bytes + reservation > config.pending_bytes:
                    raise DomainError(
                        "DEPENDENCY_UNAVAILABLE", "Retained Attempt storage byte limit reached"
                    )
                journal.snapshot = journal.snapshot | {
                    "source_snapshot": captured.snapshot.model_dump(mode="json"),
                    "storage_bytes": reservation,
                }
            observe_source()
            effect_started = True
            if directory.exists():
                if prior is None or accepted_snapshot is None:
                    raise DomainError(
                        "DEPENDENCY_UNAVAILABLE", "Workspace effect ownership requires repair"
                    )
                existing_snapshot = capture_snapshot(
                    target, max_bytes=config.snapshot_bytes, max_files=config.snapshot_files
                )
                if existing_snapshot.snapshot != captured.snapshot:
                    raise DomainError(
                        "DEPENDENCY_UNAVAILABLE", "Interrupted workspace has unrecognized changes"
                    )
                verify_snapshot_evidence(directory / "evidence", captured)
            else:
                directory.mkdir(mode=0o700)
                write_snapshot(directory / "evidence", captured)
                if captured.snapshot.kind == "GIT":
                    materialize_worktree(source, target, "attempt/" + identity, captured)
                else:
                    materialize_directory(target, captured)
            # Source evidence remains immutable outside the mutable workspace.
            repeated = capture_snapshot(
                source, max_bytes=config.snapshot_bytes, max_files=config.snapshot_files
            )
            if repeated.snapshot.snapshot_hash != captured.snapshot.snapshot_hash:
                raise DomainError("REVISION_CONFLICT", "Workspace changed during preparation")
            current_instructions = owner.read(actor, command.project_id)
            with work_transaction(self.engine, actor) as db:
                authorized_attempt(db, actor, identity, "prepare")
                current_task, current_verification = self.inputs(db, actor, command)
                refreshed = InstructionService(
                    self.engine, self.configuration
                ).deterministic_bundle(db, actor, current_task, current_instructions)
                if (
                    refreshed.content_digest != bundle.content_digest
                    or refreshed.production != bundle.production
                ):
                    raise DomainError("REVISION_CONFLICT", "Attempt instruction bindings changed")
                lease = db.get(WorkspaceLease, workspace.root_key)
                if (
                    lease is None
                    or lease.attempt_id != identity
                    or lease.fence != fence
                    or datetime.fromisoformat(lease.deadline) <= datetime.now(UTC)
                ):
                    raise DomainError("REVISION_CONFLICT", "Workspace preparation lease changed")
                manifest = RunManifest(
                    manifest_id=str(uuid4()),
                    attempt_id=identity,
                    origin=command.origin,
                    initiating_principal_id=actor.principal_id,
                    authentication_ref=actor.authentication_ref,
                    principal_epoch=actor.principal_epoch,
                    project_id=command.project_id,
                    task=current_task,
                    verification_policy=current_verification,
                    instruction_bundle=bundle,
                    workspace_key=workspace.key,
                    workspace_revision=workspace.revision,
                    root_id=workspace.root_key,
                    root_revision=workspace.root_revision,
                    workspace_kind=captured.snapshot.kind,
                    snapshot=captured.snapshot,
                    previous_attempt_id=command.previous_attempt_id,
                    created_at=view.created_at,
                    content_digest="pending",
                )
                manifest = manifest.model_copy(
                    update={
                        "content_digest": digest(
                            manifest.model_dump(mode="json", exclude={"content_digest"})
                        )
                    }
                )
                db.add(
                    AttemptManifest(
                        id=manifest.manifest_id,
                        attempt_id=identity,
                        content_hash=manifest.content_digest,
                        snapshot=manifest.model_dump(mode="json"),
                    )
                )
                view = view.model_copy(
                    update={
                        "revision": view.revision + 1,
                        "state": "PREPARED",
                        "manifest": manifest,
                    }
                )
                row = db.get(Attempt, identity)
                if row is None:
                    raise DomainError("DEPENDENCY_UNAVAILABLE", "Attempt intent is unavailable")
                row.revision, row.snapshot = view.revision, view.model_dump(mode="json")
                effect = db.get(AttemptEffect, effect_id)
                if effect is None:
                    raise DomainError("DEPENDENCY_UNAVAILABLE", "Attempt effect is unavailable")
                effect.state = "APPLIED"
                effect.snapshot = effect.snapshot | {
                    "snapshot_hash": captured.snapshot.snapshot_hash
                }
                lease.deadline = datetime.now(UTC).isoformat()
                result = AttemptReceipt(
                    operation_id=operation, committed_at=datetime.now(UTC).isoformat(), attempt=view
                )
                db.add(
                    Receipt(
                        id=operation,
                        principal_id=actor.principal_id,
                        command=result.command,
                        idempotency_key=command.idempotency_key,
                        payload_hash=command_hash,
                        project_id=command.project_id,
                        owner="work",
                        target_kind="attempt",
                        target_id=identity,
                        authentication_ref=actor.authentication_ref,
                        result=result.model_dump(mode="json"),
                    )
                )
                db.flush()
                db.add(
                    OutboxEvent(
                        event_id=str(uuid4()),
                        operation_id=operation,
                        event_type="attempt.prepared",
                        schema_version=1,
                        principal_id=actor.principal_id,
                        project_id=command.project_id,
                        owner="work",
                        target_kind="attempt",
                        target_id=identity,
                        target_revision=view.revision,
                        payload=result.model_dump(mode="json"),
                        committed_at=result.committed_at,
                    )
                )
                return result
        except BaseException:
            if identity is not None:
                # Recording uncertainty grants no further effect authority, even after revocation.
                with transaction(self.engine) as db:
                    retained = db.get(Attempt, identity)
                    if retained is not None:
                        retained.revision += 1
                        retained.snapshot = retained.snapshot | {
                            "state": "RECOVERY_REQUIRED",
                            "revision": retained.revision,
                        }
                        retained_effect = db.scalar(
                            select(AttemptEffect).where(AttemptEffect.attempt_id == identity)
                        )
                        if retained_effect is not None and effect_started:
                            retained_effect.state = "UNKNOWN"
            raise
        finally:
            if lock is not None:
                os.close(lock)
            os.close(descriptor)
