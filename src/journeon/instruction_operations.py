# SPDX-License-Identifier: AGPL-3.0-only
"""Instruction-owned receipts, checked before retained payload disclosure."""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session, defer

from journeon.contracts import DomainError
from journeon.instruction_contracts import InstructionReceipt
from journeon.instructions import digest
from journeon.models import InstructionPublication, OutboxEvent, Receipt
from journeon.permissions import AuthenticatedContext, current_owner, require_grant


def authorized(db: Session, actor: AuthenticatedContext, row: Receipt) -> InstructionReceipt:
    kinds = {
        "project.root.admit.v1": "instruction_root",
        "project.root.revoke.v1": "instruction_root",
        "instruction.candidate.register.v1": "instruction_install",
        "instruction.release.install.v1": "instruction_install",
        "project.instructions.policy.configure.v1": "project_instructions",
        "project.instructions.bind.v1": "project_instructions",
        "project.instructions.accept.v1": "project_instructions",
        "project.instructions.projection.v1": "project_instructions",
    }
    if (
        kinds.get(row.command) != row.target_kind
        or row.owner != "project_instructions"
        or (
            row.target_kind == "project_instructions"
            and (row.project_id is None or row.project_id != row.target_id)
        )
        or (
            row.target_kind in {"instruction_root", "instruction_install"}
            and row.project_id is not None
        )
        or row.target_kind
        not in {"project_instructions", "instruction_root", "instruction_install"}
    ):
        raise DomainError("PERMISSION_DENIED", "Instruction receipt scope is unavailable")
    if row.principal_id != actor.principal_id:
        raise DomainError("NOT_FOUND", "Operation is unavailable")
    if row.project_id is None:
        current_owner(db, actor)
    else:
        for action in ("read", "receipt.read"):
            require_grant(
                db,
                actor,
                "project.instruction." + action,
                resource_kind="project",
                resource_id=row.project_id,
            )
    if row.project_id is not None:
        from journeon.models import InstructionRoot, ProjectInstructionBinding

        binding = db.get(ProjectInstructionBinding, row.project_id)
        root = db.get(InstructionRoot, binding.root_id) if binding else None
        if (
            binding is None
            or root is None
            or not root.enabled
            or root.revision != binding.root_revision
        ):
            raise DomainError(
                "PERMISSION_DENIED", "Current Project instruction binding is unavailable"
            )
    return decode(row)


def decode(row: Receipt) -> InstructionReceipt:
    result = InstructionReceipt.model_validate(row.result)
    if (result.operation_id, result.command, result.target_id, result.target_kind) != (
        row.id,
        row.command,
        row.target_id,
        row.target_kind,
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Instruction receipt requires repair")
    return result


def retry(
    db: Session, actor: AuthenticatedContext, command: str, key: str, payload: object
) -> InstructionReceipt | None:
    row = db.scalar(
        select(Receipt)
        .options(defer(Receipt.result))
        .where(
            Receipt.principal_id == actor.principal_id,
            Receipt.command == command,
            Receipt.idempotency_key == key,
        )
    )
    if row is None:
        return None
    result = authorized(db, actor, row)
    if row.payload_hash != digest(payload):
        raise DomainError("IDEMPOTENCY_CONFLICT", "Operation identity has different input")
    return result


def record(
    db: Session,
    actor: AuthenticatedContext,
    command: str,
    key: str,
    payload: object,
    kind: str,
    identity: str,
    revision: int,
    content_hash: str | None,
    provenance: str,
    *,
    operation_id: str | None = None,
    origin: InstructionPublication | None = None,
    abandoned: bool = False,
) -> InstructionReceipt:
    project_id = identity if kind == "project_instructions" else None
    if project_id:
        for action in ("read", "receipt.read"):
            require_grant(
                db,
                actor,
                "project.instruction." + action,
                resource_kind="project",
                resource_id=project_id,
            )
    else:
        current_owner(db, actor)
    result = InstructionReceipt.model_validate(
        dict(
            operation_id=operation_id or str(uuid4()),
            command=command,
            target_kind=kind,
            target_id=identity,
            revision=revision,
            status="ABANDONED" if abandoned else "CANONICAL_COMMITTED",
            committed_at=datetime.now(UTC).isoformat(),
            content_hash=content_hash,
            provenance=provenance,
        )
    )
    db.add(
        Receipt(
            id=result.operation_id,
            principal_id=origin.principal_id if origin else actor.principal_id,
            command=command,
            idempotency_key=key,
            payload_hash=digest(payload),
            project_id=project_id,
            owner="project_instructions",
            target_kind=kind,
            target_id=identity,
            authentication_ref=origin.authentication_ref if origin else actor.authentication_ref,
            result=result.model_dump(mode="json"),
        )
    )
    db.flush()
    db.add(
        OutboxEvent(
            event_id=str(uuid4()),
            operation_id=result.operation_id,
            event_type=command.removesuffix(".v1") + (".abandoned" if abandoned else ".committed"),
            schema_version=1,
            principal_id=origin.principal_id if origin else actor.principal_id,
            project_id=project_id,
            owner="project_instructions",
            target_kind=kind,
            target_id=identity,
            committed_at=result.committed_at,
            target_revision=revision,
            payload=result.model_dump(mode="json"),
        )
    )
    db.flush()
    return result
