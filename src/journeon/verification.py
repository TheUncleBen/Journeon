# SPDX-License-Identifier: AGPL-3.0-only
"""Versioned proof definitions; definitions do not grant execution permission."""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session, defer

from journeon.contracts import (
    DomainError,
    TaskWorkflow,
    VerificationPolicy,
    VerificationPolicyConfigure,
    VerificationPolicyReceipt,
)
from journeon.instructions import digest
from journeon.models import OutboxEvent, Project, Receipt, VerificationPolicyRevision
from journeon.permissions import AuthenticatedContext, require_grant


def current_policy(
    db: Session, actor: AuthenticatedContext, project_id: str
) -> VerificationPolicy | None:
    require_grant(db, actor, "project.verification.read", project_id=project_id)
    row = db.scalar(
        select(VerificationPolicyRevision)
        .where(VerificationPolicyRevision.project_id == project_id)
        .order_by(VerificationPolicyRevision.revision.desc())
        .limit(1)
    )
    if row is None:
        return None
    policy = VerificationPolicy.model_validate(row.snapshot)
    if (policy.project_id, policy.revision) != (row.project_id, row.revision) or digest(
        row.snapshot
    ) != row.content_hash:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Verification policy requires repair")
    return policy


def policy_receipt(
    db: Session, actor: AuthenticatedContext, row: Receipt
) -> VerificationPolicyReceipt:
    if row.principal_id != actor.principal_id:
        raise DomainError("NOT_FOUND", "Operation is unavailable")
    for capability in ("project.verification.read", "project.receipt.read"):
        require_grant(db, actor, capability, project_id=row.project_id)
    if row.target_kind != "project" or row.target_id != row.project_id:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Verification receipt requires repair")
    result = VerificationPolicyReceipt.model_validate(row.result)
    if (
        result.operation_id != row.id
        or result.policy.project_id != row.project_id
        or result.command != row.command
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Verification receipt requires repair")
    return result


def configure(
    db: Session, actor: AuthenticatedContext, command: VerificationPolicyConfigure
) -> VerificationPolicyReceipt:
    name = "project.verification.configure.v1"
    payload_hash = digest(command.model_dump(mode="json", exclude={"idempotency_key"}))
    old = db.scalar(
        select(Receipt)
        .options(defer(Receipt.result))
        .where(
            Receipt.principal_id == actor.principal_id,
            Receipt.command == name,
            Receipt.idempotency_key == command.idempotency_key,
        )
    )
    if old is not None:
        require_grant(db, actor, "project.verification.configure", project_id=old.project_id)
        result = policy_receipt(db, actor, old)
        if old.payload_hash != payload_hash:
            raise DomainError("IDEMPOTENCY_CONFLICT", "Operation identity has different input")
        return result
    for capability in (
        "project.verification.configure",
        "project.verification.read",
        "project.receipt.read",
    ):
        require_grant(db, actor, capability, project_id=command.project_id)
    project = db.get(Project, command.project_id)
    if project is None:
        raise DomainError("NOT_FOUND", "Project is unavailable")
    previous = current_policy(db, actor, project.id)
    if (
        project.revision != command.expected_project_revision
        or (previous.revision if previous else 0) != command.expected_policy_revision
    ):
        raise DomainError("REVISION_CONFLICT", "Verification policy changed; refresh its revision")
    now = datetime.now(UTC).isoformat()
    policy = VerificationPolicy.model_validate(
        command.model_dump(
            exclude={
                "schema_version",
                "idempotency_key",
                "expected_project_revision",
                "expected_policy_revision",
            }
        )
        | {
            "revision": command.expected_policy_revision + 1,
            "created_by": actor.principal_id,
            "created_at": now,
        }
    )
    data = policy.model_dump(mode="json")
    db.add(
        VerificationPolicyRevision(
            project_id=project.id,
            revision=policy.revision,
            snapshot=data,
            content_hash=digest(data),
        )
    )
    project.revision += 1
    project.verification_policy_ref = f"verification:{project.id}:{policy.revision}"
    result = VerificationPolicyReceipt(operation_id=str(uuid4()), committed_at=now, policy=policy)
    db.add(
        Receipt(
            id=result.operation_id,
            principal_id=actor.principal_id,
            command=name,
            idempotency_key=command.idempotency_key,
            payload_hash=payload_hash,
            project_id=project.id,
            owner="projects",
            target_kind="project",
            target_id=project.id,
            authentication_ref=actor.authentication_ref,
            result=result.model_dump(mode="json"),
        )
    )
    db.flush()
    db.add(
        OutboxEvent(
            event_id=str(uuid4()),
            operation_id=result.operation_id,
            event_type="project.verification.configured",
            schema_version=1,
            principal_id=actor.principal_id,
            project_id=project.id,
            owner="projects",
            target_kind="project",
            target_id=project.id,
            target_revision=project.revision,
            payload=result.model_dump(mode="json"),
            committed_at=now,
        )
    )
    db.flush()
    return result


def validate_workflow(policy: VerificationPolicy, workflow: TaskWorkflow) -> None:
    VerificationPolicy.model_validate(policy.model_dump() | {"workflow": workflow.model_dump()})
    steps = {step.step_id: step for step in workflow.steps}
    for gate in policy.workflow.steps:
        if steps.get(gate.step_id) != gate:
            raise DomainError(
                "VALIDATION_FAILED",
                "Task workflow must preserve Project policy steps and dependencies",
            )
    if any(loop not in workflow.loops for loop in policy.workflow.loops):
        raise DomainError(
            "VALIDATION_FAILED", "Task workflow must preserve Project policy loop bounds"
        )
