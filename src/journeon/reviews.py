# SPDX-License-Identifier: AGPL-3.0-only
"""Versioned review gates; configuration does not qualify a reviewer."""

from datetime import UTC, datetime
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, defer

from journeon.contracts import (
    DomainError,
    ReviewPolicy,
    ReviewPolicyConfigure,
    ReviewPolicyReceipt,
)
from journeon.instructions import digest
from journeon.models import OutboxEvent, Project, Receipt, ReviewPolicyRevision
from journeon.permissions import AuthenticatedContext, require_grant


def current_policy(
    db: Session, actor: AuthenticatedContext, project_id: str
) -> ReviewPolicy | None:
    require_grant(db, actor, "project.review.read", project_id=project_id)
    row = db.scalar(
        select(ReviewPolicyRevision)
        .where(ReviewPolicyRevision.project_id == project_id)
        .order_by(ReviewPolicyRevision.revision.desc())
        .limit(1)
    )
    if row is None:
        return None
    policy = ReviewPolicy.model_validate(row.snapshot)
    if (policy.project_id, policy.revision) != (row.project_id, row.revision) or digest(
        row.snapshot
    ) != row.content_hash:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Review policy requires repair")
    return policy


def policy_receipt(db: Session, actor: AuthenticatedContext, row: Receipt) -> ReviewPolicyReceipt:
    if row.principal_id != actor.principal_id:
        raise DomainError("NOT_FOUND", "Operation is unavailable")
    for capability in ("project.review.read", "project.receipt.read"):
        require_grant(db, actor, capability, project_id=row.project_id)
    if row.target_kind != "project" or row.target_id != row.project_id:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Review receipt requires repair")
    result = ReviewPolicyReceipt.model_validate(row.result)
    if (
        result.operation_id != row.id
        or result.policy.project_id != row.project_id
        or result.command != row.command
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Review receipt requires repair")
    return result


def configure(
    db: Session, actor: AuthenticatedContext, command: ReviewPolicyConfigure
) -> ReviewPolicyReceipt:
    name = "project.review.configure.v1"
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
        require_grant(db, actor, "project.review.configure", project_id=old.project_id)
        result = policy_receipt(db, actor, old)
        if old.payload_hash != payload_hash:
            raise DomainError("IDEMPOTENCY_CONFLICT", "Operation identity has different input")
        return result
    for capability in (
        "project.review.configure",
        "project.review.read",
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
        raise DomainError("REVISION_CONFLICT", "Review policy changed; refresh its revision")
    now = datetime.now(UTC).isoformat()
    try:
        policy = ReviewPolicy.model_validate(
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
    except ValidationError:
        raise DomainError("VALIDATION_FAILED", "Review policy rules are inconsistent") from None
    data = policy.model_dump(mode="json")
    db.add(
        ReviewPolicyRevision(
            project_id=project.id,
            revision=policy.revision,
            snapshot=data,
            content_hash=digest(data),
        )
    )
    project.revision += 1
    result = ReviewPolicyReceipt(operation_id=str(uuid4()), committed_at=now, policy=policy)
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
            event_type="project.review.configured",
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
    for capability in ("project.review.configure", "project.review.read", "project.receipt.read"):
        require_grant(db, actor, capability, project_id=project.id)
    return result


class ReviewService:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def configure(
        self, actor: AuthenticatedContext, command: ReviewPolicyConfigure
    ) -> ReviewPolicyReceipt:
        from journeon.work import work_transaction

        with work_transaction(self.engine, actor) as db:
            return configure(db, actor, command)

    def policy(self, actor: AuthenticatedContext, project_id: str) -> ReviewPolicy:
        from journeon.work import work_transaction

        with work_transaction(self.engine, actor) as db:
            result = current_policy(db, actor, project_id)
            if result is None:
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Review policy is not configured")
            return result
