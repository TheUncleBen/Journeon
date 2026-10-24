# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable selected Attempt candidates; capture attribution is not authorship proof."""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, defer

from journeon.attempts import AttemptService, authorized_attempt, validate_attempt_view
from journeon.contracts import (
    AttemptView,
    DomainError,
    ReviewTarget,
    ReviewTargetReceipt,
    ReviewTargetSelect,
)
from journeon.instruction_config import InstructionConfiguration
from journeon.instructions import digest
from journeon.models import (
    Attempt,
    OutboxEvent,
    Project,
    Receipt,
    ReviewPolicyRevision,
    ReviewTargetRecord,
)
from journeon.permissions import AuthenticatedContext, require_grant
from journeon.reviews import current_policy
from journeon.verification import current_policy as verification_policy
from journeon.work import WorkService, task_row, task_view, work_transaction


def target_grants(db: Session, actor: AuthenticatedContext, project_id: str) -> None:
    for capability in ("task.review.read", "task.read", "project.review.read"):
        require_grant(db, actor, capability, project_id=project_id)


def target_scope(
    db: Session, actor: AuthenticatedContext, identity: str
) -> tuple[ReviewTargetRecord, Attempt]:
    row = db.get(ReviewTargetRecord, identity, options=[defer(ReviewTargetRecord.snapshot)])
    if row is None:
        raise DomainError("NOT_FOUND", "Review target is unavailable")
    target_grants(db, actor, row.project_id)
    attempt = authorized_attempt(db, actor, row.attempt_id)
    if row.principal_id != actor.principal_id or attempt.task_id != row.task_id:
        raise DomainError("NOT_FOUND", "Review target is unavailable")
    return row, attempt


def read_target(db: Session, actor: AuthenticatedContext, identity: str) -> ReviewTarget:
    row, attempt = target_scope(db, actor, identity)
    result = ReviewTarget.model_validate(row.snapshot)
    view = AttemptView.model_validate(attempt.snapshot)
    validate_attempt_view(db, attempt, view)
    policy = db.get(ReviewPolicyRevision, (row.project_id, row.review_policy_revision))
    if (
        result.target_id != row.id
        or result.selected_by != row.principal_id
        or result.manifest != view.manifest
        or result.manifest.manifest_id != row.manifest_id
        or result.manifest.task.revision != row.task_revision
        or result.manifest.project_id != row.project_id
        or policy is None
        or result.review_policy.model_dump(mode="json") != policy.snapshot
        or digest(policy.snapshot) != policy.content_hash
        or result.content_digest != row.content_hash
        or digest(result.model_dump(mode="json", exclude={"content_digest"})) != row.content_hash
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Review target binding requires repair")
    return result


def target_receipt(
    db: Session, actor: AuthenticatedContext, receipt: Receipt
) -> ReviewTargetReceipt:
    if receipt.principal_id != actor.principal_id:
        raise DomainError("NOT_FOUND", "Operation is unavailable")
    require_grant(db, actor, "task.receipt.read", project_id=receipt.project_id)
    if receipt.project_id is None:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Review target receipt scope requires repair")
    target_grants(db, actor, receipt.project_id)
    row = db.scalar(
        select(ReviewTargetRecord)
        .options(defer(ReviewTargetRecord.snapshot))
        .where(ReviewTargetRecord.operation_id == receipt.id)
    )
    if (
        row is None
        or receipt.target_kind != "task"
        or (row.project_id, row.task_id) != (receipt.project_id, receipt.target_id)
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Review target receipt requires repair")
    target = read_target(db, actor, row.id)
    result = ReviewTargetReceipt.model_validate(receipt.result)
    if (
        result.operation_id != receipt.id
        or result.command != receipt.command
        or result.target != target
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Review target receipt requires repair")
    return result


def require_current_target(
    db: Session, engine: Engine, actor: AuthenticatedContext, target: ReviewTarget
) -> None:
    manifest = target.manifest
    current = task_view(task_row(db, actor, manifest.task.task_id, "task.read"))
    policy = current_policy(db, actor, manifest.project_id)
    proof = verification_policy(db, actor, manifest.project_id)
    project = db.get(Project, manifest.project_id)
    if (
        current != manifest.task
        or policy != target.review_policy
        or proof != manifest.verification_policy
        or project is None
        or project.revision != current.verification_policy.project_revision
    ):
        raise DomainError("REVISION_CONFLICT", "Review target inputs are no longer current")
    if current.state in ("DONE", "CANCELLED", "ARCHIVED") or current.paused or current.stop_reason:
        raise DomainError(
            "REVISION_CONFLICT", "Task does not permit candidate selection or completion"
        )
    decision = WorkService(engine)._admission(
        db, actor, current, proof, datetime.now(UTC).isoformat()
    )
    if decision.decision != "ADMIT":
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Current Task gates do not permit completion")


class ReviewTargetService:
    def __init__(self, engine: Engine, configuration: InstructionConfiguration | None) -> None:
        self.engine = engine
        self.configuration = configuration

    def read(self, actor: AuthenticatedContext, identity: str) -> ReviewTarget:
        with work_transaction(self.engine, actor) as db:
            self.check_configuration(db, actor, identity)
            result = read_target(db, actor, identity)
            return result

    def check_configuration(self, db: Session, actor: AuthenticatedContext, identity: str) -> None:
        _, attempt = target_scope(db, actor, identity)
        AttemptService(self.engine, self.configuration).check_configuration(db, attempt)

    def select(
        self, actor: AuthenticatedContext, command: ReviewTargetSelect
    ) -> ReviewTargetReceipt:
        name = "task.review.select.v1"
        command_hash = digest(command.model_dump(mode="json", exclude={"idempotency_key"}))
        with work_transaction(self.engine, actor) as db:
            prior = db.scalar(
                select(Receipt)
                .options(defer(Receipt.result))
                .where(
                    Receipt.principal_id == actor.principal_id,
                    Receipt.command == name,
                    Receipt.idempotency_key == command.idempotency_key,
                )
            )
            if prior is not None:
                require_grant(db, actor, "task.review.select", project_id=prior.project_id)
                identity = db.scalar(
                    select(ReviewTargetRecord.id).where(ReviewTargetRecord.operation_id == prior.id)
                )
                if identity is None:
                    raise DomainError(
                        "DEPENDENCY_UNAVAILABLE", "Review target receipt requires repair"
                    )
                self.check_configuration(db, actor, identity)
                result = target_receipt(db, actor, prior)
                if prior.payload_hash != command_hash:
                    raise DomainError(
                        "IDEMPOTENCY_CONFLICT", "Review target identity has different input"
                    )
                return result
            task = task_row(db, actor, command.task_id, "task.review.select")
            target_grants(db, actor, task.project_id)
            require_grant(db, actor, "task.receipt.read", project_id=task.project_id)
            current = task_view(task)
            attempt = authorized_attempt(db, actor, command.attempt_id)
            if attempt.task_id != current.task_id or attempt.project_id != current.project_id:
                raise DomainError("PERMISSION_DENIED", "Attempt does not belong to this Task")
            AttemptService(self.engine, self.configuration).check_configuration(db, attempt)
            view = AttemptView.model_validate(attempt.snapshot)
            validate_attempt_view(db, attempt, view)
            policy = current_policy(db, actor, current.project_id)
            if policy is None:
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Review policy is not configured")
            if (
                current.revision != command.expected_revision
                or policy.revision != command.expected_review_policy_revision
            ):
                raise DomainError("REVISION_CONFLICT", "Task or review policy revision changed")
            if view.manifest is None:
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE", "Review target requires a prepared Attempt"
                )
            target = ReviewTarget(
                target_id=str(uuid4()),
                manifest=view.manifest,
                review_policy=policy,
                selected_by=actor.principal_id,
                selected_at=datetime.now(UTC).isoformat(),
                content_digest="pending",
            )
            require_current_target(db, self.engine, actor, target)
            target = target.model_copy(
                update={
                    "content_digest": digest(
                        target.model_dump(mode="json", exclude={"content_digest"})
                    )
                }
            )
            result = ReviewTargetReceipt(
                operation_id=str(uuid4()), committed_at=target.selected_at, target=target
            )
            db.add(
                Receipt(
                    id=result.operation_id,
                    principal_id=actor.principal_id,
                    command=name,
                    idempotency_key=command.idempotency_key,
                    payload_hash=command_hash,
                    project_id=current.project_id,
                    owner="work",
                    target_kind="task",
                    target_id=current.task_id,
                    authentication_ref=actor.authentication_ref,
                    result=result.model_dump(mode="json"),
                )
            )
            db.flush()
            db.add(
                ReviewTargetRecord(
                    id=target.target_id,
                    project_id=current.project_id,
                    task_id=current.task_id,
                    task_revision=current.revision,
                    attempt_id=attempt.id,
                    manifest_id=view.manifest.manifest_id,
                    review_policy_revision=policy.revision,
                    principal_id=actor.principal_id,
                    operation_id=result.operation_id,
                    snapshot=target.model_dump(mode="json"),
                    content_hash=target.content_digest,
                )
            )
            db.add(
                OutboxEvent(
                    event_id=str(uuid4()),
                    operation_id=result.operation_id,
                    event_type="task.review.target.selected",
                    schema_version=1,
                    principal_id=actor.principal_id,
                    project_id=current.project_id,
                    owner="work",
                    target_kind="task",
                    target_id=current.task_id,
                    target_revision=current.revision,
                    payload=result.model_dump(mode="json"),
                    committed_at=target.selected_at,
                )
            )
            db.flush()
            require_current_target(db, self.engine, actor, target)
            require_grant(db, actor, "task.review.select", project_id=current.project_id)
            require_grant(db, actor, "task.receipt.read", project_id=current.project_id)
            target_grants(db, actor, current.project_id)
            self.check_configuration(db, actor, target.target_id)
            return result
