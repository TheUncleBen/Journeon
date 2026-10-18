# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical local Task transactions; execution admission belongs to a later consumer."""

import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import Engine, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, defer

from journeon.contracts import (
    DomainError,
    TaskAction,
    TaskAssignment,
    TaskControl,
    TaskCreate,
    TaskCriterion,
    TaskPolicyBinding,
    TaskReceipt,
    TaskView,
)
from journeon.database import require_compatible_schema, transaction
from journeon.models import OutboxEvent, Project, Receipt, Task
from journeon.permissions import AuthenticatedContext, require_grant
from journeon.sessions import current_session


@contextmanager
def work_transaction(engine: Engine, actor: AuthenticatedContext) -> Iterator[Session]:
    try:
        with transaction(engine) as db:
            require_compatible_schema(db)
            current_session(
                db,
                actor.authentication_ref,
                principal_id=actor.principal_id,
                principal_epoch=actor.principal_epoch,
            )
            yield db
    except (ValidationError, json.JSONDecodeError):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored Task state requires repair") from None
    except SQLAlchemyError as exc:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "The Work store is unavailable") from exc


def task_row(db: Session, actor: AuthenticatedContext, task_id: str, action: str) -> Task:
    row = db.get(Task, task_id, options=[defer(Task.snapshot)])
    if row is None:
        raise DomainError("NOT_FOUND", "Task is unavailable")
    require_grant(db, actor, action, project_id=row.project_id)
    return row


def task_view(row: Task) -> TaskView:
    view = TaskView.model_validate(row.snapshot)
    if (
        view.task_id != row.id
        or view.project_id != row.project_id
        or view.initiating_principal_id != row.initiating_principal_id
        or view.revision != row.revision
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored Task state requires repair")
    return view


def authorized_work_receipt(db: Session, actor: AuthenticatedContext, row: Receipt) -> TaskReceipt:
    if row.principal_id != actor.principal_id:
        raise DomainError("NOT_FOUND", "Operation is unavailable")
    require_grant(db, actor, "task.receipt.read", project_id=row.project_id)
    require_grant(db, actor, "task.read", project_id=row.project_id)
    target = task_row(db, actor, row.target_id, "task.read")
    if row.target_kind != "task" or row.project_id != target.project_id:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored operation state requires repair")
    result = TaskReceipt.model_validate(row.result)
    if (
        result.operation_id != row.id
        or result.command != row.command
        or result.task.task_id != target.id
        or result.task.project_id != target.project_id
        or result.task.initiating_principal_id != target.initiating_principal_id
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored operation state requires repair")
    return result


def prior_receipt(
    db: Session,
    actor: AuthenticatedContext,
    name: str,
    command: TaskCreate | TaskControl,
    digest: str,
) -> TaskReceipt | None:
    row = db.scalar(
        select(Receipt)
        .options(defer(Receipt.result))
        .where(
            Receipt.principal_id == actor.principal_id,
            Receipt.command == name,
            Receipt.idempotency_key == command.idempotency_key,
        )
    )
    if row is None:
        return None
    # Authorize the historical target before decoding, even if the new input changes scope.
    require_grant(db, actor, name.removesuffix(".v1"), project_id=row.project_id)
    result = authorized_work_receipt(db, actor, row)
    if row.payload_hash != digest:
        raise DomainError("IDEMPOTENCY_CONFLICT", "Operation identity has different input")
    return result


def payload_hash(command: TaskCreate | TaskControl) -> str:
    data = command.model_dump(mode="json", exclude={"idempotency_key"})
    if isinstance(command, TaskCreate):
        data["dependencies"] = sorted(data["dependencies"])
    return hashlib.sha256(
        json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    ).hexdigest()


def dependencies(
    db: Session, actor: AuthenticatedContext, project_id: str, ids: list[str]
) -> list[TaskView]:
    result = []
    for task_id in ids:
        row = task_row(db, actor, task_id, "task.read")
        if row.project_id != project_id:
            raise DomainError("NOT_FOUND", "Task dependency is unavailable in this Project")
        result.append(task_view(row))
    return result


def commit_task(
    db: Session,
    actor: AuthenticatedContext,
    name: str,
    command: TaskCreate | TaskControl,
    digest: str,
    view: TaskView,
) -> TaskReceipt:
    result = TaskReceipt(
        operation_id=str(uuid4()),
        command=name,  # type: ignore[arg-type]
        committed_at=view.updated_at,
        task=view,
    )
    db.add(
        Receipt(
            id=result.operation_id,
            principal_id=actor.principal_id,
            command=name,
            idempotency_key=command.idempotency_key,
            payload_hash=digest,
            project_id=view.project_id,
            owner="work",
            target_kind="task",
            target_id=view.task_id,
            authentication_ref=actor.authentication_ref,
            result=result.model_dump(mode="json"),
        )
    )
    db.flush()
    event_types = {
        "task.create.v1": "task.created",
        "task.pause.v1": "task.paused",
        "task.resume.v1": "task.resumed",
        "task.cancel.v1": "task.cancelled",
    }
    db.add(
        OutboxEvent(
            event_id=str(uuid4()),
            operation_id=result.operation_id,
            event_type=event_types[name],
            schema_version=1,
            principal_id=actor.principal_id,
            project_id=view.project_id,
            owner="work",
            target_kind="task",
            target_id=view.task_id,
            target_revision=view.revision,
            payload=result.model_dump(mode="json"),
            committed_at=result.committed_at,
        )
    )
    db.flush()
    for capability in (name.removesuffix(".v1"), "task.read", "task.receipt.read"):
        require_grant(db, actor, capability, project_id=view.project_id)
    return result


class WorkService:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def read(self, actor: AuthenticatedContext, task_id: str) -> TaskView:
        with work_transaction(self.engine, actor) as db:
            return task_view(task_row(db, actor, task_id, "task.read"))

    def create(self, actor: AuthenticatedContext, command: TaskCreate) -> TaskReceipt:
        digest = payload_hash(command)
        with work_transaction(self.engine, actor) as db:
            previous = prior_receipt(db, actor, "task.create.v1", command, digest)
            if previous is not None:
                return previous
            for capability in ("task.create", "task.read", "task.receipt.read"):
                require_grant(db, actor, capability, project_id=command.project_id)
            project = db.get(Project, command.project_id)
            if project is None:
                raise DomainError("NOT_FOUND", "Project is unavailable")
            if project.revision != command.expected_project_revision:
                raise DomainError("REVISION_CONFLICT", "Project changed; refresh its revision")
            dependencies(db, actor, project.id, command.dependencies)
            now = datetime.now(UTC).isoformat()
            assignment = TaskAssignment(
                responsibility=command.responsibility,
                principal_id=actor.principal_id if command.responsibility == "HUMAN" else None,
                assigned_by=actor.principal_id,
                assigned_at=now,
            )
            view = TaskView(
                task_id=str(uuid4()),
                project_id=project.id,
                initiating_principal_id=actor.principal_id,
                revision=1,
                objective=command.objective,
                objective_revision=1,
                criteria_revision=1,
                success_conditions=[
                    TaskCriterion(text=text, principal_id=actor.principal_id, objective_revision=1)
                    for text in command.success_conditions
                ],
                verification_policy=TaskPolicyBinding(
                    project_id=project.id,
                    project_revision=project.revision,
                    policy_ref=project.verification_policy_ref,
                ),
                assignment=assignment,
                assignment_history=[assignment],
                dependencies=sorted(command.dependencies),
                state="BACKLOG",
                paused=False,
                pause_reason=None,
                stop_reason=None,
                blocker=None,
                created_at=now,
                updated_at=now,
            )
            db.add(
                Task(
                    id=view.task_id,
                    project_id=view.project_id,
                    initiating_principal_id=actor.principal_id,
                    revision=view.revision,
                    snapshot=view.model_dump(mode="json"),
                )
            )
            db.flush()
            return commit_task(db, actor, "task.create.v1", command, digest, view)

    def control(
        self, actor: AuthenticatedContext, action: TaskAction, command: TaskControl
    ) -> TaskReceipt:
        if action not in ("pause", "resume", "cancel"):
            raise DomainError("VALIDATION_FAILED", "Task action is unsupported")
        name = f"task.{action}.v1"
        digest = payload_hash(command)
        with work_transaction(self.engine, actor) as db:
            previous = prior_receipt(db, actor, name, command, digest)
            if previous is not None:
                return previous
            row = task_row(db, actor, command.task_id, f"task.{action}")
            for capability in ("task.read", "task.receipt.read"):
                require_grant(db, actor, capability, project_id=row.project_id)
            view = task_view(row)
            if view.revision != command.expected_revision:
                raise DomainError("REVISION_CONFLICT", "Task changed; refresh its revision")
            if view.state in ("DONE", "CANCELLED", "ARCHIVED"):
                raise DomainError(
                    "REVISION_CONFLICT", "Task no longer accepts continuation changes"
                )
            values = view.model_dump(mode="json")
            if action == "pause":
                values.update(paused=True, pause_reason=command.reason)
                if view.state not in ("RUNNING", "REVIEW", "BLOCKED"):
                    values["state"] = "WAITING"
            elif action == "cancel":
                values.update(state="CANCELLED", stop_reason=command.reason)
            else:
                if not view.paused and view.stop_reason is None:
                    raise DomainError("REVISION_CONFLICT", "Task has no pause or stop to resume")
                project = db.get(Project, view.project_id)
                if project is None:
                    raise DomainError("DEPENDENCY_UNAVAILABLE", "Task Project is unavailable")
                pending = dependencies(db, actor, view.project_id, view.dependencies)
                blocker = view.blocker
                if view.verification_policy.policy_ref is None:
                    blocker = blocker or "Verification policy is not configured"
                elif (
                    view.verification_policy.project_revision != project.revision
                    or view.verification_policy.policy_ref != project.verification_policy_ref
                ):
                    blocker = blocker or "Project verification policy requires reconciliation"
                if any(item.state in ("CANCELLED", "ARCHIVED", "BLOCKED") for item in pending):
                    blocker = blocker or "A Task dependency cannot currently continue"
                values.update(paused=False, pause_reason=None, stop_reason=None, blocker=blocker)
                if view.state not in ("RUNNING", "REVIEW"):
                    values["state"] = (
                        "BLOCKED"
                        if blocker or view.state == "BLOCKED"
                        else "WAITING"
                        if any(item.state != "DONE" for item in pending)
                        else "BACKLOG"
                    )
                # BACKLOG is deliberate: no execution, evidence or route admission is asserted.
            values.update(revision=view.revision + 1, updated_at=datetime.now(UTC).isoformat())
            updated = TaskView.model_validate(values)
            row.revision = updated.revision
            row.snapshot = updated.model_dump(mode="json")
            db.flush()
            return commit_task(db, actor, name, command, digest, updated)
