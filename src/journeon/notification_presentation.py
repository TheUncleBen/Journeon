# SPDX-License-Identifier: AGPL-3.0-only
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, defer

from journeon.attention_contracts import AttentionAction, AttentionItem, AttentionPage
from journeon.contracts import DomainError, NotificationDismiss, NotificationReceipt
from journeon.discovery import allowed, paginate, read_transaction
from journeon.instruction_config import InstructionConfiguration
from journeon.instructions import digest
from journeon.jobs import JobService, authorize
from journeon.models import Attention, Job, NotificationPresentation, OutboxEvent, Receipt
from journeon.permissions import AuthenticatedContext


def source_in(
    db: Session,
    actor: AuthenticatedContext,
    identity: str,
    engine: Engine,
    configuration: InstructionConfiguration,
) -> tuple[Attention, Job]:
    row = db.get(Attention, identity, options=[defer(Attention.history)])
    if row is None:
        raise DomainError("NOT_FOUND", "Attention is unavailable")
    source = JobService(engine, configuration).read_in(db, actor, row.job_id)
    if source.project_id != row.project_id:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Attention source requires repair")
    job = db.get(Job, source.job_id)
    assert job is not None
    return row, job


def latest_presentation(
    db: Session, actor: AuthenticatedContext, identity: str
) -> NotificationPresentation | None:
    return db.scalar(
        select(NotificationPresentation)
        .where(
            NotificationPresentation.principal_id == actor.principal_id,
            NotificationPresentation.attention_id == identity,
        )
        .order_by(NotificationPresentation.revision.desc())
        .limit(1)
    )


def validate_history(row: Attention, job: Job) -> None:
    history = row.history
    if not isinstance(history, list) or not history:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Attention history requires repair")
    occurrences = 0
    for entry in history:
        if (
            not isinstance(entry, dict)
            or type(entry.get("at")) is not int
            or entry.get("effect") not in {"NONE", "UNKNOWN", "COMMITTED", "ABANDONED"}
        ):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Attention history requires repair")
        if "revision" in entry:
            if (
                set(entry) != {"at", "revision", "effect"}
                or type(entry["revision"]) is not int
                or not 1 <= entry["revision"] <= job.revision
            ):
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Attention history requires repair")
            occurrences += 1
        elif (
            set(entry) != {"at", "operation_id", "disposition", "effect"}
            or entry["disposition"] != "RESOLVED"
            or not isinstance(entry["operation_id"], str)
        ):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Attention history requires repair")
    if occurrences != row.occurrences:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Attention history requires repair")


def presentation_receipt_source(
    db: Session,
    actor: AuthenticatedContext,
    row: Receipt,
    engine: Engine,
    configuration: InstructionConfiguration,
) -> None:
    if row.principal_id != actor.principal_id:
        raise DomainError("NOT_FOUND", "Operation is unavailable")
    presentation = db.scalar(
        select(NotificationPresentation).where(
            NotificationPresentation.operation_id == row.id,
            NotificationPresentation.principal_id == actor.principal_id,
        )
    )
    if presentation is None:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Notification receipt requires repair")
    item, job = source_in(db, actor, presentation.attention_id, engine, configuration)
    if (row.target_id, row.project_id) != (job.id, item.project_id):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Notification receipt requires repair")


def authorized_notification_receipt(
    db: Session, actor: AuthenticatedContext, row: Receipt
) -> NotificationReceipt:
    job = db.get(Job, row.target_id)
    if row.principal_id != actor.principal_id or job is None:
        raise DomainError("NOT_FOUND", "Operation is unavailable")
    authorize(db, actor, job)
    authorize(db, actor, job, "receipt.read")
    retained = db.scalar(
        select(NotificationPresentation).where(
            NotificationPresentation.operation_id == row.id,
            NotificationPresentation.principal_id == actor.principal_id,
        )
    )
    attention = (
        db.get(Attention, retained.attention_id, options=[defer(Attention.history)])
        if retained
        else None
    )
    if (
        retained is None
        or attention is None
        or (attention.job_id, attention.project_id) != (job.id, job.project_id)
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Notification receipt requires repair")
    result = NotificationReceipt.model_validate(row.result)
    event = db.scalar(
        select(OutboxEvent)
        .options(defer(OutboxEvent.payload))
        .where(OutboxEvent.operation_id == row.id)
    )
    if (
        row.owner != "jobs"
        or row.target_kind != "job"
        or row.project_id != job.project_id
        or result.operation_id != row.id
        or result.target_id != job.id
        or result.command != row.command
        or result.attention_id != retained.attention_id
        or result.principal_id != actor.principal_id
        or result.attention_id != result.request.attention_id
        or result.request.idempotency_key != row.idempotency_key
        or digest(result.request.model_dump(mode="json", exclude={"idempotency_key"}))
        != row.payload_hash
        or result.source_revision != result.request.expected_source_revision
        or result.revision != result.request.expected_revision + 1
        or attention is None
        or (attention.job_id, attention.project_id) != (job.id, job.project_id)
        or (retained.revision, retained.source_revision, retained.disposition)
        != (result.revision, result.source_revision, result.disposition)
        or event is None
        or (
            event.owner,
            event.target_kind,
            event.target_id,
            event.project_id,
            event.principal_id,
            event.target_revision,
            event.event_type,
            event.schema_version,
            event.committed_at,
        )
        != (
            "jobs",
            "job",
            job.id,
            job.project_id,
            actor.principal_id,
            result.revision,
            "notification.dismissed",
            1,
            result.committed_at,
        )
        or NotificationReceipt.model_validate(event.payload) != result
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Notification receipt requires repair")
    return result


class NotificationPresentationService:
    def __init__(self, engine: Engine, configuration: InstructionConfiguration):
        self.engine, self.configuration = engine, configuration

    def read_in(self, db: Session, actor: AuthenticatedContext, identity: str) -> AttentionItem:
        row, job = source_in(db, actor, identity, self.engine, self.configuration)
        validate_history(row, job)
        presentation = latest_presentation(db, actor, identity)
        revision = presentation.revision if presentation else 0
        actions = []
        if job.state in {"QUEUED", "RETRY_WAIT", "RUNNING"} and allowed(
            lambda: authorize(db, actor, job, "accept")
        ):
            actions.append(
                AttentionAction(
                    operation="job.cancel.v1",
                    target_id=job.id,
                    arguments={"expected_revision": job.revision},
                )
            )
        if row.disposition == "OPEN" and allowed(lambda: authorize(db, actor, job, "receipt.read")):
            actions.append(
                AttentionAction(
                    operation="notification.dismiss.v1",
                    target_id=identity,
                    arguments={
                        "attention_id": identity,
                        "expected_revision": revision,
                        "expected_source_revision": job.revision,
                    },
                )
            )
        from journeon.jobs import view

        return AttentionItem.model_validate(
            dict(
                attention_id=identity,
                project_id=row.project_id,
                source=view(job),
                source_revision=job.revision,
                reason=row.reason,
                occurrences=row.occurrences,
                canonical_disposition=row.disposition,
                presentation_disposition=presentation.disposition
                if presentation
                else "UNACKNOWLEDGED",
                presentation_revision=revision,
                presentation_source_revision=presentation.source_revision if presentation else None,
                actions=actions,
            )
        )

    def list(
        self,
        actor: AuthenticatedContext,
        limit: int,
        cursor: str | None = None,
        project_id: str | None = None,
        canonical_disposition: str | None = None,
        presentation_disposition: str | None = None,
    ) -> AttentionPage:
        with read_transaction(self.engine, actor) as db:
            statement = select(Attention.id)
            if project_id is not None:
                statement = statement.where(Attention.project_id == project_id)

            def read(identity: str) -> AttentionItem | None:
                item = self.read_in(db, actor, identity)
                if (
                    canonical_disposition is not None
                    and item.canonical_disposition != canonical_disposition
                ):
                    return None
                if (
                    presentation_disposition is not None
                    and item.presentation_disposition != presentation_disposition
                ):
                    return None
                return item

            return AttentionPage(
                supported_coverage=["JOB"],
                **paginate(
                    db,
                    actor,
                    statement,
                    Attention.id,
                    read,
                    limit=limit,
                    cursor=cursor,
                    query={
                        "operation": "attention.list.v1",
                        "project_id": project_id,
                        "canonical_disposition": canonical_disposition,
                        "presentation_disposition": presentation_disposition,
                    },
                ),
            )

    def dismiss(
        self, actor: AuthenticatedContext, command: NotificationDismiss
    ) -> NotificationReceipt:
        payload_hash = digest(command.model_dump(mode="json", exclude={"idempotency_key"}))
        with read_transaction(self.engine, actor) as db:
            row, job = source_in(db, actor, command.attention_id, self.engine, self.configuration)
            authorize(db, actor, job, "receipt.read")
            previous = db.scalar(
                select(Receipt)
                .options(defer(Receipt.result))
                .where(
                    Receipt.principal_id == actor.principal_id,
                    Receipt.command == "notification.dismiss.v1",
                    Receipt.idempotency_key == command.idempotency_key,
                )
            )
            if previous is not None:
                from journeon.receipts import check_receipt_configuration

                check_receipt_configuration(db, actor, previous, self.engine, self.configuration)
                result = authorized_notification_receipt(db, actor, previous)
                if previous.payload_hash != payload_hash:
                    raise DomainError(
                        "IDEMPOTENCY_CONFLICT", "Operation identity has different input"
                    )
                return result
            validate_history(row, job)
            presentation = latest_presentation(db, actor, row.id)
            if command.expected_source_revision != job.revision or command.expected_revision != (
                presentation.revision if presentation else 0
            ):
                raise DomainError("REVISION_CONFLICT", "Notification or source revision changed")
            if row.disposition != "OPEN":
                raise DomainError(
                    "REVISION_CONFLICT", "Notification presentation is no longer available"
                )
            result = NotificationReceipt(
                operation_id=str(uuid4()),
                target_id=job.id,
                principal_id=actor.principal_id,
                attention_id=row.id,
                revision=command.expected_revision + 1,
                source_revision=job.revision,
                committed_at=datetime.now(UTC).isoformat(),
                request=command,
            )
            db.add(
                Receipt(
                    id=result.operation_id,
                    principal_id=actor.principal_id,
                    command=result.command,
                    idempotency_key=command.idempotency_key,
                    payload_hash=payload_hash,
                    project_id=job.project_id,
                    owner="jobs",
                    target_kind="job",
                    target_id=job.id,
                    authentication_ref=actor.authentication_ref,
                    result=result.model_dump(mode="json"),
                )
            )
            db.flush()
            db.add(
                NotificationPresentation(
                    principal_id=actor.principal_id,
                    attention_id=row.id,
                    operation_id=result.operation_id,
                    revision=result.revision,
                    disposition="DISMISSED",
                    source_revision=job.revision,
                )
            )
            db.add(
                OutboxEvent(
                    event_id=str(uuid4()),
                    operation_id=result.operation_id,
                    event_type="notification.dismissed",
                    target_revision=result.revision,
                    payload=result.model_dump(mode="json"),
                    schema_version=1,
                    principal_id=actor.principal_id,
                    project_id=job.project_id,
                    owner="jobs",
                    target_kind="job",
                    target_id=job.id,
                    committed_at=result.committed_at,
                )
            )
            db.flush()
            db.expire_all()
            final, source = source_in(
                db, actor, command.attention_id, self.engine, self.configuration
            )
            authorize(db, actor, source, "receipt.read")
            if source.revision != command.expected_source_revision or final.disposition != "OPEN":
                raise DomainError("REVISION_CONFLICT", "Notification or source revision changed")
            return result
