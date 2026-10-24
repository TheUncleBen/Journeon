# SPDX-License-Identifier: AGPL-3.0-only
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import uuid4

if TYPE_CHECKING:
    from journeon.executions import ExecutionService

from sqlalchemy import Engine, func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, defer

from journeon.contracts import DomainError
from journeon.database import transaction
from journeon.instruction_config import InstructionConfiguration
from journeon.instruction_contracts import CandidateReference, CandidateView, InstructionAccept
from journeon.job_contracts import JobCancel, JobReceipt, JobView
from journeon.models import (
    Attention,
    InstructionCandidate,
    InstructionPublication,
    Job,
    OutboxEvent,
    Receipt,
    StoreIdentity,
)
from journeon.permissions import AuthenticatedContext, require_grant
from journeon.sessions import current_session, utc_seconds


@dataclass(frozen=True)
class JobExecutionIdentity:
    job_id: str
    fence: int
    owner: str
    incarnation: str


ExecutionIdentity = JobExecutionIdentity


def view(row: Job) -> JobView:
    return JobView.model_validate(
        dict(
            job_id=row.id,
            project_id=row.project_id,
            kind=row.kind,
            candidate_id=row.candidate_id,
            task_id=row.task_id,
            revision=row.revision,
            state=row.state,
            effect=row.effect,
            reason=row.reason,
            operation_id=row.operation_id,
            admission_id=row.admission_id,
        )
    )


def authorize(db: Session, actor: AuthenticatedContext, row: Job, action: str = "read") -> None:
    if row.kind == "TASK_VERIFICATION":
        require_grant(
            db,
            actor,
            "job." + ("cancel" if action == "accept" else action),
            project_id=row.project_id,
        )
        require_grant(db, actor, "task.read", project_id=row.project_id)
        if actor.principal_id != row.principal_id:
            raise DomainError("NOT_FOUND", "Job is unavailable")
        return
    require_grant(
        db,
        actor,
        "project.instruction." + action,
        resource_kind="project",
        resource_id=row.project_id,
    )
    if actor.principal_id != row.principal_id:
        raise DomainError("NOT_FOUND", "Job is unavailable")
    from journeon.models import InstructionRoot, ProjectInstructionBinding

    binding = db.get(ProjectInstructionBinding, row.project_id)
    root = db.get(InstructionRoot, binding.root_id) if binding else None
    if (
        binding is None
        or root is None
        or not root.enabled
        or root.revision != binding.root_revision
    ):
        raise DomainError("PERMISSION_DENIED", "Current Job instruction scope is unavailable")


def record(
    db: Session, row: Job, *, admission: bool = False, event_type: str | None = None
) -> None:
    identity = row.admission_id if admission else str(uuid4())
    result = JobReceipt.model_validate(
        dict(
            operation_id=identity,
            command="job.admitted.v1" if admission else "job.changed.v1",
            target_id=row.id,
            revision=row.revision,
            committed_at=datetime.now(UTC).isoformat(),
            state=row.state,
        )
    )
    db.add(
        Receipt(
            id=identity,
            principal_id=row.principal_id,
            command=result.command,
            idempotency_key=identity,
            payload_hash=row.input_hash,
            project_id=row.project_id,
            owner="jobs",
            target_kind="job",
            target_id=row.id,
            authentication_ref=row.session_id,
            result=result.model_dump(mode="json"),
        )
    )
    db.flush()
    db.add(
        OutboxEvent(
            event_id=str(uuid4()),
            operation_id=identity,
            event_type=event_type or ("job.admitted" if admission else "job.changed"),
            schema_version=1,
            principal_id=row.principal_id,
            project_id=row.project_id,
            owner="jobs",
            target_kind="job",
            target_id=row.id,
            target_revision=row.revision,
            committed_at=result.committed_at,
            payload=result.model_dump(mode="json"),
        )
    )


def attention(db: Session, row: Job, reason: str) -> None:
    item = db.scalar(
        select(Attention).where(Attention.job_id == row.id, Attention.reason == reason)
    )
    occurrence = {"at": utc_seconds(), "revision": row.revision, "effect": row.effect}
    if item is None:
        db.add(
            Attention(
                id=str(uuid4()),
                job_id=row.id,
                project_id=row.project_id,
                reason=reason,
                occurrences=1,
                disposition="OPEN",
                history=[occurrence],
            )
        )
    else:
        item.occurrences += 1
        item.disposition = "OPEN"
        item.history = [*item.history, occurrence]
    record(db, row, event_type="attention.raised")


def admit(
    db: Session,
    actor: AuthenticatedContext,
    candidate: CandidateView,
    configuration: InstructionConfiguration,
) -> str:
    policy = configuration.jobs
    if policy is None:
        raise DomainError(
            "DEPENDENCY_UNAVAILABLE", "Explicit Job runtime configuration is required"
        )
    for action in ("read", "evaluate", "accept", "receipt.read"):
        require_grant(
            db,
            actor,
            "project.instruction." + action,
            resource_kind="project",
            resource_id=candidate.project_id,
        )
    count, size = db.execute(
        select(func.count(Job.id), func.coalesce(func.sum(Job.byte_count), 0)).where(
            Job.state.in_(("QUEUED", "RUNNING", "RETRY_WAIT"))
        )
    ).one()
    if count >= policy.pending_count or size + candidate.byte_count > policy.pending_bytes:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Configured Job admission bounds are exhausted")
    store = db.get(StoreIdentity, 1)
    if store is None or not store.security_reconciled:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Store security reconciliation is required")
    identity = candidate.job_id
    assert identity is not None
    row = Job(
        id=identity,
        kind="INSTRUCTION_NAVIGATION",
        project_id=candidate.project_id,
        candidate_id=candidate.candidate_id,
        input_hash=candidate.candidate_hash,
        binding_revision=candidate.expected_binding_revision,
        policy_revision=candidate.expected_policy_revision,
        principal_id=actor.principal_id,
        principal_epoch=actor.principal_epoch,
        session_id=actor.authentication_ref,
        revision=1,
        state="QUEUED",
        fence=0,
        claim_owner=None,
        incarnation=store.incarnation,
        lease_deadline=None,
        due_at=utc_seconds(),
        attempts=0,
        cancel_requested=False,
        reason=None,
        effect="NONE",
        operation_id=None,
        admission_id=str(uuid4()),
        evidence_id=None,
        byte_count=candidate.byte_count,
    )
    db.flush()
    db.add(row)
    db.flush()
    record(db, row, admission=True)
    return identity


class JobService:
    def __init__(
        self,
        engine: Engine,
        configuration: InstructionConfiguration,
        *,
        executions: "ExecutionService | None" = None,
    ):
        self.engine = engine
        self.configuration = configuration
        self.owner = str(uuid4())
        self.executions = executions
        self.stopping = threading.Event()

    def authority(self, db: Session, row: Job, *, candidate: bool = True) -> AuthenticatedContext:
        current = current_session(
            db, row.session_id, principal_id=row.principal_id, principal_epoch=row.principal_epoch
        )
        actor = AuthenticatedContext(current.principal_id, current.principal_epoch, current.id)
        store = db.get(StoreIdentity, 1)
        if store is None or not store.security_reconciled or row.incarnation != store.incarnation:
            raise DomainError("PERMISSION_DENIED", "Job store incarnation is no longer current")
        if row.kind == "TASK_VERIFICATION":
            from journeon.task_dispatch import TaskDispatchService

            TaskDispatchService(self.engine, self.configuration).bound(
                db, actor, row, execution=True
            )
            return actor
        for action in ("read", "evaluate", "accept", "receipt.read"):
            authorize(db, actor, row, action)
        from journeon.instruction_contracts import InstructionPolicy
        from journeon.models import ProjectInstructionBinding, ProjectInstructionPolicy

        binding = db.get(ProjectInstructionBinding, row.project_id)
        if (
            binding is None
            or (binding.revision, binding.policy_revision)
            != (row.binding_revision, row.policy_revision)
            or binding.active_operation != (None if candidate else row.operation_id)
        ):
            raise DomainError("REVISION_CONFLICT", "Job candidate or policy changed")
        proposed = db.get(
            InstructionCandidate, row.candidate_id, options=[defer(InstructionCandidate.snapshot)]
        )
        if (
            proposed is None
            or proposed.project_id != row.project_id
            or proposed.payload_hash != row.input_hash
            or proposed.principal_id != row.principal_id
        ):
            raise DomainError("PERMISSION_DENIED", "Job candidate authority differs")
        candidate_view = CandidateView.model_validate(proposed.snapshot["view"])
        policy = db.get(ProjectInstructionPolicy, (row.project_id, row.policy_revision))
        if policy is None or not candidate_view.automatic or candidate_view.job_id != row.id:
            raise DomainError("PERMISSION_DENIED", "Job requires an eligible automatic candidate")
        current_policy = InstructionPolicy.model_validate(policy.snapshot)
        if (
            not current_policy.navigation_repairs
            or "NAVIGATION_REPAIR" not in current_policy.authorized_categories
        ):
            raise DomainError("PERMISSION_DENIED", "Current policy does not authorize this Job")
        return actor

    def read(self, actor: AuthenticatedContext, identity: str) -> JobView:
        with transaction(self.engine) as db:
            row = db.get(Job, identity)
            if row is None:
                raise DomainError("NOT_FOUND", "Job is unavailable")
            authorize(db, actor, row)
            if row.kind == "TASK_VERIFICATION":
                from journeon.task_dispatch import TaskDispatchService

                TaskDispatchService(self.engine, self.configuration).bound(db, actor, row)
            return view(row)

    def cancel(self, actor: AuthenticatedContext, identity: str, command: JobCancel) -> JobView:
        with transaction(self.engine) as db:
            row = db.get(Job, identity)
            if row is None:
                raise DomainError("NOT_FOUND", "Job is unavailable")
            authorize(db, actor, row, "accept")
            if row.revision != command.expected_revision:
                raise DomainError("REVISION_CONFLICT", "Job revision changed")
            if row.state in {"QUEUED", "RETRY_WAIT", "RUNNING"}:
                row.cancel_requested = True
                row.reason = "CANCEL_REQUESTED"
                if row.state != "RUNNING":
                    row.state = "CANCELLED"
                row.revision += 1
                record(db, row)
            return view(row)

    def claim(self) -> ExecutionIdentity | None:
        config = self.configuration.jobs
        if config is None:
            return None
        with transaction(self.engine) as db:
            if (
                db.scalar(select(func.count(Job.id)).where(Job.state == "RUNNING")) or 0
            ) >= config.concurrency:
                return None
            for row in db.scalars(
                select(Job)
                .where(Job.state.in_(("QUEUED", "RETRY_WAIT")), Job.due_at <= utc_seconds())
                .order_by(Job.due_at, Job.id)
            ):
                try:
                    self.authority(db, row)
                except DomainError:
                    row.state, row.reason = "FAILED", "CURRENT_AUTHORITY_REQUIRED"
                    row.revision += 1
                    attention(db, row, row.reason)
                    record(db, row)
                    continue
                if row.cancel_requested:
                    row.state = "CANCELLED"
                    row.revision += 1
                    record(db, row)
                    continue
                row.state = "RUNNING"
                row.claim_owner = self.owner
                row.fence += 1
                row.attempts += 1
                row.revision += 1
                row.lease_deadline = utc_seconds() + config.lease_seconds
                record(db, row)
                return ExecutionIdentity(row.id, row.fence, self.owner, row.incarnation)
        return None

    def check(
        self, db: Session, identity: ExecutionIdentity, *, renew: bool = False
    ) -> tuple[Job, AuthenticatedContext]:
        row = db.get(Job, identity.job_id, populate_existing=True)
        if (
            row is None
            or row.state != "RUNNING"
            or row.cancel_requested
            or (row.fence, row.claim_owner, row.incarnation)
            != (identity.fence, identity.owner, identity.incarnation)
            or row.lease_deadline is None
            or utc_seconds() >= row.lease_deadline
        ):
            raise DomainError("PERMISSION_DENIED", "Job execution ownership is no longer current")
        actor = self.authority(db, row, candidate=row.operation_id is None)
        if renew:
            assert self.configuration.jobs is not None
            row.lease_deadline = utc_seconds() + self.configuration.jobs.lease_seconds
        return row, actor

    def execute(self, identity: ExecutionIdentity) -> None:
        from journeon.project_instructions import ProjectInstructionService

        with transaction(self.engine) as db:
            row = db.get(Job, identity.job_id)
            if row is not None and row.kind == "TASK_VERIFICATION":
                task_job = True
            else:
                task_job = False
        if task_job:
            self.execute_task(identity)
            return
        service = ProjectInstructionService(self.engine, self.configuration, execution=identity)
        try:
            with transaction(self.engine) as db:
                row, actor = self.check(db, identity)
                candidate = db.get(InstructionCandidate, row.candidate_id)
                assert candidate is not None
                reference = CandidateView.model_validate(candidate.snapshot["view"])
                evidence = row.evidence_id
            if evidence is None:
                evidence = service.evaluate(actor, reference)
                with transaction(self.engine) as db:
                    row, _ = self.check(db, identity)
                    row.evidence_id = evidence
            result = service.accept(
                actor,
                InstructionAccept(
                    **reference.model_dump(include=set(CandidateReference.model_fields)),
                    idempotency_key="automatic:" + reference.candidate_id,
                    review_ids=[],
                    eval_ids=[evidence],
                ),
            )
            with transaction(self.engine) as db:
                settled = db.get(Job, identity.job_id)
                assert settled is not None
                row = settled
                if row.state == "RUNNING" and (row.fence, row.claim_owner, row.incarnation) == (
                    identity.fence,
                    identity.owner,
                    identity.incarnation,
                ):
                    row.operation_id = result.operation_id
                    row.effect, row.state, row.reason = (
                        "COMMITTED",
                        ("CANCELLED" if row.cancel_requested else "SUCCEEDED"),
                        None,
                    )
                    row.revision += 1
                    record(db, row)
        except (DomainError, OSError, ValueError):
            self.reconcile(identity.job_id, expected=identity)

    def execute_task(self, identity: ExecutionIdentity) -> None:
        from journeon.executions import ExecutionService
        from journeon.models import Execution, TaskVerificationJob
        from journeon.task_dispatch import TaskDispatchService, execution_command

        if self.executions is None:
            self.executions = ExecutionService(self.engine, self.configuration)
        dispatcher = TaskDispatchService(self.engine, self.configuration)
        try:
            with transaction(self.engine) as db:
                row, actor = self.check(db, identity, renew=True)
                binding, command, manifest = dispatcher.bound(db, actor, row, execution=True)
                linked = binding.execution_id
            if linked is None:
                self.executions.start(
                    actor, execution_command(command, manifest, row.id), job=identity
                )
            assert self.configuration.jobs is not None
            interval = min(
                self.configuration.jobs.poll_seconds, self.configuration.jobs.lease_seconds / 3
            )
            while True:
                if self.stopping.is_set():
                    self.executions.shutdown()
                with transaction(self.engine) as db:
                    found = db.get(Job, identity.job_id)
                    assert found is not None
                    row = found
                    linked_binding = db.get(
                        TaskVerificationJob, row.id, options=[defer(TaskVerificationJob.inputs)]
                    )
                    assert linked_binding is not None
                    binding = linked_binding
                    execution = (
                        db.get(
                            Execution,
                            binding.execution_id,
                            options=[defer(Execution.snapshot), defer(Execution.inputs)],
                        )
                        if binding.execution_id
                        else None
                    )
                    if execution is None:
                        break
                    if execution.state not in ("STARTING", "RUNNING"):
                        dispatcher.settle(db, row)
                        return
                    if row.lease_deadline is None or utc_seconds() + interval >= row.lease_deadline:
                        try:
                            self.check(db, identity, renew=True)
                        except DomainError:
                            pass
                self.stopping.wait(interval)
        except (DomainError, OSError, ValueError, RuntimeError):
            self.reconcile(identity.job_id, expected=identity)

    def reconcile(
        self, identity: str | None = None, *, expected: ExecutionIdentity | None = None
    ) -> None:
        config = self.configuration.jobs
        if config is None:
            return
        with transaction(self.engine) as db:
            if expected is None:
                for operation in db.scalars(
                    select(Job.operation_id)
                    .join(InstructionPublication, Job.operation_id == InstructionPublication.id)
                    .where(
                        Job.effect == "UNKNOWN",
                        InstructionPublication.status.in_(("CANONICAL_COMMITTED", "ABANDONED")),
                    )
                ).all():
                    assert operation is not None
                    settle_recovery_in_transaction(db, operation)
            query = select(Job).where(Job.state == "RUNNING")
            if identity is not None:
                query = query.where(Job.id == identity)
            for row in db.scalars(query):
                if expected is not None and (
                    row.id,
                    row.fence,
                    row.claim_owner,
                    row.incarnation,
                ) != (expected.job_id, expected.fence, expected.owner, expected.incarnation):
                    continue
                if (
                    expected is None
                    and row.lease_deadline is not None
                    and utc_seconds() < row.lease_deadline
                ):
                    continue
                if row.kind == "TASK_VERIFICATION":
                    from journeon.models import TaskVerificationJob
                    from journeon.task_dispatch import TaskDispatchService

                    if TaskDispatchService(self.engine, self.configuration).settle(
                        db, row, reconcile=True
                    ):
                        continue
                    binding = db.get(
                        TaskVerificationJob, row.id, options=[defer(TaskVerificationJob.inputs)]
                    )
                    if binding is not None and binding.execution_id is not None:
                        row.effect, row.state, row.reason = (
                            "UNKNOWN",
                            "FAILED",
                            "EXECUTION_RECONCILIATION_REQUIRED",
                        )
                        row.revision += 1
                        attention(db, row, row.reason)
                        record(db, row)
                        continue
                journal = (
                    db.get(InstructionPublication, row.operation_id) if row.operation_id else None
                )
                if journal is not None:
                    row.effect = (
                        "COMMITTED"
                        if journal.status == "CANONICAL_COMMITTED"
                        else "ABANDONED"
                        if journal.status == "ABANDONED"
                        else "UNKNOWN"
                    )
                    row.state = (
                        "CANCELLED"
                        if row.cancel_requested
                        else "SUCCEEDED"
                        if row.effect == "COMMITTED"
                        else "FAILED"
                    )
                    row.reason = (
                        None if row.effect == "COMMITTED" else "PUBLICATION_RECONCILIATION_REQUIRED"
                    )
                elif row.cancel_requested:
                    row.state, row.reason = "CANCELLED", "CANCEL_REQUESTED"
                else:
                    try:
                        self.authority(db, row)
                        if row.attempts >= config.max_attempts:
                            row.state, row.reason = "FAILED", "RETRIES_EXHAUSTED"
                        else:
                            row.state, row.reason = "RETRY_WAIT", "EFFECT_FREE_INTERRUPTION"
                            row.due_at = utc_seconds() + config.retry_seconds
                    except DomainError:
                        row.state, row.reason = "FAILED", "CURRENT_AUTHORITY_REQUIRED"
                row.revision += 1
                row.fence += 1
                if row.reason and row.state == "FAILED":
                    attention(db, row, row.reason)
                record(db, row)

    def run(self, stop: threading.Event) -> None:
        config = self.configuration.jobs
        if config is None:
            return
        pressure = 0
        self.stopping = stop
        try:
            while not stop.is_set():
                try:
                    self.reconcile()
                    identity = self.claim()
                    if identity is not None:
                        if stop.is_set():
                            self.reconcile(identity.job_id, expected=identity)
                            break
                        self.execute(identity)
                    else:
                        stop.wait(config.poll_seconds)
                    pressure = 0
                except OperationalError as error:
                    code = getattr(error.orig, "sqlite_errorcode", None)
                    if code is None or code & 0xFF not in (
                        sqlite3.SQLITE_BUSY,
                        sqlite3.SQLITE_LOCKED,
                    ):
                        raise
                    pressure += 1
                    if pressure >= config.max_attempts:
                        raise
                    print(json.dumps({"status": "JOB_STORAGE_PRESSURE"}), flush=True)
                    stop.wait(config.retry_seconds)
        except Exception:
            print(json.dumps({"status": "JOB_WORKER_FAILED"}), flush=True)


def settle_recovery(engine: Engine, operation: str) -> None:
    with transaction(engine) as db:
        settle_recovery_in_transaction(db, operation)


def settle_recovery_in_transaction(db: Session, operation: str) -> None:
    row = db.scalar(select(Job).where(Job.operation_id == operation))
    journal = db.get(InstructionPublication, operation)
    if row is None or journal is None or journal.status not in {"CANONICAL_COMMITTED", "ABANDONED"}:
        return
    if row.reason == "PROTECTED_RECOVERY_COMPLETED":
        return
    row.effect = "COMMITTED" if journal.status == "CANONICAL_COMMITTED" else "ABANDONED"
    row.state = (
        "CANCELLED"
        if row.cancel_requested
        else "SUCCEEDED"
        if row.effect == "COMMITTED"
        else "FAILED"
    )
    row.reason = "PROTECTED_RECOVERY_COMPLETED"
    row.revision += 1
    row.fence += 1
    for item in db.scalars(select(Attention).where(Attention.job_id == row.id)):
        item.disposition = "RESOLVED"
        item.history = [
            *item.history,
            {
                "at": utc_seconds(),
                "operation_id": operation,
                "disposition": "RESOLVED",
                "effect": row.effect,
            },
        ]
    record(db, row, event_type="attention.resolved")
