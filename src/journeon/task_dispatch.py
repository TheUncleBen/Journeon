# SPDX-License-Identifier: AGPL-3.0-only
"""Task verification admission and evidence owned by the canonical Job dispatcher."""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session, defer

from journeon.attempts import AttemptService, authorized_attempt, validate_attempt_view
from journeon.contracts import (
    AttemptPrepare,
    AttemptView,
    DomainError,
    ExecutionStart,
    RunManifest,
    RuntimeConfigurationUnavailable,
    TaskCriterion,
)
from journeon.instruction_config import InstructionConfiguration
from journeon.instructions import digest
from journeon.job_contracts import JobView, TaskDispatch, TaskEvidence
from journeon.models import (
    Execution,
    ExecutionEffect,
    Job,
    Receipt,
    StoreIdentity,
    TaskVerificationEvidence,
    TaskVerificationJob,
)
from journeon.permissions import AuthenticatedContext, require_grant
from journeon.sessions import utc_seconds
from journeon.work import task_row, task_view, work_transaction


def prepare_command(command: TaskDispatch) -> AttemptPrepare:
    return AttemptPrepare.model_validate(
        command.model_dump(include=set(AttemptPrepare.model_fields))
    )


def execution_command(command: TaskDispatch, manifest: RunManifest, job_id: str) -> ExecutionStart:
    assert manifest.task.workflow is not None
    step = next(item for item in manifest.task.workflow.steps if item.step_id == command.step_id)
    assert step.check_id is not None
    return ExecutionStart(
        idempotency_key=job_id,
        project_id=command.project_id,
        root_key=manifest.root_id,
        root_revision=manifest.root_revision,
        expected_policy_revision=command.expected_policy_revision,
        route_key=command.route_key,
        route_revision=command.route_revision,
        check_id=step.check_id,
    )


def require_recorded_history(manifest: RunManifest) -> None:
    if manifest.snapshot.kind == "GIT" and manifest.snapshot.git_history is None:
        raise DomainError(
            "DEPENDENCY_UNAVAILABLE", "Git history boundary was not captured; prepare a new Attempt"
        )


def check_step(db: Session, command: TaskDispatch, manifest: RunManifest) -> TaskCriterion:
    workflow = manifest.task.workflow
    if workflow is None:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Task workflow is unavailable")
    steps = {item.step_id: item for item in workflow.steps}
    step = steps.get(command.step_id)
    if step is None:
        raise DomainError("REVISION_CONFLICT", "Verification workflow step changed")
    if step.kind != "VERIFICATION" or any(command.step_id in loop.steps for loop in workflow.loops):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "This workflow step has no execution producer")
    for dependency in step.dependencies:
        if steps[dependency].kind != "VERIFICATION":
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Workflow prerequisite producer is unavailable"
            )
        prior = db.scalar(
            select(TaskVerificationEvidence)
            .join(
                TaskVerificationJob, TaskVerificationEvidence.job_id == TaskVerificationJob.job_id
            )
            .where(
                TaskVerificationEvidence.manifest_id == manifest.manifest_id,
                TaskVerificationJob.step_id == dependency,
            )
        )
        if prior is None:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Workflow prerequisite evidence is unavailable"
            )
        evidence = TaskEvidence.model_validate(prior.snapshot)
        if (
            not evidence.passed
            or evidence.manifest != manifest
            or evidence.content_digest != prior.content_hash
            or digest(evidence.model_dump(mode="json", exclude={"content_digest"}))
            != prior.content_hash
        ):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Workflow prerequisite did not pass this snapshot"
            )
    check = next(
        (item for item in manifest.verification_policy.checks if item.check_id == step.check_id),
        None,
    )
    criterion = next(
        (
            item
            for item in manifest.task.success_conditions
            if check and item.text == check.criterion
        ),
        None,
    )
    if criterion is None:
        raise DomainError(
            "PERMISSION_DENIED", "Verification check does not prove an exact Task criterion"
        )
    return criterion


class TaskDispatchService:
    def __init__(self, engine: Engine, configuration: InstructionConfiguration):
        self.engine, self.configuration = engine, configuration
        self.attempts = AttemptService(engine, configuration)

    def grants(self, db: Session, actor: AuthenticatedContext, project: str) -> None:
        for capability in (
            "task.dispatch",
            "task.read",
            "job.read",
            "job.cancel",
            "job.receipt.read",
        ):
            require_grant(db, actor, capability, project_id=project)

    def bound(
        self, db: Session, actor: AuthenticatedContext, row: Job, *, execution: bool = False
    ) -> tuple[TaskVerificationJob, TaskDispatch, RunManifest]:
        try:
            return self._bound(db, actor, row, execution=execution)
        except (ValueError, KeyError, TypeError):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Stored Task Job binding requires repair"
            ) from None

    def _bound(
        self, db: Session, actor: AuthenticatedContext, row: Job, *, execution: bool = False
    ) -> tuple[TaskVerificationJob, TaskDispatch, RunManifest]:
        from journeon.executions import ExecutionService
        from journeon.jobs import authorize

        authorize(db, actor, row)
        for capability in ("attempt.read", "project.instruction.read", "project.verification.read"):
            require_grant(db, actor, capability, project_id=row.project_id)
        if execution:
            self.grants(db, actor, row.project_id)
        binding = db.get(TaskVerificationJob, row.id, options=[defer(TaskVerificationJob.inputs)])
        if binding is None or binding.principal_id != row.principal_id:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Task Job binding requires repair")
        attempt = authorized_attempt(db, actor, binding.attempt_id)
        self.attempts.check_configuration(db, attempt)
        executions = self.configuration.executions
        if executions is None:
            raise RuntimeConfigurationUnavailable("Local execution routes are not configured")
        if executions.revision != binding.configuration_revision or not any(
            route.project_id == row.project_id
            and digest(route.model_dump(mode="json")) == binding.route_digest
            for route in executions.routes
        ):
            raise DomainError("PERMISSION_DENIED", "Task verification route scope changed")
        if row.task_id is None:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Task Job origin is unavailable")
        current = task_view(task_row(db, actor, row.task_id, "task.read"))
        command = TaskDispatch.model_validate(binding.inputs)
        if execution:
            self.attempts.inputs(db, actor, prepare_command(command))
        from journeon.verification import current_policy

        policy = current_policy(db, actor, row.project_id)
        view = AttemptView.model_validate(attempt.snapshot)
        validate_attempt_view(db, attempt, view)
        manifest = view.manifest
        if (
            manifest is None
            or manifest.manifest_id != binding.manifest_id
            or manifest.project_id != row.project_id
            or attempt.task_id != row.task_id
            or command.project_id != row.project_id
            or command.origin.task_id != row.task_id
            or digest(command.model_dump(mode="json", exclude={"idempotency_key"}))
            != row.input_hash
            or current.project_id != row.project_id
            or (execution and manifest.task != current)
            or command.origin.task_revision != row.binding_revision
            or command.expected_policy_revision != row.policy_revision
            or command.step_id != binding.step_id
            or manifest.task.revision != row.binding_revision
            or manifest.verification_policy.revision != row.policy_revision
            or (execution and policy != manifest.verification_policy)
            or (
                manifest.initiating_principal_id,
                manifest.authentication_ref,
                manifest.principal_epoch,
            )
            != (row.principal_id, row.session_id, row.principal_epoch)
        ):
            raise DomainError("REVISION_CONFLICT", "Task Job inputs are no longer current")
        if execution:
            require_recorded_history(manifest)
        check_step(db, command, manifest)
        service = ExecutionService(self.engine, self.configuration)
        route = service.route(command.route_key, command.route_revision)
        if (
            route.project_id != row.project_id
            or route.check_id != execution_command(command, manifest, row.id).check_id
            or digest(route.model_dump(mode="json")) != binding.route_digest
        ):
            raise DomainError("PERMISSION_DENIED", "Task verification route scope changed")
        if execution:
            service.inputs(db, actor, execution_command(command, manifest, row.id))
        return binding, command, manifest

    def admit(self, actor: AuthenticatedContext, command: TaskDispatch) -> JobView:
        from journeon.executions import ExecutionService
        from journeon.jobs import record, view

        command_hash = digest(command.model_dump(mode="json", exclude={"idempotency_key"}))
        with work_transaction(self.engine, actor) as db:
            self.grants(db, actor, command.project_id)
            current, policy = self.attempts.inputs(db, actor, prepare_command(command))
            prior = db.scalar(
                select(TaskVerificationJob)
                .options(defer(TaskVerificationJob.inputs))
                .where(
                    TaskVerificationJob.principal_id == actor.principal_id,
                    TaskVerificationJob.idempotency_key == command.idempotency_key,
                )
            )
            if prior is not None:
                row = db.get(Job, prior.job_id)
                assert row is not None
                self.bound(db, actor, row, execution=True)
                if row.input_hash != command_hash:
                    raise DomainError(
                        "IDEMPOTENCY_CONFLICT", "Task dispatch identity has different input"
                    )
                return view(row)
            workflow = current.workflow
            step = (
                next((item for item in workflow.steps if item.step_id == command.step_id), None)
                if workflow
                else None
            )
            if step is None:
                raise DomainError("REVISION_CONFLICT", "Verification workflow step changed")
            assert workflow is not None
            if (
                step.kind != "VERIFICATION"
                or any(
                    item.kind != "VERIFICATION"
                    for item in workflow.steps
                    if item.step_id in step.dependencies
                )
                or any(step.step_id in loop.steps for loop in workflow.loops)
            ):
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE", "Workflow prerequisite producer is unavailable"
                )
            if step.dependencies and command.attempt_id is None:
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE",
                    "Workflow prerequisites require evidence from the same Attempt",
                )
            for action in ("start", "read", "stop", "drain", "complete", "receipt.read"):
                require_grant(db, actor, "execution." + action, project_id=command.project_id)
        config = self.configuration.jobs
        if config is None:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Explicit Job runtime configuration is required"
            )
        if command.attempt_id is None:
            prepared = self.attempts.prepare(
                actor, prepare_command(command), dispatch=command
            ).attempt
        else:
            prepared = self.attempts.read(actor, command.attempt_id)
        manifest = prepared.manifest
        if manifest is None:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Task dispatch requires a prepared Attempt")
        with work_transaction(self.engine, actor) as db:
            self.grants(db, actor, command.project_id)
            current, policy = self.attempts.inputs(db, actor, prepare_command(command))
            attempt = authorized_attempt(db, actor, prepared.attempt_id)
            self.attempts.check_configuration(db, attempt)
            validate_attempt_view(db, attempt, prepared)
            if (
                manifest.task != current
                or manifest.verification_policy != policy
                or (manifest.workspace_key, manifest.workspace_revision)
                != (command.workspace_key, command.workspace_revision)
                or (
                    manifest.initiating_principal_id,
                    manifest.authentication_ref,
                    manifest.principal_epoch,
                )
                != (actor.principal_id, actor.authentication_ref, actor.principal_epoch)
            ):
                raise DomainError(
                    "REVISION_CONFLICT", "Prepared Attempt does not bind the current Task"
                )
            require_recorded_history(manifest)
            check_step(db, command, manifest)
            identity = str(uuid4())
            _, _, route = ExecutionService(self.engine, self.configuration).inputs(
                db, actor, execution_command(command, manifest, identity)
            )
            duplicate = db.scalar(
                select(TaskVerificationJob).where(
                    TaskVerificationJob.attempt_id == attempt.id,
                    TaskVerificationJob.step_id == command.step_id,
                )
            )
            if duplicate is not None:
                row = db.get(Job, duplicate.job_id)
                assert row is not None
                self.bound(db, actor, row, execution=True)
                if (
                    duplicate.idempotency_key != command.idempotency_key
                    or row.input_hash != command_hash
                ):
                    raise DomainError("IDEMPOTENCY_CONFLICT", "This Attempt step already has a Job")
                return view(row)
            count, size = db.execute(
                select(func.count(Job.id), func.coalesce(func.sum(Job.byte_count), 0)).where(
                    Job.state.in_(("QUEUED", "RUNNING", "RETRY_WAIT"))
                )
            ).one()
            byte_count = len(command.model_dump_json().encode()) + len(
                manifest.model_dump_json().encode()
            )
            if count >= config.pending_count or size + byte_count > config.pending_bytes:
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE", "Configured Job admission bounds are exhausted"
                )
            store = db.get(StoreIdentity, 1)
            if store is None or not store.security_reconciled:
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE", "Store security reconciliation is required"
                )
            row = Job(
                id=identity,
                kind="TASK_VERIFICATION",
                project_id=command.project_id,
                task_id=current.task_id,
                candidate_id=None,
                input_hash=command_hash,
                binding_revision=current.revision,
                policy_revision=policy.revision,
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
                byte_count=byte_count,
            )
            db.add(row)
            db.flush()
            assert self.configuration.executions is not None
            db.add(
                TaskVerificationJob(
                    job_id=identity,
                    attempt_id=attempt.id,
                    manifest_id=manifest.manifest_id,
                    principal_id=actor.principal_id,
                    idempotency_key=command.idempotency_key,
                    step_id=command.step_id,
                    route_digest=digest(route.model_dump(mode="json")),
                    configuration_revision=self.configuration.executions.revision,
                    inputs=command.model_dump(mode="json"),
                )
            )
            record(db, row, admission=True)
            return view(row)

    def evidence(self, actor: AuthenticatedContext, identity: str) -> TaskEvidence:
        with work_transaction(self.engine, actor) as db:
            return self.evidence_in(db, actor, identity)

    def evidence_in(self, db: Session, actor: AuthenticatedContext, identity: str) -> TaskEvidence:
        from journeon.executions import authorized_execution

        row = db.get(Job, identity)
        if row is None or row.kind != "TASK_VERIFICATION":
            raise DomainError("NOT_FOUND", "Task verification Job is unavailable")
        require_grant(db, actor, "execution.read", project_id=row.project_id)
        require_grant(db, actor, "project.read", project_id=row.project_id)
        binding, _, manifest = self.bound(db, actor, row)
        if binding.execution_id is None:
            raise DomainError("NOT_FOUND", "Task verification evidence is unavailable")
        authorized_execution(db, actor, binding.execution_id)
        evidence = db.scalar(
            select(TaskVerificationEvidence).where(TaskVerificationEvidence.job_id == identity)
        )
        if evidence is None:
            raise DomainError("NOT_FOUND", "Task verification evidence is unavailable")
        try:
            result = TaskEvidence.model_validate(evidence.snapshot)
        except ValueError:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Task verification evidence requires repair"
            ) from None
        if (
            result.evidence_id != evidence.id
            or result.job_id != row.id
            or result.attempt_id != binding.attempt_id
            or result.execution.execution_id != binding.execution_id
            or result.manifest != manifest
            or result.step_id != binding.step_id
            or result.content_digest != evidence.content_hash
            or digest(result.model_dump(mode="json", exclude={"content_digest"}))
            != evidence.content_hash
        ):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Task verification evidence requires repair"
            )
        return result

    def settle(self, db: Session, row: Job, *, reconcile: bool = False) -> bool:
        from journeon.executions import execution_view
        from journeon.jobs import JobExecutionIdentity, JobService, attention, record

        if row.state != "RUNNING":
            return True
        binding = db.get(TaskVerificationJob, row.id, options=[defer(TaskVerificationJob.inputs)])
        if binding is None or binding.execution_id is None:
            return False
        execution = db.get(Execution, binding.execution_id)
        if execution is None:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Task Execution binding requires repair")
        if execution.state in ("STARTING", "RUNNING"):
            return False
        observed = execution_view(db, execution)
        row.effect = (
            "UNKNOWN" if observed.state == "UNKNOWN" or not observed.drained else "COMMITTED"
        )
        final_state = (
            "CANCELLED" if row.cancel_requested or observed.state == "CANCELLED" else "FAILED"
        )
        row.reason = (
            "EXECUTION_RECONCILIATION_REQUIRED"
            if row.effect == "UNKNOWN"
            else "VERIFICATION_FAILED"
        )
        try:
            if (
                binding.claim_fence is None
                or binding.claim_owner is None
                or binding.claim_incarnation is None
            ):
                raise DomainError("PERMISSION_DENIED", "Task verification claim is unavailable")
            if (
                reconcile
                and observed.state == "COMPLETED"
                and observed.drained
                and not row.cancel_requested
                and execution.job_id == row.id
                and (row.fence, row.claim_owner, row.incarnation)
                == (binding.claim_fence, binding.claim_owner, binding.claim_incarnation)
            ):
                JobService(self.engine, self.configuration).authority(db, row)
                assert self.configuration.jobs is not None
                row.lease_deadline = utc_seconds() + self.configuration.jobs.lease_seconds
            _, actor = JobService(self.engine, self.configuration).check(
                db,
                JobExecutionIdentity(
                    row.id, binding.claim_fence, binding.claim_owner, binding.claim_incarnation
                ),
                renew=True,
            )
            binding, command, manifest = self.bound(db, actor, row, execution=True)
            if (
                row.cancel_requested
                or observed.state != "COMPLETED"
                or not observed.drained
                or (row.fence, row.claim_owner, row.incarnation)
                != (binding.claim_fence, binding.claim_owner, binding.claim_incarnation)
                or execution.job_id != row.id
                or execution.inputs.get("source_snapshot")
                != manifest.snapshot.model_dump(mode="json")
                or execution.inputs.get("origin")
                != {
                    "kind": "TASK_VERIFICATION",
                    "attempt_id": binding.attempt_id,
                    "manifest_id": manifest.manifest_id,
                }
                or execution.inputs.get("job")
                != {
                    "job_id": row.id,
                    "fence": binding.claim_fence,
                    "owner": binding.claim_owner,
                    "incarnation": binding.claim_incarnation,
                }
            ):
                raise DomainError(
                    "PERMISSION_DENIED", "Task verification publication is unavailable"
                )
            assert binding.claim_fence is not None
            assert binding.claim_owner is not None
            assert binding.claim_incarnation is not None
            started = db.scalar(
                select(ExecutionEffect).where(
                    ExecutionEffect.execution_id == execution.id, ExecutionEffect.kind == "STARTED"
                )
            )
            operation = (
                db.get(Receipt, row.operation_id, options=[defer(Receipt.result)])
                if row.operation_id
                else None
            )
            if (
                started is None
                or type(started.observation.get("process_id")) is not int
                or started.observation["process_id"] <= 1
                or started.observation.get("invocation_id") != observed.invocation_id
                or operation is None
                or operation.command != "execution.start.v1"
                or operation.target_id != execution.id
                or operation.principal_id != row.principal_id
            ):
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE", "Task process provenance requires repair"
                )
            criterion = check_step(db, command, manifest)
            evidence = db.scalar(
                select(TaskVerificationEvidence).where(TaskVerificationEvidence.job_id == row.id)
            )
            if evidence is None:
                result = TaskEvidence(
                    evidence_id=str(uuid4()),
                    job_id=row.id,
                    attempt_id=binding.attempt_id,
                    manifest=manifest,
                    step_id=binding.step_id,
                    criterion=criterion,
                    claim_fence=binding.claim_fence,
                    claim_owner=binding.claim_owner,
                    claim_incarnation=binding.claim_incarnation,
                    execution=observed,
                    execution_operation_id=operation.id,
                    process_id=started.observation["process_id"],
                    passed=observed.verification_passed,
                    published_at=datetime.now(UTC).isoformat(),
                    content_digest="pending",
                )
                result = result.model_copy(
                    update={
                        "content_digest": digest(
                            result.model_dump(mode="json", exclude={"content_digest"})
                        )
                    }
                )
                evidence = TaskVerificationEvidence(
                    id=result.evidence_id,
                    job_id=row.id,
                    execution_id=execution.id,
                    manifest_id=manifest.manifest_id,
                    content_hash=result.content_digest,
                    snapshot=result.model_dump(mode="json"),
                )
                db.add(evidence)
            row.evidence_id = evidence.id
            final_state = "SUCCEEDED" if observed.verification_passed else "FAILED"
            row.reason = None if observed.verification_passed else "VERIFICATION_FAILED"
        except DomainError:
            if row.effect != "UNKNOWN":
                row.reason = "EVIDENCE_PUBLICATION_BLOCKED"
        row.state = final_state
        row.revision += 1
        if row.reason:
            attention(db, row, row.reason)
        record(db, row)
        return True
