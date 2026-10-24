# SPDX-License-Identifier: AGPL-3.0-only
"""Commit one exact-candidate completion from current, service-produced evidence."""

from datetime import UTC, datetime

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, defer

from journeon.contracts import (
    DomainError,
    TaskComplete,
    TaskCompletionBinding,
    TaskReceipt,
    TaskView,
)
from journeon.executions import authorized_execution, execution_receipt, execution_view
from journeon.instruction_config import InstructionConfiguration
from journeon.models import ExecutionEffect, Job, Receipt, TaskVerificationJob
from journeon.permissions import AuthenticatedContext, require_grant
from journeon.review_targets import ReviewTargetService, read_target, require_current_target
from journeon.task_dispatch import TaskDispatchService
from journeon.work import commit_task, payload_hash, prior_receipt, task_row, task_view


def complete(
    db: Session,
    engine: Engine,
    actor: AuthenticatedContext,
    command: TaskComplete,
    configuration: InstructionConfiguration | None,
) -> TaskReceipt:
    name = "task.complete.v1"
    command_hash = payload_hash(command)
    prior = prior_receipt(db, actor, name, command, command_hash)
    if prior is not None:
        return prior
    row = task_row(db, actor, command.task_id, "task.complete")
    for capability in (
        "task.read",
        "task.receipt.read",
        "execution.read",
        "execution.receipt.read",
        "project.read",
        "job.read",
    ):
        require_grant(db, actor, capability, project_id=row.project_id)
    current = task_view(row)
    if current.revision != command.expected_revision:
        raise DomainError("REVISION_CONFLICT", "Task changed; refresh its revision")
    if current.state not in ("READY", "RUNNING", "REVIEW"):
        raise DomainError("REVISION_CONFLICT", "Task state does not permit completion")
    ReviewTargetService(engine, configuration).check_configuration(db, actor, command.target_id)
    target = read_target(db, actor, command.target_id)
    if (
        target.manifest.task.task_id != current.task_id
        or target.content_digest != command.target_digest
    ):
        raise DomainError("REVISION_CONFLICT", "Selected completion candidate changed")
    require_current_target(db, engine, actor, target)
    ReviewTargetService(engine, configuration).check_configuration(db, actor, target.target_id)
    if target.review_policy.independent_review_required:
        raise DomainError(
            "DEPENDENCY_UNAVAILABLE", "Qualified independent review evidence is unavailable"
        )
    workflow = current.workflow
    if (
        workflow is None
        or workflow.loops
        or any(
            step.kind != "VERIFICATION" or step.condition_step is not None
            for step in workflow.steps
        )
    ):
        raise DomainError(
            "DEPENDENCY_UNAVAILABLE", "Required workflow gate producer is unavailable"
        )
    if configuration is None:
        raise DomainError(
            "DEPENDENCY_UNAVAILABLE", "Task evidence runtime configuration is unavailable"
        )
    outstanding = db.scalar(
        select(Job.id)
        .where(
            Job.task_id == current.task_id,
            (Job.state.in_(("QUEUED", "RUNNING", "RETRY_WAIT"))) | (Job.effect == "UNKNOWN"),
        )
        .limit(1)
    )
    if outstanding is not None:
        raise DomainError(
            "DEPENDENCY_UNAVAILABLE", "Task execution requires settlement before completion"
        )
    checks = {item.check_id: item for item in target.manifest.verification_policy.checks}
    proof_service = TaskDispatchService(engine, configuration)
    evidence_ids: list[str] = []
    covered: set[str] = set()
    for step in workflow.steps:
        binding = db.scalar(
            select(TaskVerificationJob)
            .options(defer(TaskVerificationJob.inputs))
            .where(
                TaskVerificationJob.manifest_id == target.manifest.manifest_id,
                TaskVerificationJob.step_id == step.step_id,
            )
        )
        if binding is None:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Required verification evidence is unavailable"
            )
        proof = proof_service.evidence_in(db, actor, binding.job_id)
        job = db.get(Job, binding.job_id)
        execution = authorized_execution(db, actor, proof.execution.execution_id)
        actual = execution_view(db, execution)
        started = db.scalar(
            select(ExecutionEffect).where(
                ExecutionEffect.execution_id == execution.id,
                ExecutionEffect.kind == "STARTED",
            )
        )
        operation = db.get(Receipt, proof.execution_operation_id, options=[defer(Receipt.result)])
        check = checks.get(step.check_id or "")
        if (
            job is None
            or job.state != "SUCCEEDED"
            or job.effect != "COMMITTED"
            or job.cancel_requested
            or job.evidence_id != proof.evidence_id
            or job.operation_id != proof.execution_operation_id
            or proof.manifest != target.manifest
            or proof.step_id != step.step_id
            or not proof.passed
            or actual != proof.execution
            or actual.state != "COMPLETED"
            or not actual.verification_passed
            or not actual.drained
            or actual.completion is None
            or not actual.completion.drained
            or actual.completion.reason != "EXITED"
            or check is None
            or actual.completion.exit_code != check.expected_exit_code
            or proof.criterion not in current.success_conditions
            or proof.criterion.text != check.criterion
            or execution.job_id != job.id
            or (proof.claim_fence, proof.claim_owner, proof.claim_incarnation)
            != (binding.claim_fence, binding.claim_owner, binding.claim_incarnation)
            or (job.fence, job.claim_owner, job.incarnation)
            != (binding.claim_fence, binding.claim_owner, binding.claim_incarnation)
            or started is None
            or started.observation.get("process_id") != proof.process_id
            or started.observation.get("invocation_id") != actual.invocation_id
            or operation is None
            or operation.command != "execution.start.v1"
            or operation.target_id != execution.id
            or operation.principal_id != job.principal_id
            or operation.payload_hash != execution.payload_hash
            or operation.owner != "work"
            or operation.target_kind != "execution"
            or operation.project_id != execution.project_id
            or operation.authentication_ref != execution.authentication_ref
            or operation.idempotency_key != execution.idempotency_key
        ):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Verification provenance does not satisfy completion"
            )
        receipt = execution_receipt(db, actor, operation)
        for field in (
            "origin",
            "job_id",
            "attempt_id",
            "attempt_manifest_id",
            "project_id",
            "root_key",
            "root_revision",
            "policy_revision",
            "route_key",
            "route_revision",
            "route_digest",
            "check_id",
            "initiating_principal_id",
            "authentication_ref",
            "principal_epoch",
            "created_at",
            "unit",
            "host_fingerprint",
        ):
            if getattr(receipt.execution, field) != getattr(actual, field):
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE", "Execution receipt provenance requires repair"
                )
        evidence_ids.append(proof.evidence_id)
        covered.add(proof.criterion.text)
    if not current.success_conditions or any(
        item.text not in covered for item in current.success_conditions
    ):
        raise DomainError(
            "DEPENDENCY_UNAVAILABLE", "Every success condition requires exact verification evidence"
        )
    completion_binding = TaskCompletionBinding(
        target_id=target.target_id,
        target_digest=target.content_digest,
        attempt_id=target.manifest.attempt_id,
        manifest_id=target.manifest.manifest_id,
        snapshot_hash=target.manifest.snapshot.snapshot_hash,
        review_policy_revision=target.review_policy.revision,
        evidence_ids=evidence_ids,
    )
    require_current_target(db, engine, actor, target)
    ReviewTargetService(engine, configuration).check_configuration(db, actor, target.target_id)
    updated = TaskView.model_validate(
        current.model_dump(mode="json")
        | {
            "revision": current.revision + 1,
            "state": "DONE",
            "completion": completion_binding.model_dump(mode="json"),
            "updated_at": datetime.now(UTC).isoformat(),
            "blocker": None,
        }
    )
    row.revision, row.snapshot = updated.revision, updated.model_dump(mode="json")
    db.flush()
    for capability in (
        "task.review.read",
        "project.review.read",
        "attempt.read",
        "project.instruction.read",
        "project.verification.read",
        "execution.read",
        "execution.receipt.read",
        "project.read",
        "job.read",
        "execution.admit",
        *target.manifest.verification_policy.required_capabilities,
    ):
        require_grant(db, actor, capability, project_id=current.project_id)
    return commit_task(db, actor, name, command, command_hash, updated)
