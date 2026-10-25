# SPDX-License-Identifier: AGPL-3.0-only
"""Read original command identity through existing canonical owners, without mutation retry."""

from dataclasses import dataclass
from typing import Any

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, defer

from journeon.contracts import DomainError, OperationIdentityResolution, OperationIdentityResolve
from journeon.instruction_config import InstructionConfiguration
from journeon.models import (
    AccessGrant,
    Attempt,
    Execution,
    InstructionCandidate,
    InstructionPublication,
    Job,
    ProtectedRequest,
    Receipt,
    TaskVerificationJob,
)
from journeon.permissions import AuthenticatedContext, current_owner, require_grant


@dataclass(frozen=True)
class AuthorizedOriginalScope:
    owner: str
    project_id: str | None = None
    target_id: str | None = None


def require_instruction_configuration(
    configuration: InstructionConfiguration | None,
) -> InstructionConfiguration:
    if configuration is None:
        raise DomainError(
            "DEPENDENCY_UNAVAILABLE", "Explicit instruction runtime configuration is required"
        )
    return configuration


def original_accept_digest(
    db: Session,
    actor: AuthenticatedContext,
    publication: InstructionPublication,
    payload: dict[str, Any],
) -> str | None:
    from journeon.instruction_contracts import InstructionAccept, InstructionChangeConsent
    from journeon.instructions import digest
    from journeon.models import InstructionRequestScope

    if digest(payload) != publication.payload_hash:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Publication identity requires repair")
    accepted = InstructionAccept.model_validate(payload)
    if accepted.consent_request_id is None:
        return None
    current_owner(db, actor)
    request = db.get(
        ProtectedRequest, accepted.consent_request_id, options=[defer(ProtectedRequest.payload)]
    )
    scope = db.get(InstructionRequestScope, accepted.consent_request_id)
    if (
        request is None
        or scope is None
        or (request.principal_id, request.command, request.idempotency_key, scope.project_id)
        != (
            actor.principal_id,
            "project.instructions.accept.v1",
            publication.idempotency_key,
            publication.project_id,
        )
        or request.state not in {"APPROVED", "COMMITTED"}
        or (
            publication.status in {"CANONICAL_COMMITTED", "ABANDONED"}
            and request.state != "COMMITTED"
        )
        or request.session_id != publication.authentication_ref
        or request.operation_id != publication.id
        or request.principal_epoch != publication.principal_epoch
        or request.approved_at is None
        or request.strong_authenticated_at is None
        or request.nonce_hash is not None
        or request.nonce_deadline is not None
        or accepted.project_id != publication.project_id
        or accepted.idempotency_key != publication.idempotency_key
        or publication.principal_id != actor.principal_id
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Publication consent requires repair")
    effect = InstructionChangeConsent.model_validate(request.payload)
    if digest(effect.model_dump(mode="json")) != request.payload_hash or effect.model_dump(
        exclude={"kind"}
    ) != accepted.model_dump(exclude={"consent_request_id"}):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Publication consent requires repair")
    return request.payload_hash


def scope_value(query: OperationIdentityResolve, key: str) -> str:
    value = query.scope.get(key)
    if not isinstance(value, str):
        raise DomainError("VALIDATION_FAILED", "Original command scope is incomplete")
    return value


def exact_scope(
    query: OperationIdentityResolve, required: set[str], optional: set[str] | None = None
) -> None:
    if not required <= set(query.scope) or not set(query.scope) <= required | (optional or set()):
        raise DomainError("VALIDATION_FAILED", "Original command scope does not match its owner")


def authorize_original(
    db: Session,
    actor: AuthenticatedContext,
    query: OperationIdentityResolve,
) -> AuthorizedOriginalScope:
    name = query.command
    if name in {
        "permission.grant.set.v1",
        "permission.grant.revoke.v1",
        "egress.policy.initialize.v1",
    }:
        current_owner(db, actor)
        if name == "permission.grant.set.v1":
            exact_scope(query, {"principal_id", "capability", "resource_kind", "resource_id"})
            for key in query.scope:
                scope_value(query, key)
            return AuthorizedOriginalScope("permissions")
        if name == "permission.grant.revoke.v1":
            exact_scope(query, {"grant_id"})
            return AuthorizedOriginalScope("permissions", target_id=scope_value(query, "grant_id"))
        exact_scope(query, set())
        return AuthorizedOriginalScope("egress", target_id="deployment")
    if name in {"identity.session.revoke.v1", "identity.session.logout.v1"}:
        from journeon.identity import session_target

        exact_scope(query, {"target_session_id"})
        target = session_target(db, actor, scope_value(query, "target_session_id"))
        if name == "identity.session.logout.v1" and target.principal_id != actor.principal_id:
            raise DomainError("NOT_FOUND", "Session is unavailable")
        return AuthorizedOriginalScope("identity", target_id=target.id)
    if name == "passkey.label.v1":
        from journeon.factors import owned_key

        exact_scope(query, {"passkey_id"})
        target_key = owned_key(db, actor, scope_value(query, "passkey_id"))
        return AuthorizedOriginalScope("identity", target_id=target_key.id)
    if name == "project.create.v1":
        exact_scope(query, set())
        current_owner(db, actor)
        require_grant(db, actor, "project.receipt.read")
        return AuthorizedOriginalScope("projects")
    if name in {"project.review.configure.v1", "project.verification.configure.v1"}:
        exact_scope(query, {"project_id"})
        project = scope_value(query, "project_id")
        read = (
            "project.review.read"
            if name == "project.review.configure.v1"
            else "project.verification.read"
        )
        for capability in (read, "project.receipt.read"):
            require_grant(db, actor, capability, project_id=project)
        return AuthorizedOriginalScope("projects", project_id=project, target_id=project)
    if name in {"profile.create.v1", "bot.create.v1", "team.create.v1"}:
        exact_scope(query, set())
        current_owner(db, actor)
        return AuthorizedOriginalScope("agents")
    if name in {"profile.revise.v1", "bot.revise.v1"}:
        from journeon.agents import authorize

        kind = name.split(".")[0]
        exact_scope(query, {kind + "_id"})
        identity = scope_value(query, kind + "_id")
        for action in ("read", "receipt.read"):
            authorize(db, actor, kind, identity, action)
        return AuthorizedOriginalScope("agents", target_id=identity)
    if name == "instruction.bundle.resolve.v1":
        from journeon.agents import authorize

        exact_scope(query, {"project_id", "profile_id"}, {"bot_id", "task_id"})
        project = scope_value(query, "project_id")
        authorize(db, actor, "profile", scope_value(query, "profile_id"), "read")
        if "bot_id" in query.scope:
            authorize(db, actor, "bot", scope_value(query, "bot_id"), "read")
        require_grant(
            db, actor, "project.instruction.read", resource_kind="project", resource_id=project
        )
        if "task_id" in query.scope:
            from journeon.work import task_row

            task = task_row(db, actor, scope_value(query, "task_id"), "task.read")
            if task.project_id != project or task.initiating_principal_id != actor.principal_id:
                raise DomainError("NOT_FOUND", "Task is unavailable")
        return AuthorizedOriginalScope("instructions", project_id=project)
    task_commands = {
        "task.create.v1",
        "task.pause.v1",
        "task.resume.v1",
        "task.cancel.v1",
        "task.revise.v1",
        "task.assign.v1",
        "task.admit.v1",
        "task.complete.v1",
        "task.review.select.v1",
        "attempt.prepare.v1",
        "task.dispatch.v1",
    }
    if name in task_commands:
        from journeon.work import task_row

        if name in {"task.create.v1", "task.admit.v1"}:
            exact_scope(query, {"project_id"}, {"task_id"} if name == "task.admit.v1" else set())
            project = scope_value(query, "project_id")
            target_id = None
        else:
            exact_scope(query, {"task_id", "project_id"})
            task = task_row(db, actor, scope_value(query, "task_id"), "task.read")
            project = scope_value(query, "project_id")
            if task.project_id != project:
                raise DomainError("NOT_FOUND", "Task is unavailable")
            target_id = task.id
        for capability in ("task.read", "task.receipt.read"):
            require_grant(db, actor, capability, project_id=project)
        if name == "attempt.prepare.v1":
            for capability in ("attempt.read", "attempt.receipt.read"):
                require_grant(db, actor, capability, project_id=project)
            target_id = None
        if name == "task.review.select.v1":
            from journeon.review_targets import target_grants

            target_grants(db, actor, project)
            target_id = None
        if name == "task.dispatch.v1":
            for capability in ("job.read", "job.receipt.read", "attempt.read"):
                require_grant(db, actor, capability, project_id=project)
            return AuthorizedOriginalScope("jobs", project_id=project)
        return AuthorizedOriginalScope("work", project_id=project, target_id=target_id)
    if name in {"execution.start.v1", "execution.stop.v1"}:
        exact_scope(query, {"project_id"}, {"execution_id"})
        project = scope_value(query, "project_id")
        for capability in ("execution.read", "execution.receipt.read", "project.read"):
            require_grant(db, actor, capability, project_id=project)
        execution_identity = None
        if name == "execution.stop.v1":
            from journeon.executions import authorized_execution

            row = authorized_execution(db, actor, scope_value(query, "execution_id"))
            if row.project_id != project:
                raise DomainError("NOT_FOUND", "Execution is unavailable")
            execution_identity = row.id
        return AuthorizedOriginalScope("work", project_id=project, target_id=execution_identity)
    if name in {
        "project.root.admit.v1",
        "project.root.revoke.v1",
        "instruction.candidate.register.v1",
        "instruction.release.install.v1",
    }:
        current_owner(db, actor)
        exact_scope(query, set(), {"root_id"})
        root_identity = scope_value(query, "root_id") if "root_id" in query.scope else None
        return AuthorizedOriginalScope("project_instructions", target_id=root_identity)
    if name in {
        "project.instructions.bind.v1",
        "project.instructions.accept.v1",
        "project.instructions.policy.configure.v1",
        "project.instructions.projection.v1",
        "project.instructions.propose.v1",
        "project.instructions.restore.v1",
        "project.instructions.review.v1",
        "project.instructions.recover.v1",
    }:
        exact_scope(query, {"project_id"})
        project = scope_value(query, "project_id")
        for action in ("read", "receipt.read"):
            require_grant(
                db,
                actor,
                "project.instruction." + action,
                resource_kind="project",
                resource_id=project,
            )
        return AuthorizedOriginalScope(
            "project_instructions", project_id=project, target_id=project
        )
    if name == "lifecycle.restore.authorize.v1":
        current_owner(db, actor)
        require_grant(db, actor, "lifecycle.restore")
        exact_scope(query, {"project_ids"})
        projects = query.scope["project_ids"]
        if not isinstance(projects, list) or not projects or len(set(projects)) != len(projects):
            raise DomainError("VALIDATION_FAILED", "Original restore scope is incomplete")
        for project in projects:
            for action in ("read", "restore"):
                require_grant(
                    db,
                    actor,
                    "project.instruction." + action,
                    resource_kind="project",
                    resource_id=project,
                )
        return AuthorizedOriginalScope("lifecycle")
    raise DomainError(
        "VALIDATION_FAILED", "Command has no original-identity reconciliation binding"
    )


def resolve_original(
    db: Session,
    actor: AuthenticatedContext,
    query: OperationIdentityResolve,
    engine: Engine,
    configuration: InstructionConfiguration | None,
) -> OperationIdentityResolution:
    from journeon.administration import incarnation
    from journeon.identity import current_actor
    from journeon.receipts import authorized_receipt, check_receipt_configuration

    current_actor(db, actor)
    scope = authorize_original(db, actor, query)
    current = incarnation(db)

    def result(
        status: str,
        *,
        evidence_kind: str | None = None,
        evidence_id: str | None = None,
        observed_state: str | None = None,
        receipt: object = None,
    ) -> OperationIdentityResolution:
        values = {
            "status": status,
            "command": query.command,
            "store_incarnation": current,
            "evidence_kind": evidence_kind,
            "evidence_id": evidence_id,
            "observed_state": observed_state,
            "receipt": receipt,
        }
        return OperationIdentityResolution.model_validate(
            {key: value for key, value in values.items() if value is not None}
        )

    if query.store_incarnation != current:
        return result("RECONCILIATION_REQUIRED")
    statement = (
        select(Receipt)
        .options(defer(Receipt.result))
        .where(
            Receipt.principal_id == actor.principal_id,
            Receipt.command == query.command,
            Receipt.idempotency_key == query.idempotency_key,
            Receipt.owner == scope.owner,
        )
    )
    if scope.project_id is not None:
        statement = statement.where(Receipt.project_id == scope.project_id)
    if scope.target_id is not None:
        statement = statement.where(Receipt.target_id == scope.target_id)
    if query.command == "permission.grant.set.v1":
        statement = statement.join(AccessGrant, AccessGrant.id == Receipt.target_id).where(
            AccessGrant.principal_id == scope_value(query, "principal_id"),
            AccessGrant.capability == scope_value(query, "capability"),
            AccessGrant.resource_kind == scope_value(query, "resource_kind"),
            AccessGrant.resource_id == scope_value(query, "resource_id"),
        )
    row = db.scalar(statement)
    if row is not None:
        check_receipt_configuration(db, actor, row, engine, configuration)
        receipt = authorized_receipt(db, actor, row)
        matched = row.payload_hash == query.payload_digest
        if not matched and query.command == "project.instructions.accept.v1":
            from journeon.project_instructions import ProjectInstructionService

            publication = db.scalar(
                select(InstructionPublication)
                .options(defer(InstructionPublication.snapshot))
                .where(
                    InstructionPublication.id == row.id,
                    InstructionPublication.principal_id == actor.principal_id,
                    InstructionPublication.project_id == row.project_id,
                    InstructionPublication.idempotency_key == row.idempotency_key,
                    InstructionPublication.payload_hash == row.payload_hash,
                )
            )
            if publication is None:
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Publication identity requires repair")
            retained = ProjectInstructionService(
                engine, require_instruction_configuration(configuration)
            ).publication_data(db, actor, publication, None)
            if retained["command"] != query.command:
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Publication identity requires repair")
            matched = (
                original_accept_digest(db, actor, publication, retained["payload"])
                == query.payload_digest
            )
        if not matched:
            raise DomainError("IDEMPOTENCY_CONFLICT", "Operation identity has different input")
        return result("OBSERVED_RECEIPT", receipt=receipt)
    return durable_observation(db, actor, query, scope, engine, configuration, current)


def durable_observation(
    db: Session,
    actor: AuthenticatedContext,
    query: OperationIdentityResolve,
    scope: AuthorizedOriginalScope,
    engine: Engine,
    configuration: InstructionConfiguration | None,
    current: str,
) -> OperationIdentityResolution:
    from journeon.receipts import authorized_receipt, check_receipt_configuration

    def observed(
        kind: str, identity: str, state: str, payload_hash: str, *, pending: bool = False
    ) -> OperationIdentityResolution:
        if payload_hash != query.payload_digest:
            raise DomainError("IDEMPOTENCY_CONFLICT", "Operation identity has different input")
        return OperationIdentityResolution.model_validate(
            {
                "status": "OBSERVED_PENDING" if pending else "OBSERVED_UNKNOWN",
                "command": query.command,
                "store_incarnation": current,
                "evidence_kind": kind,
                "evidence_id": identity,
                "observed_state": state,
            }
        )

    if query.command == "task.dispatch.v1":
        from journeon.jobs import authorize
        from journeon.task_dispatch import TaskDispatchService

        bound = db.scalar(
            select(TaskVerificationJob)
            .join(Job, Job.id == TaskVerificationJob.job_id)
            .options(defer(TaskVerificationJob.inputs))
            .where(
                TaskVerificationJob.principal_id == actor.principal_id,
                TaskVerificationJob.idempotency_key == query.idempotency_key,
                Job.project_id == scope.project_id,
                Job.task_id == scope_value(query, "task_id"),
                Job.principal_id == actor.principal_id,
            )
        )
        if bound is not None:
            job = db.get(Job, bound.job_id)
            assert job is not None
            authorize(db, actor, job)
            authorize(db, actor, job, "receipt.read")
            if configuration is None:
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Task dispatcher is not configured")
            TaskDispatchService(engine, configuration).bound(db, actor, job)
            if job.input_hash != query.payload_digest:
                raise DomainError("IDEMPOTENCY_CONFLICT", "Operation identity has different input")
            row = db.get(Receipt, job.admission_id, options=[defer(Receipt.result)])
            if row is None:
                return observed("TASK_JOB", job.id, job.state, job.input_hash)
            check_receipt_configuration(db, actor, row, engine, configuration)
            receipt = authorized_receipt(db, actor, row)
            return OperationIdentityResolution.model_validate(
                {
                    "status": "OBSERVED_RECEIPT",
                    "command": query.command,
                    "store_incarnation": current,
                    "receipt": receipt,
                }
            )
    if query.command == "attempt.prepare.v1":
        from journeon.attempts import AttemptService, authorized_attempt, validate_attempt_view
        from journeon.contracts import AttemptView

        attempt = db.scalar(
            select(Attempt)
            .options(defer(Attempt.snapshot), defer(Attempt.inputs))
            .where(
                Attempt.principal_id == actor.principal_id,
                Attempt.idempotency_key == query.idempotency_key,
                Attempt.project_id == scope.project_id,
                Attempt.task_id == scope_value(query, "task_id"),
            )
        )
        if attempt is not None:
            authorized_attempt(db, actor, attempt.id)
            AttemptService(engine, configuration).check_configuration(db, attempt)
            view = AttemptView.model_validate(attempt.snapshot)
            validate_attempt_view(db, attempt, view)
            return observed(
                "ATTEMPT",
                attempt.id,
                view.state,
                attempt.payload_hash,
                pending=view.state == "PREPARING",
            )
    if query.command == "execution.start.v1":
        from journeon.executions import ExecutionService, authorized_execution

        execution = db.scalar(
            select(Execution)
            .options(defer(Execution.snapshot), defer(Execution.inputs))
            .where(
                Execution.principal_id == actor.principal_id,
                Execution.idempotency_key == query.idempotency_key,
                Execution.project_id == scope.project_id,
            )
        )
        if execution is not None:
            authorized_execution(db, actor, execution.id)
            ExecutionService(engine, configuration).check_configuration(db, actor, execution)
            return observed(
                "EXECUTION",
                execution.id,
                execution.state,
                execution.payload_hash,
                pending=execution.state in {"STARTING", "RUNNING"},
            )
    if query.command in {
        "project.instructions.bind.v1",
        "project.instructions.accept.v1",
        "project.instructions.projection.v1",
    }:
        from journeon.instructions import digest
        from journeon.project_instructions import ProjectInstructionService

        publication = db.scalar(
            select(InstructionPublication)
            .options(defer(InstructionPublication.snapshot))
            .where(
                InstructionPublication.principal_id == actor.principal_id,
                InstructionPublication.project_id == scope.project_id,
                InstructionPublication.idempotency_key == query.idempotency_key,
            )
        )
        if publication is not None:
            service = ProjectInstructionService(
                engine, require_instruction_configuration(configuration)
            )
            service.recovery_roots(db, actor, publication)
            snapshot = service.publication_data(db, actor, publication, None)
            if snapshot.get("command") != query.command:
                return OperationIdentityResolution.model_validate(
                    {
                        "status": "NOT_OBSERVED",
                        "command": query.command,
                        "store_incarnation": current,
                    }
                )
            if digest(snapshot.get("payload")) != publication.payload_hash:
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Publication identity requires repair")
            identity_hash = publication.payload_hash
            if (
                query.command == "project.instructions.accept.v1"
                and identity_hash != query.payload_digest
            ):
                original = original_accept_digest(db, actor, publication, snapshot["payload"])
                if original is not None:
                    identity_hash = original
            return observed(
                "INSTRUCTION_PUBLICATION",
                publication.id,
                publication.status,
                identity_hash,
                pending=publication.status == "PENDING",
            )
    if query.command in {"project.instructions.propose.v1", "project.instructions.restore.v1"}:
        from journeon.instructions import digest
        from journeon.project_instructions import (
            ProjectInstructionService,
            candidate_restore,
            candidate_view,
        )

        candidate = db.scalar(
            select(InstructionCandidate)
            .options(defer(InstructionCandidate.snapshot))
            .where(
                InstructionCandidate.principal_id == actor.principal_id,
                InstructionCandidate.project_id == scope.project_id,
                InstructionCandidate.idempotency_key == query.idempotency_key,
            )
        )
        if candidate is not None:
            ProjectInstructionService(
                engine, require_instruction_configuration(configuration)
            ).binding(db, actor, candidate.project_id)
            candidate_state = candidate_view(db, candidate)
            if (candidate_state.candidate_id, candidate_state.project_id) != (
                candidate.id,
                candidate.project_id,
            ):
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Candidate identity requires repair")
            identity_hash = candidate.payload_hash
            if candidate.snapshot.get("original_command") != query.command:
                return OperationIdentityResolution.model_validate(
                    {
                        "status": "NOT_OBSERVED",
                        "command": query.command,
                        "store_incarnation": current,
                    }
                )
            if query.command == "project.instructions.restore.v1":
                restored = candidate_restore(db, candidate, candidate_state)
                if restored is None:
                    return OperationIdentityResolution.model_validate(
                        {
                            "status": "NOT_OBSERVED",
                            "command": query.command,
                            "store_incarnation": current,
                        }
                    )
                identity_hash = digest(restored.model_dump(mode="json"))
            return observed("INSTRUCTION_CANDIDATE", candidate.id, "RECORDED", identity_hash)
    if query.command == "project.instructions.review.v1":
        from journeon.instruction_contracts import InstructionReview
        from journeon.instructions import digest
        from journeon.models import InstructionEvidence
        from journeon.project_instructions import ProjectInstructionService

        assert scope.project_id is not None
        service = ProjectInstructionService(
            engine, require_instruction_configuration(configuration)
        )
        service.binding(db, actor, scope.project_id, "read")
        require_grant(
            db,
            actor,
            "project.instruction.review",
            resource_kind="project",
            resource_id=scope.project_id,
        )
        evidence_rows = db.scalars(
            select(InstructionEvidence).where(
                InstructionEvidence.principal_id == actor.principal_id,
                InstructionEvidence.project_id == scope.project_id,
                InstructionEvidence.kind == "REVIEW",
            )
        )
        for evidence in evidence_rows:
            review = InstructionReview.model_validate(evidence.snapshot)
            if review.idempotency_key == query.idempotency_key:
                if (
                    review.project_id != evidence.project_id
                    or review.candidate_id != evidence.candidate_id
                ):
                    raise DomainError("DEPENDENCY_UNAVAILABLE", "Review identity requires repair")
                return observed(
                    "INSTRUCTION_REVIEW",
                    evidence.id,
                    "RECORDED",
                    digest(review.model_dump(mode="json")),
                )
    protected = db.scalar(
        select(ProtectedRequest)
        .options(defer(ProtectedRequest.payload))
        .where(
            ProtectedRequest.principal_id == actor.principal_id,
            ProtectedRequest.command == query.command,
            ProtectedRequest.idempotency_key == query.idempotency_key,
        )
    )
    if protected is not None:
        from journeon.instruction_contracts import EFFECT_ADAPTER
        from journeon.instructions import digest
        from journeon.sessions import utc_seconds

        # Protected producers are Owner operations; this check precedes retained JSON.
        current_owner(db, actor)
        if scope.project_id is not None:
            from journeon.models import InstructionRequestScope

            bound_scope = db.get(InstructionRequestScope, protected.id)
            if bound_scope is None or bound_scope.project_id != scope.project_id:
                return OperationIdentityResolution.model_validate(
                    {
                        "status": "NOT_OBSERVED",
                        "command": query.command,
                        "store_incarnation": current,
                    }
                )
        if query.command == "lifecycle.restore.authorize.v1":
            from journeon.models import RestoreRequestScope

            projects = set(
                db.scalars(
                    select(RestoreRequestScope.project_id).where(
                        RestoreRequestScope.request_id == protected.id
                    )
                )
            )
            if projects != set(query.scope["project_ids"]):
                return OperationIdentityResolution.model_validate(
                    {
                        "status": "NOT_OBSERVED",
                        "command": query.command,
                        "store_incarnation": current,
                    }
                )
        effect = EFFECT_ADAPTER.validate_python(protected.payload)
        data = effect.model_dump(mode="json")
        if (
            effect.kind != protected.command
            or effect.idempotency_key != protected.idempotency_key
            or digest(data) != protected.payload_hash
        ):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Protected identity requires repair")
        if any(
            data.get(key) != value for key, value in query.scope.items() if key != "project_ids"
        ):
            return OperationIdentityResolution.model_validate(
                {"status": "NOT_OBSERVED", "command": query.command, "store_incarnation": current}
            )
        return observed(
            "PROTECTED_REQUEST",
            protected.id,
            protected.state,
            protected.payload_hash,
            pending=protected.state in {"PENDING", "APPROVED"}
            and utc_seconds() < protected.deadline,
        )
    return OperationIdentityResolution.model_validate(
        {"status": "NOT_OBSERVED", "command": query.command, "store_incarnation": current}
    )
