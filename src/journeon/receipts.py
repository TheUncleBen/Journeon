# SPDX-License-Identifier: AGPL-3.0-only
"""One receipt lookup, with current authorization before stored result decoding."""

import json

from pydantic import ValidationError
from sqlalchemy import Engine, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, defer

from journeon.contracts import (
    CanonicalReceipt,
    DomainError,
    OperationIdentityResolution,
    OperationIdentityResolve,
    PasskeyMutationReceipt,
    RuntimeConfigurationUnavailable,
)
from journeon.database import require_compatible_schema, transaction
from journeon.instruction_config import InstructionConfiguration
from journeon.models import Passkey, Receipt
from journeon.permissions import AuthenticatedContext
from journeon.projects import _authorized_receipt
from journeon.sessions import current_session
from journeon.work import authorized_work_receipt


def authorized_receipt(db: Session, actor: AuthenticatedContext, row: Receipt) -> CanonicalReceipt:
    current_session(
        db,
        actor.authentication_ref,
        principal_id=actor.principal_id,
        principal_epoch=actor.principal_epoch,
    )
    if row.principal_id != actor.principal_id:
        raise DomainError("NOT_FOUND", "Operation is unavailable")
    if row.owner == "identity" and row.target_kind == "browser_session":
        from journeon.identity import authorized_session_receipt

        return authorized_session_receipt(db, actor, row)
    if row.owner in {"permissions", "egress"}:
        from journeon.administration import authorized_receipt as administration_receipt

        return administration_receipt(db, actor, row)
    if row.owner == "lifecycle":
        from journeon.contracts import RestoreReceipt
        from journeon.models import ProtectedRequest, RestoreRequestScope, StoreIdentity
        from journeon.permissions import current_owner, require_grant

        current_owner(db, actor)
        require_grant(db, actor, "lifecycle.restore")
        store = db.get(StoreIdentity, 1)
        if (
            store is None
            or row.command != "lifecycle.restore.v1"
            or row.target_kind != "store"
            or row.target_id != store.store_id
            or row.project_id is not None
        ):
            raise DomainError("PERMISSION_DENIED", "Restore receipt scope is unavailable")
        request = db.scalar(
            select(ProtectedRequest)
            .options(defer(ProtectedRequest.payload))
            .where(
                ProtectedRequest.operation_id == row.id,
                ProtectedRequest.payload_hash == row.payload_hash,
                ProtectedRequest.command == "lifecycle.restore.authorize.v1",
                ProtectedRequest.principal_id == actor.principal_id,
                ProtectedRequest.state == "COMMITTED",
            )
        )
        scopes = (
            list(
                db.scalars(
                    select(RestoreRequestScope.project_id).where(
                        RestoreRequestScope.request_id == request.id
                    )
                )
            )
            if request is not None
            else []
        )
        if not scopes:
            raise DomainError("PERMISSION_DENIED", "Restore scope evidence is unavailable")
        from journeon.instruction_operations import authorize_project_receipt

        for project_id in scopes:
            authorize_project_receipt(db, actor, project_id)
        restored = RestoreReceipt.model_validate(row.result)
        if restored.operation_id != row.id or restored.target_id != store.store_id:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Restore receipt requires repair")
        return restored
    if row.owner == "jobs" and row.command == "notification.dismiss.v1":
        from journeon.notification_presentation import authorized_notification_receipt

        return authorized_notification_receipt(db, actor, row)
    if row.owner == "jobs":
        from journeon.job_contracts import JobReceipt
        from journeon.jobs import authorize
        from journeon.models import Job

        job = db.get(Job, row.target_id)
        if job is None or row.target_kind != "job" or row.project_id != job.project_id:
            raise DomainError("PERMISSION_DENIED", "Job receipt scope is unavailable")
        authorize(db, actor, job)
        authorize(db, actor, job, "receipt.read")
        job_result = JobReceipt.model_validate(row.result)
        if job_result.operation_id != row.id or job_result.target_id != job.id:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Job receipt requires repair")
        return job_result
    if row.owner == "project_instructions":
        from journeon.instruction_operations import authorized

        return authorized(db, actor, row)
    if row.owner in {"agents", "instructions"}:
        from journeon.agents import authorized_configuration_receipt

        return authorized_configuration_receipt(db, actor, row)
    if row.owner == "work" and row.target_kind == "execution":
        from journeon.executions import execution_receipt

        return execution_receipt(db, actor, row)
    if row.owner == "work" and row.target_kind == "attempt":
        from journeon.attempts import authorized_attempt_receipt

        return authorized_attempt_receipt(db, actor, row)
    if row.owner == "work" and row.command == "task.review.select.v1":
        from journeon.review_targets import target_receipt

        return target_receipt(db, actor, row)
    if row.owner == "work":
        return authorized_work_receipt(db, actor, row)
    if row.command == "project.review.configure.v1" and row.owner == "projects":
        from journeon.reviews import policy_receipt as review_policy_receipt

        return review_policy_receipt(db, actor, row)
    if row.command == "project.verification.configure.v1" and row.owner == "projects":
        from journeon.verification import policy_receipt

        return policy_receipt(db, actor, row)
    if row.command == "project.create.v1" and row.owner == "projects":
        if row.target_kind != "project" or row.target_id != row.project_id:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored operation state requires repair")
        return _authorized_receipt(db, actor, row)
    if row.command == "passkey.label.v1" and row.owner == "identity":
        key = db.get(Passkey, row.target_id, populate_existing=True)
        if key is None or key.principal_id != actor.principal_id:
            raise DomainError("NOT_FOUND", "Operation is unavailable")
        if row.target_kind != "passkey" or row.project_id is not None:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored operation state requires repair")
        result = PasskeyMutationReceipt.model_validate(row.result)
        if (
            result.operation_id != row.id
            or result.command != row.command
            or result.passkey.passkey_id != row.target_id
            or result.passkey.principal_id != row.principal_id
        ):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored operation state requires repair")
        return result
    raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored operation owner is unsupported")


def check_receipt_configuration(
    db: Session,
    actor: AuthenticatedContext,
    row: Receipt,
    engine: Engine,
    configuration: InstructionConfiguration | None,
) -> None:
    if row.command == "task.review.select.v1" and row.owner == "work":
        from journeon.models import ReviewTargetRecord
        from journeon.permissions import require_grant
        from journeon.review_targets import ReviewTargetService

        if row.principal_id != actor.principal_id:
            raise DomainError("NOT_FOUND", "Operation is unavailable")
        require_grant(db, actor, "task.receipt.read", project_id=row.project_id)
        identity = db.scalar(
            select(ReviewTargetRecord.id).where(ReviewTargetRecord.operation_id == row.id)
        )
        if identity is None:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Review target receipt requires repair")
        ReviewTargetService(engine, configuration).check_configuration(db, actor, identity)
    if row.owner == "jobs":
        from journeon.jobs import JobService, authorize
        from journeon.models import Job

        job = db.get(Job, row.target_id)
        if job is None:
            raise DomainError("NOT_FOUND", "Job is unavailable")
        authorize(db, actor, job)
        authorize(db, actor, job, "receipt.read")
        if configuration is None:
            raise RuntimeConfigurationUnavailable(
                "Task dispatcher is not configured"
                if job.kind == "TASK_VERIFICATION"
                else "Explicit instruction runtime configuration is required"
            )
        if row.command == "notification.dismiss.v1":
            from journeon.notification_presentation import presentation_receipt_source

            presentation_receipt_source(db, actor, row, engine, configuration)
        else:
            JobService(engine, configuration).check_configuration(db, actor, job)
    if row.owner == "work" and row.target_kind == "execution":
        from journeon.executions import ExecutionService, authorized_execution

        execution = authorized_execution(db, actor, row.target_id)
        ExecutionService(engine, configuration).check_configuration(db, actor, execution)
    if row.owner == "work" and row.target_kind == "attempt":
        from journeon.attempts import AttemptService, authorized_attempt

        attempt = authorized_attempt(db, actor, row.target_id)
        AttemptService(engine, configuration).check_configuration(db, attempt)
    if (
        configuration is not None
        and row.principal_id == actor.principal_id
        and row.project_id is not None
        and row.owner in {"instructions", "project_instructions"}
    ):
        from journeon.models import ProjectInstructionBinding
        from journeon.project_instructions import ProjectInstructionService

        if db.get(ProjectInstructionBinding, row.project_id) is not None:
            ProjectInstructionService(engine, configuration).binding(db, actor, row.project_id)


class OperationService:
    def __init__(
        self, engine: Engine, configuration: InstructionConfiguration | None = None
    ) -> None:
        self.engine = engine
        self.configuration = configuration

    def resolve(
        self, actor: AuthenticatedContext, query: OperationIdentityResolve
    ) -> OperationIdentityResolution:
        from journeon.operation_resolution import resolve_original

        try:
            with transaction(self.engine) as db:
                require_compatible_schema(db)
                return resolve_original(db, actor, query, self.engine, self.configuration)
        except (ValidationError, json.JSONDecodeError):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Stored operation identity requires repair"
            ) from None
        except SQLAlchemyError:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "The operation store is unavailable"
            ) from None

    def receipt(self, actor: AuthenticatedContext, operation_id: str) -> CanonicalReceipt:
        try:
            with transaction(self.engine) as db:
                require_compatible_schema(db)
                current_session(
                    db,
                    actor.authentication_ref,
                    principal_id=actor.principal_id,
                    principal_epoch=actor.principal_epoch,
                )
                row = db.get(Receipt, operation_id, options=[defer(Receipt.result)])
                if row is None:
                    raise DomainError("NOT_FOUND", "Operation is unavailable")
                check_receipt_configuration(db, actor, row, self.engine, self.configuration)
                return authorized_receipt(db, actor, row)
        except (ValidationError, json.JSONDecodeError):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Stored operation state requires repair"
            ) from None
        except SQLAlchemyError as exc:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "The operation store is unavailable"
            ) from exc
