# SPDX-License-Identifier: AGPL-3.0-only
"""One receipt lookup, with current authorization before stored result decoding."""

import json

from pydantic import ValidationError
from sqlalchemy import Engine, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, defer

from journeon.contracts import CanonicalReceipt, DomainError, PasskeyMutationReceipt
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
    if row.owner == "work":
        return authorized_work_receipt(db, actor, row)
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


class OperationService:
    def __init__(
        self, engine: Engine, configuration: InstructionConfiguration | None = None
    ) -> None:
        self.engine = engine
        self.configuration = configuration

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
                if (
                    self.configuration is not None
                    and row.principal_id == actor.principal_id
                    and row.project_id is not None
                    and row.owner in {"instructions", "project_instructions"}
                ):
                    from journeon.models import ProjectInstructionBinding
                    from journeon.project_instructions import ProjectInstructionService

                    if db.get(ProjectInstructionBinding, row.project_id) is not None:
                        ProjectInstructionService(self.engine, self.configuration).binding(
                            db, actor, row.project_id
                        )
                return authorized_receipt(db, actor, row)
        except (ValidationError, json.JSONDecodeError):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Stored operation state requires repair"
            ) from None
        except SQLAlchemyError as exc:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "The operation store is unavailable"
            ) from exc
