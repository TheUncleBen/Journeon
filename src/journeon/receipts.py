# SPDX-License-Identifier: AGPL-3.0-only
"""One receipt lookup, with current authorization before stored result decoding."""

import json

from pydantic import ValidationError
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, defer

from journeon.contracts import CanonicalReceipt, DomainError, PasskeyMutationReceipt
from journeon.database import require_compatible_schema, transaction
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
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

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
                return authorized_receipt(db, actor, row)
        except (ValidationError, json.JSONDecodeError):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Stored operation state requires repair"
            ) from None
        except SQLAlchemyError as exc:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "The operation store is unavailable"
            ) from exc
