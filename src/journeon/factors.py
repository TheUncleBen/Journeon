# SPDX-License-Identifier: AGPL-3.0-only
"""Own-Principal passkey metadata mutations and canonical operation receipts."""

import hashlib
import json
from datetime import UTC, datetime
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import Engine, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, defer

from journeon.contracts import (
    DomainError,
    PasskeyLabelCommand,
    PasskeyMutationReceipt,
    PasskeySummary,
)
from journeon.database import transaction
from journeon.models import OutboxEvent, Passkey, Principal, Receipt
from journeon.permissions import AuthenticatedContext
from journeon.receipts import authorized_receipt
from journeon.sessions import current_session


def label_digest(command: PasskeyLabelCommand) -> str:
    return hashlib.sha256(
        json.dumps(
            command.model_dump(mode="json", exclude={"idempotency_key"}),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def owned_key(
    db: Session, actor: AuthenticatedContext, key_id: str, *, strong: bool = False
) -> Passkey:
    current_session(
        db,
        actor.authentication_ref,
        principal_id=actor.principal_id,
        principal_epoch=actor.principal_epoch,
        strong=strong,
    )
    key = db.get(Passkey, key_id, populate_existing=True)
    if key is None or key.principal_id != actor.principal_id:
        raise DomainError("NOT_FOUND", "Passkey is unavailable")
    return key


def apply_label(
    db: Session,
    actor: AuthenticatedContext,
    command: PasskeyLabelCommand,
    *,
    operation_id: str | None = None,
) -> PasskeyMutationReceipt:
    key = owned_key(db, actor, command.passkey_id)
    digest = label_digest(command)
    previous = db.scalar(
        select(Receipt)
        .options(defer(Receipt.result))
        .where(
            Receipt.principal_id == actor.principal_id,
            Receipt.command == "passkey.label.v1",
            Receipt.idempotency_key == command.idempotency_key,
        )
    )
    if previous is not None:
        result = authorized_receipt(db, actor, previous)
        if previous.payload_hash != digest:
            raise DomainError("IDEMPOTENCY_CONFLICT", "Operation identity has different input")
        if not isinstance(result, PasskeyMutationReceipt):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored operation state requires repair")
        return result
    owned_key(db, actor, command.passkey_id, strong=True)
    if key.revoked or key.revision != command.expected_revision:
        raise DomainError("REVISION_CONFLICT", "Passkey changed; refresh its revision")
    principal = db.get(Principal, actor.principal_id)
    assert principal is not None
    key.label = command.label
    key.revision += 1
    principal.credential_revision += 1
    operation_id = operation_id or str(uuid4())
    committed_at = datetime.now(UTC).isoformat()
    result = PasskeyMutationReceipt(
        operation_id=operation_id,
        committed_at=committed_at,
        passkey=PasskeySummary(
            passkey_id=key.id,
            principal_id=key.principal_id,
            revision=key.revision,
            label=key.label,
            revoked=key.revoked,
        ),
    )
    db.add(
        Receipt(
            id=operation_id,
            principal_id=actor.principal_id,
            command=result.command,
            idempotency_key=command.idempotency_key,
            payload_hash=digest,
            project_id=None,
            owner="identity",
            target_kind="passkey",
            target_id=key.id,
            authentication_ref=actor.authentication_ref,
            result=result.model_dump(mode="json"),
        )
    )
    db.flush()
    db.add(
        OutboxEvent(
            event_id=str(uuid4()),
            operation_id=operation_id,
            event_type="passkey.labelled",
            target_revision=result.passkey.revision,
            payload=result.model_dump(mode="json"),
            schema_version=1,
            principal_id=actor.principal_id,
            project_id=None,
            owner="identity",
            target_kind="passkey",
            target_id=key.id,
            committed_at=committed_at,
        )
    )
    db.flush()
    owned_key(db, actor, command.passkey_id, strong=True)
    return result


class FactorService:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def label(
        self, actor: AuthenticatedContext, command: PasskeyLabelCommand
    ) -> PasskeyMutationReceipt:
        try:
            with transaction(self.engine) as db:
                return apply_label(db, actor, command)
        except (ValidationError, json.JSONDecodeError):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Stored operation state requires repair"
            ) from None
        except SQLAlchemyError as exc:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "The operation store is unavailable"
            ) from exc
