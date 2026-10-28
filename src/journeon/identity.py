# SPDX-License-Identifier: AGPL-3.0-only
"""Current human context uses the canonical browser-session and Principal owners."""

import base64
import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import Engine, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, defer

from journeon.administration import incarnation
from journeon.contracts import (
    BrowserSessionItem,
    BrowserSessionPage,
    CurrentHumanContext,
    DomainError,
    SessionLogout,
    SessionMutationReceipt,
    SessionRevoke,
)
from journeon.database import transaction
from journeon.instructions import digest as content_digest
from journeon.models import (
    BrowserSession,
    OutboxEvent,
    Principal,
    ProtectedRequest,
    Receipt,
    StoreIdentity,
)
from journeon.permissions import AuthenticatedContext, current_owner
from journeon.sessions import current_session, revoke_session, security_version


@contextmanager
def identity_transaction(engine: Engine) -> Iterator[Session]:
    try:
        with transaction(engine) as db:
            yield db
    except (ValidationError, json.JSONDecodeError):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Identity state requires repair") from None
    except SQLAlchemyError:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "The identity store is unavailable") from None


class IdentityService:
    def __init__(self, engine: Engine, *, instructions_configured: bool):
        self.engine = engine
        self.instructions_configured = instructions_configured

    def context(self, actor: AuthenticatedContext) -> CurrentHumanContext:
        with identity_transaction(self.engine) as db:
            return human_context(db, actor, self.instructions_configured)


def human_context(
    db: Session, actor: AuthenticatedContext, instructions_configured: bool
) -> CurrentHumanContext:
    record = current_session(
        db,
        actor.authentication_ref,
        principal_id=actor.principal_id,
        principal_epoch=actor.principal_epoch,
    )
    principal = db.get(Principal, record.principal_id)
    store = db.get(StoreIdentity, 1)
    if principal is None or store is None or not store.security_reconciled:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Identity context requires repair")
    try:
        return CurrentHumanContext.model_validate(
            {
                "principal_id": principal.id,
                "role": principal.role,
                "session": {
                    "session_id": record.id,
                    "authentication_method": record.authentication_method,
                    "audience": record.audience,
                    "issued_at": record.issued_at,
                    "absolute_deadline": record.absolute_deadline,
                    "inactivity_seconds": record.inactivity_seconds,
                    "strong_authenticated_at": record.strong_authenticated_at,
                    "strong_freshness_seconds": record.strong_freshness_seconds,
                    "security_version": security_version(record, principal, store.incarnation),
                },
                "store_incarnation": store.incarnation,
                "preference_revision": 0,
                "preferences": None,
                "dependencies": {
                    "instruction_runtime": (
                        "CONFIGURED" if instructions_configured else "UNCONFIGURED"
                    ),
                    "display_preferences": "UNAVAILABLE",
                },
            }
        )
    except ValidationError:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Identity context requires repair") from None


def current_actor(db: Session, actor: AuthenticatedContext) -> BrowserSession:
    return current_session(
        db,
        actor.authentication_ref,
        principal_id=actor.principal_id,
        principal_epoch=actor.principal_epoch,
    )


def session_target(db: Session, actor: AuthenticatedContext, identity: str) -> BrowserSession:
    current_actor(db, actor)
    target = db.get(BrowserSession, identity, populate_existing=True)
    principal = db.get(Principal, actor.principal_id)
    if target is None or (
        target.principal_id != actor.principal_id
        and (principal is None or principal.role != "OWNER")
    ):
        raise DomainError("NOT_FOUND", "Session is unavailable")
    return target


def target_version(db: Session, row: BrowserSession) -> str:
    principal = db.get(Principal, row.principal_id, populate_existing=True)
    if principal is None:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Session identity requires repair")
    return security_version(row, principal, incarnation(db))


def validate_session_revoke(
    db: Session, actor: AuthenticatedContext, command: SessionRevoke, *, official: bool = False
) -> BrowserSession:
    target = session_target(db, actor, command.target_session_id)
    if official:
        current_owner(db, actor)
        if target.principal_id == actor.principal_id:
            raise DomainError("VALIDATION_FAILED", "Own sessions use the direct session command")
    if target.revoked or target_version(db, target) != command.expected_security_version:
        raise DomainError("REVISION_CONFLICT", "Session changed; refresh its security version")
    return target


def authorized_session_receipt(
    db: Session, actor: AuthenticatedContext, row: Receipt
) -> SessionMutationReceipt:
    current_actor(db, actor)
    if row.principal_id != actor.principal_id:
        raise DomainError("NOT_FOUND", "Operation is unavailable")
    target = session_target(db, actor, row.target_id)
    if (
        row.owner != "identity"
        or row.target_kind != "browser_session"
        or row.project_id is not None
        or row.command not in {"identity.session.revoke.v1", "identity.session.logout.v1"}
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Session receipt requires repair")
    try:
        result = SessionMutationReceipt.model_validate(row.result)
        event = db.scalar(
            select(OutboxEvent)
            .options(defer(OutboxEvent.payload))
            .where(OutboxEvent.operation_id == row.id)
        )
        if (
            result.operation_id != row.id
            or result.command != row.command
            or result.session_id != target.id
            or result.principal_id != target.principal_id
            or not target.revoked
            or result.request.kind != row.command
            or result.request.idempotency_key != row.idempotency_key
            or content_digest(result.request.model_dump(mode="json")) != row.payload_hash
            or (
                isinstance(result.request, SessionRevoke)
                and result.request.target_session_id != target.id
            )
            or (
                isinstance(result.request, SessionLogout)
                and (
                    row.authentication_ref != target.id or target.principal_id != actor.principal_id
                )
            )
            or event is None
            or (
                event.principal_id,
                event.owner,
                event.project_id,
                event.target_kind,
                event.target_id,
                event.schema_version,
                event.target_revision,
                event.event_type,
                event.committed_at,
            )
            != (
                row.principal_id,
                "identity",
                None,
                "browser_session",
                target.id,
                1,
                1,
                row.command.removesuffix(".v1"),
                result.committed_at,
            )
            or SessionMutationReceipt.model_validate(event.payload) != result
        ):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Session receipt requires repair")
        if target.principal_id != actor.principal_id:
            protected = db.scalar(
                select(ProtectedRequest)
                .options(defer(ProtectedRequest.payload))
                .where(ProtectedRequest.operation_id == row.id)
            )
            if (
                protected is None
                or (
                    protected.principal_id,
                    protected.command,
                    protected.idempotency_key,
                    protected.payload_hash,
                    protected.session_id,
                    protected.state,
                )
                != (
                    row.principal_id,
                    row.command,
                    row.idempotency_key,
                    row.payload_hash,
                    row.authentication_ref,
                    "COMMITTED",
                )
                or (
                    protected.approved_at is None
                    or protected.strong_authenticated_at is None
                    or protected.nonce_hash is not None
                    or protected.nonce_deadline is not None
                )
            ):
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Session consent requires repair")
            if SessionRevoke.model_validate(protected.payload) != result.request:
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Session consent requires repair")
        return result
    except (ValidationError, json.JSONDecodeError):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Session receipt requires repair") from None


def apply_session_end(
    db: Session,
    actor: AuthenticatedContext,
    command: SessionRevoke | SessionLogout,
    *,
    operation_id: str | None = None,
    official: bool = False,
) -> SessionMutationReceipt:
    current_actor(db, actor)
    identity = (
        command.target_session_id
        if isinstance(command, SessionRevoke)
        else actor.authentication_ref
    )
    target = session_target(db, actor, identity)
    prior = db.scalar(
        select(Receipt)
        .options(defer(Receipt.result))
        .where(
            Receipt.principal_id == actor.principal_id,
            Receipt.command == command.kind,
            Receipt.idempotency_key == command.idempotency_key,
        )
    )
    payload_hash = content_digest(command.model_dump(mode="json"))
    if prior is not None:
        result = authorized_session_receipt(db, actor, prior)
        if prior.payload_hash != payload_hash:
            raise DomainError("IDEMPOTENCY_CONFLICT", "Operation identity has different input")
        return result
    if target.principal_id != actor.principal_id and not official:
        raise DomainError(
            "PERMISSION_DENIED", "Another human's session requires exact official consent"
        )
    if official:
        current_owner(db, actor)
    if target.revoked or target_version(db, target) != command.expected_security_version:
        raise DomainError("REVISION_CONFLICT", "Session changed; refresh its security version")
    current_actor(db, actor)
    revoke_session(db, actor.authentication_ref, identity)
    result = SessionMutationReceipt(
        command=command.kind,
        operation_id=operation_id or str(uuid4()),
        committed_at=datetime.now(UTC).isoformat(),
        session_id=target.id,
        principal_id=target.principal_id,
        revoked=True,
        security_version=target_version(db, target),
        request=command,
    )
    db.add(
        Receipt(
            id=result.operation_id,
            principal_id=actor.principal_id,
            command=command.kind,
            idempotency_key=command.idempotency_key,
            payload_hash=payload_hash,
            project_id=None,
            owner="identity",
            target_kind="browser_session",
            target_id=target.id,
            authentication_ref=actor.authentication_ref,
            result=result.model_dump(mode="json"),
        )
    )
    db.flush()
    db.add(
        OutboxEvent(
            event_id=str(uuid4()),
            operation_id=result.operation_id,
            event_type=command.kind.removesuffix(".v1"),
            schema_version=1,
            principal_id=actor.principal_id,
            project_id=None,
            owner="identity",
            target_kind="browser_session",
            target_id=target.id,
            committed_at=result.committed_at,
            target_revision=1,
            payload=result.model_dump(mode="json"),
        )
    )
    db.flush()
    return result


def session_page(
    db: Session, actor: AuthenticatedContext, limit: int, cursor: str | None
) -> BrowserSessionPage:
    current_actor(db, actor)
    principal = db.get(Principal, actor.principal_id)
    assert principal is not None
    current = incarnation(db)
    after = ""
    scope = {
        "incarnation": current,
        "principal": principal.id,
        "role": principal.role,
        "epoch": principal.authorization_epoch,
    }
    if cursor is not None:
        try:
            data = json.loads(base64.urlsafe_b64decode(cursor.encode()))
            if not isinstance(data, dict) or set(data) != {*scope, "after"}:
                raise ValueError
            if any(data[name] != value for name, value in scope.items()):
                raise DomainError("REVISION_CONFLICT", "Session inventory requires a fresh read")
            if (
                not isinstance(data["after"], str)
                or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}", data["after"]) is None
            ):
                raise ValueError
            after = data["after"]
        except (ValueError, UnicodeError, TypeError):
            raise DomainError("VALIDATION_FAILED", "Invalid session inventory cursor") from None
    if not 1 <= limit <= 100:
        raise DomainError("VALIDATION_FAILED", "Session inventory limit is invalid")
    query = select(BrowserSession).where(BrowserSession.id > after)
    if principal.role != "OWNER":
        query = query.where(BrowserSession.principal_id == actor.principal_id)
    rows = list(db.scalars(query.order_by(BrowserSession.id).limit(limit + 1)))
    items = [
        BrowserSessionItem.model_validate(
            {
                "session_id": row.id,
                "principal_id": row.principal_id,
                "client_label": row.client_label,
                "authentication_method": row.authentication_method,
                "audience": row.audience,
                "issued_at": row.issued_at,
                "last_activity": row.last_activity,
                "absolute_deadline": row.absolute_deadline,
                "inactivity_seconds": row.inactivity_seconds,
                "strong_authenticated_at": row.strong_authenticated_at,
                "strong_freshness_seconds": row.strong_freshness_seconds,
                "revoked": row.revoked,
                "security_version": target_version(db, row),
            }
        )
        for row in rows[:limit]
    ]
    more = len(rows) > limit
    next_cursor = (
        base64.urlsafe_b64encode(
            json.dumps({**scope, "after": items[-1].session_id}, separators=(",", ":")).encode()
        ).decode()
        if more
        else None
    )
    return BrowserSessionPage(
        items=items,
        next_cursor=next_cursor,
        has_more=more,
        observed_at=datetime.now(UTC).isoformat(),
        store_incarnation=current,
    )
