# SPDX-License-Identifier: AGPL-3.0-only
"""Fixture-only protected protocol; no production route or lifetime defaults."""

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from uuid import uuid4

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, defer

from journeon.contracts import DomainError, PasskeyLabelCommand, PasskeyMutationReceipt
from journeon.database import transaction
from journeon.factors import apply_label, owned_key
from journeon.models import BrowserSession, IdentityState, Principal, ProtectedRequest
from journeon.permissions import AuthenticatedContext
from journeon.receipts import OperationService
from journeon.sessions import current_session, digest, utc_seconds


@dataclass(frozen=True)
class FixtureProtectedPolicy:
    request_seconds: int
    preview_seconds: int
    fixture_only: bool

    def __post_init__(self) -> None:
        if self.fixture_only is not True or any(
            type(value) is not int or not 0 < value < 2**31
            for value in (self.request_seconds, self.preview_seconds)
        ):
            raise ValueError("Explicit fixture-only protected lifetimes are required")


@dataclass(frozen=True)
class ProtectedPreview:
    request_id: str
    command: PasskeyLabelCommand
    request_hash: str
    deadline: int
    nonce: str = field(repr=False)


def request_digest(command: PasskeyLabelCommand) -> str:
    return hashlib.sha256(
        json.dumps(
            command.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def policy_hash(db: Session, record: BrowserSession) -> str:
    identity = db.get(IdentityState, 1, populate_existing=True)
    policy = [
        record.inactivity_seconds,
        record.strong_freshness_seconds,
        identity.rate_policy if identity is not None else None,
    ]
    return hashlib.sha256(
        json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def official_session(db: Session, actor: AuthenticatedContext) -> BrowserSession:
    record = current_session(
        db,
        actor.authentication_ref,
        principal_id=actor.principal_id,
        principal_epoch=actor.principal_epoch,
        strong=True,
    )
    if record.audience != "official_browser":
        raise DomainError("PERMISSION_DENIED", "Qualified official authentication is required")
    return record


class ProtectedService:
    def __init__(self, engine: Engine, *, fixture_policy: FixtureProtectedPolicy) -> None:
        if (
            not isinstance(fixture_policy, FixtureProtectedPolicy)
            or not fixture_policy.fixture_only
        ):
            raise ValueError("Protected production activation is unavailable")
        self.engine = engine
        self.policy = fixture_policy

    @classmethod
    def for_fixtures(cls, engine: Engine, policy: FixtureProtectedPolicy) -> "ProtectedService":
        return cls(engine, fixture_policy=policy)

    def prepare_label(self, actor: AuthenticatedContext, command: PasskeyLabelCommand) -> str:
        # Exercise the protocol with a real typed local effect without shipping a new consent loop.
        with transaction(self.engine) as db:
            record = official_session(db, actor)
            previous = db.scalar(
                select(ProtectedRequest)
                .options(defer(ProtectedRequest.payload))
                .where(
                    ProtectedRequest.principal_id == actor.principal_id,
                    ProtectedRequest.command == "passkey.label.v1",
                    ProtectedRequest.idempotency_key == command.idempotency_key,
                )
            )
            if previous is not None:
                if (
                    previous.payload_hash != request_digest(command)
                    or previous.session_id != record.id
                ):
                    raise DomainError(
                        "IDEMPOTENCY_CONFLICT",
                        "Protected operation identity has different input or session",
                    )
                return previous.id
            key = owned_key(db, actor, command.passkey_id, strong=True)
            if key.revoked or key.revision != command.expected_revision:
                raise DomainError("REVISION_CONFLICT", "Passkey changed; refresh its revision")
            principal = db.get(Principal, actor.principal_id)
            assert principal is not None
            now = utc_seconds()
            request_id = str(uuid4())
            db.add(
                ProtectedRequest(
                    id=request_id,
                    operation_id=str(uuid4()),
                    principal_id=actor.principal_id,
                    principal_epoch=actor.principal_epoch,
                    session_id=record.id,
                    command="passkey.label.v1",
                    idempotency_key=command.idempotency_key,
                    payload=command.model_dump(mode="json"),
                    payload_hash=request_digest(command),
                    credential_revision=principal.credential_revision,
                    policy_hash=policy_hash(db, record),
                    issued_at=now,
                    deadline=min(now + self.policy.request_seconds, record.absolute_deadline),
                    state="PENDING",
                    strong_authenticated_at=record.strong_authenticated_at,
                )
            )
            return request_id

    def _request(
        self, db: Session, actor: AuthenticatedContext, request_id: str
    ) -> ProtectedRequest:
        current_session(
            db,
            actor.authentication_ref,
            principal_id=actor.principal_id,
            principal_epoch=actor.principal_epoch,
        )
        row = db.get(ProtectedRequest, request_id, options=[defer(ProtectedRequest.payload)])
        if row is None or row.principal_id != actor.principal_id:
            raise DomainError("NOT_FOUND", "Protected request is unavailable")
        return row

    def _bound(
        self, db: Session, actor: AuthenticatedContext, row: ProtectedRequest
    ) -> PasskeyLabelCommand:
        record = official_session(db, actor)
        principal = db.get(Principal, actor.principal_id)
        now = utc_seconds()
        if (
            row.state not in {"PENDING", "APPROVED"}
            or row.session_id != record.id
            or row.principal_epoch != actor.principal_epoch
            or principal is None
            or row.credential_revision != principal.credential_revision
            or row.policy_hash != policy_hash(db, record)
            or row.strong_authenticated_at != record.strong_authenticated_at
            or row.command != "passkey.label.v1"
            or now < row.issued_at
            or now >= row.deadline
        ):
            raise DomainError("PERMISSION_DENIED", "Protected request is no longer executable")
        command = PasskeyLabelCommand.model_validate(row.payload)
        if request_digest(command) != row.payload_hash:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Protected request state requires repair")
        key = owned_key(db, actor, command.passkey_id, strong=True)
        if key.revoked or key.revision != command.expected_revision:
            raise DomainError("REVISION_CONFLICT", "Passkey changed; refresh its revision")
        return command

    def preview(self, actor: AuthenticatedContext, request_id: str) -> ProtectedPreview:
        with transaction(self.engine) as db:
            row = self._request(db, actor, request_id)
            command = self._bound(db, actor, row)
            if row.state != "PENDING":
                raise DomainError("PERMISSION_DENIED", "Protected request is not awaiting consent")
            record = official_session(db, actor)
            nonce = secrets.token_urlsafe(32)
            row.nonce_hash = digest(nonce)
            row.nonce_deadline = min(
                utc_seconds() + self.policy.preview_seconds,
                row.deadline,
                record.absolute_deadline,
                record.last_activity + record.inactivity_seconds,
            )
            return ProtectedPreview(row.id, command, row.payload_hash, row.nonce_deadline, nonce)

    def approve(self, actor: AuthenticatedContext, request_id: str, nonce: str) -> None:
        with transaction(self.engine) as db:
            row = self._request(db, actor, request_id)
            self._bound(db, actor, row)
            now = utc_seconds()
            if (
                row.state != "PENDING"
                or len(nonce) != 43
                or row.nonce_hash is None
                or row.nonce_deadline is None
                or now >= row.nonce_deadline
                or not secrets.compare_digest(row.nonce_hash, digest(nonce))
            ):
                raise DomainError("PERMISSION_DENIED", "Protected preview is unavailable")
            row.state = "APPROVED"
            row.approved_at = now
            row.approval_deadline = min(now + 300, row.deadline)
            row.nonce_hash = None
            row.nonce_deadline = None

    def commit(self, actor: AuthenticatedContext, request_id: str) -> PasskeyMutationReceipt:
        with transaction(self.engine) as db:
            row = self._request(db, actor, request_id)
            if row.state == "COMMITTED":
                operation_id = row.operation_id
            else:
                command = self._bound(db, actor, row)
                now = utc_seconds()
                if (
                    row.state != "APPROVED"
                    or row.approved_at is None
                    or row.approval_deadline is None
                    or now < row.approved_at
                    or now >= row.approval_deadline
                ):
                    raise DomainError("PERMISSION_DENIED", "Current protected consent is required")
                result = apply_label(db, actor, command, operation_id=row.operation_id)
                if result.operation_id != row.operation_id:
                    raise DomainError(
                        "IDEMPOTENCY_CONFLICT", "Operation was committed by another request"
                    )
                # Final authority and timers remain inside the same serialized write transaction.
                official_session(db, actor)
                final_now = utc_seconds()
                if final_now < now or final_now >= min(row.deadline, row.approval_deadline):
                    raise DomainError(
                        "PERMISSION_DENIED", "Protected approval expired before commit"
                    )
                row.state = "COMMITTED"
                return result
        reconciled = OperationService(self.engine).receipt(actor, operation_id)
        if not isinstance(reconciled, PasskeyMutationReceipt):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored operation state requires repair")
        return reconciled

    def cancel(self, actor: AuthenticatedContext, request_id: str) -> PasskeyMutationReceipt | None:
        with transaction(self.engine) as db:
            row = self._request(db, actor, request_id)
            committed = row.state == "COMMITTED"
            if not committed:
                if row.state in {"PENDING", "APPROVED"}:
                    row.state = "CANCELLED"
                    row.nonce_hash = None
                    row.nonce_deadline = None
                return None
        return self.commit(actor, request_id)

    def status(self, actor: AuthenticatedContext, request_id: str) -> str:
        with transaction(self.engine) as db:
            row = self._request(db, actor, request_id)
            if row.state in {"PENDING", "APPROVED"}:
                now = utc_seconds()
                if now >= row.deadline or (
                    row.approval_deadline is not None and now >= row.approval_deadline
                ):
                    row.state = "EXPIRED"
                else:
                    principal = db.get(Principal, actor.principal_id)
                    try:
                        original = current_session(
                            db,
                            row.session_id,
                            principal_id=row.principal_id,
                            principal_epoch=row.principal_epoch,
                        )
                        if (
                            original.audience != "official_browser"
                            or principal is None
                            or principal.credential_revision != row.credential_revision
                            or policy_hash(db, original) != row.policy_hash
                        ):
                            row.state = "INVALIDATED"
                    except DomainError:
                        row.state = "INVALIDATED"
                if row.state in {"EXPIRED", "INVALIDATED"}:
                    row.nonce_hash = None
                    row.nonce_deadline = None
            return row.state
