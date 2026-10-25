# SPDX-License-Identifier: AGPL-3.0-only
"Durable session primitives for trusted authentication services; no login ceremony."

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from journeon.contracts import DomainError
from journeon.database import require_compatible_schema
from journeon.models import BrowserSession, Principal, ProtectedRequest


def utc_seconds() -> int:
    return int(time.time())


def digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def denied() -> DomainError:
    return DomainError("AUTHENTICATION_REQUIRED", "A current authenticated session is required")


@dataclass(frozen=True)
class SessionPolicy:
    absolute_seconds: int = 604800
    inactivity_seconds: int = 43200
    strong_freshness_seconds: int = 300

    def __post_init__(self) -> None:
        for value in (
            self.absolute_seconds,
            self.inactivity_seconds,
            self.strong_freshness_seconds,
        ):
            if type(value) is not int or not 0 < value < 2**62:
                raise ValueError("Session durations must be finite positive integer seconds")


DEFAULT_SESSION_POLICY = SessionPolicy()


@dataclass(frozen=True)
class IssuedSession:
    session_id: str
    token: str = field(repr=False)
    csrf_token: str = field(repr=False)


def issue_session(
    session: Session,
    principal_id: str,
    *,
    authentication_method: str,
    client_label: str,
    strong: bool,
    policy: SessionPolicy = DEFAULT_SESSION_POLICY,
) -> IssuedSession:
    "Call only after trusted authentication verification, in its committing transaction."
    require_compatible_schema(session)
    principal = session.get(Principal, principal_id, populate_existing=True)
    if principal is None or not principal.enabled:
        raise denied()
    if not authentication_method or len(authentication_method) > 128 or len(client_label) > 128:
        raise ValueError("Authentication method and client label must fit session metadata")
    now = utc_seconds()
    if not 0 <= now < 2**62:
        raise denied()
    issued = IssuedSession(str(uuid4()), secrets.token_urlsafe(32), secrets.token_urlsafe(32))
    session.add(
        BrowserSession(
            id=issued.session_id,
            token_hash=digest(issued.token),
            csrf_hash=digest(issued.csrf_token),
            principal_id=principal.id,
            principal_epoch=principal.authorization_epoch,
            authentication_method=authentication_method,
            client_label=client_label,
            issued_at=now,
            last_activity=now,
            last_observed=now,
            absolute_deadline=now + policy.absolute_seconds,
            inactivity_seconds=policy.inactivity_seconds,
            strong_authenticated_at=now if strong else None,
            strong_freshness_seconds=policy.strong_freshness_seconds,
            revoked=False,
        )
    )
    session.flush()
    return issued


def current_session(
    session: Session,
    session_id: str,
    *,
    principal_id: str | None = None,
    principal_epoch: int | None = None,
    strong: bool = False,
    activity: bool = False,
) -> BrowserSession:
    require_compatible_schema(session)
    record = session.get(BrowserSession, session_id, populate_existing=True)
    now = utc_seconds()
    if record is None:
        raise denied()
    observations = session.info.get("session_clock_observations")
    if observations is None:
        raise DomainError(
            "DEPENDENCY_UNAVAILABLE", "Session validation requires a service transaction"
        )
    observations[record.id] = max(observations.get(record.id, 0), now)
    principal = session.get(Principal, record.principal_id, populate_existing=True)
    if (
        record.revoked
        or principal is None
        or not principal.enabled
        or record.principal_epoch != principal.authorization_epoch
        or (principal_id is not None and record.principal_id != principal_id)
        or (principal_epoch is not None and record.principal_epoch != principal_epoch)
        or now < record.last_observed
        or now < observations[record.id]
        or now < record.issued_at
        or now >= record.absolute_deadline
        or now >= record.last_activity + record.inactivity_seconds
        or (
            strong
            and (
                record.strong_authenticated_at is None
                or now < record.strong_authenticated_at
                or now >= record.strong_authenticated_at + record.strong_freshness_seconds
            )
        )
    ):
        raise denied()
    record.last_observed = now
    if activity:
        record.last_activity = now
    session.flush()
    return record


def resolve_cookie(
    session: Session,
    token: str,
    *,
    csrf_token: str | None = None,
    mutation: bool = False,
    activity: bool | None = None,
) -> BrowserSession:
    if not token or len(token) != 43:
        raise denied()
    record = session.scalar(
        select(BrowserSession).where(BrowserSession.token_hash == digest(token))
    )
    if record is None:
        raise denied()
    if mutation and (
        csrf_token is None
        or len(csrf_token) != 43
        or not secrets.compare_digest(record.csrf_hash, digest(csrf_token))
    ):
        raise denied()
    # Only explicit commands qualify as activity; reads and polling cannot prolong idle access.
    return current_session(session, record.id, activity=mutation if activity is None else activity)


def rotate_session(session: Session, session_id: str, *, strong: bool) -> IssuedSession:
    "Rotate after verified reauthentication; preserve the existing absolute deadline."
    old = current_session(session, session_id)
    remaining = old.absolute_deadline - old.last_observed
    replacement = issue_session(
        session,
        old.principal_id,
        authentication_method=old.authentication_method,
        client_label=old.client_label,
        strong=strong,
        policy=SessionPolicy(remaining, old.inactivity_seconds, old.strong_freshness_seconds),
    )
    new = session.get(BrowserSession, replacement.session_id)
    assert new is not None
    observations = session.info["session_clock_observations"]
    observations[old.id] = max(observations[old.id], new.issued_at)
    if new.issued_at < old.last_observed or new.issued_at >= old.absolute_deadline:
        raise denied()
    new.absolute_deadline = old.absolute_deadline
    new.audience = old.audience
    old.revoked = True
    invalidate_protected(session, old.id)
    session.flush()
    return replacement


def revoke_session(session: Session, acting_session_id: str, target_session_id: str) -> None:
    actor = current_session(session, acting_session_id)
    principal = session.get(Principal, actor.principal_id)
    target = session.get(BrowserSession, target_session_id)
    if target is None or (
        target.principal_id != actor.principal_id
        and (principal is None or principal.role != "OWNER")
    ):
        raise DomainError("NOT_FOUND", "Session is unavailable")
    target.revoked = True
    invalidate_protected(session, target.id)
    session.flush()


def session_inventory(
    session: Session, acting_session_id: str
) -> list[dict[str, str | int | bool | None]]:
    actor = current_session(session, acting_session_id)
    principal = session.get(Principal, actor.principal_id)
    query = select(BrowserSession)
    if principal is None or principal.role != "OWNER":
        query = query.where(BrowserSession.principal_id == actor.principal_id)
    return [
        {
            "session_id": row.id,
            "principal_id": row.principal_id,
            "authentication_method": row.authentication_method,
            "client_label": row.client_label,
            "issued_at": row.issued_at,
            "last_activity": row.last_activity,
            "absolute_deadline": row.absolute_deadline,
            "revoked": row.revoked,
        }
        for row in session.scalars(query.order_by(BrowserSession.issued_at, BrowserSession.id))
    ]


def invalidate_protected(session: Session, session_id: str) -> None:
    session.execute(
        update(ProtectedRequest)
        .where(
            ProtectedRequest.session_id == session_id,
            ProtectedRequest.state.in_(("PENDING", "APPROVED")),
        )
        .values(state="INVALIDATED", nonce_hash=None, nonce_deadline=None)
    )


def security_version(record: BrowserSession, principal: Principal, incarnation: str) -> str:
    "Hash security state after authorization; this version conveys no authority."
    state = {
        "version": 1,
        "store_incarnation": incarnation,
        "session_id": record.id,
        "principal_id": record.principal_id,
        "principal_epoch": record.principal_epoch,
        "principal_enabled": principal.enabled,
        "principal_role": principal.role,
        "authorization_epoch": principal.authorization_epoch,
        "credential_revision": principal.credential_revision,
        "authentication_method": record.authentication_method,
        "audience": record.audience,
        "issued_at": record.issued_at,
        "absolute_deadline": record.absolute_deadline,
        "inactivity_seconds": record.inactivity_seconds,
        "strong_authenticated_at": record.strong_authenticated_at,
        "strong_freshness_seconds": record.strong_freshness_seconds,
        "revoked": record.revoked,
    }
    return digest(json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
