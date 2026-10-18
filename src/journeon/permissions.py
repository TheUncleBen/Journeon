# SPDX-License-Identifier: AGPL-3.0-only
"""Trusted actor context and current service-owned grant evaluation."""

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from journeon.contracts import DomainError
from journeon.models import AccessGrant, Principal


@dataclass(frozen=True)
class AuthenticatedContext:
    principal_id: str
    principal_epoch: int
    authentication_ref: str


def current_owner(session: Session, actor: AuthenticatedContext) -> Principal:
    principal = session.get(Principal, actor.principal_id, populate_existing=True)
    if (
        principal is None
        or not principal.enabled
        or principal.role != "OWNER"
        or principal.authorization_epoch != actor.principal_epoch
    ):
        raise DomainError("PERMISSION_DENIED", "Current Owner authority is required")
    return principal


def require_grant(
    session: Session,
    actor: AuthenticatedContext,
    capability: str,
    *,
    project_id: str | None = None,
) -> None:
    # Each capability is explicit: a creation grant is never a read/share grant.
    grants = session.scalars(
        select(AccessGrant).where(
            AccessGrant.principal_id == actor.principal_id,
            AccessGrant.capability == capability,
            AccessGrant.enabled.is_(True),
        )
    )
    now = datetime.now(UTC)
    for grant in grants:
        if grant.expires_at is not None:
            try:
                expiry = datetime.fromisoformat(grant.expires_at)
                if expiry.tzinfo is None or expiry <= now:
                    continue
            except ValueError:
                continue
        deployment = grant.resource_kind == "deployment" and grant.resource_id == "deployment"
        project = (
            project_id is not None
            and grant.resource_kind == "project"
            and grant.resource_id == project_id
        )
        if deployment or project:
            return
    raise DomainError("PERMISSION_DENIED", "The current operation grant is missing or expired")
