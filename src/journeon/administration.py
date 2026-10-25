# SPDX-License-Identifier: AGPL-3.0-only
"""Exact Owner administration of existing permission and egress records."""

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

from journeon.contracts import (
    DeploymentPolicyReceipt,
    DeploymentPolicyView,
    DomainError,
    GrantCapability,
    GrantCatalog,
    GrantPage,
    GrantReceipt,
    GrantRevoke,
    GrantSet,
    GrantView,
    PolicyInitialize,
)
from journeon.database import transaction
from journeon.instructions import digest
from journeon.models import (
    AccessGrant,
    AgentProfile,
    Bot,
    DeploymentPolicy,
    InstructionBundle,
    OutboxEvent,
    Principal,
    Project,
    ProtectedRequest,
    Receipt,
    StoreIdentity,
    Team,
)
from journeon.permissions import AuthenticatedContext, current_owner
from journeon.policy import PolicyState

AdministrativeEffect = GrantSet | GrantRevoke | PolicyInitialize
AdministrativeReceipt = GrantReceipt | DeploymentPolicyReceipt
ADMINISTRATION_COMMANDS = frozenset(
    ("permission.grant.set.v1", "permission.grant.revoke.v1", "egress.policy.initialize.v1")
)


@contextmanager
def administration_transaction(engine: Engine) -> Iterator[Session]:
    try:
        with transaction(engine) as db:
            yield db
    except (ValidationError, json.JSONDecodeError):
        raise DomainError(
            "DEPENDENCY_UNAVAILABLE", "Administration state requires repair"
        ) from None
    except SQLAlchemyError:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Administration store is unavailable") from None


def catalog(db: Session, actor: AuthenticatedContext) -> GrantCatalog:
    current_owner(db, actor)
    from journeon.registry import MODULES

    entries = []
    for capability in sorted({p for module in MODULES.values() for p in module["permissions"]}):
        kinds = grant_scopes(capability)
        if kinds:
            entries.append(GrantCapability(capability=capability, resource_kinds=list(kinds)))
    return GrantCatalog(capabilities=entries, unavailable_new_resource_kinds=["legacy_collection"])


def grant_scopes(capability: str) -> tuple[str, ...]:
    if capability in {"project.create", "lifecycle.restore"}:
        return ("deployment",)
    if capability.startswith("project.instruction."):
        return ("project",)
    namespace = capability.split(".", 1)[0]
    if namespace in {"profile", "bot", "team", "instruction_bundle"}:
        return (namespace,)
    if namespace in {"project", "task", "attempt", "execution", "job"}:
        return ("deployment", "project")
    return ()


def grant_view(row: AccessGrant) -> GrantView:
    return GrantView.model_validate(
        dict(
            grant_id=row.id,
            principal_id=row.principal_id,
            capability=row.capability,
            resource_kind=row.resource_kind,
            resource_id=row.resource_id,
            enabled=row.enabled,
            revision=row.revision,
            expires_at=row.expires_at,
            provenance=row.provenance,
        )
    )


def policy_view(db: Session, actor: AuthenticatedContext) -> DeploymentPolicyView:
    current_owner(db, actor)
    row = db.get(DeploymentPolicy, 1)
    if row is None:
        return DeploymentPolicyView(
            status="UNCONFIGURED",
            revision=0,
            approval_id=None,
            approved_by=None,
            approved_providers=[],
            verification_policy_ref=None,
        )
    policy = PolicyState.model_validate(row, from_attributes=True)
    return DeploymentPolicyView(status="CONFIGURED", **policy.model_dump())


def incarnation(db: Session) -> str:
    store = db.get(StoreIdentity, 1)
    if store is None or not store.security_reconciled:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Store security reconciliation is required")
    return store.incarnation


def list_grants(
    db: Session, actor: AuthenticatedContext, limit: int, cursor: str | None
) -> GrantPage:
    current_owner(db, actor)
    current = incarnation(db)
    after = ""
    if cursor is not None:
        try:
            if len(cursor) > 1024:
                raise ValueError
            data = json.loads(base64.urlsafe_b64decode(cursor.encode()))
            if not isinstance(data, dict) or set(data) != {"incarnation", "principal", "after"}:
                raise ValueError
            if data["incarnation"] != current or data["principal"] != actor.principal_id:
                raise DomainError("REVISION_CONFLICT", "Grant inventory requires a fresh read")
            if not isinstance(data["after"], str) or len(data["after"]) > 128:
                raise ValueError
            after = data["after"]
        except (ValueError, UnicodeError, TypeError):
            raise DomainError("VALIDATION_FAILED", "Invalid grant inventory cursor") from None
    if not 1 <= limit <= 100:
        raise DomainError("VALIDATION_FAILED", "Grant inventory limit is invalid")
    rows = list(
        db.scalars(
            select(AccessGrant)
            .where(AccessGrant.id > after)
            .order_by(AccessGrant.id)
            .limit(limit + 1)
        )
    )
    more = len(rows) > limit
    items = [grant_view(row) for row in rows[:limit]]
    next_cursor = None
    if more:
        next_cursor = base64.urlsafe_b64encode(
            json.dumps(
                {
                    "incarnation": current,
                    "principal": actor.principal_id,
                    "after": items[-1].grant_id,
                },
                separators=(",", ":"),
            ).encode()
        ).decode()
    return GrantPage(
        items=items,
        next_cursor=next_cursor,
        has_more=more,
        observed_at=datetime.now(UTC).isoformat(),
        store_incarnation=current,
    )


def validate_effect(
    db: Session, actor: AuthenticatedContext, effect: AdministrativeEffect
) -> AccessGrant | None:
    current_owner(db, actor)
    incarnation(db)
    if isinstance(effect, PolicyInitialize):
        if db.get(DeploymentPolicy, 1) is not None:
            raise DomainError("REVISION_CONFLICT", "Deployment policy is already configured")
        return None
    if isinstance(effect, GrantRevoke):
        row = db.get(AccessGrant, effect.grant_id)
        if row is None:
            raise DomainError("NOT_FOUND", "Grant is unavailable")
        if row.revision != effect.expected_revision:
            raise DomainError("REVISION_CONFLICT", "Grant changed; refresh its revision")
        return row
    subject = db.get(Principal, effect.principal_id)
    if subject is None or not subject.enabled:
        raise DomainError("NOT_FOUND", "Grant subject is unavailable")
    if effect.resource_kind == "legacy_collection":
        if (
            re.fullmatch(
                r"legacy_collection\.preview:[1-9][0-9]*:[a-f0-9]{64}:[a-zA-Z0-9][a-zA-Z0-9._:-]*",
                effect.capability,
            )
            is None
        ):
            raise DomainError(
                "VALIDATION_FAILED", "Legacy grant requires its exact evidence identity"
            )
        if not db.scalar(
            select(AccessGrant.id).where(
                AccessGrant.principal_id == effect.principal_id,
                AccessGrant.capability == effect.capability,
                AccessGrant.resource_kind == effect.resource_kind,
                AccessGrant.resource_id == effect.resource_id,
            )
        ):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Legacy inventory grant provisioning is unavailable"
            )
    available = {
        entry.capability: entry.resource_kinds for entry in catalog(db, actor).capabilities
    }
    if effect.resource_kind == "legacy_collection":
        available[effect.capability] = ["legacy_collection"]
    if effect.resource_kind not in available.get(effect.capability, ()):
        raise DomainError("VALIDATION_FAILED", "Capability does not support the selected scope")
    if effect.resource_kind == "deployment":
        if effect.resource_id != "deployment":
            raise DomainError("VALIDATION_FAILED", "Deployment grant scope is invalid")
    elif effect.resource_kind != "legacy_collection":
        identities = {
            "project": Project.id,
            "profile": AgentProfile.id,
            "bot": Bot.id,
            "team": Team.id,
            "instruction_bundle": InstructionBundle.id,
        }
        identity = identities[effect.resource_kind]
        if db.scalar(select(identity).where(identity == effect.resource_id)) is None:
            raise DomainError("NOT_FOUND", "Grant resource is unavailable")
    if effect.expires_at is not None:
        try:
            expiry = datetime.fromisoformat(effect.expires_at)
            if expiry.tzinfo is None or (effect.enabled and expiry <= datetime.now(UTC)):
                raise ValueError
        except ValueError:
            raise DomainError(
                "VALIDATION_FAILED", "Grant expiry must be an explicit future time"
            ) from None
    rows = list(
        db.scalars(
            select(AccessGrant).where(
                AccessGrant.principal_id == effect.principal_id,
                AccessGrant.capability == effect.capability,
                AccessGrant.resource_kind == effect.resource_kind,
                AccessGrant.resource_id == effect.resource_id,
            )
        )
    )
    if len(rows) > 1:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Duplicate grant scope requires reconciliation")
    row = rows[0] if rows else None
    if (row.revision if row else 0) != effect.expected_revision:
        raise DomainError("REVISION_CONFLICT", "Grant changed; refresh its revision")
    return row


def _receipt_evidence(db: Session, row: Receipt) -> tuple[AdministrativeEffect, OutboxEvent]:
    request = db.scalar(
        select(ProtectedRequest)
        .options(defer(ProtectedRequest.payload))
        .where(ProtectedRequest.operation_id == row.id)
    )
    if (
        request is None
        or request.state != "COMMITTED"
        or request.principal_id != row.principal_id
        or request.command != row.command
        or request.idempotency_key != row.idempotency_key
        or request.payload_hash != row.payload_hash
        or request.session_id != row.authentication_ref
        or request.approved_at is None
        or not request.issued_at <= request.approved_at < request.deadline
        or request.strong_authenticated_at is None
        or request.nonce_hash is not None
        or request.nonce_deadline is not None
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Administration receipt requires repair")
    event = db.scalar(
        select(OutboxEvent)
        .options(defer(OutboxEvent.payload))
        .where(OutboxEvent.operation_id == row.id)
    )
    expected_event = {
        "permission.grant.set.v1": "permission.grant.set",
        "permission.grant.revoke.v1": "permission.grant.revoked",
        "egress.policy.initialize.v1": "egress.policy.initialized",
    }[row.command]
    if event is None or (
        event.principal_id,
        event.owner,
        event.target_kind,
        event.target_id,
        event.project_id,
        event.schema_version,
        event.event_type,
    ) != (
        row.principal_id,
        row.owner,
        row.target_kind,
        row.target_id,
        row.project_id,
        1,
        expected_event,
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Administration receipt requires repair")
    effect: AdministrativeEffect
    if row.command == "permission.grant.set.v1":
        effect = GrantSet.model_validate(request.payload)
    elif row.command == "permission.grant.revoke.v1":
        effect = GrantRevoke.model_validate(request.payload)
    else:
        effect = PolicyInitialize.model_validate(request.payload)
    if (
        effect.kind != row.command
        or effect.idempotency_key != row.idempotency_key
        or digest(effect.model_dump(mode="json")) != row.payload_hash
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Administration receipt requires repair")
    return effect, event


def authorized_receipt(
    db: Session, actor: AuthenticatedContext, row: Receipt
) -> AdministrativeReceipt:
    current_owner(db, actor)
    if row.principal_id != actor.principal_id:
        raise DomainError("NOT_FOUND", "Operation is unavailable")
    if row.command in {"permission.grant.set.v1", "permission.grant.revoke.v1"}:
        if row.owner != "permissions" or row.target_kind != "grant" or row.project_id is not None:
            raise DomainError("PERMISSION_DENIED", "Grant receipt scope is unavailable")
    elif row.command == "egress.policy.initialize.v1":
        if (row.owner, row.target_kind, row.target_id, row.project_id) != (
            "egress",
            "deployment_policy",
            "deployment",
            None,
        ):
            raise DomainError("PERMISSION_DENIED", "Policy receipt scope is unavailable")
    else:
        raise DomainError("PERMISSION_DENIED", "Administration receipt is unavailable")
    # Current authority and scalar lineage precede every retained JSON decode.
    try:
        effect, event = _receipt_evidence(db, row)
        if isinstance(effect, PolicyInitialize):
            policy = DeploymentPolicyReceipt.model_validate(row.result)
            expected = DeploymentPolicyView(
                status="CONFIGURED",
                revision=1,
                approval_id=row.id,
                approved_by=row.principal_id,
                approved_providers=[],
                verification_policy_ref=None,
            )
            if (
                policy.operation_id != row.id
                or policy.command != row.command
                or policy.policy != expected
                or event.target_revision != 1
                or event.committed_at != policy.committed_at
                or DeploymentPolicyReceipt.model_validate(event.payload) != policy
            ):
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE", "Administration receipt requires repair"
                )
            return policy
        result = GrantReceipt.model_validate(row.result)
        grant = result.grant
        if (
            (result.operation_id, result.command, grant.grant_id, grant.revision, grant.provenance)
            != (row.id, row.command, row.target_id, effect.expected_revision + 1, row.id)
            or event.target_revision != grant.revision
            or event.committed_at != result.committed_at
            or GrantReceipt.model_validate(event.payload) != result
        ):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Administration receipt requires repair")
        if isinstance(effect, GrantSet):
            expected_grant = GrantView(
                grant_id=row.target_id,
                principal_id=effect.principal_id,
                capability=effect.capability,
                resource_kind=effect.resource_kind,
                resource_id=effect.resource_id,
                enabled=effect.enabled,
                revision=effect.expected_revision + 1,
                expires_at=effect.expires_at,
                provenance=row.id,
            )
            if grant != expected_grant:
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE", "Administration receipt requires repair"
                )
        elif effect.grant_id != grant.grant_id or grant.enabled:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Administration receipt requires repair")
        identity = db.execute(
            select(
                AccessGrant.principal_id,
                AccessGrant.capability,
                AccessGrant.resource_kind,
                AccessGrant.resource_id,
            ).where(AccessGrant.id == grant.grant_id)
        ).one_or_none()
        # These fields never change on an existing grant. Mutable revision, enabled,
        # expiry and provenance belong to the retained result, not today's grant.
        if identity is None or tuple(identity) != (
            grant.principal_id,
            grant.capability,
            grant.resource_kind,
            grant.resource_id,
        ):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Administration receipt requires repair")
        return result
    except (ValidationError, json.JSONDecodeError):
        raise DomainError(
            "DEPENDENCY_UNAVAILABLE", "Administration receipt requires repair"
        ) from None


def apply(
    db: Session, actor: AuthenticatedContext, effect: AdministrativeEffect, operation_id: str
) -> AdministrativeReceipt:
    current_owner(db, actor)
    previous = db.scalar(
        select(Receipt)
        .options(defer(Receipt.result))
        .where(
            Receipt.principal_id == actor.principal_id,
            Receipt.command == effect.kind,
            Receipt.idempotency_key == effect.idempotency_key,
        )
    )
    payload_hash = digest(effect.model_dump(mode="json"))
    if previous is not None:
        accepted = authorized_receipt(db, actor, previous)
        if previous.payload_hash != payload_hash:
            raise DomainError("IDEMPOTENCY_CONFLICT", "Operation identity has different input")
        return accepted
    row = validate_effect(db, actor, effect)
    now = datetime.now(UTC).isoformat()
    result: AdministrativeReceipt
    if isinstance(effect, PolicyInitialize):
        db.add(
            DeploymentPolicy(
                id=1,
                revision=1,
                approval_id=operation_id,
                approved_by=actor.principal_id,
                approved_providers=[],
                verification_policy_ref=None,
            )
        )
        db.flush()
        result = DeploymentPolicyReceipt(
            operation_id=operation_id, committed_at=now, policy=policy_view(db, actor)
        )
        owner, kind, identity, revision, event = (
            "egress",
            "deployment_policy",
            "deployment",
            1,
            "egress.policy.initialized",
        )
    else:
        if isinstance(effect, GrantRevoke):
            assert row is not None
            row.enabled = False
            row.revision += 1
            row.provenance = operation_id
        elif row is None:
            row = AccessGrant(
                id=str(uuid4()),
                principal_id=effect.principal_id,
                capability=effect.capability,
                resource_kind=effect.resource_kind,
                resource_id=effect.resource_id,
                enabled=effect.enabled,
                revision=1,
                expires_at=effect.expires_at,
                provenance=operation_id,
            )
            db.add(row)
        else:
            row.enabled = effect.enabled
            row.expires_at = effect.expires_at
            row.revision += 1
            row.provenance = operation_id
        db.flush()
        result = GrantReceipt(
            command=effect.kind, operation_id=operation_id, committed_at=now, grant=grant_view(row)
        )
        owner, kind, identity, revision = "permissions", "grant", row.id, row.revision
        event = (
            "permission.grant.revoked"
            if isinstance(effect, GrantRevoke)
            else "permission.grant.set"
        )
    db.add(
        Receipt(
            id=operation_id,
            principal_id=actor.principal_id,
            command=effect.kind,
            idempotency_key=effect.idempotency_key,
            payload_hash=payload_hash,
            project_id=None,
            owner=owner,
            target_kind=kind,
            target_id=identity,
            authentication_ref=actor.authentication_ref,
            result=result.model_dump(mode="json"),
        )
    )
    db.flush()
    db.add(
        OutboxEvent(
            event_id=str(uuid4()),
            operation_id=operation_id,
            event_type=event,
            schema_version=1,
            principal_id=actor.principal_id,
            project_id=None,
            owner=owner,
            target_kind=kind,
            target_id=identity,
            target_revision=revision,
            committed_at=now,
            payload=result.model_dump(mode="json"),
        )
    )
    db.flush()
    current_owner(db, actor)
    return result
