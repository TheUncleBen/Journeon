# SPDX-License-Identifier: AGPL-3.0-only
"""Production confirmation for the closed instruction administration command set."""

import json
import secrets
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, defer

from journeon.administration import ADMINISTRATION_COMMANDS, administration_transaction
from journeon.contracts import (
    DeploymentPolicyReceipt,
    DomainError,
    GrantReceipt,
    GrantRevoke,
    GrantSet,
    PolicyInitialize,
)
from journeon.database import require_compatible_schema, transaction
from journeon.instruction_config import InstructionConfiguration
from journeon.instruction_contracts import (
    EFFECT_ADAPTER,
    ExactConfirmation,
    InstructionAccept,
    InstructionChangeConsent,
    InstructionReceipt,
    OfficialPreview,
    ProtectedEffect,
    PublicationRecovery,
)
from journeon.instructions import digest as content_digest
from journeon.models import (
    InstructionPublication,
    InstructionRequestScope,
    ProtectedRequest,
    Receipt,
)
from journeon.permissions import AuthenticatedContext, current_owner, require_grant
from journeon.protected import official_session, policy_hash
from journeon.restore_contracts import RestoreAuthorization, RestorePlan
from journeon.sessions import digest, utc_seconds


class InstructionConfirmation:
    def __init__(self, engine: Engine, configuration: InstructionConfiguration):
        self.engine = engine
        self.configuration = configuration

    def _policy(self, db: Session, actor: AuthenticatedContext, command: str = "") -> str:
        record = official_session(db, actor)
        material: list[object] = [
            policy_hash(db, record),
            self.configuration.model_dump(mode="json"),
        ]
        if command in ADMINISTRATION_COMMANDS:
            from journeon.administration import incarnation

            material.append(incarnation(db))
        return content_digest(material)

    def prepare(self, actor: AuthenticatedContext, effect: ProtectedEffect) -> str:
        with transaction(self.engine) as db:
            require_compatible_schema(db)
            principal = current_owner(db, actor)
            if isinstance(effect, RestorePlan):
                require_grant(db, actor, "lifecycle.restore")
            if isinstance(effect, (InstructionChangeConsent, PublicationRecovery)):
                for action in ("read", "accept"):
                    require_grant(
                        db,
                        actor,
                        "project.instruction." + action,
                        resource_kind="project",
                        resource_id=effect.project_id,
                    )
            projection = False
            if isinstance(effect, PublicationRecovery):
                journal = db.get(
                    InstructionPublication,
                    effect.operation_id,
                    options=[defer(InstructionPublication.snapshot)],
                )
                if journal is None or journal.project_id != effect.project_id:
                    raise DomainError("NOT_FOUND", "Recovery publication is unavailable")
                from journeon.project_instructions import ProjectInstructionService

                ProjectInstructionService(self.engine, self.configuration).recovery_roots(
                    db, actor, journal
                )
                projection = journal.projection
                if projection:
                    require_grant(
                        db,
                        actor,
                        "project.instruction.projection",
                        resource_kind="project",
                        resource_id=effect.project_id,
                    )
            session = official_session(db, actor)
            previous = db.scalar(
                select(ProtectedRequest)
                .options(defer(ProtectedRequest.payload))
                .where(
                    ProtectedRequest.principal_id == actor.principal_id,
                    ProtectedRequest.command == effect.kind,
                    ProtectedRequest.idempotency_key == effect.idempotency_key,
                )
            )
            payload = effect.model_dump(mode="json")
            if previous:
                if (
                    previous.payload_hash != content_digest(payload)
                    or previous.session_id != session.id
                ):
                    raise DomainError(
                        "IDEMPOTENCY_CONFLICT", "Protected operation identity has different input"
                    )
                return previous.id
            if isinstance(effect, (GrantSet, GrantRevoke, PolicyInitialize)):
                from journeon.administration import validate_effect

                validate_effect(db, actor, effect)
            now = utc_seconds()
            row = ProtectedRequest(
                id=str(uuid4()),
                operation_id=str(uuid4()),
                principal_id=actor.principal_id,
                principal_epoch=actor.principal_epoch,
                session_id=session.id,
                command=effect.kind,
                idempotency_key=effect.idempotency_key,
                payload=payload,
                payload_hash=content_digest(payload),
                credential_revision=principal.credential_revision,
                policy_hash=self._policy(db, actor, effect.kind),
                issued_at=now,
                deadline=min(
                    now + self.configuration.protected_request_seconds, session.absolute_deadline
                ),
                state="PENDING",
                strong_authenticated_at=session.strong_authenticated_at,
            )
            db.add(row)
            db.flush()
            if isinstance(effect, RestorePlan):
                from journeon.models import RestoreRequestScope

                for selected in effect.selection:
                    for capability in ("read", "restore"):
                        require_grant(
                            db,
                            actor,
                            "project.instruction." + capability,
                            resource_kind="project",
                            resource_id=selected.project_id,
                        )
                    db.add(RestoreRequestScope(request_id=row.id, project_id=selected.project_id))
            if isinstance(effect, (InstructionChangeConsent, PublicationRecovery)):
                db.add(
                    InstructionRequestScope(
                        request_id=row.id,
                        project_id=effect.project_id,
                        projection=projection,
                        publication_id=effect.operation_id
                        if isinstance(effect, PublicationRecovery)
                        else None,
                    )
                )
            return row.id

    def _request(self, db: Session, actor: AuthenticatedContext, identity: str) -> ProtectedRequest:
        current_owner(db, actor)
        official_session(db, actor)
        row = db.get(ProtectedRequest, identity, options=[defer(ProtectedRequest.payload)])
        if (
            row is None
            or row.principal_id != actor.principal_id
            or row.command == "passkey.label.v1"
        ):
            raise DomainError("NOT_FOUND", "Protected request is unavailable")
        if row.command == "lifecycle.restore.authorize.v1":
            require_grant(db, actor, "lifecycle.restore")
            from journeon.models import RestoreRequestScope

            scopes = list(
                db.scalars(
                    select(RestoreRequestScope).where(RestoreRequestScope.request_id == row.id)
                )
            )
            if not scopes:
                raise DomainError("PERMISSION_DENIED", "Restore scope evidence is unavailable")
            for restore_scope in scopes:
                for capability in ("read", "restore"):
                    require_grant(
                        db,
                        actor,
                        "project.instruction." + capability,
                        resource_kind="project",
                        resource_id=restore_scope.project_id,
                    )
        if row.command in {"project.instructions.accept.v1", "project.instructions.recover.v1"}:
            scope = db.get(InstructionRequestScope, row.id)
            if scope is None:
                raise DomainError("PERMISSION_DENIED", "Instruction consent scope is unavailable")
            for action in ("read", "accept"):
                require_grant(
                    db,
                    actor,
                    "project.instruction." + action,
                    resource_kind="project",
                    resource_id=scope.project_id,
                )
            if scope.projection:
                require_grant(
                    db,
                    actor,
                    "project.instruction.projection",
                    resource_kind="project",
                    resource_id=scope.project_id,
                )
            from journeon.project_instructions import ProjectInstructionService

            service = ProjectInstructionService(self.engine, self.configuration)
            if scope.publication_id:
                journal = db.get(
                    InstructionPublication,
                    scope.publication_id,
                    options=[defer(InstructionPublication.snapshot)],
                )
                if journal is None or journal.project_id != scope.project_id:
                    raise DomainError("PERMISSION_DENIED", "Recovery publication scope differs")
                service.recovery_roots(db, actor, journal)
            else:
                service.binding(db, actor, scope.project_id)
        return row

    def _bound(
        self,
        db: Session,
        actor: AuthenticatedContext,
        row: ProtectedRequest,
        *,
        check_target: bool = True,
    ) -> ProtectedEffect:
        principal = current_owner(db, actor)
        session = official_session(db, actor)
        now = utc_seconds()
        if (
            row.state not in {"PENDING", "APPROVED"}
            or (
                row.state == "APPROVED"
                and (row.approval_deadline is None or now >= row.approval_deadline)
            )
            or row.session_id != session.id
            or row.principal_epoch != actor.principal_epoch
            or row.credential_revision != principal.credential_revision
            or row.policy_hash != self._policy(db, actor, row.command)
            or row.strong_authenticated_at != session.strong_authenticated_at
            or not row.issued_at <= now < row.deadline
        ):
            raise DomainError("PERMISSION_DENIED", "Protected request is no longer executable")
        try:
            effect = EFFECT_ADAPTER.validate_python(row.payload)
        except (ValidationError, json.JSONDecodeError):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Protected request requires repair"
            ) from None
        if (
            content_digest(effect.model_dump(mode="json")) != row.payload_hash
            or effect.kind != row.command
            or effect.idempotency_key != row.idempotency_key
        ):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Protected request requires repair")
        if check_target and isinstance(effect, (GrantSet, GrantRevoke, PolicyInitialize)):
            from journeon.administration import validate_effect

            validate_effect(db, actor, effect)
        return effect

    def preview(self, actor: AuthenticatedContext, identity: str) -> OfficialPreview:
        with transaction(self.engine) as db:
            require_compatible_schema(db)
            row = self._request(db, actor, identity)
            effect = self._bound(db, actor, row)
            if row.state != "PENDING":
                raise DomainError("PERMISSION_DENIED", "Protected request is not awaiting consent")
            session = official_session(db, actor)
            nonce = secrets.token_urlsafe(32)
            row.nonce_hash = digest(nonce)
            row.nonce_deadline = min(
                utc_seconds() + self.configuration.protected_preview_seconds,
                row.deadline,
                session.absolute_deadline,
                session.last_activity + session.inactivity_seconds,
            )
            return OfficialPreview(
                request_id=row.id,
                request_hash=row.payload_hash,
                effect=effect,
                deadline=row.nonce_deadline,
                nonce=nonce,
            )

    def confirm(
        self, actor: AuthenticatedContext, command: ExactConfirmation
    ) -> InstructionReceipt | RestoreAuthorization | GrantReceipt | DeploymentPolicyReceipt:
        # External observations happen before the serialized effect transaction.
        from journeon.instruction_admin import InstructionAdministration

        admin = InstructionAdministration(self.engine, self.configuration)
        with transaction(self.engine) as db:
            row = self._request(db, actor, command.request_id)
            if row.command == "lifecycle.restore.authorize.v1" and row.state == "APPROVED":
                self._bound(db, actor, row)
                if command.request_hash != row.payload_hash:
                    raise DomainError("PERMISSION_DENIED", "Exact restore consent is required")
                from journeon.restore import authorization

                return authorization(row)
            if row.state == "COMMITTED":
                from journeon.instruction_operations import authorized

                scope = db.get(InstructionRequestScope, row.id)
                operation = (
                    scope.publication_id if scope and scope.publication_id else row.operation_id
                )
                receipt = db.get(Receipt, operation, options=[defer(Receipt.result)])
                if receipt is None or command.request_hash != row.payload_hash:
                    raise DomainError("PERMISSION_DENIED", "Protected receipt is unavailable")
                if scope and scope.publication_id:
                    for action in ("read", "receipt.read"):
                        require_grant(
                            db,
                            actor,
                            "project.instruction." + action,
                            resource_kind="project",
                            resource_id=scope.project_id,
                        )
                    if receipt.project_id != scope.project_id:
                        raise DomainError("PERMISSION_DENIED", "Recovery receipt scope differs")
                    from journeon.instruction_operations import decode
                    from journeon.jobs import settle_recovery_in_transaction

                    result = decode(receipt)
                    settle_recovery_in_transaction(db, operation)
                    return result
                if row.command in ADMINISTRATION_COMMANDS:
                    from journeon.administration import authorized_receipt

                    return authorized_receipt(db, actor, receipt)
                return authorized(db, actor, receipt)
            effect = self._bound(db, actor, row)
        if isinstance(effect, RestorePlan):
            from journeon.restore import authorization, preview
            from journeon.restore_contracts import RestorePreview

            current = preview(
                self.engine,
                self.configuration,
                actor,
                RestorePreview.model_validate(
                    effect.model_dump(include=set(RestorePreview.model_fields))
                ),
            )
            if current != effect:
                raise DomainError("REVISION_CONFLICT", "Restore plan changed")
            with transaction(self.engine) as db:
                row = self._request(db, actor, command.request_id)
                self._bound(db, actor, row)
                now = utc_seconds()
                if (
                    command.request_hash != row.payload_hash
                    or row.nonce_hash is None
                    or row.nonce_deadline is None
                    or now >= row.nonce_deadline
                    or not secrets.compare_digest(row.nonce_hash, digest(command.nonce))
                ):
                    raise DomainError(
                        "PERMISSION_DENIED", "Current exact preview consent is required"
                    )
                row.state = "APPROVED"
                row.approved_at = now
                row.approval_deadline = min(now + 300, row.deadline)
                row.nonce_hash = None
                row.nonce_deadline = None
                return authorization(row)
        if isinstance(effect, (InstructionChangeConsent, PublicationRecovery)):
            with transaction(self.engine) as db:
                row = self._request(db, actor, command.request_id)
                self._bound(db, actor, row)
                now = utc_seconds()
                if command.request_hash != row.payload_hash:
                    raise DomainError("PERMISSION_DENIED", "Exact instruction consent is required")
                if row.state == "PENDING":
                    if (
                        row.nonce_hash is None
                        or row.nonce_deadline is None
                        or now >= row.nonce_deadline
                        or not secrets.compare_digest(row.nonce_hash, digest(command.nonce))
                    ):
                        raise DomainError(
                            "PERMISSION_DENIED", "Current exact preview consent is required"
                        )
                    row.state = "APPROVED"
                    row.approved_at = now
                    row.approval_deadline = min(now + 300, row.deadline)
                    row.nonce_hash = None
                    row.nonce_deadline = None
            from journeon.project_instructions import ProjectInstructionService

            if isinstance(effect, PublicationRecovery):
                return ProjectInstructionService(self.engine, self.configuration).recover(
                    actor, effect, command.request_id
                )
            accepted = InstructionAccept.model_validate(
                {**effect.model_dump(exclude={"kind"}), "consent_request_id": command.request_id}
            )
            return ProjectInstructionService(self.engine, self.configuration).accept(
                actor, accepted
            )
        if isinstance(effect, (GrantSet, GrantRevoke, PolicyInitialize)):
            from journeon.administration import apply

            with administration_transaction(self.engine) as db:
                row = self._request(db, actor, command.request_id)
                bound = self._bound(db, actor, row)
                if not isinstance(bound, (GrantSet, GrantRevoke, PolicyInitialize)):
                    raise DomainError("PERMISSION_DENIED", "Administration effect is unavailable")
                now = utc_seconds()
                if (
                    command.request_hash != row.payload_hash
                    or row.nonce_hash is None
                    or row.nonce_deadline is None
                    or now >= row.nonce_deadline
                    or not secrets.compare_digest(row.nonce_hash, digest(command.nonce))
                ):
                    raise DomainError(
                        "PERMISSION_DENIED", "Current exact preview consent is required"
                    )
                administration_result = apply(db, actor, bound, row.operation_id)
                self._bound(db, actor, row, check_target=False)
                row.state = "COMMITTED"
                row.approved_at = now
                row.approval_deadline = None
                row.nonce_hash = None
                row.nonce_deadline = None
                return administration_result
        observation = admin.observe(actor, effect)
        with transaction(self.engine) as db:
            require_compatible_schema(db)
            row = self._request(db, actor, command.request_id)
            effect = self._bound(db, actor, row)
            now = utc_seconds()
            if (
                command.request_hash != row.payload_hash
                or row.nonce_hash is None
                or row.nonce_deadline is None
                or now >= row.nonce_deadline
                or not secrets.compare_digest(row.nonce_hash, digest(command.nonce))
            ):
                raise DomainError("PERMISSION_DENIED", "Current exact preview consent is required")
            result = admin.apply(db, actor, effect, observation, row.operation_id)
            self._bound(db, actor, row)
            if utc_seconds() >= min(row.deadline, now + 300):
                raise DomainError("PERMISSION_DENIED", "Protected consent expired before commit")
            row.state = "COMMITTED"
            row.approved_at = now
            row.approval_deadline = min(row.deadline, now + 300)
            row.nonce_hash = None
            row.nonce_deadline = None
            return result

    def cancel(self, actor: AuthenticatedContext, identity: str) -> str:
        with transaction(self.engine) as db:
            row = self._request(db, actor, identity)
            if row.state in {"PENDING", "APPROVED"}:
                row.state = "CANCELLED"
                row.nonce_hash = None
                row.nonce_deadline = None
            return row.state


def verify_instruction_consent(
    db: Session,
    actor: AuthenticatedContext,
    command: InstructionAccept,
    configuration: InstructionConfiguration,
) -> ProtectedRequest:
    if command.consent_request_id is None:
        raise DomainError("PERMISSION_DENIED", "Exact protected instruction consent is required")
    service = InstructionConfirmation(db.get_bind().engine, configuration)
    row = service._request(db, actor, command.consent_request_id)
    effect = service._bound(db, actor, row)
    now = utc_seconds()
    if (
        not isinstance(effect, InstructionChangeConsent)
        or row.state != "APPROVED"
        or row.approved_at is None
        or row.approval_deadline is None
        or not row.approved_at <= now < row.approval_deadline
    ):
        raise DomainError("PERMISSION_DENIED", "Current exact instruction approval is required")
    if effect.model_dump(exclude={"kind"}) != command.model_dump(exclude={"consent_request_id"}):
        raise DomainError("PERMISSION_DENIED", "Instruction approval operands differ")
    return row


def verify_recovery_consent(
    db: Session, actor: AuthenticatedContext, identity: str, configuration: InstructionConfiguration
) -> tuple[ProtectedRequest, PublicationRecovery]:
    service = InstructionConfirmation(db.get_bind().engine, configuration)
    row = service._request(db, actor, identity)
    effect = service._bound(db, actor, row)
    now = utc_seconds()
    if (
        not isinstance(effect, PublicationRecovery)
        or row.state != "APPROVED"
        or row.approved_at is None
        or row.approval_deadline is None
        or not row.approved_at <= now < row.approval_deadline
    ):
        raise DomainError("PERMISSION_DENIED", "Current exact recovery consent is required")
    return row, effect
