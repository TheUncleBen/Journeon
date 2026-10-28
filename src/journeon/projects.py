# SPDX-License-Identifier: AGPL-3.0-only
"""Project Service: local registration with durable authorized receipts."""

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
    OperationReceipt,
    ProjectCreate,
    ProjectCreated,
    ProjectView,
    ProviderSnapshot,
)
from journeon.database import require_compatible_schema, transaction
from journeon.discovery import allowed, paginate, read_transaction
from journeon.discovery_contracts import DiscoveryLink, ProjectPage, ProjectSummary
from journeon.models import DeploymentPolicy, OutboxEvent, Principal, Project, Receipt
from journeon.permissions import AuthenticatedContext, current_owner, require_grant
from journeon.policy import PolicyState
from journeon.registry import PROJECT_CREATE


def payload_hash(command: ProjectCreate) -> str:
    payload = command.model_dump(mode="json", exclude={"idempotency_key"})
    if payload["selected_providers"] is not None:
        payload["selected_providers"] = sorted(payload["selected_providers"])
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _authorized_receipt(
    session: Session,
    actor: AuthenticatedContext,
    receipt: Receipt,
) -> OperationReceipt:
    current_owner(session, actor)
    if receipt.principal_id != actor.principal_id:
        raise DomainError("NOT_FOUND", "Operation is unavailable")
    require_grant(session, actor, "project.receipt.read", project_id=receipt.project_id)
    # This is the historical accepted result, not a current grant/egress assertion.
    result = OperationReceipt.model_validate(receipt.result)
    if (
        result.operation_id != receipt.id
        or result.project.project_id != receipt.project_id
        or result.command != receipt.command
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored operation state requires repair")
    return result


class ProjectService:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def create(self, actor: AuthenticatedContext, command: ProjectCreate) -> OperationReceipt:
        digest = payload_hash(command)
        try:
            with transaction(self.engine) as session:
                require_compatible_schema(session)
                current_owner(session, actor)
                previous = session.scalar(
                    select(Receipt)
                    .options(defer(Receipt.result))
                    .where(
                        Receipt.principal_id == actor.principal_id,
                        Receipt.command == PROJECT_CREATE.name,
                        Receipt.idempotency_key == command.idempotency_key,
                    )
                )
                if previous is not None:
                    result = _authorized_receipt(session, actor, previous)
                    if previous.payload_hash != digest:
                        raise DomainError(
                            "IDEMPOTENCY_CONFLICT", "Operation identity has different input"
                        )
                    return result

                require_grant(session, actor, "project.create")
                require_grant(session, actor, "project.receipt.read")
                stored_policy = session.get(DeploymentPolicy, 1)
                if stored_policy is None:
                    raise DomainError(
                        "DEPENDENCY_UNAVAILABLE", "Deployment policy is not configured"
                    )
                policy = PolicyState.model_validate(stored_policy, from_attributes=True)
                if policy.revision != command.expected_policy_revision:
                    raise DomainError(
                        "REVISION_CONFLICT", "Deployment policy changed; refresh its revision"
                    )
                if policy.approval_id is None:
                    approved: set[str] = set()
                else:
                    approver = session.get(Principal, policy.approved_by)
                    if approver is None or not approver.enabled or approver.role != "OWNER":
                        raise DomainError(
                            "DEPENDENCY_UNAVAILABLE", "Provider approval needs reconciliation"
                        )
                    approved = set(policy.approved_providers)
                if command.provider_mode == "LOCAL_ONLY":
                    chosen: set[str] = set()
                elif command.provider_mode == "NARROW":
                    chosen = set(command.selected_providers or [])
                    if not chosen <= approved:
                        raise DomainError(
                            "PERMISSION_DENIED", "Provider selection exceeds current approval"
                        )
                else:
                    chosen = approved
                snapshot = ProviderSnapshot(
                    mode=command.provider_mode,
                    policy_revision=policy.revision,
                    approval_id=policy.approval_id,
                    providers=sorted(chosen),
                )
                project_id, operation_id = str(uuid4()), str(uuid4())
                committed_at = datetime.now(UTC).isoformat()
                view = ProjectCreated(
                    project_id=project_id,
                    revision=1,
                    name=command.name,
                    description=command.description,
                    instruction_authority_ref=f"environment:project:{project_id}",
                    provider_allowance_at_creation=snapshot,
                    verification_policy_ref=policy.verification_policy_ref,
                    resource_refs=[],
                )
                result = OperationReceipt(
                    operation_id=operation_id, committed_at=committed_at, project=view
                )
                session.add(
                    Project(
                        id=project_id,
                        revision=1,
                        name=view.name,
                        description=view.description,
                        created_by=actor.principal_id,
                        instruction_owner=view.instruction_owner,
                        instruction_authority_ref=view.instruction_authority_ref,
                        provider_snapshot=snapshot.model_dump(mode="json"),
                        verification_policy_ref=view.verification_policy_ref,
                        resource_refs=[],
                        created_at=committed_at,
                    )
                )
                session.flush()
                from journeon.project_instructions import initialize_project_policy

                initialize_project_policy(session, actor, project_id)
                session.add(
                    Receipt(
                        id=operation_id,
                        principal_id=actor.principal_id,
                        command=PROJECT_CREATE.name,
                        idempotency_key=command.idempotency_key,
                        payload_hash=digest,
                        project_id=project_id,
                        target_id=project_id,
                        authentication_ref=actor.authentication_ref,
                        result=result.model_dump(mode="json"),
                    )
                )
                session.flush()
                session.add(
                    OutboxEvent(
                        event_id=str(uuid4()),
                        operation_id=operation_id,
                        event_type="project.created",
                        target_revision=view.revision,
                        payload=result.model_dump(mode="json"),
                        schema_version=1,
                        principal_id=actor.principal_id,
                        project_id=project_id,
                        target_id=project_id,
                        committed_at=committed_at,
                    )
                )
                session.flush()
                # The same locked transaction is the final current-authority boundary.
                current_owner(session, actor)
                require_grant(session, actor, "project.create")
                require_grant(session, actor, "project.receipt.read", project_id=project_id)
            return result
        except (ValidationError, json.JSONDecodeError):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Stored operation state requires repair"
            ) from None
        except SQLAlchemyError as exc:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "The operation store is unavailable"
            ) from exc

    def read(self, actor: AuthenticatedContext, project_id: str) -> ProjectView:
        try:
            with transaction(self.engine) as session:
                require_compatible_schema(session)
                return self.read_in(session, actor, project_id)
        except (ValidationError, json.JSONDecodeError):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Stored Project state requires repair"
            ) from None
        except SQLAlchemyError as exc:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "The Project store is unavailable") from exc

    def read_in(
        self, session: Session, actor: AuthenticatedContext, project_id: str
    ) -> ProjectView:
        require_grant(session, actor, "project.read", project_id=project_id)
        project = session.get(Project, project_id)
        if project is None:
            raise DomainError("NOT_FOUND", "Project is unavailable")
        return ProjectView.model_validate(
            {
                "project_id": project.id,
                "revision": project.revision,
                "name": project.name,
                "description": project.description,
                "instruction_owner": project.instruction_owner,
                "instruction_authority_ref": project.instruction_authority_ref,
                "provider_allowance_at_creation": project.provider_snapshot,
                "verification_policy_ref": project.verification_policy_ref,
                "resource_refs": project.resource_refs,
            }
        )

    def list(
        self, actor: AuthenticatedContext, limit: int, cursor: str | None = None
    ) -> ProjectPage:
        with read_transaction(self.engine, actor) as db:

            def summary(identity: str) -> ProjectSummary:
                item = self.read_in(db, actor, identity)
                links = []
                if allowed(lambda: require_grant(db, actor, "task.read", project_id=identity)):
                    links.append(
                        DiscoveryLink(
                            relation="tasks",
                            href=f"/api/v1/projects/{identity}/tasks?limit={limit}",
                        )
                    )
                return ProjectSummary(
                    project_id=item.project_id, revision=item.revision, name=item.name, links=links
                )

            return ProjectPage(
                **paginate(
                    db,
                    actor,
                    select(Project.id),
                    Project.id,
                    summary,
                    limit=limit,
                    cursor=cursor,
                    query={"operation": "project.list.v1"},
                )
            )

    def receipt(self, actor: AuthenticatedContext, operation_id: str) -> OperationReceipt:
        try:
            with transaction(self.engine) as session:
                require_compatible_schema(session)
                current_owner(session, actor)
                receipt = session.get(Receipt, operation_id, options=[defer(Receipt.result)])
                if receipt is None or receipt.principal_id != actor.principal_id:
                    raise DomainError("NOT_FOUND", "Operation is unavailable")
                return _authorized_receipt(session, actor, receipt)
        except (ValidationError, json.JSONDecodeError):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Stored operation state requires repair"
            ) from None
        except SQLAlchemyError as exc:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "The operation store is unavailable"
            ) from exc
