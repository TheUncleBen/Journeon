# SPDX-License-Identifier: AGPL-3.0-only
"""Owner administration routes share the existing exact-effect confirmation owner."""

from typing import Annotated, Any

from fastapi import Depends, FastAPI, Query
from sqlalchemy import Engine

from journeon.administration import administration_transaction, catalog, list_grants, policy_view
from journeon.api import authenticated_context
from journeon.contracts import (
    DeploymentPolicyReceipt,
    DeploymentPolicyView,
    DomainError,
    ErrorEnvelope,
    GrantCatalog,
    GrantPage,
    GrantReceipt,
    GrantRevoke,
    GrantRevokeConfirmed,
    GrantSet,
    GrantSetConfirmed,
    PolicyInitialize,
    PolicyInitializeConfirmed,
)
from journeon.instruction_config import InstructionConfiguration
from journeon.instruction_contracts import ExactConfirmation
from journeon.instruction_protected import InstructionConfirmation
from journeon.instructions import digest
from journeon.permissions import AuthenticatedContext
from journeon.registry import configuration_metadata


def bind_administration_api(
    app: FastAPI, engine: Engine, configuration: InstructionConfiguration | None
) -> None:
    errors: dict[int | str, dict[str, Any]] = {
        status: {"model": ErrorEnvelope} for status in (401, 403, 404, 409, 422, 503)
    }

    def confirm(
        actor: AuthenticatedContext,
        command: GrantSetConfirmed | GrantRevokeConfirmed | PolicyInitializeConfirmed,
    ) -> GrantReceipt | DeploymentPolicyReceipt:
        if configuration is None:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Explicit confirmation configuration is required"
            )
        payload = command.model_dump(mode="json", exclude={"request_id", "request_hash", "nonce"})
        effect: GrantSet | GrantRevoke | PolicyInitialize
        if isinstance(command, GrantSetConfirmed):
            effect = GrantSet.model_validate(payload)
        elif isinstance(command, GrantRevokeConfirmed):
            effect = GrantRevoke.model_validate(payload)
        else:
            effect = PolicyInitialize.model_validate(payload)
        service = InstructionConfirmation(engine, configuration)
        with administration_transaction(engine) as db:
            row = service._request(db, actor, command.request_id)
            if row.command != effect.kind or row.payload_hash != digest(
                effect.model_dump(mode="json")
            ):
                raise DomainError("PERMISSION_DENIED", "Confirmed administration operands differ")
        result = service.confirm(
            actor,
            ExactConfirmation(
                request_id=command.request_id,
                request_hash=command.request_hash,
                nonce=command.nonce,
            ),
        )
        if not isinstance(result, (GrantReceipt, DeploymentPolicyReceipt)):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Administration result requires repair")
        return result

    @app.get(
        "/api/v1/permissions/catalog",
        response_model=GrantCatalog,
        responses=errors,
        operation_id="getGrantCatalog",
        openapi_extra=configuration_metadata("permission.catalog.read.v1"),
    )
    def capabilities(
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> GrantCatalog:
        with administration_transaction(engine) as db:
            return catalog(db, actor)

    @app.get(
        "/api/v1/permissions/grants",
        response_model=GrantPage,
        responses=errors,
        operation_id="listGrants",
        openapi_extra=configuration_metadata("permission.grants.read.v1"),
    )
    def grants(
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
        limit: Annotated[int, Query(ge=1, le=100)],
        cursor: Annotated[str | None, Query(max_length=1024)] = None,
    ) -> GrantPage:
        with administration_transaction(engine) as db:
            return list_grants(db, actor, limit, cursor)

    @app.get(
        "/api/v1/egress/policy",
        response_model=DeploymentPolicyView,
        responses=errors,
        operation_id="getDeploymentPolicy",
        openapi_extra=configuration_metadata("egress.policy.read.v1"),
    )
    def policy(
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> DeploymentPolicyView:
        with administration_transaction(engine) as db:
            return policy_view(db, actor)

    @app.post(
        "/api/v1/permissions/grants/set",
        response_model=GrantReceipt,
        responses=errors,
        operation_id="setGrant",
        openapi_extra=configuration_metadata("permission.grant.set.v1"),
    )
    def set_grant(
        command: GrantSetConfirmed,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> GrantReceipt:
        result = confirm(actor, command)
        if not isinstance(result, GrantReceipt):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Grant result requires repair")
        return result

    @app.post(
        "/api/v1/permissions/grants/revoke",
        response_model=GrantReceipt,
        responses=errors,
        operation_id="revokeGrant",
        openapi_extra=configuration_metadata("permission.grant.revoke.v1"),
    )
    def revoke_grant(
        command: GrantRevokeConfirmed,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> GrantReceipt:
        result = confirm(actor, command)
        if not isinstance(result, GrantReceipt):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Grant result requires repair")
        return result

    @app.post(
        "/api/v1/egress/policy/initialize",
        response_model=DeploymentPolicyReceipt,
        responses=errors,
        operation_id="initializeDeploymentPolicy",
        openapi_extra=configuration_metadata("egress.policy.initialize.v1"),
    )
    def initialize(
        command: PolicyInitializeConfirmed,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> DeploymentPolicyReceipt:
        result = confirm(actor, command)
        if not isinstance(result, DeploymentPolicyReceipt):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Policy result requires repair")
        return result
