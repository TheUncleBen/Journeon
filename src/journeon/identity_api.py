# SPDX-License-Identifier: AGPL-3.0-only
"""Session identity routes retain cookie, Origin and exact-effect authority boundaries."""

import secrets
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Query, Request, Response
from sqlalchemy import Engine

from journeon.api import authenticated_context
from journeon.browser_auth import COOKIE_NAME, BrowserAuth
from journeon.contracts import (
    BrowserSessionPage,
    ContextBootstrap,
    ContextBootstrapped,
    DomainError,
    ErrorEnvelope,
    SessionLogout,
    SessionMutationReceipt,
    SessionRevoke,
    SessionRevokeRequest,
)
from journeon.identity import (
    apply_session_end,
    human_context,
    identity_transaction,
    session_page,
    session_target,
)
from journeon.instruction_config import InstructionConfiguration
from journeon.instruction_contracts import ExactConfirmation
from journeon.instruction_protected import InstructionConfirmation
from journeon.instructions import digest as content_digest
from journeon.permissions import AuthenticatedContext
from journeon.registry import configuration_metadata
from journeon.sessions import denied, digest, resolve_cookie


def bind_identity_api(
    app: FastAPI,
    engine: Engine,
    binding: BrowserAuth | None,
    configuration: InstructionConfiguration | None,
) -> None:
    errors: dict[int | str, dict[str, Any]] = {
        status: {"model": ErrorEnvelope} for status in (401, 403, 404, 409, 422, 503)
    }

    @app.post(
        "/api/v1/auth/context/bootstrap",
        response_model=ContextBootstrapped,
        responses=errors,
        operation_id="bootstrapCurrentContext",
        openapi_extra={
            "x-journeon-owner": "identity",
            "x-journeon-authentication": "identity.context.bootstrap.v1",
        },
    )
    def bootstrap(
        command: ContextBootstrap,
        request: Request,
        response: Response,
    ) -> ContextBootstrapped:
        if binding is None or request.headers.get("origin") != binding.canonical_origin:
            raise denied()
        with identity_transaction(engine) as db:
            record = resolve_cookie(db, request.cookies.get(COOKIE_NAME, ""), activity=False)
            token = secrets.token_urlsafe(32)
            record.csrf_hash = digest(token)
            actor = AuthenticatedContext(record.principal_id, record.principal_epoch, record.id)
            current = human_context(db, actor, configuration is not None)
            result = ContextBootstrapped.model_validate(
                {**current.model_dump(), "csrf_token": token}
            )
        response.headers["Cache-Control"] = "no-store"
        return result

    @app.get(
        "/api/v1/auth/sessions",
        response_model=BrowserSessionPage,
        responses=errors,
        operation_id="listBrowserSessions",
        openapi_extra=configuration_metadata("identity.sessions.read.v1"),
    )
    def inventory(
        response: Response,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
        limit: Annotated[int, Query(ge=1, le=100)],
        cursor: Annotated[str | None, Query(max_length=1024)] = None,
    ) -> BrowserSessionPage:
        with identity_transaction(engine) as db:
            result = session_page(db, actor, limit, cursor)
        response.headers["Cache-Control"] = "no-store"
        return result

    @app.post(
        "/api/v1/auth/sessions/revoke",
        response_model=SessionMutationReceipt,
        responses=errors,
        operation_id="revokeBrowserSession",
        openapi_extra=configuration_metadata("identity.session.revoke.v1"),
    )
    def revoke(
        command: SessionRevokeRequest,
        response: Response,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> SessionMutationReceipt:
        effect = SessionRevoke.model_validate(
            command.model_dump(exclude={"request_id", "request_hash", "nonce"})
        )
        with identity_transaction(engine) as db:
            target = session_target(db, actor, effect.target_session_id)
            if target.principal_id == actor.principal_id:
                if command.request_id is not None:
                    raise DomainError(
                        "VALIDATION_FAILED", "Own sessions use the direct session command"
                    )
                result = apply_session_end(db, actor, effect)
                response.headers["Cache-Control"] = "no-store"
                return result
        if (
            configuration is None
            or command.request_id is None
            or command.request_hash is None
            or command.nonce is None
        ):
            raise DomainError(
                "PERMISSION_DENIED", "Another human's session requires exact official consent"
            )
        service = InstructionConfirmation(engine, configuration)
        with identity_transaction(engine) as db:
            row = service._request(db, actor, command.request_id)
            if row.command != effect.kind or row.payload_hash != content_digest(
                effect.model_dump(mode="json")
            ):
                raise DomainError("PERMISSION_DENIED", "Confirmed session operands differ")
        confirmed = service.confirm(
            actor,
            ExactConfirmation(
                request_id=command.request_id,
                request_hash=command.request_hash,
                nonce=command.nonce,
            ),
        )
        if not isinstance(confirmed, SessionMutationReceipt):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Session result requires repair")
        response.headers["Cache-Control"] = "no-store"
        return confirmed

    @app.post(
        "/api/v1/auth/logout",
        response_model=SessionMutationReceipt,
        responses=errors,
        operation_id="logoutBrowserSession",
        openapi_extra=configuration_metadata("identity.session.logout.v1"),
    )
    def logout(
        command: SessionLogout,
        response: Response,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> SessionMutationReceipt:
        with identity_transaction(engine) as db:
            result = apply_session_end(db, actor, command)
        if binding is None:
            raise denied()
        binding.clear_cookie(response)
        return result
