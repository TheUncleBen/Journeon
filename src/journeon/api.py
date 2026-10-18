# SPDX-License-Identifier: AGPL-3.0-only
"""Session-bound API with explicitly configured passkey authentication."""

import tomllib
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError

from journeon.body_limit import BodyLimitMiddleware
from journeon.browser_auth import BrowserAuth
from journeon.contracts import (
    ERROR_HTTP_STATUS,
    CanonicalReceipt,
    DomainError,
    ErrorEnvelope,
    Identifier,
    OperationReceipt,
    PasskeyLabelCommand,
    PasskeyMutationReceipt,
    ProjectCreate,
)
from journeon.factors import FactorService
from journeon.passkey_api import routes as passkey_routes
from journeon.passkeys import PasskeyService, RejectedPasskeyInput
from journeon.permissions import AuthenticatedContext
from journeon.projects import ProjectService
from journeon.receipts import OperationService


def authenticated_context(request: Request) -> AuthenticatedContext:
    binding: BrowserAuth | None = request.app.state.browser_auth
    if binding is None:
        raise DomainError("AUTHENTICATION_REQUIRED", "Authenticated service context is required")
    return binding.resolve(request.app.state.engine, request)


def create_app(
    engine: Engine,
    *,
    browser_auth: BrowserAuth | None = None,
    passkeys: PasskeyService | None = None,
) -> FastAPI:
    if passkeys is not None and (
        browser_auth is None
        or browser_auth.canonical_origin != passkeys.origin
        or passkeys.engine is not engine
    ):
        raise ValueError("Passkey and browser authentication bindings must match")
    with (Path(__file__).resolve().parents[2] / "pyproject.toml").open("rb") as metadata_file:
        version = tomllib.load(metadata_file)["project"]["version"]
    app = FastAPI(title="Journeon foundation", version=version)
    app.state.browser_auth = browser_auth
    app.state.engine = engine
    app.add_middleware(BodyLimitMiddleware, passkeys=passkeys)
    service = ProjectService(engine)

    @app.exception_handler(DomainError)
    async def domain_error(_request: Request, exc: DomainError) -> JSONResponse:
        if isinstance(exc, RejectedPasskeyInput):
            _request.scope["journeon.rejected_passkey_input"] = True
        return JSONResponse(
            status_code=ERROR_HTTP_STATUS[exc.code],
            content=ErrorEnvelope(code=exc.code, reason=exc.reason).model_dump(),
        )

    @app.exception_handler(SQLAlchemyError)
    async def unavailable_store(_request: Request, _exc: SQLAlchemyError) -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content=ErrorEnvelope(
                code="DEPENDENCY_UNAVAILABLE", reason="The service store is unavailable"
            ).model_dump(),
        )

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request: Request, exc: RequestValidationError) -> JSONResponse:
        # Do not echo invalid input (which may contain secrets) or raw validator internals.
        if any(
            error["loc"] == ("body", "schema_version") and error["type"] == "literal_error"
            for error in exc.errors()
        ):
            return JSONResponse(
                status_code=422,
                content=ErrorEnvelope(
                    code="SCHEMA_UNSUPPORTED",
                    reason="The operation schema version is unsupported",
                ).model_dump(),
            )
        return JSONResponse(
            status_code=422,
            content=ErrorEnvelope(
                code="VALIDATION_FAILED",
                reason="Request does not match the operation schema",
            ).model_dump(),
        )

    errors: dict[int | str, dict[str, Any]] = {
        status: {"model": ErrorEnvelope} for status in (401, 403, 404, 409, 413, 422, 503)
    }

    @app.post(
        "/api/v1/projects",
        response_model=OperationReceipt,
        operation_id="createProject",
        responses=errors,
        openapi_extra={
            "x-journeon-owner": "projects",
            "x-journeon-command": "project.create.v1",
            "x-journeon-permissions": ["project.create", "project.receipt.read"],
        },
    )
    def create_project(
        command: ProjectCreate,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> OperationReceipt:
        return service.create(actor, command)

    @app.get(
        "/api/v1/operations/{operation_id}",
        response_model=CanonicalReceipt,
        operation_id="getOperationReceipt",
        responses=errors,
        openapi_extra={
            "x-journeon-owner": "operations",
            "x-journeon-query": "operation.receipt.read.v1",
            "x-journeon-permissions": ["operation.receipt.read"],
        },
    )
    def get_receipt(
        operation_id: Identifier,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> CanonicalReceipt:
        return OperationService(engine).receipt(actor, operation_id)

    @app.post(
        "/api/v1/auth/passkeys/label",
        response_model=PasskeyMutationReceipt,
        operation_id="labelPasskey",
        responses=errors,
        openapi_extra={
            "x-journeon-owner": "identity",
            "x-journeon-command": "passkey.label.v1",
            "x-journeon-permissions": ["passkey.self.manage"],
        },
    )
    def label_passkey(
        command: PasskeyLabelCommand,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> PasskeyMutationReceipt:
        return FactorService(engine).label(actor, command)

    app.include_router(passkey_routes(passkeys, browser_auth))
    return app
