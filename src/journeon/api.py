# SPDX-License-Identifier: AGPL-3.0-only
"""Session-bound API. Login ceremonies require separate verified integration."""

import tomllib
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import Engine

from journeon.body_limit import BodyLimitMiddleware
from journeon.browser_auth import BrowserAuth
from journeon.contracts import (
    ERROR_HTTP_STATUS,
    DomainError,
    ErrorEnvelope,
    Identifier,
    OperationReceipt,
    ProjectCreate,
)
from journeon.permissions import AuthenticatedContext
from journeon.projects import ProjectService


def authenticated_context(request: Request) -> AuthenticatedContext:
    binding: BrowserAuth | None = request.app.state.browser_auth
    if binding is None:
        raise DomainError("AUTHENTICATION_REQUIRED", "Authenticated service context is required")
    return binding.resolve(request.app.state.engine, request)


def create_app(engine: Engine, *, browser_auth: BrowserAuth | None = None) -> FastAPI:
    with (Path(__file__).resolve().parents[2] / "pyproject.toml").open("rb") as metadata_file:
        version = tomllib.load(metadata_file)["project"]["version"]
    app = FastAPI(title="Journeon foundation", version=version)
    app.state.browser_auth = browser_auth
    app.state.engine = engine
    app.add_middleware(BodyLimitMiddleware)
    service = ProjectService(engine)

    @app.exception_handler(DomainError)
    async def domain_error(_request: Request, exc: DomainError) -> JSONResponse:
        return JSONResponse(
            status_code=ERROR_HTTP_STATUS[exc.code],
            content=ErrorEnvelope(code=exc.code, reason=exc.reason).model_dump(),
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
        response_model=OperationReceipt,
        operation_id="getOperationReceipt",
        responses=errors,
        openapi_extra={
            "x-journeon-owner": "operations",
            "x-journeon-query": "operation.receipt.read.v1",
            "x-journeon-permissions": ["project.receipt.read"],
        },
    )
    def get_receipt(
        operation_id: Identifier,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> OperationReceipt:
        return service.receipt(actor, operation_id)

    return app
