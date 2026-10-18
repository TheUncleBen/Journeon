# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed API binding. Operational authentication is a later dependency."""

from typing import Annotated, Any

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import Engine

from journeon.body_limit import BodyLimitMiddleware
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


def authenticated_context() -> AuthenticatedContext:
    # No headers, environment switch, hardcoded identity, or local auth exception.
    raise DomainError("AUTHENTICATION_REQUIRED", "Authenticated service context is required")


def create_app(engine: Engine) -> FastAPI:
    app = FastAPI(title="Journeon foundation", version="0.0.0.dev1")
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
        openapi_extra={"x-journeon-owner": "projects", "x-journeon-command": "project.create.v1"},
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
        openapi_extra={"x-journeon-owner": "operations"},
    )
    def get_receipt(
        operation_id: Identifier,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> OperationReceipt:
        return service.receipt(actor, operation_id)

    return app
