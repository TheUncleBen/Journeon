# SPDX-License-Identifier: AGPL-3.0-only
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, Query, Response
from sqlalchemy import Engine

from journeon.api import authenticated_context
from journeon.attention_contracts import AttentionPage
from journeon.contracts import (
    ErrorEnvelope,
    Identifier,
    NotificationDismiss,
    NotificationReceipt,
    RuntimeConfigurationUnavailable,
)
from journeon.instruction_config import InstructionConfiguration
from journeon.notification_presentation import NotificationPresentationService
from journeon.permissions import AuthenticatedContext
from journeon.registry import configuration_metadata
from journeon.search import SearchService
from journeon.search_contracts import SearchPage


def bind_workspace_api(
    app: FastAPI, engine: Engine, configuration: InstructionConfiguration | None
) -> None:
    errors: dict[int | str, dict[str, Any]] = {
        status: {"model": ErrorEnvelope} for status in (401, 403, 404, 409, 422, 503)
    }

    def notifications() -> NotificationPresentationService:
        if configuration is None:
            raise RuntimeConfigurationUnavailable(
                "Explicit instruction runtime configuration is required"
            )
        return NotificationPresentationService(engine, configuration)

    @app.get(
        "/api/v1/search",
        response_model=SearchPage,
        operation_id="searchWorkspace",
        responses=errors,
        openapi_extra=configuration_metadata("workspace.search.v1"),
    )
    def search(
        response: Response,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
        q: Annotated[str, Query(min_length=1, max_length=200)],
        kinds: Annotated[list[str], Query(min_length=1, max_length=5)],
        limit: Annotated[int, Query(ge=1, le=100)],
        project_id: Identifier | None = None,
        cursor: Annotated[str | None, Query(max_length=4096)] = None,
    ) -> SearchPage:
        response.headers["Cache-Control"] = "no-store"
        return SearchService(engine, configuration).read(actor, q, kinds, limit, cursor, project_id)

    @app.get(
        "/api/v1/attention",
        response_model=AttentionPage,
        operation_id="listAttention",
        responses=errors,
        openapi_extra=configuration_metadata("attention.list.v1"),
    )
    def attention(
        response: Response,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
        limit: Annotated[int, Query(ge=1, le=100)],
        cursor: Annotated[str | None, Query(max_length=4096)] = None,
        project_id: Identifier | None = None,
        canonical_disposition: Literal["OPEN", "DISMISSED", "RESOLVED"] | None = None,
        presentation_disposition: Literal["UNACKNOWLEDGED", "DISMISSED"] | None = None,
    ) -> AttentionPage:
        response.headers["Cache-Control"] = "no-store"
        return notifications().list(
            actor, limit, cursor, project_id, canonical_disposition, presentation_disposition
        )

    @app.post(
        "/api/v1/notifications/dismiss",
        response_model=NotificationReceipt,
        operation_id="dismissNotification",
        responses=errors,
        openapi_extra=configuration_metadata("notification.dismiss.v1"),
    )
    def dismiss(
        command: NotificationDismiss,
        response: Response,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> NotificationReceipt:
        response.headers["Cache-Control"] = "no-store"
        return notifications().dismiss(actor, command)
