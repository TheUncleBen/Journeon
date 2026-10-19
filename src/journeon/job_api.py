# SPDX-License-Identifier: AGPL-3.0-only
from typing import Annotated, Any, cast

from fastapi import Depends, FastAPI
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import defer

from journeon.api import authenticated_context
from journeon.contracts import DomainError, ErrorEnvelope
from journeon.database import transaction
from journeon.instruction_config import InstructionConfiguration
from journeon.job_contracts import (
    AttentionList,
    AttentionView,
    JobCancel,
    JobView,
    ReplayCursor,
    ReplayEvent,
    ReplayPage,
    ReplayQuery,
)
from journeon.jobs import JobService, authorize
from journeon.models import Attention, Job, OutboxEvent, Receipt, StoreIdentity
from journeon.permissions import AuthenticatedContext
from journeon.receipts import authorized_receipt
from journeon.sessions import current_session


def replay(engine: Engine, actor: AuthenticatedContext, query: ReplayQuery) -> ReplayPage:
    with transaction(engine) as db:
        current_session(
            db,
            actor.authentication_ref,
            principal_id=actor.principal_id,
            principal_epoch=actor.principal_epoch,
        )
        store = db.get(StoreIdentity, 1)
        if store is None or not store.security_reconciled:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Store security reconciliation is required")
        cursor = ReplayCursor(incarnation=store.incarnation, sequence=0)
        if query.cursor is not None and query.cursor.incarnation != store.incarnation:
            return ReplayPage(
                status="CANONICAL_REFETCH_REQUIRED", cursor=cursor, events=[], truncated=False
            )
        after = query.cursor.sequence if query.cursor else 0
        ceiling = db.scalar(select(func.max(OutboxEvent.sequence))) or 0
        if after > ceiling:
            return ReplayPage(
                status="CANONICAL_REFETCH_REQUIRED", cursor=cursor, events=[], truncated=False
            )
        events: list[ReplayEvent] = []
        truncated = False
        scanned = 0
        for event in db.scalars(
            select(OutboxEvent)
            .options(defer(OutboxEvent.payload))
            .where(OutboxEvent.sequence > after, OutboxEvent.principal_id == actor.principal_id)
            .order_by(OutboxEvent.sequence)
            .limit(1001)
        ):
            scanned += 1
            if scanned > 1000:
                return ReplayPage(
                    status="CANONICAL_REFETCH_REQUIRED", cursor=cursor, events=[], truncated=False
                )
            from journeon.registry import MODULES

            if event.schema_version != 1 or event.event_type not in MODULES.get(
                event.owner, {}
            ).get("events_published", ()):
                continue
            receipt = db.get(Receipt, event.operation_id, options=[defer(Receipt.result)])
            if receipt is None:
                continue
            if (event.owner, event.target_kind, event.target_id, event.project_id) != (
                receipt.owner,
                receipt.target_kind,
                receipt.target_id,
                receipt.project_id,
            ):
                continue
            try:
                result = authorized_receipt(db, actor, receipt)
                from pydantic import TypeAdapter

                from journeon.contracts import CanonicalReceipt

                adapter: TypeAdapter[CanonicalReceipt] = TypeAdapter(cast(Any, CanonicalReceipt))
                retained = adapter.validate_python(event.payload)
                if retained != result:
                    continue
            except (DomainError, ValueError):
                continue
            if len(events) == query.limit:
                truncated = True
                break
            events.append(
                ReplayEvent(
                    event_id=event.event_id,
                    event_type=event.event_type,
                    target_id=event.target_id,
                    target_revision=event.target_revision,
                    operation_id=event.operation_id,
                )
            )
            cursor = cursor.model_copy(update={"sequence": event.sequence})
        if cursor.sequence == 0:
            cursor = cursor.model_copy(update={"sequence": after})
        return ReplayPage(status="AVAILABLE", cursor=cursor, events=events, truncated=truncated)


def bind_job_api(
    app: FastAPI, engine: Engine, configuration: InstructionConfiguration | None
) -> None:
    errors: dict[int | str, dict[str, Any]] = {
        status: {"model": ErrorEnvelope} for status in (401, 403, 404, 409, 422, 503)
    }

    def service() -> JobService:
        if configuration is None:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Explicit instruction runtime configuration is required"
            )
        return JobService(engine, configuration)

    from journeon.restore_contracts import RestorePlan, RestorePreview

    @app.post(
        "/api/v1/lifecycle/restore-preview",
        responses=errors,
        response_model=RestorePlan,
        operation_id="previewRestore",
    )
    def restore_preview(
        command: RestorePreview,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> RestorePlan:
        from journeon.restore import preview

        return preview(engine, service().configuration, actor, command)

    @app.get(
        "/api/v1/jobs/{identity}", responses=errors, response_model=JobView, operation_id="readJob"
    )
    def read(
        identity: str, actor: Annotated[AuthenticatedContext, Depends(authenticated_context)]
    ) -> JobView:
        return service().read(actor, identity)

    @app.post(
        "/api/v1/jobs/{identity}/cancel",
        responses=errors,
        response_model=JobView,
        operation_id="cancelJob",
    )
    def cancel(
        identity: str,
        command: JobCancel,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> JobView:
        return service().cancel(actor, identity, command)

    @app.post(
        "/api/v1/events/replay",
        responses=errors,
        response_model=ReplayPage,
        operation_id="replayEvents",
    )
    def events(
        command: ReplayQuery, actor: Annotated[AuthenticatedContext, Depends(authenticated_context)]
    ) -> ReplayPage:
        return replay(engine, actor, command)

    @app.get(
        "/api/v1/jobs/{identity}/attention",
        responses=errors,
        response_model=AttentionList,
        operation_id="readJobAttention",
    )
    def attention(
        identity: str, actor: Annotated[AuthenticatedContext, Depends(authenticated_context)]
    ) -> list[AttentionView]:
        with transaction(engine) as db:
            job = db.get(Job, identity)
            if job is None:
                raise DomainError("NOT_FOUND", "Job is unavailable")
            authorize(db, actor, job)
            return [
                AttentionView.model_validate(
                    dict(
                        attention_id=row.id,
                        job_id=row.job_id,
                        reason=row.reason,
                        occurrences=row.occurrences,
                        disposition=row.disposition,
                    )
                )
                for row in db.scalars(select(Attention).where(Attention.job_id == identity))
            ]

    from fastapi.routing import APIRoute

    from journeon.registry import JOB_ROUTES, configuration_metadata

    for route in app.routes:
        if isinstance(route, APIRoute) and route.operation_id in JOB_ROUTES:
            route.openapi_extra = configuration_metadata(JOB_ROUTES[route.operation_id][0])
