# SPDX-License-Identifier: AGPL-3.0-only
"""Authenticated production instruction operation bindings."""

from typing import Annotated, Any, Protocol

from fastapi import Depends, FastAPI, Response
from sqlalchemy import Engine

from journeon.api import authenticated_context
from journeon.contracts import DeploymentPolicyReceipt, DomainError, ErrorEnvelope, GrantReceipt
from journeon.instruction_admin import InstructionAdministration
from journeon.instruction_config import InstructionConfiguration, RootObservation
from journeon.instruction_contracts import (
    EvidenceIdentity,
    ExactConfirmation,
    InstructionReceipt,
    OfficialPreview,
    ProtectedEffectResult,
    ProtectedIdentity,
    ProtectedPrepare,
    ProtectedState,
    RecoveryInspect,
    RecoveryTarget,
    ReleaseVerify,
    RootInspect,
)
from journeon.instruction_protected import InstructionConfirmation
from journeon.permissions import AuthenticatedContext
from journeon.restore_contracts import RestoreAuthorization


def bind_instruction_api(
    app: FastAPI, engine: Engine, configuration: InstructionConfiguration | None
) -> None:
    from journeon.instruction_surface import bind_surface

    bind_surface(app, engine, configuration)
    errors: dict[int | str, dict[str, Any]] = {
        status: {"model": ErrorEnvelope} for status in (401, 403, 404, 409, 413, 422, 503)
    }

    def configured() -> InstructionConfiguration:
        if configuration is None:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Explicit instruction runtime configuration is required"
            )
        return configuration

    @app.post(
        "/api/v1/project-roots/inspect",
        responses=errors,
        response_model=RootObservation,
        operation_id="inspectInstructionRoot",
    )
    def inspect(
        command: RootInspect, actor: Annotated[AuthenticatedContext, Depends(authenticated_context)]
    ) -> RootObservation:
        return InstructionAdministration(engine, configured()).inspect(actor, command)

    @app.post(
        "/api/v1/protected-operations/prepare",
        responses=errors,
        response_model=ProtectedIdentity,
        operation_id="prepareInstructionEffect",
    )
    def prepare(
        command: ProtectedPrepare,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> ProtectedIdentity:
        return ProtectedIdentity(
            request_id=InstructionConfirmation(engine, configured()).prepare(actor, command.effect)
        )

    @app.post(
        "/api/v1/protected-operations/preview",
        responses=errors,
        response_model=OfficialPreview,
        operation_id="previewInstructionEffect",
    )
    def preview(
        command: ProtectedIdentity,
        response: Response,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> OfficialPreview:
        response.headers["Cache-Control"] = "no-store"
        return InstructionConfirmation(engine, configured()).preview(actor, command.request_id)

    @app.post(
        "/api/v1/protected-operations/confirm",
        responses=errors,
        response_model=ProtectedEffectResult,
        operation_id="confirmInstructionEffect",
    )
    def confirm(
        command: ExactConfirmation,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> InstructionReceipt | RestoreAuthorization | GrantReceipt | DeploymentPolicyReceipt:
        return InstructionConfirmation(engine, configured()).confirm(actor, command)

    @app.post(
        "/api/v1/protected-operations/cancel",
        responses=errors,
        response_model=ProtectedState,
        operation_id="cancelInstructionEffect",
    )
    def cancel(
        command: ProtectedIdentity,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> ProtectedState:
        return ProtectedState.model_validate(
            {
                "state": InstructionConfirmation(engine, configured()).cancel(
                    actor, command.request_id
                )
            }
        )

    from journeon.instruction_contracts import (
        CandidateReference,
        CandidateView,
        InstructionAccept,
        InstructionBind,
        InstructionPropose,
        InstructionRestore,
        InstructionReview,
        InstructionView,
    )
    from journeon.project_instructions import ProjectInstructionService

    class ProjectCommand(Protocol):
        project_id: str

    def project_command(identity: str, command: ProjectCommand) -> None:
        if command.project_id != identity:
            raise DomainError("PERMISSION_DENIED", "Project command scope does not match")

    @app.post(
        "/api/v1/projects/{identity}/instructions/recovery",
        responses=errors,
        response_model=RecoveryTarget,
        operation_id="inspectInstructionRecovery",
    )
    def recovery(
        identity: str,
        command: RecoveryInspect,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> RecoveryTarget:
        project_command(identity, command)
        return ProjectInstructionService(engine, configured()).recovery_target(actor, identity)

    @app.post(
        "/api/v1/projects/{identity}/instructions/binding",
        responses=errors,
        response_model=InstructionReceipt,
        operation_id="bindProjectInstructions",
    )
    def bind(
        identity: str,
        command: InstructionBind,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> InstructionReceipt:
        project_command(identity, command)
        return ProjectInstructionService(engine, configured()).bind(actor, command)

    from journeon.instruction_contracts import (
        BindingImpact,
        BindingPreview,
        Document,
        DocumentRead,
        HistoryRead,
        HistoryView,
    )

    @app.post(
        "/api/v1/projects/{identity}/instructions/binding-preview",
        responses=errors,
        response_model=BindingImpact,
        operation_id="previewInstructionBinding",
    )
    def binding_preview(
        identity: str,
        command: BindingPreview,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> BindingImpact:
        project_command(identity, command)
        return ProjectInstructionService(engine, configured()).preview_binding(actor, command)

    @app.post(
        "/api/v1/projects/{identity}/instructions/history",
        responses=errors,
        response_model=HistoryView,
        operation_id="readInstructionHistory",
    )
    def history(
        identity: str,
        command: HistoryRead,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> HistoryView:
        project_command(identity, command)
        return ProjectInstructionService(engine, configured()).history(actor, command)

    @app.post(
        "/api/v1/projects/{identity}/instructions/document",
        responses=errors,
        response_model=Document,
        operation_id="readInstructionDocument",
    )
    def document(
        identity: str,
        command: DocumentRead,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> Document:
        project_command(identity, command)
        return ProjectInstructionService(engine, configured()).document(actor, command)

    @app.get(
        "/api/v1/projects/{identity}/instructions",
        responses=errors,
        response_model=InstructionView,
        operation_id="readProjectInstructions",
    )
    def read(
        identity: str, actor: Annotated[AuthenticatedContext, Depends(authenticated_context)]
    ) -> InstructionView:
        return ProjectInstructionService(engine, configured()).read(actor, identity)

    @app.post(
        "/api/v1/projects/{identity}/instructions/candidates",
        responses=errors,
        response_model=CandidateView,
        operation_id="proposeProjectInstructions",
    )
    def propose(
        identity: str,
        command: InstructionPropose,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> CandidateView:
        project_command(identity, command)
        return ProjectInstructionService(engine, configured()).propose(actor, command)

    @app.post(
        "/api/v1/projects/{identity}/instructions/preview",
        responses=errors,
        response_model=CandidateView,
        operation_id="previewProjectInstructions",
    )
    def candidate_preview(
        identity: str,
        command: CandidateReference,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> CandidateView:
        project_command(identity, command)
        return ProjectInstructionService(engine, configured()).preview(actor, command)

    @app.post(
        "/api/v1/projects/{identity}/instructions/evals",
        responses=errors,
        response_model=EvidenceIdentity,
        operation_id="evaluateProjectInstructions",
    )
    def evaluate(
        identity: str,
        command: CandidateReference,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> EvidenceIdentity:
        project_command(identity, command)
        return EvidenceIdentity(
            evidence_id=ProjectInstructionService(engine, configured()).evaluate(actor, command)
        )

    @app.post(
        "/api/v1/projects/{identity}/instructions/reviews",
        responses=errors,
        response_model=EvidenceIdentity,
        operation_id="reviewProjectInstructions",
    )
    def review(
        identity: str,
        command: InstructionReview,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> EvidenceIdentity:
        project_command(identity, command)
        return EvidenceIdentity(
            evidence_id=ProjectInstructionService(engine, configured()).review(actor, command)
        )

    @app.post(
        "/api/v1/projects/{identity}/instructions/accept",
        responses=errors,
        response_model=InstructionReceipt,
        operation_id="acceptProjectInstructions",
    )
    def accept(
        identity: str,
        command: InstructionAccept,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> InstructionReceipt:
        project_command(identity, command)
        return ProjectInstructionService(engine, configured()).accept(actor, command)

    @app.post(
        "/api/v1/projects/{identity}/instructions/restore",
        responses=errors,
        response_model=CandidateView,
        operation_id="restoreProjectInstructions",
    )
    def restore(
        identity: str,
        command: InstructionRestore,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> CandidateView:
        project_command(identity, command)
        return ProjectInstructionService(engine, configured()).restore(actor, command)

    @app.post(
        "/api/v1/releases/evidence/verify",
        responses=errors,
        response_model=EvidenceIdentity,
        operation_id="verifyInstalledRelease",
    )
    def verify(
        command: ReleaseVerify,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> EvidenceIdentity:
        from journeon.installed_instructions import candidate_manifest
        from journeon.release_evidence import verify_release

        if command.expected_manifest_digest != candidate_manifest().digest:
            raise DomainError("REVISION_CONFLICT", "Installed manifest changed")
        return EvidenceIdentity(evidence_id=verify_release(engine, configured(), actor))

    from journeon.instruction_contracts import PolicyConfigure, ProjectionCommand, ProjectionView

    @app.post(
        "/api/v1/projects/{identity}/instructions/projections/{action}",
        responses=errors,
        response_model=ProjectionView,
        operation_id="projectInstructionProjection",
    )
    def projection(
        identity: str,
        action: str,
        command: ProjectionCommand,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> ProjectionView:
        project_command(identity, command)
        return ProjectInstructionService(engine, configured()).projection(actor, command, action)

    @app.post(
        "/api/v1/projects/{identity}/instructions/policy",
        responses=errors,
        response_model=ProtectedIdentity,
        operation_id="prepareInstructionPolicy",
    )
    def policy(
        identity: str,
        command: PolicyConfigure,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> ProtectedIdentity:
        project_command(identity, command)
        return ProtectedIdentity(
            request_id=InstructionConfirmation(engine, configured()).prepare(actor, command)
        )

    from fastapi.routing import APIRoute

    from journeon.registry import INSTRUCTION_ROUTES, configuration_metadata

    for route in app.routes:
        if isinstance(route, APIRoute):
            if route.operation_id in INSTRUCTION_ROUTES:
                route.openapi_extra = configuration_metadata(
                    INSTRUCTION_ROUTES[route.operation_id][0]
                )
            elif route.operation_id == "readProjectInstructions":
                route.openapi_extra = configuration_metadata("project.instructions.read.v1")
