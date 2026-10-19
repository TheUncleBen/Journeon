# SPDX-License-Identifier: AGPL-3.0-only
"""Session-bound API with explicitly configured passkey authentication."""

import tomllib
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError

from journeon.agents import AgentService
from journeon.body_limit import BodyLimitMiddleware
from journeon.browser_auth import BrowserAuth
from journeon.contracts import (
    ERROR_HTTP_STATUS,
    BotCreate,
    BotRevise,
    BotView,
    BundleResolve,
    BundleResult,
    BundleView,
    CanonicalReceipt,
    ConfigurationKind,
    ConfigurationReceipt,
    DomainError,
    EffectivePermission,
    EffectiveSettings,
    ErrorEnvelope,
    Identifier,
    LegacyPlan,
    LegacyPreview,
    OperationReceipt,
    PasskeyLabelCommand,
    PasskeyMutationReceipt,
    ProfileCreate,
    ProfileImpact,
    ProfileRevise,
    ProfileRevisionPreview,
    ProfileView,
    ProjectCreate,
    TaskAdmission,
    TaskAssign,
    TaskControl,
    TaskCreate,
    TaskReceipt,
    TaskRevise,
    TaskView,
    TeamCreate,
    TeamView,
    VerificationPolicy,
    VerificationPolicyConfigure,
    VerificationPolicyReceipt,
    WorkflowTemplates,
)
from journeon.factors import FactorService
from journeon.instruction_config import InstructionConfiguration
from journeon.instructions import InstructionService
from journeon.passkey_api import routes as passkey_routes
from journeon.passkeys import PasskeyService, RejectedPasskeyInput
from journeon.permissions import AuthenticatedContext
from journeon.projects import ProjectService
from journeon.receipts import OperationService
from journeon.registry import configuration_metadata
from journeon.work import WorkService


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
    instructions: InstructionConfiguration | None = None,
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
        return OperationService(engine, instructions).receipt(actor, operation_id)

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

    @app.get(
        "/api/v1/tasks/workflow-templates",
        response_model=WorkflowTemplates,
        operation_id="getWorkflowTemplates",
        responses=errors,
        openapi_extra={
            "x-journeon-owner": "work",
            "x-journeon-query": "task.workflows.read.v1",
            "x-journeon-permissions": ["task.read"],
        },
    )
    def get_workflow_templates(
        project_id: Identifier,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> WorkflowTemplates:
        from journeon.permissions import require_grant
        from journeon.work import work_transaction
        from journeon.workflows import templates

        with work_transaction(engine, actor) as db:
            require_grant(db, actor, "task.read", project_id=project_id)
            return templates()

    @app.get(
        "/api/v1/tasks/{task_id}",
        response_model=TaskView,
        operation_id="getTask",
        responses=errors,
        openapi_extra={
            "x-journeon-owner": "work",
            "x-journeon-query": "task.read.v1",
            "x-journeon-permissions": ["task.read"],
        },
    )
    def get_task(
        task_id: Identifier,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> TaskView:
        return WorkService(engine).read(actor, task_id)

    @app.post(
        "/api/v1/tasks",
        response_model=TaskReceipt,
        operation_id="createTask",
        responses=errors,
        openapi_extra={
            "x-journeon-owner": "work",
            "x-journeon-command": "task.create.v1",
            "x-journeon-permissions": ["task.create", "task.read", "task.receipt.read"],
        },
    )
    def create_task(
        command: TaskCreate,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> TaskReceipt:
        return WorkService(engine).create(actor, command)

    @app.post(
        "/api/v1/tasks/pause",
        response_model=TaskReceipt,
        operation_id="pauseTask",
        responses=errors,
        openapi_extra={
            "x-journeon-owner": "work",
            "x-journeon-command": "task.pause.v1",
            "x-journeon-permissions": ["task.pause", "task.read", "task.receipt.read"],
        },
    )
    def pause_task(
        command: TaskControl,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> TaskReceipt:
        return WorkService(engine).control(actor, "pause", command)

    @app.post(
        "/api/v1/tasks/resume",
        response_model=TaskReceipt,
        operation_id="resumeTask",
        responses=errors,
        openapi_extra={
            "x-journeon-owner": "work",
            "x-journeon-command": "task.resume.v1",
            "x-journeon-permissions": ["task.resume", "task.read", "task.receipt.read"],
        },
    )
    def resume_task(
        command: TaskControl,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> TaskReceipt:
        return WorkService(engine).control(actor, "resume", command)

    @app.post(
        "/api/v1/tasks/cancel",
        response_model=TaskReceipt,
        operation_id="cancelTask",
        responses=errors,
        openapi_extra={
            "x-journeon-owner": "work",
            "x-journeon-command": "task.cancel.v1",
            "x-journeon-permissions": ["task.cancel", "task.read", "task.receipt.read"],
        },
    )
    def cancel_task(
        command: TaskControl,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> TaskReceipt:
        return WorkService(engine).control(actor, "cancel", command)

    @app.post(
        "/api/v1/tasks/revise",
        response_model=TaskReceipt,
        operation_id="reviseTask",
        responses=errors,
        openapi_extra=configuration_metadata("task.revise.v1"),
    )
    def revise_task(
        command: TaskRevise, actor: Annotated[AuthenticatedContext, Depends(authenticated_context)]
    ) -> TaskReceipt:
        return WorkService(engine).revise(actor, command)

    @app.post(
        "/api/v1/tasks/assign",
        response_model=TaskReceipt,
        operation_id="assignTask",
        responses=errors,
        openapi_extra=configuration_metadata("task.assign.v1"),
    )
    def assign_task(
        command: TaskAssign, actor: Annotated[AuthenticatedContext, Depends(authenticated_context)]
    ) -> TaskReceipt:
        return WorkService(engine).assign(actor, command)

    @app.post(
        "/api/v1/tasks/admit",
        response_model=TaskReceipt,
        operation_id="admitTask",
        responses=errors,
        openapi_extra=configuration_metadata("task.admit.v1"),
    )
    def admit_task(
        command: TaskAdmission,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> TaskReceipt:
        return WorkService(engine).create_or_continue_task(actor, command)

    @app.post(
        "/api/v1/projects/verification",
        response_model=VerificationPolicyReceipt,
        operation_id="configureVerification",
        responses=errors,
        openapi_extra={
            "x-journeon-owner": "projects",
            "x-journeon-command": "project.verification.configure.v1",
            "x-journeon-permissions": [
                "project.verification.configure",
                "project.verification.read",
                "project.receipt.read",
            ],
        },
    )
    def configure_verification(
        command: VerificationPolicyConfigure,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> VerificationPolicyReceipt:
        return WorkService(engine).configure_verification(actor, command)

    @app.get(
        "/api/v1/projects/{project_id}/verification",
        response_model=VerificationPolicy,
        operation_id="getVerification",
        responses=errors,
        openapi_extra={
            "x-journeon-owner": "projects",
            "x-journeon-query": "project.verification.read.v1",
            "x-journeon-permissions": ["project.verification.read"],
        },
    )
    def get_verification(
        project_id: Identifier,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> VerificationPolicy:
        return WorkService(engine).verification(actor, project_id)

    @app.post(
        "/api/v1/profiles",
        response_model=ConfigurationReceipt,
        operation_id="createProfile",
        responses=errors,
        openapi_extra=configuration_metadata("profile.create.v1"),
    )
    def create_profile_configuration(
        command: ProfileCreate,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> ConfigurationReceipt:
        return AgentService(engine).create_profile(actor, command)

    @app.post(
        "/api/v1/profiles/preview-revision",
        response_model=ProfileImpact,
        operation_id="previewProfileRevision",
        responses=errors,
        openapi_extra=configuration_metadata("profile.preview-revision.v1"),
    )
    def preview_profile_configuration(
        command: ProfileRevisionPreview,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> ProfileImpact:
        return AgentService(engine).preview_profile(actor, command)

    @app.post(
        "/api/v1/profiles/revise",
        response_model=ConfigurationReceipt,
        operation_id="reviseProfile",
        responses=errors,
        openapi_extra=configuration_metadata("profile.revise.v1"),
    )
    def revise_profile_configuration(
        command: ProfileRevise,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> ConfigurationReceipt:
        return AgentService(engine).revise_profile(actor, command)

    @app.post(
        "/api/v1/bots",
        response_model=ConfigurationReceipt,
        operation_id="createBot",
        responses=errors,
        openapi_extra=configuration_metadata("bot.create.v1"),
    )
    def create_bot_configuration(
        command: BotCreate, actor: Annotated[AuthenticatedContext, Depends(authenticated_context)]
    ) -> ConfigurationReceipt:
        return AgentService(engine).create_bot(actor, command)

    @app.post(
        "/api/v1/bots/revise",
        response_model=ConfigurationReceipt,
        operation_id="reviseBot",
        responses=errors,
        openapi_extra=configuration_metadata("bot.revise.v1"),
    )
    def revise_bot_configuration(
        command: BotRevise, actor: Annotated[AuthenticatedContext, Depends(authenticated_context)]
    ) -> ConfigurationReceipt:
        return AgentService(engine).revise_bot(actor, command)

    @app.post(
        "/api/v1/teams",
        response_model=ConfigurationReceipt,
        operation_id="createTeam",
        responses=errors,
        openapi_extra=configuration_metadata("team.create.v1"),
    )
    def create_team_configuration(
        command: TeamCreate, actor: Annotated[AuthenticatedContext, Depends(authenticated_context)]
    ) -> ConfigurationReceipt:
        return AgentService(engine).create_team(actor, command)

    @app.post(
        "/api/v1/legacy-memory/preview",
        response_model=LegacyPlan,
        operation_id="previewLegacyMemory",
        responses=errors,
        openapi_extra=configuration_metadata("legacy-memory.preview.v1"),
    )
    def legacy_preview_configuration(
        command: LegacyPreview,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> LegacyPlan:
        return AgentService(engine).legacy_preview(actor, command)

    @app.post(
        "/api/v1/instruction-bundles",
        response_model=BundleResult,
        operation_id="resolveInstructionBundle",
        responses=errors,
        openapi_extra=configuration_metadata("instruction.bundle.resolve.v1"),
    )
    def resolve_configuration(
        command: BundleResolve,
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> BundleResult:
        if instructions is None:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Explicit instruction runtime configuration is required"
            )
        return InstructionService(engine, instructions).resolve(actor, command)

    @app.get(
        "/api/v1/profiles/{identity}",
        response_model=ProfileView,
        operation_id="getProfile",
        responses=errors,
        openapi_extra=configuration_metadata("profile.read.v1"),
    )
    def profile_configuration_read(
        identity: Identifier, actor: Annotated[AuthenticatedContext, Depends(authenticated_context)]
    ) -> ProfileView:
        return AgentService(engine).profile(actor, identity)

    @app.get(
        "/api/v1/bots/{identity}",
        response_model=BotView,
        operation_id="getBot",
        responses=errors,
        openapi_extra=configuration_metadata("bot.read.v1"),
    )
    def bot_configuration_read(
        identity: Identifier, actor: Annotated[AuthenticatedContext, Depends(authenticated_context)]
    ) -> BotView:
        return AgentService(engine).bot(actor, identity)

    @app.get(
        "/api/v1/teams/{identity}",
        response_model=TeamView,
        operation_id="getTeam",
        responses=errors,
        openapi_extra=configuration_metadata("team.read.v1"),
    )
    def team_configuration_read(
        identity: Identifier, actor: Annotated[AuthenticatedContext, Depends(authenticated_context)]
    ) -> TeamView:
        return AgentService(engine).team(actor, identity)

    @app.get(
        "/api/v1/bots/{identity}/effective-settings",
        response_model=EffectiveSettings,
        operation_id="getBotSettings",
        responses=errors,
        openapi_extra=configuration_metadata("bot.settings.read.v1"),
    )
    def settings_configuration_read(
        identity: Identifier, actor: Annotated[AuthenticatedContext, Depends(authenticated_context)]
    ) -> EffectiveSettings:
        return AgentService(engine).settings(actor, identity)

    @app.get(
        "/api/v1/instruction-bundles/{identity}",
        response_model=BundleView,
        operation_id="getInstructionBundle",
        responses=errors,
        openapi_extra=configuration_metadata("instruction.bundle.read.v1"),
    )
    def read_configuration_read(
        identity: Identifier, actor: Annotated[AuthenticatedContext, Depends(authenticated_context)]
    ) -> BundleView:
        return InstructionService(engine, instructions).read(actor, identity)

    @app.get(
        "/api/v1/permissions/effective",
        response_model=EffectivePermission,
        operation_id="getEffectivePermission",
        responses=errors,
        openapi_extra=configuration_metadata("permission.effective.v1"),
    )
    def effective_permission(
        resource_kind: ConfigurationKind,
        resource_id: Identifier,
        action: Literal["read", "revise", "use", "receipt.read"],
        actor: Annotated[AuthenticatedContext, Depends(authenticated_context)],
    ) -> EffectivePermission:
        return AgentService(engine).permission(actor, resource_kind, resource_id, action)

    app.include_router(passkey_routes(passkeys, browser_auth))
    from journeon.instruction_api import bind_instruction_api

    bind_instruction_api(app, engine, instructions)
    from journeon.job_api import bind_job_api

    bind_job_api(app, engine, instructions)
    return app
