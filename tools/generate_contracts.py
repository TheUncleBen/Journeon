# SPDX-License-Identifier: AGPL-3.0-only
"Generate inspectable wire schemas and a small typed fetch client from the real API."

import argparse
import json
import types
from pathlib import Path
from typing import Annotated, Any, Literal, Union, get_args, get_origin

from pydantic import BaseModel, TypeAdapter
from sqlalchemy import create_engine

from journeon.api import create_app
from journeon.attention_contracts import AttentionPage
from journeon.contracts import (
    AttemptPrepare,
    AttemptReceipt,
    AttemptView,
    BotCreate,
    BotRevise,
    BotView,
    BrowserSessionPage,
    BundleResolve,
    BundleResult,
    BundleView,
    ConfigurationReceipt,
    ContextBootstrap,
    ContextBootstrapped,
    CurrentHumanContext,
    EffectivePermission,
    EffectiveSettings,
    ErrorEnvelope,
    ExecutionReceipt,
    ExecutionStart,
    ExecutionStop,
    ExecutionView,
    LegacyPlan,
    LegacyPreview,
    NotificationDismiss,
    NotificationReceipt,
    OperationIdentityResolution,
    OperationIdentityResolve,
    OperationReceipt,
    PasskeyLabelCommand,
    PasskeyMutationReceipt,
    ProfileCreate,
    ProfileImpact,
    ProfileRevise,
    ProfileRevisionPreview,
    ProfileView,
    ProjectCreate,
    ProjectView,
    ReviewPolicy,
    ReviewPolicyConfigure,
    ReviewPolicyReceipt,
    ReviewTarget,
    ReviewTargetReceipt,
    ReviewTargetSelect,
    SessionLogout,
    SessionMutationReceipt,
    SessionRevoke,
    SessionRevokeRequest,
    TaskAdmission,
    TaskAssign,
    TaskComplete,
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
)
from journeon.discovery_contracts import AttemptPage, JobPage, ProjectPage, TaskPage
from journeon.instruction_contracts import ProtectedEffect
from journeon.passkey_api import PasskeyAuthenticated, PasskeyBegin, PasskeyChallenge, PasskeyFinish
from journeon.registry import AUTHENTICATION, COMMANDS, registry_manifest
from journeon.search_contracts import SearchPage

ROOT = Path(__file__).resolve().parents[1]


def ts_type(schema: dict[str, Any]) -> str:
    if "$ref" in schema:
        return str(schema["$ref"]).rsplit("/", 1)[-1]
    if "const" in schema:
        return json.dumps(schema["const"])
    if "enum" in schema:
        return " | ".join(json.dumps(value) for value in schema["enum"])
    if "oneOf" in schema:
        return " | ".join(ts_type(part) for part in schema["oneOf"])
    if "anyOf" in schema:
        return " | ".join(ts_type(part) for part in schema["anyOf"])
    kind = schema.get("type")
    if kind == "array":
        return f"Array<{ts_type(schema['items'])}>"
    if kind == "object":
        required = schema.get("required", [])
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties")
        if not properties and isinstance(additional, dict) and additional:
            return f"Record<string, {ts_type(additional)}>"
        if not properties:
            if additional is False:
                return "Record<string, never>"
            raise ValueError("Unbounded object schema needs an explicit client binding")
        lines = ["{"]
        for name, definition in sorted(properties.items()):
            optional = "" if name in required else "?"
            lines.append(f"  {json.dumps(name)}{optional}: {ts_type(definition)};")
        return "\n".join([*lines, "}"])
    primitive = {
        "string": "string",
        "integer": "number",
        "number": "number",
        "boolean": "boolean",
        "null": "null",
    }
    if kind in primitive:
        return primitive[kind]
    raise ValueError(f"Unsupported schema shape: {schema}")


def artifacts() -> dict[str, str]:
    # No connection is opened; the engine supplies the app factory's schema-only dependency.
    engine = create_engine("sqlite://")
    try:
        app = create_app(engine)
        registry = registry_manifest(app)
        openapi = app.openapi()
    finally:
        engine.dispose()
    definitions = dict(openapi["components"]["schemas"])
    for model, _, _ in bindings().values():
        definition = model.model_json_schema()
        for name, nested in definition.pop("$defs", {}).items():
            definitions.setdefault(name, nested)
        definitions.setdefault(model.__name__, definition)
    receipt_schema = openapi["paths"]["/api/v1/operations/{operation_id}"]["get"]["responses"][
        "200"
    ]["content"]["application/json"]["schema"]
    types = []
    for name, schema in sorted(definitions.items()):
        types.append(f"export type {name} = {ts_type(schema)};")
    operations = {
        value["operationId"]: (method.upper(), path)
        for path, methods in openapi["paths"].items()
        for method, value in methods.items()
    }
    expected_operations = {
        "createProfile": ("POST", "/api/v1/profiles"),
        "previewProfileRevision": ("POST", "/api/v1/profiles/preview-revision"),
        "reviseProfile": ("POST", "/api/v1/profiles/revise"),
        "createBot": ("POST", "/api/v1/bots"),
        "reviseBot": ("POST", "/api/v1/bots/revise"),
        "createTeam": ("POST", "/api/v1/teams"),
        "previewLegacyMemory": ("POST", "/api/v1/legacy-memory/preview"),
        "resolveInstructionBundle": ("POST", "/api/v1/instruction-bundles"),
        "getProfile": ("GET", "/api/v1/profiles/{identity}"),
        "getBot": ("GET", "/api/v1/bots/{identity}"),
        "getTeam": ("GET", "/api/v1/teams/{identity}"),
        "getBotSettings": ("GET", "/api/v1/bots/{identity}/effective-settings"),
        "getInstructionBundle": ("GET", "/api/v1/instruction-bundles/{identity}"),
        "getEffectivePermission": ("GET", "/api/v1/permissions/effective"),
        "getWorkflowTemplates": ("GET", "/api/v1/tasks/workflow-templates"),
        "getTask": ("GET", "/api/v1/tasks/{task_id}"),
        "prepareAttempt": ("POST", "/api/v1/attempts/prepare"),
        "getAttempt": ("GET", "/api/v1/attempts/{attempt_id}"),
        "createTask": ("POST", "/api/v1/tasks"),
        "pauseTask": ("POST", "/api/v1/tasks/pause"),
        "resumeTask": ("POST", "/api/v1/tasks/resume"),
        "reviseTask": ("POST", "/api/v1/tasks/revise"),
        "assignTask": ("POST", "/api/v1/tasks/assign"),
        "admitTask": ("POST", "/api/v1/tasks/admit"),
        "configureReviewPolicy": ("POST", "/api/v1/projects/review-policy"),
        "getReviewPolicy": ("GET", "/api/v1/projects/{project_id}/review-policy"),
        "selectReviewTarget": ("POST", "/api/v1/tasks/review-targets"),
        "getReviewTarget": ("GET", "/api/v1/review-targets/{identity}"),
        "completeTask": ("POST", "/api/v1/tasks/complete"),
        "configureVerification": ("POST", "/api/v1/projects/verification"),
        "getProject": ("GET", "/api/v1/projects/{project_id}"),
        "getVerification": ("GET", "/api/v1/projects/{project_id}/verification"),
        "cancelTask": ("POST", "/api/v1/tasks/cancel"),
        "beginPasskey": ("POST", AUTHENTICATION["passkey.begin.v1"].path),
        "finishPasskey": ("POST", AUTHENTICATION["passkey.finish.v1"].path),
        "labelPasskey": ("POST", "/api/v1/auth/passkeys/label"),
        "createProject": ("POST", "/api/v1/projects"),
        "getOperationReceipt": ("GET", "/api/v1/operations/{operation_id}"),
    }
    from journeon.registry import INSTRUCTION_ROUTES

    instruction_paths = {
        "inspectInstructionRoot": "/api/v1/project-roots/inspect",
        "prepareInstructionEffect": "/api/v1/protected-operations/prepare",
        "previewInstructionEffect": "/api/v1/protected-operations/preview",
        "confirmInstructionEffect": "/api/v1/protected-operations/confirm",
        "cancelInstructionEffect": "/api/v1/protected-operations/cancel",
        "bindProjectInstructions": "/api/v1/projects/{identity}/instructions/binding",
        "proposeProjectInstructions": "/api/v1/projects/{identity}/instructions/candidates",
        "previewProjectInstructions": "/api/v1/projects/{identity}/instructions/preview",
        "evaluateProjectInstructions": "/api/v1/projects/{identity}/instructions/evals",
        "reviewProjectInstructions": "/api/v1/projects/{identity}/instructions/reviews",
        "acceptProjectInstructions": "/api/v1/projects/{identity}/instructions/accept",
        "restoreProjectInstructions": "/api/v1/projects/{identity}/instructions/restore",
        "projectInstructionProjection": (
            "/api/v1/projects/{identity}/instructions/projections/{action}"
        ),
        "previewInstructionBinding": "/api/v1/projects/{identity}/instructions/binding-preview",
        "readInstructionHistory": "/api/v1/projects/{identity}/instructions/history",
        "inspectInstructionRecovery": "/api/v1/projects/{identity}/instructions/recovery",
        "readInstructionDocument": "/api/v1/projects/{identity}/instructions/document",
        "prepareInstructionPolicy": "/api/v1/projects/{identity}/instructions/policy",
        "verifyInstalledRelease": "/api/v1/releases/evidence/verify",
    }
    expected_operations.update({name: ("POST", path) for name, path in instruction_paths.items()})
    expected_operations["readProjectInstructions"] = (
        "GET",
        "/api/v1/projects/{identity}/instructions",
    )
    job_paths = {
        "dispatchTask": ("POST", "/api/v1/tasks/dispatch"),
        "readTaskEvidence": ("GET", "/api/v1/jobs/{identity}/evidence"),
        "readJob": ("GET", "/api/v1/jobs/{identity}"),
        "cancelJob": ("POST", "/api/v1/jobs/{identity}/cancel"),
        "replayEvents": ("POST", "/api/v1/events/replay"),
        "readJobAttention": ("GET", "/api/v1/jobs/{identity}/attention"),
        "previewRestore": ("POST", "/api/v1/lifecycle/restore-preview"),
    }
    expected_operations.update(job_paths)
    administration_paths = {
        "getGrantCatalog": ("GET", "/api/v1/permissions/catalog"),
        "listGrants": ("GET", "/api/v1/permissions/grants"),
        "getDeploymentPolicy": ("GET", "/api/v1/egress/policy"),
        "setGrant": ("POST", "/api/v1/permissions/grants/set"),
        "revokeGrant": ("POST", "/api/v1/permissions/grants/revoke"),
        "initializeDeploymentPolicy": ("POST", "/api/v1/egress/policy/initialize"),
    }
    expected_operations.update(administration_paths)
    expected_operations["getCurrentContext"] = ("GET", "/api/v1/auth/context")
    identity_paths = {
        "bootstrapCurrentContext": ("POST", AUTHENTICATION["identity.context.bootstrap.v1"].path),
        "listBrowserSessions": ("GET", "/api/v1/auth/sessions"),
        "revokeBrowserSession": ("POST", "/api/v1/auth/sessions/revoke"),
        "logoutBrowserSession": ("POST", "/api/v1/auth/logout"),
        "resolveOperationIdentity": ("POST", "/api/v1/operations/resolve"),
    }
    expected_operations.update(identity_paths)
    expected_operations.update(
        {
            "listProjects": ("GET", "/api/v1/projects"),
            "listTasks": ("GET", "/api/v1/projects/{project_id}/tasks"),
            "listAttempts": ("GET", "/api/v1/tasks/{task_id}/attempts"),
            "listJobs": ("GET", "/api/v1/jobs"),
            "searchWorkspace": ("GET", "/api/v1/search"),
            "listAttention": ("GET", "/api/v1/attention"),
            "dismissNotification": ("POST", "/api/v1/notifications/dismiss"),
        }
    )
    if operations != expected_operations:
        raise ValueError("Update client generation for changed operation bindings")
    instruction_methods = [
        "  getCurrentContext(): Promise<CurrentHumanContext> { "
        "return this.request('/api/v1/auth/context', {method: 'GET'}); }"
    ]
    instruction_methods.extend(
        [
            "  bootstrapCurrentContext(): Promise<ContextBootstrapped> { "
            "return this.request('/api/v1/auth/context/bootstrap', "
            "{method: 'POST', body: '{}'}); }",
            "  listBrowserSessions(limit: number, cursor?: string): Promise<BrowserSessionPage> { "
            "const query = new URLSearchParams({limit: String(limit)}); "
            "if (cursor !== undefined) query.set('cursor', cursor); "
            "return this.request(`/api/v1/auth/sessions?${query}`, {method: 'GET'}); }",
        ]
    )
    instruction_methods.extend(
        [
            "  listProjects(limit: number, cursor?: string): Promise<ProjectPage> { "
            "const query = new URLSearchParams({limit: String(limit)}); "
            "if (cursor !== undefined) query.set('cursor', cursor); "
            "return this.request(`/api/v1/projects?${query}`, {method: 'GET'}); }",
            "  listTasks(projectId: string, limit: number, cursor?: string, "
            "state?: TaskSummary['state']): Promise<TaskPage> { "
            "const query = new URLSearchParams({limit: String(limit)}); "
            "if (cursor !== undefined) query.set('cursor', cursor); "
            "if (state !== undefined) query.set('state', state); "
            "return this.request(`/api/v1/projects/${encodeURIComponent(projectId)}"
            "/tasks?${query}`, "
            "{method: 'GET'}); }",
            "  listAttempts(taskId: string, limit: number, "
            "cursor?: string): Promise<AttemptPage> { "
            "const query = new URLSearchParams({limit: String(limit)}); "
            "if (cursor !== undefined) query.set('cursor', cursor); "
            "return this.request(`/api/v1/tasks/${encodeURIComponent(taskId)}/attempts?${query}`, "
            "{method: 'GET'}); }",
            "  listJobs(limit: number, filters: {project_id?: string; task_id?: string; "
            "attempt_id?: string; cursor?: string} = {}): Promise<JobPage> { "
            "const query = new URLSearchParams({limit: String(limit)}); "
            "for (const name of ['project_id', 'task_id', 'attempt_id', 'cursor'] as const) { "
            "const value = filters[name]; if (value !== undefined) query.set(name, value); } "
            "return this.request(`/api/v1/jobs?${query}`, {method: 'GET'}); }",
        ]
    )
    instruction_methods.extend(
        [
            "  searchWorkspace(q: string, kinds: SearchItem['kind'][], limit: number, "
            "filters: {project_id?: string; cursor?: string} = {}): Promise<SearchPage> { "
            "const query = new URLSearchParams({q, limit: String(limit)}); "
            "for (const kind of kinds) query.append('kinds', kind); "
            "for (const name of ['project_id', 'cursor'] as const) { "
            "const value = filters[name]; if (value !== undefined) query.set(name, value); } "
            "return this.request(`/api/v1/search?${query}`, {method: 'GET'}); }",
            "  listAttention(limit: number, filters: {project_id?: string; cursor?: string; "
            "canonical_disposition?: AttentionItem['canonical_disposition']; "
            "presentation_disposition?: AttentionItem['presentation_disposition']} = {}): "
            "Promise<AttentionPage> { "
            "const query = new URLSearchParams({limit: String(limit)}); "
            "for (const name of ['project_id', 'cursor', 'canonical_disposition', "
            "'presentation_disposition'] as const) { "
            "const value = filters[name]; if (value !== undefined) query.set(name, value); } "
            "return this.request(`/api/v1/attention?${query}`, {method: 'GET'}); }",
            "  dismissNotification(command: NotificationDismiss, csrfToken: string): "
            "Promise<NotificationReceipt> { "
            "return this.request('/api/v1/notifications/dismiss', {method: 'POST', "
            "headers: {'X-CSRF-Token': csrfToken}, body: JSON.stringify(command)}); }",
        ]
    )
    for operation, request_name, result_name in (
        ("revokeBrowserSession", "SessionRevokeRequest", "SessionMutationReceipt"),
        ("logoutBrowserSession", "SessionLogout", "SessionMutationReceipt"),
        ("resolveOperationIdentity", "OperationIdentityResolve", "OperationIdentityResolution"),
    ):
        _, path = identity_paths[operation]
        instruction_methods.append(
            f"  {operation}(command: {request_name}, csrfToken: string): Promise<{result_name}> {{ "
            f"return this.request('{path}', {{method: 'POST', "
            "headers: {'X-CSRF-Token': csrfToken}, body: JSON.stringify(command)}); }"
        )
    for operation, path in instruction_paths.items():
        _, input_model, result_model, _ = INSTRUCTION_ROUTES[operation]
        parameters = []
        for parameter in ("identity", "action"):
            if "{" + parameter + "}" in path:
                parameters.append(parameter + ": string")
                path = path.replace(
                    "{" + parameter + "}", "${encodeURIComponent(" + parameter + ")}"
                )
        parameters += ["command: " + input_model.__name__, "csrfToken: string"]
        instruction_methods.append(
            f"  {operation}({', '.join(parameters)}): Promise<{result_model.__name__}> {{\n"
            f"    return this.request(`{path}`, {{method: 'POST', "
            "headers: {'X-CSRF-Token': csrfToken}, body: JSON.stringify(command)});\n  }"
        )
    instruction_methods.append(
        "  readProjectInstructions(identity: string): Promise<InstructionV"
        "iew> { return this.request(`/api/v1/projects/${encodeURIComponent"
        "(identity)}/instructions`, {method: 'GET'}); }"
    )
    from journeon.registry import JOB_ROUTES

    for operation, (method, path) in job_paths.items():
        _, job_input, job_result, _ = JOB_ROUTES[operation]
        parameters = []
        if "{identity}" in path:
            parameters.append("identity: string")
            path = path.replace("{identity}", "${encodeURIComponent(identity)}")
        if job_input is not None:
            parameters.extend(["command: " + job_input.__name__, "csrfToken: string"])
        result_name = (
            "Array<AttentionView>" if operation == "readJobAttention" else job_result.__name__
        )
        options = (
            "{method: 'GET'}"
            if method == "GET"
            else (
                "{method: 'POST', headers: {'X-CSRF-Token': csrfToken}, body: JSON"
                ".stringify(command)}"
            )
        )
        instruction_methods.append(
            f"  {operation}({', '.join(parameters)}): Promise<{result_name}> {{ "
            f"return this.request(`{path}`, {options}); }}"
        )
    from journeon.registry import ADMINISTRATION_ROUTES

    for operation, (method, path) in administration_paths.items():
        _, _, administration_input, administration_result = ADMINISTRATION_ROUTES[operation]
        if operation == "listGrants":
            instruction_methods.append(
                "  listGrants(limit: number, cursor?: string): Promise<GrantPage> {\n"
                "    const query = new URLSearchParams({limit: String(limit)});\n"
                "    if (cursor !== undefined) query.set('cursor', cursor);\n"
                "    return this.request(`/api/v1/permissions/grants?${query}`, "
                "{method: 'GET'});\n  }"
            )
            continue
        parameters = []
        if administration_input is not None:
            parameters = ["command: " + administration_input.__name__, "csrfToken: string"]
        options = (
            "{method: 'GET'}"
            if method == "GET"
            else (
                "{method: 'POST', headers: {'X-CSRF-Token': csrfToken}, "
                "body: JSON.stringify(command)}"
            )
        )
        instruction_methods.append(
            f"  {operation}({', '.join(parameters)}): Promise<{administration_result.__name__}> {{ "
            f"return this.request(`{path}`, {options}); }}"
        )
    client = (
        """// SPDX-License-Identifier: AGPL-3.0-only
// Generated by tools/generate_contracts.py; do not edit.
"""
        + "\n\n".join(types)
        + """

export type CanonicalReceipt = """
        + ts_type(receipt_schema)
        + """;

export class JourneonError extends Error {
  constructor(public readonly status: number, public readonly body: unknown) {
    super(`Journeon request failed (${status})`);
  }
}

export class JourneonClient {
  constructor(private readonly baseUrl = "", private readonly transport: typeof fetch = fetch) {}

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    const response = await this.transport(`${this.baseUrl}${path}`, {
      ...init, credentials: "same-origin",
      headers: {"Content-Type": "application/json", ...init.headers},
    });
    const body: unknown = await response.json();
    if (!response.ok) throw new JourneonError(response.status, body);
    return body as T;
  }

  createProfile(command: ProfileCreate, csrfToken: string): Promise<ConfigurationReceipt> {
    return this.request("/api/v1/profiles", {
      method: "POST", headers: {"X-CSRF-Token": csrfToken}, body: JSON.stringify(command),
    });
  }
  previewProfileRevision(
    command: ProfileRevisionPreview, csrfToken: string,
  ): Promise<ProfileImpact> {
    return this.request("/api/v1/profiles/preview-revision", {
      method: "POST", headers: {"X-CSRF-Token": csrfToken}, body: JSON.stringify(command),
    });
  }
  reviseProfile(command: ProfileRevise, csrfToken: string): Promise<ConfigurationReceipt> {
    return this.request("/api/v1/profiles/revise", {
      method: "POST", headers: {"X-CSRF-Token": csrfToken}, body: JSON.stringify(command),
    });
  }
  createBot(command: BotCreate, csrfToken: string): Promise<ConfigurationReceipt> {
    return this.request("/api/v1/bots", {
      method: "POST", headers: {"X-CSRF-Token": csrfToken}, body: JSON.stringify(command),
    });
  }
  reviseBot(command: BotRevise, csrfToken: string): Promise<ConfigurationReceipt> {
    return this.request("/api/v1/bots/revise", {
      method: "POST", headers: {"X-CSRF-Token": csrfToken}, body: JSON.stringify(command),
    });
  }
  createTeam(command: TeamCreate, csrfToken: string): Promise<ConfigurationReceipt> {
    return this.request("/api/v1/teams", {
      method: "POST", headers: {"X-CSRF-Token": csrfToken}, body: JSON.stringify(command),
    });
  }
  previewLegacyMemory(command: LegacyPreview, csrfToken: string): Promise<LegacyPlan> {
    return this.request("/api/v1/legacy-memory/preview", {
      method: "POST", headers: {"X-CSRF-Token": csrfToken}, body: JSON.stringify(command),
    });
  }
  resolveInstructionBundle(command: BundleResolve, csrfToken: string): Promise<BundleResult> {
    return this.request("/api/v1/instruction-bundles", {
      method: "POST", headers: {"X-CSRF-Token": csrfToken}, body: JSON.stringify(command),
    });
  }
  getProfile(identity: string): Promise<ProfileView> {
    return this.request(`/api/v1/profiles/${encodeURIComponent(identity)}`,
      {method: "GET"});
  }
  getBot(identity: string): Promise<BotView> {
    return this.request(`/api/v1/bots/${encodeURIComponent(identity)}`,
      {method: "GET"});
  }
  getTeam(identity: string): Promise<TeamView> {
    return this.request(`/api/v1/teams/${encodeURIComponent(identity)}`,
      {method: "GET"});
  }
  getBotSettings(identity: string): Promise<EffectiveSettings> {
    return this.request(`/api/v1/bots/${encodeURIComponent(identity)}/effective-settings`,
      {method: "GET"});
  }
  getInstructionBundle(identity: string): Promise<BundleView> {
    return this.request(`/api/v1/instruction-bundles/${encodeURIComponent(identity)}`,
      {method: "GET"});
  }
  getEffectivePermission(
    resourceKind: EffectivePermission["resource_kind"], resourceId: string,
    action: EffectivePermission["action"],
  ): Promise<EffectivePermission> {
    const query = new URLSearchParams({
      resource_kind: resourceKind, resource_id: resourceId, action,
    });
    return this.request(`/api/v1/permissions/effective?${query}`,
      {method: "GET"});
  }

  beginPasskey(command: PasskeyBegin, csrfToken?: string): Promise<PasskeyChallenge> {
    return this.request("/api/v1/auth/passkeys/begin", {
      method: "POST", body: JSON.stringify(command),
      headers: csrfToken ? {"X-CSRF-Token": csrfToken} : {}});
  }

  finishPasskey(command: PasskeyFinish, csrfToken?: string): Promise<PasskeyAuthenticated> {
    return this.request("/api/v1/auth/passkeys/finish", {
      method: "POST", body: JSON.stringify(command),
      headers: csrfToken ? {"X-CSRF-Token": csrfToken} : {}});
  }

  createProject(command: ProjectCreate, csrfToken?: string): Promise<OperationReceipt> {
    return this.request("/api/v1/projects", {method: "POST", body: JSON.stringify(command),
      headers: csrfToken ? {"X-CSRF-Token": csrfToken} : {}});
  }

  labelPasskey(command: PasskeyLabelCommand, csrfToken?: string): Promise<PasskeyMutationReceipt> {
    return this.request("/api/v1/auth/passkeys/label", {
      method: "POST", body: JSON.stringify(command),
      headers: csrfToken ? {"X-CSRF-Token": csrfToken} : {}});
  }

  getTask(taskId: string): Promise<TaskView> {
    return this.request(`/api/v1/tasks/${encodeURIComponent(taskId)}`,
      {method: "GET"});
  }

  createTask(command: TaskCreate, csrfToken?: string): Promise<TaskReceipt> {
    return this.request("/api/v1/tasks", {method: "POST", body: JSON.stringify(command),
      headers: csrfToken ? {"X-CSRF-Token": csrfToken} : {}});
  }

  pauseTask(command: TaskControl, csrfToken?: string): Promise<TaskReceipt> {
    return this.request("/api/v1/tasks/pause", {method: "POST", body: JSON.stringify(command),
      headers: csrfToken ? {"X-CSRF-Token": csrfToken} : {}});
  }

  resumeTask(command: TaskControl, csrfToken?: string): Promise<TaskReceipt> {
    return this.request("/api/v1/tasks/resume", {method: "POST", body: JSON.stringify(command),
      headers: csrfToken ? {"X-CSRF-Token": csrfToken} : {}});
  }

  cancelTask(command: TaskControl, csrfToken?: string): Promise<TaskReceipt> {
    return this.request("/api/v1/tasks/cancel", {method: "POST", body: JSON.stringify(command),
      headers: csrfToken ? {"X-CSRF-Token": csrfToken} : {}});
  }

  reviseTask(command: TaskRevise, csrfToken?: string): Promise<TaskReceipt> {
    return this.request("/api/v1/tasks/revise", {method: "POST", body: JSON.stringify(command),
      headers: csrfToken ? {"X-CSRF-Token": csrfToken} : {}});
  }

  assignTask(command: TaskAssign, csrfToken?: string): Promise<TaskReceipt> {
    return this.request("/api/v1/tasks/assign", {method: "POST", body: JSON.stringify(command),
      headers: csrfToken ? {"X-CSRF-Token": csrfToken} : {}});
  }

  admitTask(command: TaskAdmission, csrfToken?: string): Promise<TaskReceipt> {
    return this.request("/api/v1/tasks/admit", {method: "POST", body: JSON.stringify(command),
      headers: csrfToken ? {"X-CSRF-Token": csrfToken} : {}});
  }

  prepareAttempt(command: AttemptPrepare, csrfToken: string): Promise<AttemptReceipt> {
    return this.request("/api/v1/attempts/prepare", {method: "POST", body: JSON.stringify(command),
      headers: {"X-CSRF-Token": csrfToken}});
  }

  getAttempt(attemptId: string): Promise<AttemptView> {
    return this.request(`/api/v1/attempts/${encodeURIComponent(attemptId)}`, {method: "GET"});
  }

  configureReviewPolicy(command: ReviewPolicyConfigure,
    csrfToken: string): Promise<ReviewPolicyReceipt> {
    return this.request('/api/v1/projects/review-policy', {method: 'POST',
      headers: {'X-CSRF-Token': csrfToken}, body: JSON.stringify(command)});
  }
  getReviewPolicy(projectId: string): Promise<ReviewPolicy> {
    return this.request(`/api/v1/projects/${encodeURIComponent(projectId)}/review-policy`,
      {method: 'GET'});
  }
  selectReviewTarget(command: ReviewTargetSelect, csrfToken: string): Promise<ReviewTargetReceipt> {
    return this.request('/api/v1/tasks/review-targets', {method: 'POST',
      headers: {'X-CSRF-Token': csrfToken}, body: JSON.stringify(command)});
  }
  getReviewTarget(identity: string): Promise<ReviewTarget> {
    return this.request(`/api/v1/review-targets/${encodeURIComponent(identity)}`, {method: 'GET'});
  }
  completeTask(command: TaskComplete, csrfToken: string): Promise<TaskReceipt> {
    return this.request('/api/v1/tasks/complete', {method: 'POST',
      headers: {'X-CSRF-Token': csrfToken}, body: JSON.stringify(command)});
  }
  configureVerification(command: VerificationPolicyConfigure,
    csrfToken?: string): Promise<VerificationPolicyReceipt> {
    return this.request("/api/v1/projects/verification",
      {method: "POST", body: JSON.stringify(command),
      headers: csrfToken ? {"X-CSRF-Token": csrfToken} : {}});
  }

  getProject(projectId: string): Promise<ProjectView> {
    return this.request(`/api/v1/projects/${encodeURIComponent(projectId)}`, {method: "GET"});
  }

  getVerification(projectId: string): Promise<VerificationPolicy> {
    return this.request(`/api/v1/projects/${encodeURIComponent(projectId)}/verification`,
      {method: "GET"});
  }

  getWorkflowTemplates(projectId: string): Promise<WorkflowTemplates> {
    const query = new URLSearchParams({project_id: projectId});
    return this.request(`/api/v1/tasks/workflow-templates?${query}`, {method: "GET"});
  }

  getOperationReceipt(operationId: string): Promise<CanonicalReceipt> {
    return this.request(`/api/v1/operations/${encodeURIComponent(operationId)}`,
      {method: "GET"});
  }
}
"""
    )
    client = client.replace(
        "  createProfile(", "\n".join(instruction_methods) + "\n\n  createProfile(", 1
    )
    schemas = {
        model.__name__: model.model_json_schema()
        for model in (
            ProfileCreate,
            ProfileRevisionPreview,
            ProfileRevise,
            ProfileImpact,
            ProfileView,
            BotCreate,
            BotRevise,
            BotView,
            TeamCreate,
            TeamView,
            ConfigurationReceipt,
            EffectiveSettings,
            EffectivePermission,
            LegacyPreview,
            LegacyPlan,
            BundleResolve,
            BundleView,
            BundleResult,
            ProjectCreate,
            CurrentHumanContext,
            BrowserSessionPage,
            ProjectPage,
            TaskPage,
            AttemptPage,
            JobPage,
            SearchPage,
            AttentionPage,
            NotificationDismiss,
            NotificationReceipt,
            ContextBootstrap,
            ContextBootstrapped,
            SessionRevokeRequest,
            SessionLogout,
            SessionMutationReceipt,
            OperationIdentityResolve,
            OperationIdentityResolution,
            AttemptPrepare,
            AttemptReceipt,
            AttemptView,
            ExecutionStart,
            ExecutionStop,
            ExecutionView,
            ExecutionReceipt,
            TaskCreate,
            TaskRevise,
            TaskAssign,
            TaskAdmission,
            ReviewPolicyConfigure,
            ReviewPolicyReceipt,
            ReviewPolicy,
            ReviewTargetSelect,
            ReviewTargetReceipt,
            ReviewTarget,
            TaskComplete,
            VerificationPolicyConfigure,
            VerificationPolicyReceipt,
            VerificationPolicy,
            ProjectView,
            TaskControl,
            TaskReceipt,
            TaskView,
            PasskeyLabelCommand,
            PasskeyMutationReceipt,
            OperationReceipt,
            ErrorEnvelope,
            PasskeyBegin,
            PasskeyFinish,
            PasskeyChallenge,
            PasskeyAuthenticated,
        )
    }
    for _, input_model, result_model, _ in INSTRUCTION_ROUTES.values():
        for model in (input_model, result_model):
            schemas[model.__name__] = model.model_json_schema()
    for _, job_input, job_result, _ in JOB_ROUTES.values():
        for job_model in (job_input, job_result):
            if job_model is not None:
                schemas[job_model.__name__] = job_model.model_json_schema()
    for _, _, administration_input, administration_result in ADMINISTRATION_ROUTES.values():
        for administration_model in (administration_input, administration_result):
            if administration_model is not None:
                schemas[administration_model.__name__] = administration_model.model_json_schema()
    return {
        "registry.json": json.dumps(registry, indent=2, sort_keys=True) + "\n",
        "openapi.json": json.dumps(openapi, indent=2, sort_keys=True) + "\n",
        "contracts.schema.json": json.dumps(schemas, indent=2, sort_keys=True) + "\n",
        "client.ts": client + generate_digest_helpers(),
    }


EXCLUDE_KEY_COMMANDS = {
    "notification.dismiss.v1",
    "project.create.v1",
    "passkey.label.v1",
    "profile.create.v1",
    "profile.revise.v1",
    "bot.create.v1",
    "bot.revise.v1",
    "team.create.v1",
    "instruction.bundle.resolve.v1",
    "project.review.configure.v1",
    "project.verification.configure.v1",
    "task.create.v1",
    "task.pause.v1",
    "task.resume.v1",
    "task.cancel.v1",
    "task.revise.v1",
    "task.assign.v1",
    "task.admit.v1",
    "task.complete.v1",
    "task.review.select.v1",
    "attempt.prepare.v1",
    "task.dispatch.v1",
    "execution.start.v1",
    "execution.stop.v1",
}
INSTRUCTION_COMMANDS = {
    "project.instructions.bind.v1",
    "project.instructions.accept.v1",
    "project.instructions.projection.v1",
    "project.instructions.propose.v1",
    "project.instructions.restore.v1",
    "project.instructions.review.v1",
}


def bindings() -> dict[str, tuple[type[BaseModel], type[BaseModel], bool]]:
    result: dict[str, tuple[type[BaseModel], type[BaseModel], bool]] = {}
    execution_models: dict[str, type[BaseModel]] = {
        "execution.start.v1": ExecutionStart,
        "execution.stop.v1": ExecutionStop,
    }
    for name in sorted(EXCLUDE_KEY_COMMANDS | INSTRUCTION_COMMANDS):
        model = (
            execution_models[name] if name.startswith("execution.") else COMMANDS[name].input_model
        )
        result[model.__name__] = (model, model, name in EXCLUDE_KEY_COMMANDS)
    for model in get_args(get_args(ProtectedEffect)[0]):
        result[model.__name__] = (model, model, False)
        name = model.model_fields["kind"].default
        if name in COMMANDS and COMMANDS[name].input_model != model:
            route = COMMANDS[name].input_model
            if set(route.model_fields) - set(model.model_fields) <= {
                "request_id",
                "request_hash",
                "nonce",
            }:
                result[route.__name__] = (route, model, False)
    for model in (SessionLogout, SessionRevoke):
        result[model.__name__] = (model, model, False)
    result["SessionRevokeRequest"] = (SessionRevokeRequest, SessionRevoke, False)
    return result


def generate_digest_helpers() -> str:
    models: dict[str, Any] = {}

    def schema(annotation: Any, metadata: Any = ()) -> dict[str, Any]:
        origin, args = get_origin(annotation), get_args(annotation)
        if origin is Annotated:
            return schema(args[0], (*metadata, *args[1:]))
        if origin in (Union, types.UnionType):
            return {"union": [schema(item) for item in args]}
        if origin is Literal:
            return {"literal": list(args)}
        if origin is list:
            return {"array": schema(args[0])}
        if origin is dict and args[0] is str:
            return {"map": schema(args[1])}
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            name = annotation.__name__
            if name not in models:
                models[name] = {}
                fields = {}
                for key, field in annotation.model_fields.items():
                    item = {"schema": schema(field.annotation, field.metadata)}
                    if not field.is_required():
                        assert field.annotation is not None
                        item["default"] = TypeAdapter(field.annotation).dump_python(
                            field.get_default(call_default_factory=True), mode="json"
                        )
                    fields[key] = item
                models[name] = {"fields": fields}
            return {"model": name}
        if annotation in (str, int, float, bool, type(None)):
            result: dict[str, Any] = {
                "type": {
                    str: "string",
                    int: "integer",
                    float: "float",
                    bool: "boolean",
                    type(None): "null",
                }[annotation]
            }
            if annotation is str and any(
                getattr(item, "strip_whitespace", False) for item in metadata
            ):
                result["trim"] = True
            return result
        raise ValueError(f"Unbound command digest input: {annotation!r}")

    functions = []
    for name, (route, model, exclude_key) in sorted(bindings().items()):
        schema(model)
        excluded = sorted(set(route.model_fields) - set(model.model_fields))
        if exclude_key:
            excluded.append("idempotency_key")
        sort = {"ProjectCreate": "selected_providers", "TaskCreate": "dependencies"}.get(name)
        functions.append(
            f"export function digest{name}(command: {name}): Promise<string> {{\n"
            f"  return commandDigest({json.dumps(model.__name__)}, command, "
            f"{json.dumps(excluded)}, {json.dumps(sort)});\n}}"
        )
    return (
        DIGEST_RUNTIME
        + "\nconst digestModels: Record<string, DigestSchema> = "
        + json.dumps(models, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + ";\n\n"
        + "\n\n".join(functions)
        + "\n"
    )


DIGEST_RUNTIME = r"""
type DigestSchema = {
  type?: string; trim?: boolean; model?: string; literal?: unknown[];
  union?: DigestSchema[]; array?: DigestSchema; map?: DigestSchema;
  fields?: Record<string, {schema: DigestSchema; default?: unknown}>;
};

function digestKeyOrder(left: string, right: string): number {
  const a = Array.from(left, c => c.codePointAt(0)!);
  const b = Array.from(right, c => c.codePointAt(0)!);
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

function digestString(value: string): string {
  for (const character of value) {
    const point = character.codePointAt(0)!;
    if (point >= 0xd800 && point <= 0xdfff) {
      throw new TypeError("Command contains an unpaired surrogate");
    }
  }
  return JSON.stringify(value);
}

function digestFloat(value: number): string {
  if (!Number.isFinite(value)) throw new TypeError("Command numbers must be finite");
  // JSON command transport writes either signed zero as 0 before Python normalization.
  if (value === 0) return "0.0";
  const [mantissa, exponent] = value.toExponential().split("e");
  const power = Number(exponent);
  if (power >= -4 && power < 16) {
    const text = value.toString();
    return text.includes(".") ? text : text + ".0";
  }
  return mantissa + "e" + (power < 0 ? "-" : "+") + String(Math.abs(power)).padStart(2, "0");
}

function digestValue(
  schema: DigestSchema, value: unknown, excluded: string[] = [], sort: string | null = null,
): string {
  if (schema.model) return digestValue(digestModels[schema.model], value, excluded, sort);
  if (schema.union) {
    for (const member of schema.union) {
      try { return digestValue(member, value); }
      catch (error) { if (!(error instanceof TypeError)) throw error; }
    }
    throw new TypeError("Command value does not match its declared variants");
  }
  if (schema.literal) {
    if (!schema.literal.some(item => item === value)) {
      throw new TypeError("Command literal is invalid");
    }
    return JSON.stringify(value);
  }
  if (schema.type === "null" && value === null) return "null";
  if (schema.type === "boolean" && typeof value === "boolean") return JSON.stringify(value);
  if (schema.type === "string" && typeof value === "string") {
    if (schema.trim) {
      const spaces = "[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a"
        + "\u2028\u2029\u202f\u205f\u3000]";
      value = value.replace(new RegExp("^" + spaces + "+|" + spaces + "+$", "g"), "");
    }
    return digestString(value as string);
  }
  if (schema.type === "integer" && typeof value === "number" && Number.isInteger(value)) {
    const wire = JSON.stringify(value);
    if (!/[eE]/.test(wire)) return wire;
    throw new TypeError("Command integer has no exact integer JSON transport token");
  }
  if (schema.type === "float" && typeof value === "number") return digestFloat(value);
  if (schema.array && Array.isArray(value)) {
    return "[" + Array.from(value, item => digestValue(schema.array!, item)).join(",") + "]";
  }
  if ((schema.fields || schema.map) && value !== null
      && typeof value === "object" && !Array.isArray(value)) {
    const input = value as Record<string, unknown>;
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("Command objects must contain plain JSON data");
    }
    if (schema.fields && Object.keys(input).some(key =>
        !Object.hasOwn(schema.fields!, key) && !excluded.includes(key))) {
      throw new TypeError("Command contains an unknown field");
    }
    const keys = Object.keys(schema.fields ?? input)
      .filter(key => !excluded.includes(key)).sort(digestKeyOrder);
    return "{" + keys.map(key => {
      const field = schema.fields?.[key];
      let item = Object.hasOwn(input, key) && input[key] !== undefined
        ? input[key] : field?.default;
      if (item === undefined) throw new TypeError("Command is missing a required field");
      if (key === sort && Array.isArray(item)) item = [...item].sort(digestKeyOrder);
      return digestString(key) + ":" + digestValue(field?.schema ?? schema.map!, item);
    }).join(",") + "}";
  }
  throw new TypeError("Command value cannot be represented by its canonical input type");
}

async function commandDigest(
  model: string, command: object, excluded: string[], sort: string | null,
): Promise<string> {
  const bytes = new TextEncoder().encode(digestValue({model}, command, excluded, sort));
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, "0")).join("");
}
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for name, content in artifacts().items():
        path = ROOT / "generated" / name
        if args.check:
            if not path.exists() or path.read_text() != content:
                raise SystemExit(f"Generated contract is stale: {name}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)


if __name__ == "__main__":
    main()
