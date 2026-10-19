# SPDX-License-Identifier: AGPL-3.0-only
"Generate inspectable wire schemas and a small typed fetch client from the real API."

import argparse
import json
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine

from journeon.api import create_app
from journeon.contracts import (
    BotCreate,
    BotRevise,
    BotView,
    BundleResolve,
    BundleResult,
    BundleView,
    ConfigurationReceipt,
    EffectivePermission,
    EffectiveSettings,
    ErrorEnvelope,
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
    TaskControl,
    TaskCreate,
    TaskReceipt,
    TaskView,
    TeamCreate,
    TeamView,
)
from journeon.passkey_api import PasskeyAuthenticated, PasskeyBegin, PasskeyChallenge, PasskeyFinish
from journeon.registry import registry_manifest

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
        if not properties:
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
    definitions = openapi["components"]["schemas"]
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
        "getTask": ("GET", "/api/v1/tasks/{task_id}"),
        "createTask": ("POST", "/api/v1/tasks"),
        "pauseTask": ("POST", "/api/v1/tasks/pause"),
        "resumeTask": ("POST", "/api/v1/tasks/resume"),
        "cancelTask": ("POST", "/api/v1/tasks/cancel"),
        "beginPasskey": ("POST", "/api/v1/auth/passkeys/begin"),
        "finishPasskey": ("POST", "/api/v1/auth/passkeys/finish"),
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
    if operations != expected_operations:
        raise ValueError("Update client generation for changed operation bindings")
    instruction_methods = []
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
    client = (
        """// SPDX-License-Identifier: AGPL-3.0-only
// Generated by tools/generate_contracts.py; do not edit.
"""
        + "\n\n".join(types)
        + """

export type CanonicalReceipt =
  OperationReceipt | PasskeyMutationReceipt | TaskReceipt |
  ConfigurationReceipt | InstructionReceipt;

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
            TaskCreate,
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
    return {
        "registry.json": json.dumps(registry, indent=2, sort_keys=True) + "\n",
        "openapi.json": json.dumps(openapi, indent=2, sort_keys=True) + "\n",
        "contracts.schema.json": json.dumps(schemas, indent=2, sort_keys=True) + "\n",
        "client.ts": client,
    }


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
