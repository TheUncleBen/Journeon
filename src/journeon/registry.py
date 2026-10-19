# SPDX-License-Identifier: AGPL-3.0-only
"""Bound command and module metadata; not a second permission authority."""

from dataclasses import asdict, dataclass, replace
from typing import Any

from alembic.script import ScriptDirectory
from fastapi import FastAPI
from fastapi.routing import APIRoute, iter_route_contexts
from pydantic import BaseModel

from journeon.contracts import (
    BotCreate,
    BotRevise,
    BotView,
    BundleResolve,
    BundleResult,
    BundleView,
    CanonicalReceipt,
    ConfigurationReceipt,
    EffectivePermission,
    EffectiveSettings,
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
from journeon.health import schema_and_database
from journeon.migrate import configuration
from journeon.models import Base
from journeon.passkey_api import PasskeyAuthenticated, PasskeyBegin, PasskeyChallenge, PasskeyFinish


@dataclass(frozen=True)
class CommandDefinition:
    name: str
    owner: str
    input_model: type[BaseModel]
    result_model: type[BaseModel]
    permissions: tuple[str, ...]
    risk: str
    external_effects: tuple[str, ...]
    reversibility: str
    dry_run: bool
    idempotent: bool
    verification: str
    stability: str = "INTERNAL"


PROJECT_CREATE = CommandDefinition(
    name="project.create.v1",
    owner="projects",
    input_model=ProjectCreate,
    result_model=OperationReceipt,
    permissions=("project.create", "project.receipt.read"),
    risk="LOCAL_CANONICAL_MUTATION",
    external_effects=(),
    reversibility="No automatic undo; separate authorized lifecycle operation required",
    dry_run=False,
    idempotent=True,
    verification="Atomic Project, receipt and outbox persistence",
)

PASSKEY_LABEL = CommandDefinition(
    name="passkey.label.v1",
    owner="identity",
    input_model=PasskeyLabelCommand,
    result_model=PasskeyMutationReceipt,
    permissions=("passkey.self.manage",),
    risk="LOCAL_METADATA_MUTATION",
    external_effects=(),
    reversibility="A later authorized label change creates a new revision",
    dry_run=False,
    idempotent=True,
    verification="Current own-Principal strong session; atomic label, receipt and event",
)

WORK_COMMANDS = tuple(
    CommandDefinition(
        name=f"task.{action}.v1",
        owner="work",
        input_model=TaskCreate if action == "create" else TaskControl,
        result_model=TaskReceipt,
        permissions=(f"task.{action}", "task.read", "task.receipt.read"),
        risk="LOCAL_CANONICAL_MUTATION",
        external_effects=(),
        reversibility="A separate authorized lifecycle command retains prior receipts",
        dry_run=False,
        idempotent=True,
        verification="Atomic versioned Task, receipt and event; current Project grants",
    )
    for action in ("create", "pause", "resume", "cancel")
)
COMMANDS = {command.name: command for command in (PROJECT_CREATE, PASSKEY_LABEL, *WORK_COMMANDS)}

MODULES: dict[str, dict[str, Any]] = {
    "work": {
        "core": True,
        "api_prefixes": ("/api/v1/tasks",),
        "dashboards": (),
        "events_published": ("task.created", "task.paused", "task.resumed", "task.cancelled"),
        "events_consumed": (),
        "tables": ("tasks",),
        "backup_class": "R0",
        "health": "schema_and_database",
        "permissions": (
            "task.create",
            "task.read",
            "task.receipt.read",
            "task.pause",
            "task.resume",
            "task.cancel",
        ),
        "migration": "0006_work",
        "settings": (),
        "environment_migrations": (),
    },
    "identity": {
        "core": True,
        "api_prefixes": ("/api/v1/auth/passkeys",),
        "dashboards": (),
        "events_published": ("passkey.labelled",),
        "events_consumed": (),
        "tables": (
            "principals",
            "browser_sessions",
            "identity_state",
            "passkeys",
            "auth_ceremonies",
            "auth_rates",
            "auth_rate_events",
            "protected_requests",
        ),
        "backup_class": "R0",
        "health": "schema_and_database",
        "permissions": ("passkey.self.manage",),
        "migration": "0005_protected_operations",
        "settings": (),
        "environment_migrations": (),
    },
    "permissions": {
        "core": True,
        "api_prefixes": (),
        "dashboards": (),
        "events_published": (),
        "events_consumed": (),
        "tables": ("access_grants",),
        "backup_class": "R0",
        "health": "schema_and_database",
        "permissions": ("project.create", "project.receipt.read"),
        "migration": "0001_foundation",
        "settings": (),
        "environment_migrations": (),
    },
    "egress": {
        "core": True,
        "api_prefixes": (),
        "dashboards": (),
        "events_published": (),
        "events_consumed": (),
        "tables": ("deployment_policy",),
        "backup_class": "R0",
        "health": "schema_and_database",
        "permissions": (),
        "migration": "0001_foundation",
        "settings": (),
        "environment_migrations": (),
    },
    "projects": {
        "core": True,
        "api_prefixes": ("/api/v1/projects",),
        "dashboards": (),
        "events_published": ("project.created",),
        "events_consumed": (),
        "tables": ("projects",),
        "backup_class": "R0",
        "health": "schema_and_database",
        "permissions": ("project.create", "project.receipt.read"),
        "migration": "0001_foundation",
        "settings": (),
        "environment_migrations": (),
    },
    "operations": {
        "core": True,
        "api_prefixes": ("/api/v1/operations",),
        "dashboards": (),
        "events_published": (),
        "events_consumed": (),
        "tables": ("operation_receipts", "outbox_events"),
        "backup_class": "R1",
        "health": "schema_and_database",
        "permissions": ("operation.receipt.read",),
        "migration": "0006_work",
        "settings": (),
        "environment_migrations": (),
    },
}


QUERIES: dict[str, dict[str, Any]] = {
    "task.read.v1": {"owner": "work", "permissions": ("task.read",), "result_model": TaskView},
    "operation.receipt.read.v1": {
        "owner": "operations",
        "permissions": ("operation.receipt.read",),
        "result_model": CanonicalReceipt,
    },
}

COMMANDS["profile.create.v1"] = CommandDefinition(
    name="profile.create.v1",
    owner="agents",
    input_model=ProfileCreate,
    result_model=ConfigurationReceipt,
    permissions=(),
    risk="LOCAL_CANONICAL_MUTATION",
    external_effects=(),
    reversibility="Immutable history; changes require another authorized command",
    dry_run=False,
    idempotent=True,
    verification="Current exact authority and transaction checks",
)
COMMANDS["profile.preview-revision.v1"] = CommandDefinition(
    name="profile.preview-revision.v1",
    owner="agents",
    input_model=ProfileRevisionPreview,
    result_model=ProfileImpact,
    permissions=(),
    risk="READ_ONLY_PREVIEW",
    external_effects=(),
    reversibility="Immutable history; changes require another authorized command",
    dry_run=True,
    idempotent=False,
    verification="Current exact authority and transaction checks",
)
COMMANDS["profile.revise.v1"] = CommandDefinition(
    name="profile.revise.v1",
    owner="agents",
    input_model=ProfileRevise,
    result_model=ConfigurationReceipt,
    permissions=(),
    risk="LOCAL_CANONICAL_MUTATION",
    external_effects=(),
    reversibility="Immutable history; changes require another authorized command",
    dry_run=False,
    idempotent=True,
    verification="Current exact authority and transaction checks",
)
COMMANDS["bot.create.v1"] = CommandDefinition(
    name="bot.create.v1",
    owner="agents",
    input_model=BotCreate,
    result_model=ConfigurationReceipt,
    permissions=(),
    risk="LOCAL_CANONICAL_MUTATION",
    external_effects=(),
    reversibility="Immutable history; changes require another authorized command",
    dry_run=False,
    idempotent=True,
    verification="Current exact authority and transaction checks",
)
COMMANDS["bot.revise.v1"] = CommandDefinition(
    name="bot.revise.v1",
    owner="agents",
    input_model=BotRevise,
    result_model=ConfigurationReceipt,
    permissions=(),
    risk="LOCAL_CANONICAL_MUTATION",
    external_effects=(),
    reversibility="Immutable history; changes require another authorized command",
    dry_run=False,
    idempotent=True,
    verification="Current exact authority and transaction checks",
)
COMMANDS["team.create.v1"] = CommandDefinition(
    name="team.create.v1",
    owner="agents",
    input_model=TeamCreate,
    result_model=ConfigurationReceipt,
    permissions=(),
    risk="LOCAL_CANONICAL_MUTATION",
    external_effects=(),
    reversibility="Immutable history; changes require another authorized command",
    dry_run=False,
    idempotent=True,
    verification="Current exact authority and transaction checks",
)
COMMANDS["legacy-memory.preview.v1"] = CommandDefinition(
    name="legacy-memory.preview.v1",
    owner="agents",
    input_model=LegacyPreview,
    result_model=LegacyPlan,
    permissions=(),
    risk="READ_ONLY_PREVIEW",
    external_effects=(),
    reversibility="Immutable history; changes require another authorized command",
    dry_run=True,
    idempotent=False,
    verification="Current exact authority and transaction checks",
)
COMMANDS["instruction.bundle.resolve.v1"] = CommandDefinition(
    name="instruction.bundle.resolve.v1",
    owner="instructions",
    input_model=BundleResolve,
    result_model=BundleResult,
    permissions=(),
    risk="LOCAL_CANONICAL_MUTATION",
    external_effects=(),
    reversibility="Immutable history; changes require another authorized command",
    dry_run=False,
    idempotent=True,
    verification="Current exact authority and transaction checks",
)
QUERIES["profile.read.v1"] = {
    "owner": "agents",
    "permissions": (),
    "result_model": ProfileView,
}
QUERIES["bot.read.v1"] = {"owner": "agents", "permissions": (), "result_model": BotView}
QUERIES["team.read.v1"] = {
    "owner": "agents",
    "permissions": (),
    "result_model": TeamView,
}
QUERIES["bot.settings.read.v1"] = {
    "owner": "agents",
    "permissions": (),
    "result_model": EffectiveSettings,
}
QUERIES["instruction.bundle.read.v1"] = {
    "owner": "instructions",
    "permissions": (),
    "result_model": BundleView,
}
QUERIES["permission.effective.v1"] = {
    "owner": "permissions",
    "permissions": (),
    "result_model": EffectivePermission,
}
MODULES["agents"] = {
    "core": True,
    "api_prefixes": ("/api/v1/profiles", "/api/v1/bots", "/api/v1/teams", "/api/v1/legacy-memory"),
    "dashboards": (),
    "events_published": (
        "profile.create.committed",
        "profile.revise.committed",
        "bot.create.committed",
        "bot.revise.committed",
        "team.create.committed",
    ),
    "events_consumed": (),
    "tables": ("agent_profiles", "profile_revisions", "bots", "bot_revisions", "teams"),
    "backup_class": "R0",
    "health": "schema_and_database",
    "permissions": (),
    "migration": "0007_identity_instructions",
    "settings": (),
    "environment_migrations": (),
}
MODULES["instructions"] = {
    "core": True,
    "api_prefixes": ("/api/v1/instruction-bundles",),
    "dashboards": (),
    "events_published": ("instruction.bundle.resolve.committed",),
    "events_consumed": (),
    "tables": ("instruction_assets", "instruction_revisions", "instruction_bundles"),
    "backup_class": "R0",
    "health": "schema_and_database",
    "permissions": (),
    "migration": "0007_identity_instructions",
    "settings": (),
    "environment_migrations": (),
}
MODULES["permissions"]["api_prefixes"] = ("/api/v1/permissions",)
MODULES["permissions"]["migration"] = "0007_identity_instructions"
MODULES["operations"]["migration"] = "0007_identity_instructions"


# Descriptive service contracts, not an authorization evaluator or grant issuer.
# A permission inventory includes conditional checks; grant_checks binds their scopes.
def grant_check(
    capability: str, scope: str, when: str = "always", *, owner: bool = True
) -> dict[str, Any]:
    return {
        "capability": capability,
        "resource": scope,
        "when": when,
        "owner_configuration_authority": owner,
    }


BUNDLE_DISCLOSURE = [
    grant_check("instruction_bundle.read", "bundle.id"),
    grant_check("profile.read", "bundle.profile_id"),
    grant_check("bot.read", "bundle.bot_id", "named Bot"),
    grant_check("project.instruction.read", "bundle.project_id", owner=False),
    grant_check("task.read", "bundle.project_id", "Task origin", owner=False),
]
CONFIGURATION_AUTHORIZATION: dict[str, dict[str, Any]] = {
    "profile.create.v1": {"owner_only": True, "grant_checks": []},
    "profile.preview-revision.v1": {
        "grant_checks": [
            grant_check("profile.revise", "profile_id"),
            grant_check("profile.read", "profile_id"),
            grant_check(
                "bot.read",
                "affected Bot.id",
                "filter disclosed Bots; absence does not deny preview",
            ),
        ]
    },
    "profile.revise.v1": {
        "grant_checks": [
            grant_check("profile.revise", "profile_id"),
            grant_check("profile.read", "profile_id"),
            grant_check("profile.receipt.read", "profile_id"),
            grant_check(
                "bot.read",
                "affected Bot.id",
                "new commit: filter disclosed impact; absence does not deny revision",
            ),
        ]
    },
    "bot.create.v1": {
        "owner_only": True,
        "grant_checks": [
            grant_check("profile.read", "profile_id", "new creation"),
            grant_check("profile.use", "profile_id", "new creation"),
            grant_check("bot.read", "new or accepted Bot.id"),
            grant_check("bot.receipt.read", "new or accepted Bot.id"),
        ],
    },
    "bot.revise.v1": {
        "grant_checks": [
            grant_check("bot.revise", "bot_id"),
            grant_check("bot.read", "bot_id"),
            grant_check("bot.receipt.read", "bot_id"),
        ]
    },
    "team.create.v1": {
        "owner_only": True,
        "grant_checks": [
            grant_check("profile.read", "each new member.profile_id", "new creation"),
            grant_check("profile.use", "each new member.profile_id", "new creation"),
            grant_check("team.read", "new or accepted Team.id"),
            grant_check("team.receipt.read", "new or accepted Team.id"),
            grant_check("bot.read", "each accepted member.id", "accepted receipt retry"),
        ],
    },
    "legacy-memory.preview.v1": {
        "grant_checks": [
            grant_check(
                "legacy_collection.preview:{version}:{content_hash}:{provenance_ref}",
                "mapping.collection_id",
                "each mapping; hash is 64 lowercase SHA-256 hex characters",
                owner=False,
            ),
            grant_check("bot.read", "mapping.bot_id", "each mapping"),
            grant_check("bot.revise", "mapping.bot_id", "each mapping"),
        ]
    },
    "instruction.bundle.resolve.v1": {
        "initiating_human": "accepted bundle and Task origin must belong to actor",
        "grant_checks": [
            *BUNDLE_DISCLOSURE,
            grant_check("instruction_bundle.receipt.read", "new or accepted bundle.id"),
            grant_check("profile.use", "profile_id", "new construction only"),
            grant_check("bot.use", "origin.bot_id", "new named-Bot construction only"),
            grant_check(
                "profile.read", "component.owner_id", "all rendering: Profile-owned component"
            ),
            grant_check("bot.read", "component.owner_id", "all rendering: Bot-owned component"),
        ],
    },
    "profile.read.v1": {"grant_checks": [grant_check("profile.read", "profile_id")]},
    "bot.read.v1": {"grant_checks": [grant_check("bot.read", "bot_id")]},
    "team.read.v1": {
        "grant_checks": [
            grant_check("team.read", "team_id"),
            grant_check(
                "bot.read",
                "member.id",
                "filter expanded members and lead; absence does not deny Team read",
            ),
        ]
    },
    "bot.settings.read.v1": {
        "grant_checks": [
            grant_check("bot.read", "bot_id"),
            grant_check("profile.read", "Bot.profile_id"),
        ]
    },
    "instruction.bundle.read.v1": {
        "initiating_human": "bundle must belong to actor",
        "grant_checks": BUNDLE_DISCLOSURE,
    },
    "permission.effective.v1": {
        "diagnostic_only": True,
        "grant_checks": [
            grant_check(
                "{resource_kind}.{action}",
                "resource_id",
                "evaluate supported requested action for authenticated actor; "
                "no permission.effective grant",
            ),
            *[
                {**check, "when": "instruction_bundle diagnostic: " + check["when"]}
                for check in BUNDLE_DISCLOSURE
            ],
        ],
    },
}
for name, authorization in CONFIGURATION_AUTHORIZATION.items():
    authorization.setdefault("owner_only", False)
    authorization["authentication"] = "current session and Principal epoch"
    authorization["semantics"] = "scoped checks, with conditions; no rights follow from metadata"
    permissions = tuple(
        dict.fromkeys(
            check["capability"]
            for check in authorization["grant_checks"]
            if "{" not in check["capability"]
        )
    )
    if name in COMMANDS:
        COMMANDS[name] = replace(COMMANDS[name], permissions=permissions)
    else:
        QUERIES[name]["permissions"] = permissions
for owner in ("agents", "instructions"):
    MODULES[owner]["permissions"] = tuple(
        dict.fromkeys(
            permission
            for name in CONFIGURATION_AUTHORIZATION
            for permission in (
                COMMANDS[name].permissions if name in COMMANDS else QUERIES[name]["permissions"]
            )
            if (COMMANDS[name].owner if name in COMMANDS else QUERIES[name]["owner"]) == owner
        )
    )
MODULES["permissions"]["permissions"] = (
    "project.create",
    "project.receipt.read",
    *QUERIES["permission.effective.v1"]["permissions"],
)


def configuration_metadata(name: str) -> dict[str, Any]:
    command = COMMANDS.get(name)
    owner = command.owner if command else QUERIES[name]["owner"]
    permissions = command.permissions if command else QUERIES[name]["permissions"]
    return {
        "x-journeon-owner": owner,
        "x-journeon-command" if command else "x-journeon-query": name,
        "x-journeon-permissions": list(permissions),
        "x-journeon-authorization": CONFIGURATION_AUTHORIZATION[name],
    }


@dataclass(frozen=True)
class AuthenticationDefinition:
    name: str
    owner: str
    input_model: type[BaseModel]
    result_model: type[BaseModel]


AUTHENTICATION = {
    name: AuthenticationDefinition(name, "identity", input_model, result_model)
    for name, input_model, result_model in (
        ("passkey.begin.v1", PasskeyBegin, PasskeyChallenge),
        ("passkey.finish.v1", PasskeyFinish, PasskeyAuthenticated),
    )
}


def registry_manifest(app: FastAPI) -> dict[str, Any]:
    """Validate actual service bindings before generating an inspectable manifest."""
    tables = [table for module in MODULES.values() for table in module["tables"]]
    if len(tables) != len(set(tables)) or set(tables) != set(Base.metadata.tables):
        raise ValueError("Every canonical table requires exactly one registered owner")
    revisions = {
        revision.revision
        for revision in ScriptDirectory.from_config(configuration()).walk_revisions()
    }
    for module in MODULES.values():
        if (
            module["backup_class"] not in {"R0", "R1", "R2", "R3"}
            or module["migration"] not in revisions
            or module["health"] != schema_and_database.__name__
            or type(module["core"]) is not bool
            or module["settings"] != ()
            or module["environment_migrations"] != ()
        ):
            raise ValueError("Module backup, migration, health or core declaration is invalid")
    for name, definition in COMMANDS.items():
        if (
            definition.name != name
            or not definition.risk
            or not definition.reversibility
            or not definition.verification
            or not definition.stability
            or type(definition.dry_run) is not bool
            or type(definition.idempotent) is not bool
        ):
            raise ValueError("Command effect and verification metadata is incomplete")
    operations = []
    bound_commands: set[str] = set()
    bound_queries: set[str] = set()
    bound_authentication: set[str] = set()
    operation_ids: set[str] = set()
    for route in iter_route_contexts(app.routes):
        if not isinstance(route.original_route, APIRoute):
            continue
        if not route.methods:
            raise ValueError("API operation requires an HTTP method")
        if route.path is None or route.endpoint is None:
            raise ValueError("API operation requires a path and endpoint")
        metadata = route.openapi_extra or {}
        owner = metadata.get("x-journeon-owner")
        if owner not in MODULES:
            raise ValueError("API operation has no registered module owner")
        module = MODULES[owner]
        if not any(
            route.path == prefix or route.path.startswith(prefix + "/")
            for prefix in module["api_prefixes"]
        ):
            raise ValueError("API operation is outside its owning module prefix")
        permissions = tuple(metadata.get("x-journeon-permissions", ()))
        if not route.operation_id or route.operation_id in operation_ids:
            raise ValueError("API operation requires a unique explicit identity")
        operation_ids.add(route.operation_id)
        command_name = metadata.get("x-journeon-command")
        query_name = metadata.get("x-journeon-query")
        authentication_name = metadata.get("x-journeon-authentication")
        if sum(bool(name) for name in (command_name, query_name, authentication_name)) != 1:
            raise ValueError(
                "API operation must bind exactly one command or query or authentication"
            )
        authorization_name = command_name or query_name
        authorization = (
            CONFIGURATION_AUTHORIZATION.get(authorization_name)
            if isinstance(authorization_name, str)
            else None
        )
        if metadata.get("x-journeon-authorization") != authorization:
            raise ValueError("API authorization description differs from its service contract")
        if not authentication_name and (
            (not permissions and not (authorization and authorization.get("owner_only")))
            or not set(permissions) <= set(module["permissions"])
        ):
            raise ValueError("API operation permissions are missing or outside its owner")
        if command_name:
            command = COMMANDS.get(command_name)
            if (
                command is None
                or command.name != command_name
                or command.owner != owner
                or command.permissions != permissions
                or route.body_field is None
                or route.body_field.field_info.annotation is not command.input_model
                or route.response_model is not command.result_model
                or route.methods & {"GET", "HEAD", "OPTIONS"}
                or command_name in bound_commands
            ):
                raise ValueError("Command registration differs from its actual API binding")
            bound_commands.add(command_name)
        elif query_name:
            query = QUERIES.get(query_name)
            if (
                query is None
                or query["owner"] != owner
                or query["permissions"] != permissions
                or route.response_model is not query["result_model"]
                or not route.methods <= {"GET", "HEAD"}
                or query_name in bound_queries
            ):
                raise ValueError("Query registration differs from its actual API binding")
            bound_queries.add(query_name)
        else:
            authentication = (
                AUTHENTICATION.get(authentication_name)
                if isinstance(authentication_name, str)
                else None
            )
            if (
                authentication is None
                or authentication.name != authentication_name
                or authentication.owner != owner
                or "x-journeon-permissions" in metadata
                or route.body_field is None
                or route.body_field.field_info.annotation is not authentication.input_model
                or route.response_model is not authentication.result_model
                or route.methods != {"POST"}
                or authentication_name in bound_authentication
            ):
                raise ValueError("Authentication registration differs from its actual API binding")
            bound_authentication.add(authentication_name)
        operations.append(
            {
                "operation_id": route.operation_id,
                "owner": owner,
                "path": route.path,
                "methods": sorted(route.methods),
                "permissions": permissions,
                **({"authorization": authorization} if authorization else {}),
                "command": command_name,
                "query": query_name,
                "authentication": authentication_name,
                "endpoint": f"{route.endpoint.__module__}.{route.endpoint.__qualname__}",
            }
        )
    if bound_commands != set(COMMANDS) or bound_queries != set(QUERIES):
        raise ValueError("Registered commands and queries must have actual API bindings")
    if bound_authentication != set(AUTHENTICATION):
        raise ValueError("Registered authentication operations must have actual API bindings")
    return {
        "modules": [
            {
                "module_id": name,
                "version": app.version,
                **module,
                "permission_namespaces": sorted({p.split(".")[0] for p in module["permissions"]}),
            }
            for name, module in sorted(MODULES.items())
        ],
        "commands": [
            {
                **asdict(command),
                **(
                    {"authorization": CONFIGURATION_AUTHORIZATION[command.name]}
                    if command.name in CONFIGURATION_AUTHORIZATION
                    else {}
                ),
                "input_model": command.input_model.__name__,
                "result_model": command.result_model.__name__,
            }
            for command in COMMANDS.values()
        ],
        "queries": [
            {
                "name": name,
                **query,
                **(
                    {"authorization": CONFIGURATION_AUTHORIZATION[name]}
                    if name in CONFIGURATION_AUTHORIZATION
                    else {}
                ),
                "result_model": getattr(query["result_model"], "__name__", "CanonicalReceipt"),
            }
            for name, query in QUERIES.items()
        ],
        "authentication": [
            {
                **asdict(authentication),
                "input_model": authentication.input_model.__name__,
                "result_model": authentication.result_model.__name__,
            }
            for authentication in AUTHENTICATION.values()
        ],
        "api_operations": operations,
    }
