# SPDX-License-Identifier: AGPL-3.0-only
"""Bound command and module metadata; not a second permission authority."""

from dataclasses import asdict, dataclass
from typing import Any

from alembic.script import ScriptDirectory
from fastapi import FastAPI
from fastapi.routing import APIRoute, iter_route_contexts
from pydantic import BaseModel

from journeon.contracts import (
    CanonicalReceipt,
    OperationReceipt,
    PasskeyLabelCommand,
    PasskeyMutationReceipt,
    ProjectCreate,
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

COMMANDS = {command.name: command for command in (PROJECT_CREATE, PASSKEY_LABEL)}

MODULES: dict[str, dict[str, Any]] = {
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
        "migration": "0005_protected_operations",
        "settings": (),
        "environment_migrations": (),
    },
}


QUERIES: dict[str, dict[str, Any]] = {
    "operation.receipt.read.v1": {
        "owner": "operations",
        "permissions": ("operation.receipt.read",),
        "result_model": CanonicalReceipt,
    }
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
        if not authentication_name and (
            not permissions or not set(permissions) <= set(module["permissions"])
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
                "input_model": command.input_model.__name__,
                "result_model": command.result_model.__name__,
            }
            for command in COMMANDS.values()
        ],
        "queries": [
            {
                "name": name,
                **query,
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
