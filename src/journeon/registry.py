# SPDX-License-Identifier: AGPL-3.0-only
"Bound command and module metadata; not a second permission authority."

from dataclasses import asdict, dataclass, replace
from typing import Any

from alembic.script import ScriptDirectory
from fastapi import FastAPI
from fastapi.routing import APIRoute, iter_route_contexts
from pydantic import BaseModel

from journeon import instruction_contracts as instruction_dto
from journeon.attempt_contracts import AttemptPrepare, AttemptReceipt, AttemptView
from journeon.contracts import (
    BotCreate,
    BotRevise,
    BotView,
    BundleResolve,
    BundleResult,
    BundleView,
    CanonicalReceipt,
    ConfigurationReceipt,
    DeploymentPolicyReceipt,
    DeploymentPolicyView,
    EffectivePermission,
    EffectiveSettings,
    GrantCatalog,
    GrantPage,
    GrantReceipt,
    GrantRevokeConfirmed,
    GrantSetConfirmed,
    LegacyPlan,
    LegacyPreview,
    OperationReceipt,
    PasskeyLabelCommand,
    PasskeyMutationReceipt,
    PolicyInitializeConfirmed,
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
    WorkflowTemplates,
)
from journeon.health import schema_and_database
from journeon.instruction_config import RootObservation
from journeon.job_contracts import (
    AttentionList,
    JobCancel,
    JobView,
    ReplayPage,
    ReplayQuery,
    TaskDispatch,
    TaskEvidence,
)
from journeon.migrate import configuration
from journeon.models import Base
from journeon.passkey_api import PasskeyAuthenticated, PasskeyBegin, PasskeyChallenge, PasskeyFinish
from journeon.restore_contracts import RestorePlan, RestorePreview


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


# Production instruction services retain their own scoped authorization contract.

INSTRUCTION_ROUTES: dict[str, tuple[str, type[BaseModel], type[BaseModel], str | None]] = {
    "inspectInstructionRoot": (
        "project.root.inspect.v1",
        instruction_dto.RootInspect,
        RootObservation,
        None,
    ),
    "prepareInstructionEffect": (
        "instruction.protected.prepare.v1",
        instruction_dto.ProtectedPrepare,
        instruction_dto.ProtectedIdentity,
        None,
    ),
    "previewInstructionEffect": (
        "instruction.protected.preview.v1",
        instruction_dto.ProtectedIdentity,
        instruction_dto.OfficialPreview,
        None,
    ),
    "confirmInstructionEffect": (
        "instruction.protected.confirm.v1",
        instruction_dto.ExactConfirmation,
        instruction_dto.ProtectedEffectResult,
        None,
    ),
    "cancelInstructionEffect": (
        "instruction.protected.cancel.v1",
        instruction_dto.ProtectedIdentity,
        instruction_dto.ProtectedState,
        None,
    ),
    "bindProjectInstructions": (
        "project.instructions.bind.v1",
        instruction_dto.InstructionBind,
        instruction_dto.InstructionReceipt,
        "bind",
    ),
    "proposeProjectInstructions": (
        "project.instructions.propose.v1",
        instruction_dto.InstructionPropose,
        instruction_dto.CandidateView,
        "propose",
    ),
    "previewProjectInstructions": (
        "project.instructions.preview.v1",
        instruction_dto.CandidateReference,
        instruction_dto.CandidateView,
        "read",
    ),
    "evaluateProjectInstructions": (
        "project.instructions.evaluate.v1",
        instruction_dto.CandidateReference,
        instruction_dto.EvidenceIdentity,
        "evaluate",
    ),
    "reviewProjectInstructions": (
        "project.instructions.review.v1",
        instruction_dto.InstructionReview,
        instruction_dto.EvidenceIdentity,
        "review",
    ),
    "acceptProjectInstructions": (
        "project.instructions.accept.v1",
        instruction_dto.InstructionAccept,
        instruction_dto.InstructionReceipt,
        "accept",
    ),
    "restoreProjectInstructions": (
        "project.instructions.restore.v1",
        instruction_dto.InstructionRestore,
        instruction_dto.CandidateView,
        "propose",
    ),
    "projectInstructionProjection": (
        "project.instructions.projection.v1",
        instruction_dto.ProjectionCommand,
        instruction_dto.ProjectionView,
        "projection",
    ),
    "prepareInstructionPolicy": (
        "project.instructions.policy.prepare.v1",
        instruction_dto.PolicyConfigure,
        instruction_dto.ProtectedIdentity,
        None,
    ),
    "verifyInstalledRelease": (
        "release.evidence.verify.v1",
        instruction_dto.ReleaseVerify,
        instruction_dto.EvidenceIdentity,
        None,
    ),
}
INSTRUCTION_ROUTES.update(
    {
        "inspectInstructionRecovery": (
            "project.instructions.recovery.inspect.v1",
            instruction_dto.RecoveryInspect,
            instruction_dto.RecoveryTarget,
            "accept",
        ),
        "previewInstructionBinding": (
            "project.instructions.binding.preview.v1",
            instruction_dto.BindingPreview,
            instruction_dto.BindingImpact,
            "bind",
        ),
        "readInstructionHistory": (
            "project.instructions.history.v1",
            instruction_dto.HistoryRead,
            instruction_dto.HistoryView,
            "read",
        ),
        "readInstructionDocument": (
            "project.instructions.document.v1",
            instruction_dto.DocumentRead,
            instruction_dto.Document,
            "read",
        ),
    }
)
for operation_id, (name, input_model, result_model, action) in INSTRUCTION_ROUTES.items():
    permissions = ("project.instruction." + action,) if action else ()
    checks = [grant_check(permission, "project_id", owner=False) for permission in permissions]
    if action in {"bind", "accept", "propose", "projection", "review", "evaluate"}:
        checks.append(grant_check("project.instruction.read", "project_id", owner=False))
    if action in {"bind", "accept", "propose"} and operation_id not in {
        "previewInstructionBinding",
        "inspectInstructionRecovery",
    }:
        checks.append(
            grant_check(
                "project.instruction.receipt.read",
                "project_id",
                "canonical publication response",
                owner=False,
            )
        )
        checks.append(
            grant_check(
                "project.instruction.accept",
                "project_id",
                "publication or qualifying automatic candidate",
                owner=False,
            )
        )
    if operation_id == "proposeProjectInstructions":
        checks.append(
            grant_check(
                "project.instruction.evaluate",
                "project_id",
                "qualifying automatic candidate",
                owner=False,
            )
        )
    if action == "projection":
        checks.append(
            grant_check(
                "project.instruction.receipt.read",
                "project_id",
                "materialize or reconcile its journal",
                owner=False,
            )
        )
    if operation_id in {
        "prepareInstructionEffect",
        "previewInstructionEffect",
        "confirmInstructionEffect",
        "cancelInstructionEffect",
    }:
        for capability in ("read", "accept"):
            checks.append(
                grant_check(
                    "project.instruction." + capability,
                    "trusted instruction request scope.project_id",
                    "Project instruction acceptance or recovery variant",
                    owner=False,
                )
            )
    if operation_id == "confirmInstructionEffect":
        for capability in ("read", "receipt.read"):
            checks.append(
                grant_check(
                    "project.instruction." + capability,
                    "effect.project_id",
                    "Project policy, acceptance or recovery canonical receipt",
                    owner=False,
                )
            )
    if operation_id in {
        "inspectInstructionRecovery",
        "prepareInstructionEffect",
        "previewInstructionEffect",
        "confirmInstructionEffect",
        "cancelInstructionEffect",
    }:
        checks.append(
            grant_check(
                "project.instruction.projection",
                "trusted publication Project scope",
                "projection recovery variant",
                owner=False,
            )
        )
    authorization = {
        "owner_only": action is None or operation_id == "inspectInstructionRecovery",
        "authentication": (
            "current session and Principal epoch; protected operations additio"
            "nally require official audience and recent strong authentication"
        ),
        "grant_checks": checks,
        "semantics": (
            "exact Project grants and admitted roots; no authority follows from metadata"
        ),
    }
    CONFIGURATION_AUTHORIZATION[name] = authorization
    permissions = tuple(dict.fromkeys(check["capability"] for check in checks))
    COMMANDS[name] = CommandDefinition(
        name=name,
        owner="project_instructions",
        input_model=input_model,
        result_model=result_model,
        permissions=permissions,
        risk="SCOPED_INSTRUCTION_OPERATION",
        external_effects=("CONFIGURED_RELEASE_BACKUP",)
        if operation_id == "verifyInstalledRelease"
        else ("ADMITTED_LOCAL_FILESYSTEM",)
        if operation_id
        in {
            "bindProjectInstructions",
            "proposeProjectInstructions",
            "acceptProjectInstructions",
            "projectInstructionProjection",
            "confirmInstructionEffect",
        }
        else (),
        reversibility="Versioned candidates and scoped journal reconciliation",
        dry_run=operation_id
        in {
            "inspectInstructionRoot",
            "previewProjectInstructions",
            "previewInstructionBinding",
            "readInstructionHistory",
            "readInstructionDocument",
            "inspectInstructionRecovery",
        },
        idempotent="idempotency_key" in input_model.model_fields,
        verification="Exact current operands; canonical commit only after observed bytes agree",
    )
CONFIGURATION_AUTHORIZATION["project.instructions.read.v1"] = {
    "owner_only": False,
    "authentication": "current session and Principal epoch",
    "grant_checks": [grant_check("project.instruction.read", "project_id", owner=False)],
    "semantics": "current canonical tree and admitted root; selected fragments only",
}
QUERIES["project.instructions.read.v1"] = {
    "owner": "project_instructions",
    "permissions": ("project.instruction.read",),
    "result_model": instruction_dto.InstructionView,
}
MODULES["project_instructions"] = {
    "core": True,
    "dashboards": (),
    "events_published": (
        "project.instructions.projection.committed",
        "project.instructions.projection.abandoned",
        "project.instructions.bind.abandoned",
        "project.instructions.accept.abandoned",
        "project.instructions.bind.committed",
        "project.instructions.accept.committed",
        "project.instructions.policy.configure.committed",
        "project.root.admit.committed",
        "project.root.revoke.committed",
        "instruction.candidate.register.committed",
        "instruction.release.install.committed",
    ),
    "events_consumed": (),
    "api_prefixes": (
        "/api/v1/project-roots",
        "/api/v1/protected-operations",
        "/api/v1/projects",
        "/api/v1/releases",
    ),
    "tables": (
        "instruction_request_scopes",
        "instruction_roots",
        "project_instruction_bindings",
        "project_instruction_revisions",
        "project_instruction_policies",
        "instruction_candidates",
        "instruction_evidence",
        "instruction_publications",
        "instruction_installations",
        "installed_release_evidence",
        "instruction_projections",
    ),
    "backup_class": "R0",
    "health": "schema_and_database",
    "permissions": tuple(
        sorted(
            {
                permission
                for command in COMMANDS.values()
                if command.owner == "project_instructions"
                for permission in command.permissions
            }
        )
    ),
    "migration": "0009_instruction_scope",
    "settings": (),
    "environment_migrations": (),
}
for module in ("projects", "identity", "operations", "instructions"):
    MODULES[module]["migration"] = "0009_instruction_scope"


MODULES["jobs"] = {
    "core": True,
    "api_prefixes": ("/api/v1/jobs", "/api/v1/events"),
    "dashboards": (),
    "events_published": ("job.admitted", "job.changed", "attention.raised", "attention.resolved"),
    "events_consumed": (),
    "tables": ("jobs", "attention"),
    "backup_class": "R0",
    "health": "schema_and_database",
    "permissions": (
        "project.instruction.read",
        "project.instruction.accept",
        "project.instruction.restore",
        "lifecycle.restore",
    ),
    "migration": "0010_work_execution",
    "settings": (),
    "environment_migrations": (),
}
MODULES["lifecycle"] = {
    "core": True,
    "api_prefixes": ("/api/v1/lifecycle",),
    "dashboards": (),
    "events_published": ("lifecycle.history.restored",),
    "events_consumed": (),
    "tables": ("store_identity", "restore_request_scopes"),
    "backup_class": "R0",
    "health": "schema_and_database",
    "permissions": ("lifecycle.restore", "project.instruction.restore", "project.instruction.read"),
    "migration": "0010_work_execution",
    "settings": (),
    "environment_migrations": (),
}
for execution_module in MODULES.values():
    if set(execution_module["tables"]) & {
        "operation_receipts",
        "outbox_events",
        "protected_requests",
    }:
        execution_module["migration"] = "0010_work_execution"

JOB_ROUTES: dict[str, tuple[str, type[BaseModel] | None, type[BaseModel], tuple[str, ...]]] = {
    "dispatchTask": (
        "task.dispatch.v1",
        TaskDispatch,
        JobView,
        (
            "task.dispatch",
            "task.read",
            "job.read",
            "job.cancel",
            "job.receipt.read",
            "attempt.prepare",
            "attempt.read",
            "attempt.receipt.read",
            "execution.admit",
            "execution.start",
            "execution.read",
            "execution.stop",
            "execution.drain",
            "execution.complete",
            "execution.receipt.read",
            "project.read",
            "project.verification.read",
            "project.instruction.read",
        ),
    ),
    "readTaskEvidence": (
        "task.evidence.read.v1",
        None,
        TaskEvidence,
        (
            "job.read",
            "execution.read",
            "project.read",
            "task.read",
            "attempt.read",
            "project.instruction.read",
            "project.verification.read",
        ),
    ),
    "readJob": ("job.read.v1", None, JobView, ("project.instruction.read", "job.read")),
    "cancelJob": (
        "job.cancel.v1",
        JobCancel,
        JobView,
        ("project.instruction.accept", "job.cancel"),
    ),
    "replayEvents": ("event.replay.v1", ReplayQuery, ReplayPage, ("project.instruction.read",)),
    "readJobAttention": (
        "job.attention.read.v1",
        None,
        AttentionList,
        ("project.instruction.read",),
    ),
    "previewRestore": (
        "lifecycle.restore.preview.v1",
        RestorePreview,
        RestorePlan,
        ("lifecycle.restore", "project.instruction.restore", "project.instruction.read"),
    ),
}
for operation, (name, job_input, job_result, permissions) in JOB_ROUTES.items():
    CONFIGURATION_AUTHORIZATION[name] = {
        "owner_only": operation == "previewRestore",
        "grant_checks": [
            grant_check(permission, "current target scope", owner=False)
            for permission in permissions
        ],
        "semantics": "Current service-owned target authorization precedes disclosure and effects",
    }
    if job_input is None:
        QUERIES[name] = {"owner": "jobs", "permissions": permissions, "result_model": job_result}
    else:
        COMMANDS[name] = CommandDefinition(
            name=name,
            owner="lifecycle"
            if operation == "previewRestore"
            else "work"
            if operation == "dispatchTask"
            else "jobs",
            input_model=job_input,
            result_model=job_result,
            permissions=permissions,
            risk="LOCAL_CANONICAL_CONTROL"
            if operation in {"cancelJob", "dispatchTask"}
            else "AUTHORIZED_QUERY",
            external_effects=(),
            reversibility="Prior canonical evidence is retained",
            dry_run=operation not in {"cancelJob", "dispatchTask"},
            idempotent=True,
            verification="Current scope, revision and durable owning records",
        )


for operation in ("readJob", "cancelJob", "readJobAttention", "replayEvents"):
    name = JOB_ROUTES[operation][0]
    authorization = CONFIGURATION_AUTHORIZATION[name]
    authorization["semantics"] = (
        "Authorize each typed target before decoding; instruction Jobs use instruction grants "
        "and Task Jobs use Task, Attempt and verification grants"
    )
    authorization["grant_checks"] = [
        grant_check(permission, "job.project_id", "instruction origin", owner=False)
        for permission in JOB_ROUTES[operation][3]
        if permission.startswith("project.instruction.")
    ] + [
        grant_check(permission, "job.project_id", "Task origin", owner=False)
        for permission in (
            ("job.cancel", "task.read")
            if operation == "cancelJob"
            else (
                "job.read",
                "task.read",
                "attempt.read",
                "project.instruction.read",
                "project.verification.read",
            )
        )
    ]
    permissions = tuple(
        dict.fromkeys(check["capability"] for check in authorization["grant_checks"])
    )
    if name in COMMANDS:
        COMMANDS[name] = replace(COMMANDS[name], permissions=permissions)
    else:
        QUERIES[name]["permissions"] = permissions
    prior = JOB_ROUTES[operation]
    JOB_ROUTES[operation] = (prior[0], prior[1], prior[2], permissions)
MODULES["jobs"]["tables"] += ("task_verification_jobs", "task_verification_evidence")
MODULES["jobs"]["migration"] = "0013_task_dispatch"
MODULES["jobs"]["permissions"] = tuple(
    dict.fromkeys(
        (
            *MODULES["jobs"]["permissions"],
            *(permission for item in JOB_ROUTES.values() for permission in item[3]),
        )
    )
)
MODULES["work"]["permissions"] = tuple(
    dict.fromkeys((*MODULES["work"]["permissions"], *COMMANDS["task.dispatch.v1"].permissions))
)


for admission_action, admission_model in (
    ("revise", TaskRevise),
    ("assign", TaskAssign),
    ("admit", TaskAdmission),
):
    admission_name = f"task.{admission_action}.v1"
    COMMANDS[admission_name] = CommandDefinition(
        name=admission_name,
        owner="work",
        input_model=admission_model,
        result_model=TaskReceipt,
        permissions=(f"task.{admission_action}", "task.read", "task.receipt.read"),
        risk="LOCAL_CANONICAL_MUTATION",
        external_effects=(),
        reversibility="A subsequent authorized change retains the original history",
        dry_run=False,
        idempotent=True,
        verification="Current policy, assignment and Task revisions; no process execution",
    )

COMMANDS["attempt.prepare.v1"] = CommandDefinition(
    name="attempt.prepare.v1",
    owner="work",
    input_model=AttemptPrepare,
    result_model=AttemptReceipt,
    permissions=("attempt.prepare", "attempt.read", "attempt.receipt.read"),
    risk="LOCAL_WORKSPACE_MUTATION",
    external_effects=("Attempt workspace and snapshot storage",),
    reversibility="Retain preparation evidence; no automatic workspace removal",
    dry_run=False,
    idempotent=True,
    verification="Current Task inputs and immutable produced workspace snapshot",
)
CONFIGURATION_AUTHORIZATION["attempt.prepare.v1"] = {
    "owner_only": False,
    "grant_checks": [
        grant_check(capability, "project_id", owner=False)
        for capability in (
            "attempt.prepare",
            "attempt.read",
            "attempt.receipt.read",
            "task.read",
            "execution.admit",
            "project.verification.read",
        )
    ]
    + [grant_check("project.instruction.read", "project_id", owner=False)],
    "semantics": (
        "Current original Principal, Task admission and exact accepted instruction inputs; "
        "preparation grants no process authority"
    ),
}
QUERIES["attempt.read.v1"] = {
    "owner": "work",
    "permissions": ("attempt.read", "task.read"),
    "result_model": AttemptView,
}
CONFIGURATION_AUTHORIZATION["attempt.read.v1"] = {
    "owner_only": False,
    "grant_checks": [
        grant_check(capability, "attempt.project_id", owner=False)
        for capability in ("attempt.read", "task.read")
    ],
    "semantics": (
        "Current originating Principal and Project grants before stored Attempt disclosure"
    ),
}
MODULES["work"]["permissions"] += ("attempt.prepare", "attempt.read", "attempt.receipt.read")
MODULES["work"]["tables"] += (
    "attempts",
    "attempt_manifests",
    "attempt_effects",
    "workspace_leases",
)
MODULES["work"]["api_prefixes"] += ("/api/v1/attempts",)
MODULES["work"]["events_published"] += (
    "attempt.prepared",
    "execution.admitted",
    "execution.stop_requested",
)
MODULES["work"]["tables"] += ("executions", "execution_manifests", "execution_effects")
MODULES["work"]["permissions"] += (
    "execution.start",
    "execution.read",
    "execution.stop",
    "execution.drain",
    "execution.complete",
    "execution.receipt.read",
)

MODULES["work"]["permissions"] += ("task.revise", "task.assign", "task.admit", "execution.admit")
MODULES["work"]["tables"] += ("task_revisions",)
MODULES["work"]["events_published"] += ("task.revised", "task.assigned", "task.admission.checked")
MODULES["work"]["migration"] = "0013_task_dispatch"
MODULES["projects"]["tables"] += ("verification_policy_revisions",)
MODULES["projects"]["permissions"] += (
    "project.verification.configure",
    "project.verification.read",
)
MODULES["projects"]["events_published"] += ("project.verification.configured",)
MODULES["projects"]["migration"] = "0011_task_admission"
COMMANDS["project.verification.configure.v1"] = CommandDefinition(
    name="project.verification.configure.v1",
    owner="projects",
    input_model=VerificationPolicyConfigure,
    result_model=VerificationPolicyReceipt,
    permissions=(
        "project.verification.configure",
        "project.verification.read",
        "project.receipt.read",
    ),
    risk="LOCAL_CANONICAL_MUTATION",
    external_effects=(),
    reversibility="A subsequent policy revision retains previous proof definitions",
    dry_run=False,
    idempotent=True,
    verification="Immutable proof definitions confer no execution authority",
)
MODULES["projects"]["tables"] += ("review_policy_revisions",)
MODULES["projects"]["permissions"] += (
    "project.review.configure",
    "project.review.read",
)
MODULES["projects"]["events_published"] += ("project.review.configured",)
MODULES["projects"]["migration"] = "0014_review_completion"
COMMANDS["project.review.configure.v1"] = CommandDefinition(
    name="project.review.configure.v1",
    owner="projects",
    input_model=ReviewPolicyConfigure,
    result_model=ReviewPolicyReceipt,
    permissions=(
        "project.review.configure",
        "project.review.read",
        "project.receipt.read",
    ),
    risk="LOCAL_CANONICAL_MUTATION",
    external_effects=(),
    reversibility="A subsequent policy revision retains previous review rules",
    dry_run=False,
    idempotent=True,
    verification="Versioned review rules confer no reviewer execution authority",
)
QUERIES["project.review.read.v1"] = {
    "owner": "projects",
    "permissions": ("project.review.read",),
    "result_model": ReviewPolicy,
}

MODULES["projects"]["permissions"] += ("project.read",)
QUERIES["project.read.v1"] = {
    "owner": "projects",
    "permissions": ("project.read",),
    "result_model": ProjectView,
}
QUERIES["project.verification.read.v1"] = {
    "owner": "projects",
    "permissions": ("project.verification.read",),
    "result_model": VerificationPolicy,
}

MODULES["work"]["tables"] += ("review_targets",)
MODULES["work"]["api_prefixes"] += ("/api/v1/review-targets",)
MODULES["work"]["permissions"] += ("task.review.select", "task.review.read", "task.complete")
MODULES["work"]["events_published"] += ("task.review.target.selected", "task.completed")
MODULES["work"]["migration"] = "0014_review_completion"
REVIEW_TARGET_READ_PERMISSIONS = (
    "task.review.read",
    "task.read",
    "project.review.read",
    "attempt.read",
    "project.instruction.read",
)
for name, input_model, result_model, permissions in (
    (
        "task.review.select.v1",
        ReviewTargetSelect,
        ReviewTargetReceipt,
        (
            "task.review.select",
            "task.receipt.read",
            "project.verification.read",
            "execution.admit",
            *REVIEW_TARGET_READ_PERMISSIONS,
        ),
    ),
    (
        "task.complete.v1",
        TaskComplete,
        TaskReceipt,
        (
            "task.complete",
            "task.receipt.read",
            "project.verification.read",
            "execution.admit",
            "execution.read",
            "execution.receipt.read",
            "project.read",
            "job.read",
            *REVIEW_TARGET_READ_PERMISSIONS,
        ),
    ),
):
    COMMANDS[name] = CommandDefinition(
        name=name,
        owner="work",
        input_model=input_model,
        result_model=result_model,
        permissions=permissions,
        risk="LOCAL_CANONICAL_MUTATION",
        external_effects=(),
        reversibility="Immutable candidate and completion receipts retain the selected snapshot",
        dry_run=False,
        idempotent=True,
        verification="Current exact candidate, policy and service-produced evidence bindings",
    )
    checks = [
        grant_check(
            capability,
            "task.project_id",
            "always"
            if capability in ("task.complete", "task.read", "task.receipt.read")
            or (
                name == "task.review.select.v1"
                and capability not in ("project.verification.read", "execution.admit")
            )
            else "new target or completion; historical receipt replay retains its own grants",
            owner=False,
        )
        for capability in permissions
    ]
    checks.extend(
        [
            grant_check(
                "bot.read", "receiver.bot_id", "new target or completion with Bot assignment"
            ),
            grant_check(
                "bot.use", "receiver.bot_id", "new target or completion with Bot assignment"
            ),
            grant_check(
                "profile.read",
                "receiver.profile_id",
                "new target or completion with Bot assignment",
            ),
            grant_check(
                "profile.use", "receiver.profile_id", "new target or completion with Bot assignment"
            ),
            grant_check(
                "{policy.required_capability}",
                "task.project_id",
                "new target or completion with configured requirement",
                owner=False,
            ),
        ]
    )
    CONFIGURATION_AUTHORIZATION[name] = {
        "owner_only": False,
        "grant_checks": checks,
        "semantics": (
            "Current target and admission authority; "
            "historical receipts retain their original candidate"
        ),
    }
    COMMANDS[name] = replace(
        COMMANDS[name],
        permissions=tuple(
            dict.fromkeys(check["capability"] for check in checks if "{" not in check["capability"])
        ),
    )
    MODULES["work"]["permissions"] = tuple(
        dict.fromkeys((*MODULES["work"]["permissions"], *COMMANDS[name].permissions))
    )
QUERIES["task.review.read.v1"] = {
    "owner": "work",
    "permissions": REVIEW_TARGET_READ_PERMISSIONS,
    "result_model": ReviewTarget,
}
CONFIGURATION_AUTHORIZATION["task.review.read.v1"] = {
    "owner_only": False,
    "grant_checks": [
        grant_check(capability, "target.project_id", owner=False)
        for capability in REVIEW_TARGET_READ_PERMISSIONS
    ],
    "semantics": "Target and Attempt belong to the initiating Principal and current admitted root",
}

QUERIES["task.workflows.read.v1"] = {
    "owner": "work",
    "permissions": ("task.read",),
    "result_model": WorkflowTemplates,
}

for action in ("revise", "assign", "admit"):
    name = f"task.{action}.v1"
    checks = [
        grant_check(capability, "task.project_id", owner=False)
        for capability in COMMANDS[name].permissions
    ]
    checks.append(grant_check("project.verification.read", "task.project_id", owner=False))
    if action in ("assign", "admit"):
        checks.extend(
            [
                grant_check(
                    "execution.admit", "task.project_id", "admission or Bot assignment", owner=False
                ),
                grant_check("bot.read", "receiver.bot_id", "Bot assignment or admission"),
                grant_check("bot.use", "receiver.bot_id", "Bot assignment or admission"),
                grant_check("profile.read", "receiver.profile_id", "Bot assignment or admission"),
                grant_check("profile.use", "receiver.profile_id", "Bot assignment or admission"),
                grant_check(
                    "{policy.required_capability}",
                    "task.project_id",
                    "configured policy requirement",
                    owner=False,
                ),
            ]
        )
    CONFIGURATION_AUTHORIZATION[name] = {
        "owner_only": False,
        "grant_checks": checks,
        "semantics": "Current Task preparation authority; no permission to execute a later effect",
    }
    COMMANDS[name] = replace(
        COMMANDS[name],
        permissions=tuple(
            dict.fromkeys(check["capability"] for check in checks if "{" not in check["capability"])
        ),
    )
    MODULES["work"]["permissions"] = tuple(
        dict.fromkeys((*MODULES["work"]["permissions"], *COMMANDS[name].permissions))
    )


ADMINISTRATION_ROUTES: dict[str, tuple[str, str, type[BaseModel] | None, type[BaseModel]]] = {
    "getGrantCatalog": ("permission.catalog.read.v1", "permissions", None, GrantCatalog),
    "listGrants": ("permission.grants.read.v1", "permissions", None, GrantPage),
    "getDeploymentPolicy": ("egress.policy.read.v1", "egress", None, DeploymentPolicyView),
    "setGrant": ("permission.grant.set.v1", "permissions", GrantSetConfirmed, GrantReceipt),
    "revokeGrant": (
        "permission.grant.revoke.v1",
        "permissions",
        GrantRevokeConfirmed,
        GrantReceipt,
    ),
    "initializeDeploymentPolicy": (
        "egress.policy.initialize.v1",
        "egress",
        PolicyInitializeConfirmed,
        DeploymentPolicyReceipt,
    ),
}
for (
    administration_name,
    administration_owner,
    administration_input,
    administration_result,
) in ADMINISTRATION_ROUTES.values():
    CONFIGURATION_AUTHORIZATION[administration_name] = {
        "owner_only": True,
        "grant_checks": [],
        "semantics": (
            "Current Owner administration; mutations require official strong "
            "exact-effect confirmation; no ordinary-resource grant bypass"
        ),
    }
    if administration_input is None:
        QUERIES[administration_name] = {
            "owner": administration_owner,
            "permissions": (),
            "result_model": administration_result,
        }
    else:
        COMMANDS[administration_name] = CommandDefinition(
            name=administration_name,
            owner=administration_owner,
            input_model=administration_input,
            result_model=administration_result,
            permissions=(),
            risk="SECURITY_ADMINISTRATION",
            external_effects=(),
            reversibility="A separate authorized command retains the accepted history",
            dry_run=False,
            idempotent=True,
            verification=(
                "Current official exact-effect consent and atomic state, receipt and outbox"
            ),
        )
MODULES["permissions"]["api_prefixes"] = ("/api/v1/permissions",)
MODULES["permissions"]["events_published"] = ("permission.grant.set", "permission.grant.revoked")
MODULES["egress"]["api_prefixes"] = ("/api/v1/egress",)
MODULES["egress"]["events_published"] = ("egress.policy.initialized",)
for owner in ("permissions", "egress", "identity", "operations"):
    MODULES[owner]["migration"] = "0015_workspace_read_models"


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


INSTRUCTION_SURFACES = {
    "instructionConfirmationPage": {
        "path": "/instructions/confirmation/{request_id}",
        "authorization": (
            "Current Owner official session, strong authentication and "
            "exact stored request scopes; nonce issuance"
        ),
    },
    "instructionAuthenticationPage": {
        "path": "/instructions/authenticate",
        "authorization": (
            "Public trusted authentication controls; authentication and "
            "step-up require their existing API checks"
        ),
    },
    "instructionSurfaceScript": {
        "path": "/instructions/surface.js",
        "authorization": "Public trusted static script",
    },
    "instructionSurfaceStyles": {
        "path": "/instructions/surface.css",
        "authorization": "Public trusted static stylesheet",
    },
}


def execution_service_manifest() -> dict[str, Any]:
    from inspect import signature

    from journeon.contracts import ExecutionReceipt, ExecutionStart, ExecutionStop
    from journeon.executions import ExecutionService

    operations = []
    for name, input_model in (("start", ExecutionStart), ("stop", ExecutionStop)):
        method = getattr(ExecutionService, name)
        binding = signature(method)
        if (
            binding.parameters["command"].annotation is not input_model
            or binding.return_annotation is not ExecutionReceipt
        ):
            raise ValueError("Execution service operation contract differs from its owner")
        operations.append(
            {
                "command": "execution." + name + ".v1",
                "method": method.__qualname__,
                "input_model": input_model.__name__,
                "result_model": "ExecutionReceipt",
                "permissions": ["execution." + name, "execution.read", "execution.receipt.read"],
                "origin": "DIRECT_VERIFICATION",
                "transport": "IN_PROCESS",
            }
        )
    return {
        "owner": "work",
        "service": "journeon.executions.ExecutionService",
        "operations": operations,
        "doctor": "ExecutionService.doctor",
        "reconciliation": "ExecutionService.reconcile",
    }


def registry_manifest(app: FastAPI) -> dict[str, Any]:
    "Validate actual service bindings before generating an inspectable manifest."
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
    bound_surfaces: set[str] = set()
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
        surface = metadata.get("x-journeon-surface")
        if surface:
            declaration = INSTRUCTION_SURFACES.get(surface)
            if (
                declaration is None
                or surface in bound_surfaces
                or route.path != declaration["path"]
                or route.operation_id != surface
                or route.methods != {"GET"}
                or route.original_route.include_in_schema
                or route.endpoint.__module__ != "journeon.instruction_surface"
                or metadata
                != {"x-journeon-surface": surface, "x-journeon-owner": "project_instructions"}
            ):
                raise ValueError("Instruction surface differs from its registered binding")
            bound_surfaces.add(surface)
            continue
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
    if bound_surfaces != set(INSTRUCTION_SURFACES):
        raise ValueError("Instruction surfaces require actual registered bindings")
    if bound_commands != set(COMMANDS) or bound_queries != set(QUERIES):
        raise ValueError("Registered commands and queries must have actual API bindings")
    if bound_authentication != set(AUTHENTICATION):
        raise ValueError("Registered authentication operations must have actual API bindings")
    return {
        "surfaces": [
            {"operation_id": name, "owner": "project_instructions", **definition}
            for name, definition in sorted(INSTRUCTION_SURFACES.items())
        ],
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
        "internal_services": [execution_service_manifest()],
    }
