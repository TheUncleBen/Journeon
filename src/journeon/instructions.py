# SPDX-License-Identifier: AGPL-3.0-only
"""Typed assets and deterministic literal-variable rendering."""

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from sqlalchemy.orm import Session, defer

from journeon.contracts import ComponentRef, DomainError, InstructionTemplate, VariableBinding
from journeon.models import InstructionAsset, InstructionBundle, InstructionRevision
from journeon.permissions import AuthenticatedContext

if TYPE_CHECKING:
    from sqlalchemy import Engine

    from journeon.contracts import BundleResolve, BundleResult, BundleView

PLACEHOLDER = re.compile(r"\{\{([a-zA-Z][a-zA-Z0-9_]*)\}\}")


def canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def validate_template(template: InstructionTemplate) -> None:
    names = PLACEHOLDER.findall(template.template)
    remainder = PLACEHOLDER.sub("", template.template)
    if (
        "{" in remainder
        or "}" in remainder
        or set(names) != set(template.required_variables)
        or len(set(template.required_variables)) != len(template.required_variables)
        or len(set(template.eval_ids)) != len(template.eval_ids)
        or not template.eval_ids
    ):
        raise DomainError("VALIDATION_FAILED", "Instruction template declarations are invalid")


def render(template: InstructionTemplate, variables: dict[str, str]) -> str:
    validate_template(template)
    if set(variables) != set(template.required_variables):
        raise DomainError("VALIDATION_FAILED", "Required instruction variables do not match")
    segments: list[dict[str, Any]] = []
    offset = 0
    for match in PLACEHOLDER.finditer(template.template):
        segments.append({"trust": "INSTRUCTION", "text": template.template[offset : match.start()]})
        value = variables[match.group(1)]
        segments.append(
            {
                "trust": "LOWER_TRUST_DATA",
                "name": match.group(1),
                "bytes": len(value.encode()),
                "text": value,
            }
        )
        offset = match.end()
    segments.append({"trust": "INSTRUCTION", "text": template.template[offset:]})
    return canonical(segments)


def write_asset(
    db: Session,
    actor: AuthenticatedContext,
    kind: str,
    owner_id: str,
    template: InstructionTemplate,
    reason: str,
    *,
    asset_id: str | None = None,
    expected_hash: str | None = None,
) -> ComponentRef:
    if kind not in {"profile", "bot"}:
        raise DomainError("PERMISSION_DENIED", "Protected assets require their owning service")
    validate_template(template)
    previous_hash = None
    asset: InstructionAsset | None
    if asset_id is None:
        asset = InstructionAsset(
            id=str(uuid4()),
            owner_kind=kind,
            owner_id=owner_id,
            purpose=kind.upper(),
            trust="CONFIGURATION",
            revision=1,
        )
        db.add(asset)
        db.flush()
    else:
        asset = db.get(InstructionAsset, asset_id)
        if asset is None or asset.owner_kind != kind or asset.owner_id != owner_id:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Instruction owner is unavailable")
        previous = db.get(InstructionRevision, (asset.id, asset.revision))
        if previous is None or previous.content_hash != expected_hash:
            raise DomainError("REVISION_CONFLICT", "Instruction revision changed")
        previous_hash = previous.content_hash
        asset.revision += 1
    value = template.model_dump(mode="json")
    content_hash = digest(value)
    db.add(
        InstructionRevision(
            asset_id=asset.id,
            revision=asset.revision,
            template=value,
            content_hash=content_hash,
            previous_hash=previous_hash,
            author=actor.principal_id,
            reason=reason,
            created_at=datetime.now(UTC).isoformat(),
        )
    )
    db.flush()
    return ComponentRef(asset_id=asset.id, revision=asset.revision, content_hash=content_hash)


def authorized_bundle(db: Session, actor: AuthenticatedContext, identity: str) -> InstructionBundle:
    from journeon.agents import authorize
    from journeon.permissions import require_grant

    authorize(db, actor, "instruction_bundle", identity, "read")
    row = db.get(InstructionBundle, identity, options=[defer(InstructionBundle.snapshot)])
    if row is None or row.principal_id != actor.principal_id:
        raise DomainError("NOT_FOUND", "Bundle is unavailable")
    authorize(db, actor, "profile", row.profile_id, "read")
    if row.bot_id is not None:
        authorize(db, actor, "bot", row.bot_id, "read")
    require_grant(db, actor, "project.instruction.read", project_id=row.project_id)
    if row.task_id is not None:
        require_grant(db, actor, "task.read", project_id=row.project_id)

    return row


def authorize_component(
    db: Session, actor: AuthenticatedContext, asset: InstructionAsset, command: "BundleResolve"
) -> None:
    from journeon.agents import authorize

    if asset.owner_kind == "profile":
        authorize(db, actor, "profile", asset.owner_id, "read")
    elif asset.owner_kind == "bot":
        authorize(db, actor, "bot", asset.owner_id, "read")
    elif asset.owner_kind == "task":
        if asset.owner_id != command.origin.task_id:
            raise DomainError("PERMISSION_DENIED", "Instruction scope is unavailable")
    elif asset.owner_kind in {"project", "skill"}:
        if asset.owner_id != command.project_id:
            raise DomainError("PERMISSION_DENIED", "Instruction scope is unavailable")
    elif (
        asset.owner_kind != "system"
        or asset.trust != "PROTECTED"
        or asset.purpose not in {"CORE", "NAVIGATION"}
    ):
        raise DomainError("PERMISSION_DENIED", "Instruction authority is unavailable")


def render_components(
    db: Session,
    assets: list[InstructionAsset],
    components: list[ComponentRef],
    bindings: list[VariableBinding],
) -> str:
    variables: dict[str, dict[str, str]] = {}
    for binding in bindings:
        if binding.asset_id not in {
            item.asset_id for item in components
        } or binding.name in variables.setdefault(binding.asset_id, {}):
            raise DomainError("VALIDATION_FAILED", "Instruction variable binding is invalid")
        variables[binding.asset_id][binding.name] = binding.value
    rendered = []
    for asset, ref in zip(assets, components, strict=True):
        revision = db.get(InstructionRevision, (ref.asset_id, ref.revision))
        if (
            revision is None
            or revision.content_hash != ref.content_hash
            or digest(revision.template) != ref.content_hash
        ):
            raise DomainError("REVISION_CONFLICT", "Instruction content changed")
        template = InstructionTemplate.model_validate(revision.template)
        rendered.append(
            {
                "purpose": asset.purpose,
                "trust": asset.trust,
                "asset": ref.model_dump(mode="json"),
                "segments": json.loads(render(template, variables.get(asset.id, {}))),
            }
        )
    rendering = canonical(rendered)
    return rendering


class InstructionService:
    def __init__(self, engine: "Engine") -> None:
        self.engine = engine

    def read(self, actor: AuthenticatedContext, identity: str) -> "BundleView":
        from journeon.agents import configuration_transaction
        from journeon.contracts import BundleView
        from journeon.database import require_compatible_schema

        with configuration_transaction(self.engine) as db:
            require_compatible_schema(db)
            row = authorized_bundle(db, actor, identity)
            return BundleView.model_validate(row.snapshot)

    def resolve(self, actor: AuthenticatedContext, command: "BundleResolve") -> "BundleResult":
        from journeon.agents import (
            authorize,
            bot_view,
            configuration_transaction,
            profile_view,
            record,
            retry,
        )
        from journeon.contracts import BundleResult, BundleView
        from journeon.database import require_compatible_schema
        from journeon.models import InstructionBundle, Project, Task
        from journeon.permissions import require_grant

        with configuration_transaction(self.engine) as db:
            require_compatible_schema(db)
            previous = retry(
                db,
                actor,
                "instruction.bundle.resolve.v1",
                command.idempotency_key,
                digest(command.model_dump(mode="json", exclude={"idempotency_key"})),
            )
            if previous is not None:
                old = authorized_bundle(db, actor, previous.target_id)
                accepted = BundleView.model_validate(old.snapshot)
                assets = []
                for ref in accepted.components:
                    asset = db.get(InstructionAsset, ref.asset_id)
                    if asset is None:
                        raise DomainError(
                            "DEPENDENCY_UNAVAILABLE", "Instruction revision is unavailable"
                        )
                    authorize_component(db, actor, asset, command)
                    assets.append(asset)
                rendering = render_components(db, assets, accepted.components, command.variables)
                if (
                    hashlib.sha256(rendering.encode()).hexdigest() != accepted.content_digest
                    or len(rendering.encode()) != accepted.byte_count
                ):
                    raise DomainError(
                        "DEPENDENCY_UNAVAILABLE", "Accepted instruction rendering requires repair"
                    )
                return BundleResult(
                    receipt=previous,
                    bundle=accepted,
                    rendering=rendering,
                )
            profile = profile_view(db, actor, command.profile_id)
            authorize(db, actor, "profile", command.profile_id, "use")
            require_grant(db, actor, "project.instruction.read", project_id=command.project_id)
            project = db.get(Project, command.project_id)
            if (
                project is None
                or project.revision != command.project_revision
                or profile.revision != command.profile_revision
            ):
                raise DomainError("REVISION_CONFLICT", "Bundle configuration changed")
            bot = None
            if command.origin.bot_id is not None:
                bot = bot_view(db, actor, command.origin.bot_id)
                authorize(db, actor, "bot", bot.bot_id, "use")
                if (
                    bot.profile_id != profile.profile_id
                    or bot.revision != command.origin.bot_revision
                ):
                    raise DomainError("REVISION_CONFLICT", "Bundle configuration changed")
            if command.origin.task_id is not None:
                require_grant(db, actor, "task.read", project_id=project.id)
                task = db.get(Task, command.origin.task_id)
                if (
                    task is None
                    or task.project_id != project.id
                    or task.initiating_principal_id != actor.principal_id
                ):
                    raise DomainError("PERMISSION_DENIED", "Task origin is unavailable")
            required = (
                ["CORE", "NAVIGATION", "PROFILE"]
                + (["BOT"] if bot else [])
                + ["PROJECT", "SKILLS"]
                + (["TASK", "WORKFLOW"] if command.origin.task_id else [])
            )
            order = [
                "CORE",
                "NAVIGATION",
                "PROFILE",
                "BOT",
                "PROJECT",
                "SKILLS",
                "TASK",
                "WORKFLOW",
            ]
            assets = []
            for ref in command.components:
                asset = db.get(InstructionAsset, ref.asset_id)
                if asset is None:
                    raise DomainError(
                        "DEPENDENCY_UNAVAILABLE", "Required instruction dependency is unavailable"
                    )
                authorize_component(db, actor, asset, command)
                if ref.revision != asset.revision:
                    raise DomainError("REVISION_CONFLICT", "Instruction revision changed")
                if asset.purpose == "PROFILE" and (ref.asset_id, ref.revision) != (
                    profile.baseline_asset_id,
                    profile.baseline_revision,
                ):
                    raise DomainError("PERMISSION_DENIED", "Profile baseline is mandatory")
                if asset.purpose == "BOT" and (
                    bot is None
                    or (ref.asset_id, ref.revision)
                    != (bot.additive_asset_id, bot.additive_revision)
                ):
                    raise DomainError("PERMISSION_DENIED", "Bot additive instruction is mandatory")
                assets.append(asset)
            purposes = [asset.purpose for asset in assets]
            if purposes != required or purposes != sorted(purposes, key=order.index):
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE", "Required instruction dependencies are unavailable"
                )
            rendering = render_components(db, assets, command.components, command.variables)
            identity = str(uuid4())
            view = BundleView(
                bundle_id=identity,
                initiating_principal_id=actor.principal_id,
                profile_id=profile.profile_id,
                profile_revision=profile.revision,
                project_id=project.id,
                project_revision=project.revision,
                origin=command.origin,
                components=command.components,
                content_digest=hashlib.sha256(rendering.encode()).hexdigest(),
                byte_count=len(rendering.encode()),
            )
            db.add(
                InstructionBundle(
                    id=identity,
                    principal_id=actor.principal_id,
                    profile_id=profile.profile_id,
                    bot_id=bot.bot_id if bot else None,
                    project_id=project.id,
                    task_id=command.origin.task_id,
                    snapshot=view.model_dump(mode="json"),
                )
            )
            db.flush()
            receipt = record(
                db,
                actor,
                command,
                "instruction.bundle.resolve.v1",
                "instruction_bundle",
                identity,
                1,
                project_id=project.id,
            )
            return BundleResult(receipt=receipt, bundle=view, rendering=rendering)
