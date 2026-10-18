# SPDX-License-Identifier: AGPL-3.0-only
"""Current authorized Profile, Bot and Team configuration transactions."""

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import Engine, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, defer

from journeon.contracts import (
    BotCreate,
    BotImpact,
    BotRevise,
    BotView,
    ConfigurationKind,
    ConfigurationReceipt,
    DomainError,
    EffectiveField,
    EffectivePermission,
    EffectiveSettings,
    LegacyPlan,
    LegacyPreview,
    PreferenceKey,
    Preferences,
    ProfileCreate,
    ProfileImpact,
    ProfileRevise,
    ProfileRevisionPreview,
    ProfileView,
    TeamCreate,
    TeamView,
)
from journeon.database import require_compatible_schema, transaction
from journeon.instructions import digest, validate_template, write_asset
from journeon.models import (
    AgentProfile,
    Bot,
    BotRevision,
    InstructionBundle,
    InstructionRevision,
    OutboxEvent,
    Principal,
    ProfileRevision,
    Receipt,
    Team,
)
from journeon.permissions import AuthenticatedContext, current_owner, require_grant
from journeon.sessions import current_session


@contextmanager
def configuration_transaction(engine: Engine) -> Iterator[Session]:
    try:
        with transaction(engine) as db:
            yield db
    except (ValidationError, json.JSONDecodeError, SQLAlchemyError):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Configuration state requires repair") from None


FIELDS: tuple[PreferenceKey, ...] = ("harness", "model", "provider", "host")


def authorize(
    db: Session, actor: AuthenticatedContext, kind: str, identity: str, action: str
) -> None:
    current_session(
        db,
        actor.authentication_ref,
        principal_id=actor.principal_id,
        principal_epoch=actor.principal_epoch,
    )
    principal = db.get(Principal, actor.principal_id, populate_existing=True)
    if (
        principal is not None
        and principal.role == "OWNER"
        and kind in {"profile", "bot", "team", "instruction_bundle"}
    ):
        current_owner(db, actor)
        return
    require_grant(db, actor, f"{kind}.{action}", resource_kind=kind, resource_id=identity)


def visible(db: Session, actor: AuthenticatedContext, kind: str, identity: str) -> bool:
    try:
        authorize(db, actor, kind, identity, "read")
        return True
    except DomainError as exc:
        if exc.code != "PERMISSION_DENIED":
            raise
        return False


def profile_view(db: Session, actor: AuthenticatedContext, identity: str) -> ProfileView:
    authorize(db, actor, "profile", identity, "read")
    row = db.get(AgentProfile, identity)
    if row is None:
        raise DomainError("NOT_FOUND", "Configuration is unavailable")
    revision = db.get(ProfileRevision, (identity, row.revision))
    if revision is None:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Configuration history is unavailable")
    if not isinstance(revision.snapshot, dict):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Configuration state requires repair")
    data = dict(revision.snapshot)
    baseline = db.get(
        InstructionRevision, (data.get("baseline_asset_id"), data.get("baseline_revision"))
    )
    if (
        baseline is None
        or baseline.content_hash != data.get("baseline_hash")
        or digest(baseline.template) != baseline.content_hash
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Instruction revision is unavailable")
    data["baseline"] = baseline.template
    return ProfileView.model_validate(data)


def bot_view(db: Session, actor: AuthenticatedContext, identity: str) -> BotView:
    authorize(db, actor, "bot", identity, "read")
    row = db.get(Bot, identity)
    if row is None:
        raise DomainError("NOT_FOUND", "Configuration is unavailable")
    if not isinstance(row.snapshot, dict):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Configuration state requires repair")
    data = dict(row.snapshot)
    additive = db.get(
        InstructionRevision, (data.get("additive_asset_id"), data.get("additive_revision"))
    )
    if (
        additive is None
        or additive.content_hash != data.get("additive_hash")
        or digest(additive.template) != additive.content_hash
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Instruction revision is unavailable")
    data["additive"] = additive.template
    view = BotView.model_validate(data)
    if (
        view.bot_id,
        view.profile_id,
        view.team_id,
        view.revision,
        view.memory_enabled,
        view.builtin_role,
        view.namespace_ref,
    ) != (
        row.id,
        row.profile_id,
        row.team_id,
        row.revision,
        row.memory_enabled,
        row.builtin_role,
        row.namespace_ref,
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Configuration state requires repair")
    return view


def authorized_configuration_receipt(
    db: Session, actor: AuthenticatedContext, row: Receipt
) -> ConfigurationReceipt:
    if row.principal_id != actor.principal_id:
        raise DomainError("NOT_FOUND", "Operation is unavailable")
    authorize(db, actor, row.target_kind, row.target_id, "receipt.read")
    authorize(db, actor, row.target_kind, row.target_id, "read")
    result = ConfigurationReceipt.model_validate(row.result)
    if (result.target_id, result.target_kind, result.command, result.operation_id) != (
        row.target_id,
        row.target_kind,
        row.command,
        row.id,
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored operation state requires repair")
    for identity in result.member_ids:
        authorize(db, actor, "bot", identity, "read")
    return result


def retry(
    db: Session, actor: AuthenticatedContext, command_name: str, key: str, payload_digest: str
) -> ConfigurationReceipt | None:
    row = db.scalar(
        select(Receipt)
        .options(defer(Receipt.result))
        .where(
            Receipt.principal_id == actor.principal_id,
            Receipt.command == command_name,
            Receipt.idempotency_key == key,
        )
    )
    if row is None:
        return None
    result = authorized_configuration_receipt(db, actor, row)
    if row.payload_hash != payload_digest:
        raise DomainError("IDEMPOTENCY_CONFLICT", "Operation identity has different input")
    return result


def record(
    db: Session,
    actor: AuthenticatedContext,
    command: Any,
    command_name: Any,
    kind: ConfigurationKind,
    identity: str,
    revision: int,
    *,
    members: list[str] | None = None,
    project_id: str | None = None,
) -> ConfigurationReceipt:
    result = ConfigurationReceipt(
        operation_id=str(uuid4()),
        command=command_name,
        committed_at=datetime.now(UTC).isoformat(),
        target_kind=kind,
        target_id=identity,
        revision=revision,
        member_ids=members or [],
    )
    owner = "instructions" if kind == "instruction_bundle" else "agents"
    db.add(
        Receipt(
            id=result.operation_id,
            principal_id=actor.principal_id,
            command=command_name,
            idempotency_key=command.idempotency_key,
            payload_hash=digest(command.model_dump(mode="json", exclude={"idempotency_key"})),
            project_id=project_id,
            owner=owner,
            target_kind=kind,
            target_id=identity,
            authentication_ref=actor.authentication_ref,
            result=result.model_dump(mode="json"),
        )
    )
    db.flush()
    db.add(
        OutboxEvent(
            event_id=str(uuid4()),
            operation_id=result.operation_id,
            event_type=command_name.removesuffix(".v1") + ".committed",
            schema_version=1,
            principal_id=actor.principal_id,
            project_id=project_id,
            owner=owner,
            target_kind=kind,
            target_id=identity,
            committed_at=result.committed_at,
            target_revision=revision,
            payload=result.model_dump(mode="json"),
        )
    )
    db.flush()
    authorize(db, actor, kind, identity, "read")
    authorize(db, actor, kind, identity, "receipt.read")
    return result


def impact(
    db: Session, actor: AuthenticatedContext, command: ProfileRevisionPreview
) -> ProfileImpact:
    authorize(db, actor, "profile", command.profile_id, "revise")
    profile = profile_view(db, actor, command.profile_id)
    if (profile.revision, profile.baseline_hash) != (
        command.expected_revision,
        command.expected_hash,
    ):
        raise DomainError("REVISION_CONFLICT", "Configuration changed; refresh the preview")
    validate_template(command.baseline)
    affected = []
    for identity in db.scalars(
        select(Bot.id).where(Bot.profile_id == profile.profile_id).order_by(Bot.id)
    ):
        if not visible(db, actor, "bot", identity):
            continue
        bot = bot_view(db, actor, identity)
        changed = [
            key
            for key in FIELDS
            if getattr(bot.overrides, key) is None
            and getattr(profile.preferences, key) != getattr(command.preferences, key)
        ]
        affected.append(
            BotImpact(
                bot_id=identity,
                revision=bot.revision,
                changed_inherited_fields=changed,
                baseline_changed=profile.baseline != command.baseline,
            )
        )
    payload = command.model_dump(
        mode="json", exclude={"preview_digest", "expected_affected_bots", "idempotency_key"}
    )
    value = digest(
        {
            "payload": payload,
            "profile_hash": profile.baseline_hash,
            "revision": profile.revision,
            "affected": [item.model_dump(mode="json") for item in affected],
        }
    )
    return ProfileImpact(digest=value, profile_revision=profile.revision, affected_bots=affected)


class AgentService:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def profile(self, actor: AuthenticatedContext, identity: str) -> ProfileView:
        with configuration_transaction(self.engine) as db:
            require_compatible_schema(db)
            return profile_view(db, actor, identity)

    def bot(self, actor: AuthenticatedContext, identity: str) -> BotView:
        with configuration_transaction(self.engine) as db:
            require_compatible_schema(db)
            return bot_view(db, actor, identity)

    def create_profile(
        self, actor: AuthenticatedContext, command: ProfileCreate
    ) -> ConfigurationReceipt:
        with configuration_transaction(self.engine) as db:
            require_compatible_schema(db)
            current_owner(db, actor)
            previous = retry(
                db,
                actor,
                "profile.create.v1",
                command.idempotency_key,
                digest(command.model_dump(mode="json", exclude={"idempotency_key"})),
            )
            if previous is not None:
                return previous
            identity = str(uuid4())
            asset = write_asset(db, actor, "profile", identity, command.baseline, "Profile created")
            view = ProfileView(
                profile_id=identity,
                revision=1,
                name=command.name,
                baseline_asset_id=asset.asset_id,
                baseline_revision=asset.revision,
                baseline_hash=asset.content_hash,
                baseline=command.baseline,
                preferences=command.preferences,
                eligibility=command.eligibility,
                visual_ref=command.visual_ref,
            )
            db.add(AgentProfile(id=identity, revision=1, name=command.name))
            db.flush()
            self._profile_history(db, actor, view, "Profile created")
            return record(db, actor, command, "profile.create.v1", "profile", identity, 1)

    def _profile_history(
        self, db: Session, actor: AuthenticatedContext, view: ProfileView, reason: str
    ) -> None:
        snapshot = view.model_dump(mode="json", exclude={"baseline", "additive"})
        db.add(
            ProfileRevision(
                profile_id=view.profile_id,
                revision=view.revision,
                snapshot=snapshot,
                author=actor.principal_id,
                reason=reason,
                content_hash=digest(snapshot),
                created_at=datetime.now(UTC).isoformat(),
            )
        )
        db.flush()

    def preview_profile(
        self, actor: AuthenticatedContext, command: ProfileRevisionPreview
    ) -> ProfileImpact:
        with configuration_transaction(self.engine) as db:
            require_compatible_schema(db)
            return impact(db, actor, command)

    def revise_profile(
        self, actor: AuthenticatedContext, command: ProfileRevise
    ) -> ConfigurationReceipt:
        with configuration_transaction(self.engine) as db:
            require_compatible_schema(db)
            authorize(db, actor, "profile", command.profile_id, "revise")
            previous = retry(
                db,
                actor,
                "profile.revise.v1",
                command.idempotency_key,
                digest(command.model_dump(mode="json", exclude={"idempotency_key"})),
            )
            if previous is not None:
                return previous
            preview = impact(db, actor, command)
            if (
                preview.digest != command.preview_digest
                or preview.affected_bots != command.expected_affected_bots
            ):
                raise DomainError("REVISION_CONFLICT", "Configuration changed; refresh the preview")
            old = profile_view(db, actor, command.profile_id)
            asset = write_asset(
                db,
                actor,
                "profile",
                old.profile_id,
                command.baseline,
                command.reason,
                asset_id=old.baseline_asset_id,
                expected_hash=command.expected_hash,
            )
            view = ProfileView(
                profile_id=old.profile_id,
                revision=old.revision + 1,
                name=command.name,
                baseline_asset_id=asset.asset_id,
                baseline_revision=asset.revision,
                baseline_hash=asset.content_hash,
                baseline=command.baseline,
                preferences=command.preferences,
                eligibility=command.eligibility,
                visual_ref=command.visual_ref,
            )
            row = db.get(AgentProfile, old.profile_id)
            assert row is not None
            row.revision, row.name = view.revision, view.name
            self._profile_history(db, actor, view, command.reason)
            authorize(db, actor, "profile", old.profile_id, "revise")
            return record(
                db, actor, command, "profile.revise.v1", "profile", old.profile_id, view.revision
            )

    def _new_bot(
        self,
        db: Session,
        actor: AuthenticatedContext,
        command: BotCreate,
        *,
        identity: str,
        team_id: str | None = None,
    ) -> BotView:
        profile = profile_view(db, actor, command.profile_id)
        authorize(db, actor, "profile", profile.profile_id, "use")
        if profile.revision != command.expected_profile_revision:
            raise DomainError("REVISION_CONFLICT", "Profile revision changed")
        asset = write_asset(db, actor, "bot", identity, command.additive, "Bot created")
        view = BotView(
            bot_id=identity,
            revision=1,
            name=command.name,
            profile_id=profile.profile_id,
            team_id=team_id,
            additive_asset_id=asset.asset_id,
            additive_revision=asset.revision,
            additive_hash=asset.content_hash,
            additive=command.additive,
            memory_enabled=command.memory_enabled,
            namespace_ref=f"bot:{identity}",
            overrides=command.overrides,
            visual_ref=profile.visual_ref,
            builtin_role=None,
        )
        db.add(
            Bot(
                id=identity,
                profile_id=profile.profile_id,
                team_id=team_id,
                revision=1,
                namespace_ref=view.namespace_ref,
                memory_enabled=view.memory_enabled,
                builtin_role=None,
                snapshot=view.model_dump(mode="json", exclude={"additive"}),
            )
        )
        db.flush()
        self._bot_history(db, actor, view, "Bot created")
        return view

    def _bot_history(
        self, db: Session, actor: AuthenticatedContext, view: BotView, reason: str
    ) -> None:
        snapshot = view.model_dump(mode="json", exclude={"baseline", "additive"})
        db.add(
            BotRevision(
                bot_id=view.bot_id,
                revision=view.revision,
                snapshot=snapshot,
                author=actor.principal_id,
                reason=reason,
                content_hash=digest(snapshot),
                created_at=datetime.now(UTC).isoformat(),
            )
        )
        db.flush()

    def create_bot(self, actor: AuthenticatedContext, command: BotCreate) -> ConfigurationReceipt:
        with configuration_transaction(self.engine) as db:
            require_compatible_schema(db)
            current_owner(db, actor)
            previous = retry(
                db,
                actor,
                "bot.create.v1",
                command.idempotency_key,
                digest(command.model_dump(mode="json", exclude={"idempotency_key"})),
            )
            if previous is not None:
                return previous
            view = self._new_bot(db, actor, command, identity=str(uuid4()))
            return record(db, actor, command, "bot.create.v1", "bot", view.bot_id, 1)

    def revise_bot(self, actor: AuthenticatedContext, command: BotRevise) -> ConfigurationReceipt:
        with configuration_transaction(self.engine) as db:
            require_compatible_schema(db)
            authorize(db, actor, "bot", command.bot_id, "revise")
            previous = retry(
                db,
                actor,
                "bot.revise.v1",
                command.idempotency_key,
                digest(command.model_dump(mode="json", exclude={"idempotency_key"})),
            )
            if previous is not None:
                return previous
            old = bot_view(db, actor, command.bot_id)
            if (old.revision, old.additive_hash) != (
                command.expected_revision,
                command.expected_hash,
            ):
                raise DomainError("REVISION_CONFLICT", "Bot revision changed")
            values = command.overrides.model_dump()
            for key in command.reset_to_inherit:
                values[key] = None
            asset = write_asset(
                db,
                actor,
                "bot",
                old.bot_id,
                command.additive,
                command.reason,
                asset_id=old.additive_asset_id,
                expected_hash=command.expected_hash,
            )
            view = old.model_copy(
                update={
                    "revision": old.revision + 1,
                    "name": command.name,
                    "additive": command.additive,
                    "additive_revision": asset.revision,
                    "additive_hash": asset.content_hash,
                    "overrides": Preferences.model_validate(values),
                    "visual_ref": command.visual_ref,
                }
            )
            row = db.get(Bot, old.bot_id)
            assert row is not None
            row.revision, row.snapshot = (
                view.revision,
                view.model_dump(mode="json", exclude={"additive"}),
            )
            self._bot_history(db, actor, view, command.reason)
            authorize(db, actor, "bot", old.bot_id, "revise")
            return record(db, actor, command, "bot.revise.v1", "bot", old.bot_id, view.revision)

    def create_team(self, actor: AuthenticatedContext, command: TeamCreate) -> ConfigurationReceipt:
        with configuration_transaction(self.engine) as db:
            require_compatible_schema(db)
            current_owner(db, actor)
            previous = retry(
                db,
                actor,
                "team.create.v1",
                command.idempotency_key,
                digest(command.model_dump(mode="json", exclude={"idempotency_key"})),
            )
            if previous is not None:
                return previous
            identity = str(uuid4())
            identities = {member.key: str(uuid4()) for member in command.members}
            db.add(
                Team(
                    id=identity,
                    name=command.name,
                    revision=1,
                    lead_bot_id=identities[command.lead_key],
                )
            )
            db.flush()
            for member in command.members:
                self._new_bot(
                    db, actor, member.bot, identity=identities[member.key], team_id=identity
                )
            return record(
                db,
                actor,
                command,
                "team.create.v1",
                "team",
                identity,
                1,
                members=list(identities.values()),
            )

    def team(self, actor: AuthenticatedContext, identity: str) -> TeamView:
        with configuration_transaction(self.engine) as db:
            require_compatible_schema(db)
            authorize(db, actor, "team", identity, "read")
            row = db.get(Team, identity)
            if row is None:
                raise DomainError("NOT_FOUND", "Configuration is unavailable")
            members = [
                bot_view(db, actor, member)
                for member in db.scalars(
                    select(Bot.id).where(Bot.team_id == identity).order_by(Bot.id)
                )
                if visible(db, actor, "bot", member)
            ]
            return TeamView(
                team_id=identity,
                revision=row.revision,
                name=row.name,
                authorized_members=members,
                authorized_lead_id=row.lead_bot_id
                if any(member.bot_id == row.lead_bot_id for member in members)
                else None,
            )

    def settings(self, actor: AuthenticatedContext, identity: str) -> EffectiveSettings:
        with configuration_transaction(self.engine) as db:
            require_compatible_schema(db)
            bot = bot_view(db, actor, identity)
            profile = profile_view(db, actor, bot.profile_id)
            fields = []
            for key in FIELDS:
                override = getattr(bot.overrides, key)
                fields.append(
                    EffectiveField(
                        field=key,
                        value=override
                        if override is not None
                        else getattr(profile.preferences, key),
                        source="BOT_OVERRIDE" if override is not None else "PROFILE",
                        source_revision=bot.revision if override is not None else profile.revision,
                    )
                )
            return EffectiveSettings(
                bot_id=identity,
                fields=fields,
                visual_ref=bot.visual_ref,
                eligibility=profile.eligibility,
            )

    def permission(
        self,
        actor: AuthenticatedContext,
        kind: ConfigurationKind,
        identity: str,
        action: Literal["read", "revise", "use", "receipt.read"],
    ) -> EffectivePermission:
        with configuration_transaction(self.engine) as db:
            require_compatible_schema(db)
            try:
                if kind in {"team", "instruction_bundle"} and action in {"revise", "use"}:
                    raise DomainError("PERMISSION_DENIED", "Configuration action is unavailable")
                authorize(db, actor, kind, identity, action)
                model = {
                    "profile": AgentProfile,
                    "bot": Bot,
                    "team": Team,
                    "instruction_bundle": InstructionBundle,
                }.get(kind)
                row = db.get(model, identity, options=[defer("*")]) if model is not None else None
                if not isinstance(row, (AgentProfile, Bot, Team, InstructionBundle)):
                    raise DomainError("PERMISSION_DENIED", "Configuration is unavailable")
                if isinstance(row, InstructionBundle):
                    from journeon.instructions import InstructionService

                    InstructionService(self.engine)._authorize_bundle(db, actor, row)
                return EffectivePermission(
                    allowed=True,
                    resource_kind=kind,
                    resource_id=identity,
                    action=action,
                    checked_revision=1 if isinstance(row, InstructionBundle) else row.revision,
                    reason="CURRENT_AUTHORITY",
                )
            except DomainError as exc:
                if exc.code != "PERMISSION_DENIED":
                    raise
                return EffectivePermission(
                    allowed=False,
                    resource_kind=kind,
                    resource_id=identity,
                    action=action,
                    checked_revision=None,
                    reason="UNAVAILABLE",
                )

    def legacy_preview(self, actor: AuthenticatedContext, command: LegacyPreview) -> LegacyPlan:
        with configuration_transaction(self.engine) as db:
            require_compatible_schema(db)
            current_session(
                db,
                actor.authentication_ref,
                principal_id=actor.principal_id,
                principal_epoch=actor.principal_epoch,
            )
            identities = [item.collection_id for item in command.mappings]
            if len(set(identities)) != len(identities) or set(identities) & set(command.unmapped):
                raise DomainError("VALIDATION_FAILED", "Legacy mapping is ambiguous")
            for item in command.mappings:
                # Inventory evidence is an exact capability binding, never caller authority.
                require_grant(
                    db,
                    actor,
                    f"legacy_collection.preview:{item.version}:{item.content_hash}:{item.provenance_ref}",
                    resource_kind="legacy_collection",
                    resource_id=item.collection_id,
                )
                bot = bot_view(db, actor, item.bot_id)
                authorize(db, actor, "bot", item.bot_id, "revise")
                if (
                    not item.memory_enabled
                    or not bot.memory_enabled
                    or bot.revision != item.expected_bot_revision
                ):
                    raise DomainError("REVISION_CONFLICT", "Legacy destination is unavailable")
            return LegacyPlan(mappings=command.mappings, unmapped=command.unmapped)
