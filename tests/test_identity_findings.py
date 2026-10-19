# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from pydantic import ValidationError
from test_agents import commit, grant, proposed, setup_agents, shared_actor
from test_instructions import configured_bundle

from journeon.agents import AgentService
from journeon.contracts import DomainError, LegacyMapping
from journeon.database import transaction
from journeon.instructions import InstructionService
from journeon.models import AccessGrant
from journeon.receipts import OperationService
from journeon.registry import COMMANDS, QUERIES


def test_legacy_evidence_collision_is_rejected(database, actor):
    _, _, bot, _ = setup_agents(database, actor)
    item = dict(
        collection_id="legacy",
        version=1,
        content_hash="a" * 64,
        provenance_ref="inventory:version",
        bot_id=bot.bot_id,
        expected_bot_revision=1,
        memory_enabled=True,
        destination_consent=True,
    )
    assert LegacyMapping.model_validate(item).provenance_ref == "inventory:version"
    with pytest.raises(ValidationError):
        LegacyMapping.model_validate(
            {
                **item,
                "content_hash": item["content_hash"] + ":inventory",
                "provenance_ref": "version",
            }
        )


def test_bundle_receipt_rechecks_constituent_authority(database, actor):
    command = configured_bundle(database, actor)
    result = InstructionService(database[0]).resolve(actor, command)
    with transaction(database[0]) as db:
        db.get(AccessGrant, "instruction-read").enabled = False
    with pytest.raises(DomainError) as error:
        OperationService(database[0]).receipt(actor, result.receipt.operation_id)
    assert error.value.code == "PERMISSION_DENIED"


def test_accepted_bundle_retry_uses_accepted_revisions(database, actor):
    command = configured_bundle(database, actor)
    service = InstructionService(database[0])
    result = service.resolve(actor, command)
    agents = AgentService(database[0])
    preview = proposed(agents.profile(actor, command.profile_id))
    agents.revise_profile(actor, commit(preview, agents.preview_profile(actor, preview)))
    assert service.resolve(actor, command) == result


def test_metadata_describes_actual_settings_and_preview_authority(database, actor):
    service, profile, bot, _ = setup_agents(database, actor)
    shared = shared_actor(database[0])
    grant(database[0], shared, "bot", bot.bot_id, "read")
    grant(database[0], shared, "profile", profile.profile_id, "read")
    assert service.settings(shared, bot.bot_id).bot_id == bot.bot_id
    assert QUERIES["bot.settings.read.v1"]["permissions"] == ("bot.read", "profile.read")
    assert "profile.revise" in COMMANDS["profile.preview-revision.v1"].permissions
    with pytest.raises(DomainError):
        service.preview_profile(shared, proposed(profile))
    grant(database[0], shared, "profile", profile.profile_id, "revise")
    assert service.preview_profile(shared, proposed(profile)).profile_revision == 1


def test_legacy_hash_binding_service_and_real_http(database, actor):
    from fastapi.testclient import TestClient
    from test_agents import counts

    from journeon.api import create_app
    from journeon.browser_auth import COOKIE_NAME, BrowserAuth
    from journeon.contracts import LegacyPreview
    from journeon.sessions import issue_session

    service, _, bot, _ = setup_agents(database, actor)
    item = LegacyMapping(
        collection_id="legacy",
        version=1,
        content_hash="a" * 64,
        provenance_ref="inventory:version",
        bot_id=bot.bot_id,
        expected_bot_revision=1,
        memory_enabled=True,
        destination_consent=True,
    )
    grant(
        database[0],
        actor,
        "legacy_collection",
        "legacy",
        "preview:1:" + "a" * 64 + ":inventory:version",
    )
    command = LegacyPreview(mappings=[item], unmapped=[])
    before = counts(database[0])
    with transaction(database[0]) as db:
        issued = issue_session(
            db,
            actor.principal_id,
            authentication_method="fixture",
            client_label="Fixture",
            strong=True,
        )
    with TestClient(
        create_app(database[0], browser_auth=BrowserAuth("https://testserver")),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(COOKIE_NAME, issued.token)
        headers = {"Origin": "https://testserver", "X-CSRF-Token": issued.csrf_token}
        assert (
            client.post(
                "/api/v1/legacy-memory/preview", json=command.model_dump(), headers=headers
            ).status_code
            == 200
        )
        for invalid in ["", "a" * 63, "a" * 65, "g" * 64, "A" * 64, "a" * 64 + ":inventory"]:
            bad = item.model_copy(update={"content_hash": invalid, "provenance_ref": "version"})
            with pytest.raises(ValidationError):
                LegacyMapping.model_validate(bad.model_dump())
            with pytest.raises(DomainError) as error:
                service.legacy_preview(actor, command.model_copy(update={"mappings": [bad]}))
            assert error.value.code == "VALIDATION_FAILED"
            response = client.post(
                "/api/v1/legacy-memory/preview",
                json={"mappings": [bad.model_dump()], "unmapped": []},
                headers=headers,
            )
            assert response.status_code == 422
    assert counts(database[0]) == before


@pytest.mark.parametrize("revocation", ["project", "session", "principal"])
def test_bundle_denial_precedes_all_receipt_and_snapshot_decoding(database, actor, revocation):
    from sqlalchemy import text

    from journeon.agents import retry
    from journeon.instructions import digest
    from journeon.models import BrowserSession, Principal

    command = configured_bundle(database, actor)
    service = InstructionService(database[0])
    result = service.resolve(actor, command)
    with transaction(database[0]) as db:
        db.execute(
            text("UPDATE operation_receipts SET result='broken-json' WHERE id=:id"),
            {"id": result.receipt.operation_id},
        )
        db.execute(text("DROP TRIGGER immutable_instruction_bundles_update"))
        db.execute(
            text("UPDATE instruction_bundles SET snapshot='broken-json' WHERE id=:id"),
            {"id": result.bundle.bundle_id},
        )
        if revocation == "project":
            db.get(AccessGrant, "instruction-read").enabled = False
        elif revocation == "session":
            db.get(BrowserSession, actor.authentication_ref).revoked = True
        else:
            db.get(Principal, actor.principal_id).authorization_epoch += 1
    expected = "PERMISSION_DENIED" if revocation == "project" else "AUTHENTICATION_REQUIRED"
    for action in [
        lambda: OperationService(database[0]).receipt(actor, result.receipt.operation_id),
        lambda: service.read(actor, result.bundle.bundle_id),
        lambda: service.resolve(actor, command),
    ]:
        with pytest.raises(DomainError) as error:
            action()
        assert error.value.code == expected
    with pytest.raises(DomainError) as error, transaction(database[0]) as db:
        retry(
            db,
            actor,
            "instruction.bundle.resolve.v1",
            command.idempotency_key,
            digest(command.model_dump(mode="json", exclude={"idempotency_key"})),
        )
    assert error.value.code == expected
    if revocation == "project":
        assert (
            not AgentService(database[0])
            .permission(actor, "instruction_bundle", result.bundle.bundle_id, "read")
            .allowed
        )
    else:
        with pytest.raises(DomainError) as error:
            AgentService(database[0]).permission(
                actor, "instruction_bundle", result.bundle.bundle_id, "read"
            )
        assert error.value.code == expected


@pytest.mark.parametrize("change", ["bot", "component"])
def test_accepted_bundle_retry_after_other_revision_changes(database, actor, change):
    from sqlalchemy import func, select

    from journeon.contracts import BotRevise
    from journeon.instructions import digest
    from journeon.models import (
        InstructionAsset,
        InstructionBundle,
        InstructionRevision,
        OutboxEvent,
        Receipt,
    )

    command = configured_bundle(database, actor)
    service = InstructionService(database[0])
    accepted = service.resolve(actor, command)
    if change == "bot":
        agents = AgentService(database[0])
        bot = agents.bot(actor, command.origin.bot_id)
        agents.revise_bot(
            actor,
            BotRevise(
                idempotency_key="bot-revision",
                bot_id=bot.bot_id,
                expected_revision=bot.revision,
                expected_hash=bot.additive_hash,
                name=bot.name,
                additive=bot.additive.model_copy(update={"template": "New additive"}),
                overrides=bot.overrides,
                reset_to_inherit=[],
                visual_ref=bot.visual_ref,
                reason="Revise additive",
            ),
        )
    else:
        with transaction(database[0]) as db:
            asset = db.get(InstructionAsset, "fixture-project")
            old = db.get(InstructionRevision, (asset.id, 1))
            template = {**old.template, "template": "New Project instructions {{input}}"}
            asset.revision = 2
            db.add(
                InstructionRevision(
                    asset_id=asset.id,
                    revision=2,
                    template=template,
                    content_hash=digest(template),
                    previous_hash=old.content_hash,
                    author=actor.principal_id,
                    reason="Canonical fixture revision",
                    created_at=old.created_at,
                )
            )

    def counts():
        with transaction(database[0]) as db:
            return tuple(
                db.scalar(select(func.count()).select_from(model))
                for model in (InstructionBundle, Receipt, OutboxEvent)
            )

    before = counts()
    assert service.resolve(actor, command) == accepted
    changed = command.model_copy(
        update={
            "variables": [command.variables[0].model_copy(update={"value": "Different variable"})]
        }
    )
    with pytest.raises(DomainError) as error:
        service.resolve(actor, changed)
    assert error.value.code == "IDEMPOTENCY_CONFLICT"
    with pytest.raises(DomainError) as error:
        service.resolve(actor, command.model_copy(update={"idempotency_key": "new-construction"}))
    assert error.value.code == "REVISION_CONFLICT"
    assert counts() == before
    assert service.read(actor, accepted.bundle.bundle_id) == accepted.bundle


@pytest.mark.parametrize("revoked_kind", ["profile", "bot"])
def test_shared_bundle_namespace_and_current_constituents(
    database, actor, monkeypatch, revoked_kind
):
    from uuid import UUID

    from sqlalchemy import select, text

    from journeon.registry import CONFIGURATION_AUTHORIZATION

    command = configured_bundle(database, actor)
    shared = shared_actor(database[0])
    future_id = "33333333-3333-3333-3333-333333333333"
    monkeypatch.setattr("journeon.instructions.uuid4", lambda: UUID(future_id))
    for kind, identity in [("profile", command.profile_id), ("bot", command.origin.bot_id)]:
        for action in ("read", "use"):
            grant(database[0], shared, kind, identity, action)
    grant(database[0], shared, "instruction_bundle", future_id, "receipt.read")
    with transaction(database[0]) as db:
        db.add(
            AccessGrant(
                id="shared-instructions",
                principal_id=shared.principal_id,
                capability="project.instruction.read",
                resource_kind="project",
                resource_id=command.project_id,
                enabled=True,
                revision=1,
                provenance="fixture",
            )
        )
        db.add(
            AccessGrant(
                id="wrong-alias",
                principal_id=shared.principal_id,
                capability="instruction.bundle.read",
                resource_kind="instruction_bundle",
                resource_id=future_id,
                enabled=True,
                revision=1,
                provenance="fixture",
            )
        )
    service = InstructionService(database[0])
    with pytest.raises(DomainError):
        service.resolve(shared, command)
    assert "instruction_bundle.read" in QUERIES["instruction.bundle.read.v1"]["permissions"]
    assert "instruction.bundle.read" not in QUERIES["instruction.bundle.read.v1"]["permissions"]
    grant(database[0], shared, "instruction_bundle", future_id, "read")
    accepted = service.resolve(shared, command)
    assert service.read(shared, future_id) == accepted.bundle
    assert (
        OperationService(database[0]).receipt(shared, accepted.receipt.operation_id)
        == accepted.receipt
    )
    assert not CONFIGURATION_AUTHORIZATION["instruction.bundle.resolve.v1"]["owner_only"]
    assert (
        AgentService(database[0])
        .permission(shared, "instruction_bundle", future_id, "read")
        .allowed
    )
    with transaction(database[0]) as db:
        for row in db.scalars(
            select(AccessGrant).where(
                AccessGrant.principal_id == shared.principal_id,
                AccessGrant.capability == revoked_kind + ".read",
            )
        ):
            row.enabled = False
        db.execute(
            text("UPDATE operation_receipts SET result='broken-json' WHERE id=:id"),
            {"id": accepted.receipt.operation_id},
        )
        db.execute(text("DROP TRIGGER immutable_instruction_bundles_update"))
        db.execute(
            text("UPDATE instruction_bundles SET snapshot='broken-json' WHERE id=:id"),
            {"id": future_id},
        )
    for action in [
        lambda: service.read(shared, future_id),
        lambda: service.resolve(shared, command),
        lambda: OperationService(database[0]).receipt(shared, accepted.receipt.operation_id),
    ]:
        with pytest.raises(DomainError) as error:
            action()
        assert error.value.code == "PERMISSION_DENIED"
    assert (
        not AgentService(database[0])
        .permission(shared, "instruction_bundle", future_id, "read")
        .allowed
    )


def test_metadata_owner_creations_and_filtered_reads(database, actor):
    from test_agents import profile_command

    from journeon.contracts import TeamCreate, TeamMember
    from journeon.registry import CONFIGURATION_AUTHORIZATION

    service, profile, bot, bot_command = setup_agents(database, actor)
    shared = shared_actor(database[0])
    team_command = TeamCreate(
        idempotency_key="team",
        name="Team",
        members=[TeamMember(key="lead", bot=bot_command)],
        lead_key="lead",
    )
    for name, action, command in [
        ("profile.create.v1", service.create_profile, profile_command("other")),
        (
            "bot.create.v1",
            service.create_bot,
            bot_command.model_copy(update={"idempotency_key": "other"}),
        ),
        ("team.create.v1", service.create_team, team_command),
    ]:
        assert CONFIGURATION_AUTHORIZATION[name]["owner_only"] is True
        kind = name.split(".")[0]
        grant(database[0], shared, kind, "deployment", "create")
        with pytest.raises(DomainError):
            action(shared, command)
        assert action(actor, command).revision == 1
    team = service.team(actor, service.create_team(actor, team_command).target_id)
    grant(database[0], shared, "team", team.team_id, "read")
    assert service.team(shared, team.team_id).authorized_members == []
    assert any(
        "filter" in check["when"]
        for check in CONFIGURATION_AUTHORIZATION["team.read.v1"]["grant_checks"]
    )
    for kind, identity, read in [
        ("profile", profile.profile_id, service.profile),
        ("bot", bot.bot_id, service.bot),
    ]:
        assert QUERIES[kind + ".read.v1"]["permissions"] == (kind + ".read",)
        with pytest.raises(DomainError):
            read(shared, identity)
        grant(database[0], shared, kind, identity, "read")
        assert read(shared, identity).revision == 1
    assert CONFIGURATION_AUTHORIZATION["permission.effective.v1"]["diagnostic_only"] is True
    assert "permission.effective" not in QUERIES["permission.effective.v1"]["permissions"]
    assert service.permission(shared, "bot", bot.bot_id, "read").allowed
    assert not service.permission(shared, "bot", bot.bot_id, "revise").allowed
    inventory = CONFIGURATION_AUTHORIZATION["legacy-memory.preview.v1"]["grant_checks"][0]
    assert (
        inventory["capability"]
        == "legacy_collection.preview:{version}:{content_hash}:{provenance_ref}"
    )
    assert inventory["owner_configuration_authority"] is False
