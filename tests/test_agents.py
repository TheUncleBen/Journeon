# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from pydantic import ValidationError
from sqlalchemy import func, select, text

from journeon.agents import AgentService
from journeon.contracts import (
    BotCreate,
    BotRevise,
    DomainError,
    InstructionTemplate,
    Preferences,
    ProfileCreate,
    ProfileRevise,
    ProfileRevisionPreview,
    TeamCreate,
    TeamMember,
)
from journeon.database import transaction
from journeon.models import (
    AccessGrant,
    AgentProfile,
    Bot,
    BrowserSession,
    OutboxEvent,
    ProfileRevision,
    Receipt,
    Team,
)
from journeon.permissions import AuthenticatedContext
from journeon.sessions import issue_session


def test_profile_restart_and_retry(database, actor):
    command = ProfileCreate(
        idempotency_key="profile-one",
        name="Example",
        baseline=InstructionTemplate(
            template="Be precise",
            template_id="baseline",
            required_variables=[],
            eval_ids=["precision"],
        ),
        preferences=Preferences(),
        eligibility=[],
    )
    service = AgentService(database[0])
    receipt = service.create_profile(actor, command)
    assert service.create_profile(actor, command) == receipt
    assert AgentService(database[0]).profile(actor, receipt.target_id).revision == 1


def profile_command(key="profile"):
    return ProfileCreate(
        idempotency_key=key,
        name="Example",
        baseline=InstructionTemplate(
            template="Be precise",
            template_id="baseline",
            required_variables=[],
            eval_ids=["precision"],
        ),
        preferences=Preferences(model="model-a"),
        eligibility=["skill-a"],
        visual_ref="portrait-a",
    )


def setup_agents(database, actor):
    service = AgentService(database[0])
    result = service.create_profile(actor, profile_command())
    profile = service.profile(actor, result.target_id)
    command = BotCreate(
        idempotency_key="bot-a",
        name="Specialist",
        profile_id=profile.profile_id,
        expected_profile_revision=1,
        additive=profile.baseline,
        memory_enabled=True,
        overrides=Preferences(provider="provider-a"),
    )
    bot = service.bot(actor, service.create_bot(actor, command).target_id)
    return service, profile, bot, command


def proposed(profile):
    return ProfileRevisionPreview(
        **profile_command("revise").model_dump(exclude={"preferences", "visual_ref"}),
        profile_id=profile.profile_id,
        expected_revision=profile.revision,
        expected_hash=profile.baseline_hash,
        reason="Update references",
        preferences=Preferences(model="model-b", provider="provider-b"),
        visual_ref="portrait-b",
    )


def commit(preview, impact):
    return ProfileRevise(
        **preview.model_dump(),
        preview_digest=impact.digest,
        expected_affected_bots=impact.affected_bots,
    )


def counts(engine):
    with transaction(engine) as db:
        return tuple(
            db.scalar(select(func.count()).select_from(model))
            for model in (AgentProfile, ProfileRevision, Bot, Team, Receipt, OutboxEvent)
        )


def shared_actor(engine):
    with transaction(engine) as db:
        issued = issue_session(
            db,
            "viewer-test",
            authentication_method="test-fixture",
            client_label="Synthetic",
            strong=True,
        )
    return AuthenticatedContext("viewer-test", 1, issued.session_id)


def grant(engine, actor, kind, identity, action):
    from uuid import uuid4

    with transaction(engine) as db:
        db.add(
            AccessGrant(
                id=str(uuid4()),
                principal_id=actor.principal_id,
                capability=f"{kind}.{action}",
                resource_kind=kind,
                resource_id=identity,
                enabled=True,
                revision=1,
                provenance="fixture",
            )
        )


def test_preview_inheritance_pins_visual_and_no_mutation(database, actor):
    service, profile, bot, command = setup_agents(database, actor)
    second = service.bot(
        actor,
        service.create_bot(
            actor, command.model_copy(update={"idempotency_key": "bot-b"})
        ).target_id,
    )
    assert second.namespace_ref != bot.namespace_ref
    preview = proposed(profile)
    before = counts(database[0])
    impact = service.preview_profile(actor, preview)
    assert counts(database[0]) == before
    assert all(item.changed_inherited_fields == ["model"] for item in impact.affected_bots)
    service.revise_profile(actor, commit(preview, impact))
    settings = service.settings(actor, bot.bot_id)
    values = {item.field: item for item in settings.fields}
    assert values["model"].value == "model-b" and values["model"].source == "PROFILE"
    assert values["provider"].value == "provider-a" and values["provider"].source == "BOT_OVERRIDE"
    assert settings.visual_ref == "portrait-a"
    with transaction(database[0]) as db:
        assert (
            db.get(ProfileRevision, (profile.profile_id, 1)).snapshot["preferences"]["model"]
            == "model-a"
        )
    revised = BotRevise(
        idempotency_key="reset",
        bot_id=bot.bot_id,
        expected_revision=1,
        expected_hash=bot.additive_hash,
        name=bot.name,
        additive=bot.additive,
        overrides=bot.overrides,
        reset_to_inherit=["provider"],
        visual_ref=bot.visual_ref,
        reason="Inherit provider",
    )
    service.revise_bot(actor, revised)
    assert {x.field: x.value for x in service.settings(actor, bot.bot_id).fields}[
        "provider"
    ] == "provider-b"


@pytest.mark.parametrize("change", ["payload", "bot", "profile", "visible", "revoke"])
def test_stale_preview_rejected(database, actor, change):
    service, profile, bot, command = setup_agents(database, actor)
    shared = shared_actor(database[0])
    for action in ["read", "revise", "receipt.read"]:
        grant(database[0], shared, "profile", profile.profile_id, action)
    grant(database[0], shared, "bot", bot.bot_id, "read")
    preview = proposed(profile)
    impact = service.preview_profile(shared, preview)
    if change == "payload":
        preview = preview.model_copy(update={"name": "Changed"})
    elif change == "bot":
        service.revise_bot(
            actor,
            BotRevise(
                idempotency_key="bot-edit",
                bot_id=bot.bot_id,
                expected_revision=1,
                expected_hash=bot.additive_hash,
                name="Revised",
                additive=bot.additive,
                overrides=bot.overrides,
                reset_to_inherit=[],
                visual_ref=bot.visual_ref,
                reason="Edit",
            ),
        )
    elif change == "profile":
        service.revise_profile(actor, commit(preview, service.preview_profile(actor, preview)))
    elif change == "visible":
        new = service.create_bot(actor, command.model_copy(update={"idempotency_key": "second"}))
        grant(database[0], shared, "bot", new.target_id, "read")
    else:
        with transaction(database[0]) as db:
            for row in db.scalars(
                select(AccessGrant).where(
                    AccessGrant.principal_id == shared.principal_id,
                    AccessGrant.resource_kind == "bot",
                )
            ):
                row.enabled = False
    before = counts(database[0])
    with pytest.raises(DomainError, match="refresh"):
        service.revise_profile(shared, commit(preview, impact))
    assert counts(database[0]) == before


def test_hidden_bot_payload_not_decoded_or_fingerprinted(database, actor):
    service, profile, bot, command = setup_agents(database, actor)
    shared = shared_actor(database[0])
    for action in ["read", "revise"]:
        grant(database[0], shared, "profile", profile.profile_id, action)
    preview = proposed(profile)
    first = service.preview_profile(shared, preview)
    assert first.affected_bots == []
    with transaction(database[0]) as db:
        db.execute(
            text("UPDATE bots SET snapshot='not-json', revision=revision+1 WHERE id=:id"),
            {"id": bot.bot_id},
        )
    assert service.preview_profile(shared, preview) == first
    with pytest.raises(DomainError, match="grant"):
        service.bot(shared, bot.bot_id)


def test_team_atomicity_and_strict_memory_choice(database, actor):
    service, profile, bot, command = setup_agents(database, actor)
    for mutation in [
        {"memory_enabled": None},
        {"builtin_role": "RESEARCHER"},
        {"copy_memory": True},
    ]:
        with pytest.raises(ValidationError):
            BotCreate.model_validate({**command.model_dump(), **mutation})
    payload = command.model_dump()
    del payload["memory_enabled"]
    with pytest.raises(ValidationError):
        BotCreate.model_validate(payload)
    with pytest.raises(ValidationError):
        TeamCreate(idempotency_key="team", name="Team", members=[], lead_key="missing")
    bad = TeamCreate(
        idempotency_key="bad-team",
        name="Team",
        members=[
            TeamMember(key="a", bot=command),
            TeamMember(key="b", bot=command.model_copy(update={"expected_profile_revision": 99})),
        ],
        lead_key="a",
    )
    before = counts(database[0])
    with pytest.raises(DomainError):
        service.create_team(actor, bad)
    assert counts(database[0]) == before
    good = bad.model_copy(
        update={"members": [TeamMember(key="a", bot=command), TeamMember(key="b", bot=command)]}
    )
    receipt = service.create_team(actor, good)
    team = service.team(actor, receipt.target_id)
    assert len(team.authorized_members) == 2 and team.authorized_lead_id in receipt.member_ids
    assert service.bot(actor, bot.bot_id).team_id is None
    shared = shared_actor(database[0])
    grant(database[0], shared, "team", team.team_id, "read")
    hidden = service.team(shared, team.team_id)
    assert hidden.authorized_members == [] and hidden.authorized_lead_id is None


def test_authority_expiry_receipt_revocation_and_collision(database, actor):
    from journeon.receipts import OperationService

    service, profile, bot, command = setup_agents(database, actor)
    with pytest.raises(DomainError, match="different input"):
        service.create_bot(actor, command.model_copy(update={"name": "Collision"}))
    shared = shared_actor(database[0])
    grant(database[0], shared, "bot", bot.bot_id, "read")
    assert service.bot(shared, bot.bot_id) == bot
    with pytest.raises(DomainError):
        service.settings(shared, bot.bot_id)
    with transaction(database[0]) as db:
        row = db.scalar(select(AccessGrant).where(AccessGrant.principal_id == shared.principal_id))
        row.expires_at = "2000-01-01T00:00:00+00:00"
    with pytest.raises(DomainError):
        service.bot(shared, bot.bot_id)
    receipt = service.create_bot(actor, command)
    with transaction(database[0]) as db:
        db.execute(
            text("UPDATE operation_receipts SET result='not-json' WHERE id=:id"),
            {"id": receipt.operation_id},
        )
        db.get(BrowserSession, actor.authentication_ref).revoked = True
    with pytest.raises(DomainError):
        OperationService(database[0]).receipt(actor, receipt.operation_id)


def test_real_cookie_csrf_and_cross_human_http(database):
    from fastapi.testclient import TestClient

    from journeon.api import create_app
    from journeon.browser_auth import COOKIE_NAME, BrowserAuth

    engine = database[0]
    with transaction(engine) as db:
        owner = issue_session(
            db,
            "owner-test",
            authentication_method="test-fixture",
            client_label="Browser",
            strong=True,
        )
        viewer = issue_session(
            db,
            "viewer-test",
            authentication_method="test-fixture",
            client_label="Browser",
            strong=True,
        )
    with TestClient(
        create_app(engine, browser_auth=BrowserAuth("https://testserver")),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(COOKIE_NAME, owner.token)
        headers = {"Origin": "https://testserver", "X-CSRF-Token": owner.csrf_token}
        assert (
            client.post("/api/v1/profiles", json=profile_command().model_dump()).status_code == 401
        )
        response = client.post(
            "/api/v1/profiles", json=profile_command().model_dump(), headers=headers
        )
        assert response.status_code == 200, response.text
        identity = response.json()["target_id"]
        assert client.get(f"/api/v1/profiles/{identity}").status_code == 200
        client.cookies.set(COOKIE_NAME, viewer.token)
        assert client.get(f"/api/v1/profiles/{identity}").status_code == 403
        assert (
            client.get(f"/api/v1/operations/{response.json()['operation_id']}").status_code == 404
        )
        grant(
            engine,
            AuthenticatedContext("viewer-test", 1, viewer.session_id),
            "profile",
            identity,
            "read",
        )
        assert client.get(f"/api/v1/profiles/{identity}").status_code == 200
        denied = client.get(
            "/api/v1/permissions/effective",
            params={"resource_kind": "bot", "resource_id": identity, "action": "read"},
        )
        assert denied.status_code == 200 and denied.json()["allowed"] is False


def test_legacy_mapping_exact_evidence_and_preview_only(database, actor):
    from journeon.contracts import LegacyMapping, LegacyPreview

    service, profile, bot, _ = setup_agents(database, actor)
    item = LegacyMapping(
        collection_id="old-collection",
        version=2,
        content_hash="a" * 64,
        provenance_ref="inventory",
        bot_id=bot.bot_id,
        expected_bot_revision=1,
        memory_enabled=True,
        destination_consent=True,
    )
    command = LegacyPreview(mappings=[item], unmapped=[])
    with pytest.raises(DomainError):
        service.legacy_preview(actor, command)
    grant(
        database[0],
        actor,
        "legacy_collection",
        item.collection_id,
        f"preview:{item.version}:{item.content_hash}:{item.provenance_ref}",
    )
    before = counts(database[0])
    assert service.legacy_preview(actor, command).mappings == [item]
    assert counts(database[0]) == before
    for change in [
        {"content_hash": "b" * 64},
        {"memory_enabled": False},
        {"expected_bot_revision": 2},
    ]:
        with pytest.raises(DomainError):
            service.legacy_preview(
                actor, command.model_copy(update={"mappings": [item.model_copy(update=change)]})
            )
    with pytest.raises(DomainError):
        service.legacy_preview(actor, command.model_copy(update={"mappings": [item, item]}))


def test_database_fixed_memory_namespace_and_history_guards(database, actor):
    from sqlalchemy.exc import IntegrityError

    service, profile, bot, _ = setup_agents(database, actor)
    for sql in [
        "UPDATE bots SET builtin_role='RESEARCHER'",
        "UPDATE bots SET namespace_ref='shared'",
        "UPDATE profile_revisions SET reason='Rewrite'",
        "DELETE FROM bot_revisions",
    ]:
        with pytest.raises(IntegrityError), transaction(database[0]) as db:
            db.execute(text(sql))
    with pytest.raises(IntegrityError), transaction(database[0]) as db:
        db.add(Team(id="bad-team", name="Bad", revision=1, lead_bot_id=bot.bot_id))


@pytest.mark.parametrize("field,value", [("expected_revision", 99), ("expected_hash", "0" * 64)])
def test_profile_stale_revision_or_hash_fails_without_mutation(database, actor, field, value):
    service, profile, _, _ = setup_agents(database, actor)
    command = proposed(profile).model_copy(update={field: value})
    before = counts(database[0])
    with pytest.raises(DomainError):
        service.preview_profile(actor, command)
    assert counts(database[0]) == before


def test_profile_unknown_fields_and_canonical_instruction_source(database, actor):
    from journeon.models import InstructionRevision

    with pytest.raises(ValidationError):
        ProfileCreate.model_validate({**profile_command().model_dump(), "memory_enabled": True})
    service, profile, bot, _ = setup_agents(database, actor)
    with transaction(database[0]) as db:
        assert "baseline" not in db.get(ProfileRevision, (profile.profile_id, 1)).snapshot
        assert "additive" not in db.get(Bot, bot.bot_id).snapshot
        assert (
            db.get(InstructionRevision, (profile.baseline_asset_id, 1)).template
            == profile.baseline.model_dump()
        )
