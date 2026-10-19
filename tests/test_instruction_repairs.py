# SPDX-License-Identifier: AGPL-3.0-only
from pathlib import Path

import pytest
from test_production_instructions import bound_instructions
from test_production_instructions import official as _official


@pytest.fixture
def official(tmp_path):
    yield from _official.__wrapped__(tmp_path)


@pytest.mark.parametrize("change", ["root", "grant", "session", "generation"])
def test_projection_revocation_before_replace(official, monkeypatch, change):
    from journeon import release_evidence
    from journeon.database import transaction
    from journeon.models import (
        AccessGrant,
        BrowserSession,
        InstructionRoot,
        ProjectInstructionBinding,
    )

    engine, client, headers, config = official
    identity, base, path = bound_instructions(official)
    original = release_evidence.regular_bytes
    triggered = False

    def observe_then_revoke(location, limit):
        nonlocal triggered
        if location.endswith("/AGENTS.md") and not triggered:
            triggered = True
            with transaction(engine) as db:
                if change == "root":
                    db.get(InstructionRoot, "environment").enabled = False
                elif change == "grant":
                    db.get(AccessGrant, "instruction-projection").enabled = False
                elif change == "generation":
                    db.get(ProjectInstructionBinding, identity).generation += 1
                else:
                    from sqlalchemy import select

                    db.scalar(select(BrowserSession)).revoked = True
        return original(location, limit)

    monkeypatch.setattr(release_evidence, "regular_bytes", observe_then_revoke)
    response = client.post(
        f"/api/v1/projects/{identity}/instructions/projections/materialize",
        headers=headers,
        json={
            "idempotency_key": "projection",
            "project_id": identity,
            "expected_revision": 1,
            "root_id": "environment",
            "expected_root_revision": 1,
            "filename": "AGENTS.md",
            "expected_observed_hash": None,
        },
    )
    assert triggered
    assert (
        response.status_code
        == {"root": 403, "grant": 403, "session": 401, "generation": 409}[change]
    )
    assert not (Path(config.roots[0].path) / "AGENTS.md").exists(), (
        "Projection was written after root revocation and before final denial"
    )


@pytest.mark.parametrize("change", ["root", "read"])
def test_revoked_pending_binding_authorizes_before_json_decode(official, monkeypatch, change):
    from sqlalchemy import text

    from journeon import project_instructions
    from journeon.database import transaction
    from journeon.models import AccessGrant, InstructionRoot

    engine, client, headers, config = official

    def interrupt(*args, **kwargs):
        raise OSError("synthetic staging interruption")

    with monkeypatch.context() as patch:
        patch.setattr(project_instructions, "replace_document", interrupt)
        identity, base, path, command = bound_instructions(official, expected_status=503)
    with transaction(engine) as db:
        if change == "root":
            db.get(InstructionRoot, "environment").enabled = False
        else:
            db.get(AccessGrant, "instruction-read").enabled = False
        db.execute(
            text("UPDATE instruction_publications SET snapshot = :bad WHERE project_id = :project"),
            {"bad": "{", "project": identity},
        )
    response = client.post(
        f"/api/v1/projects/{identity}/instructions/binding", headers=headers, json=command
    )
    assert response.status_code == 403, response.text


def test_terminal_abandoned_publication_is_not_unresolved_on_restart(
    official, monkeypatch, tmp_path
):
    from test_production_instructions import (
        test_changed_policy_allows_exact_abandon_and_new_binding,
    )
    from test_runtime import settings

    from journeon.runtime import RuntimeConfig, application

    test_changed_policy_allows_exact_abandon_and_new_binding(official, monkeypatch)
    engine, client, headers, config = official
    runtime = settings.__wrapped__((engine, Path(engine.url.database)), tmp_path)
    app = application(RuntimeConfig.model_validate(runtime))
    try:
        assert app.state.instruction_dependencies["publication"] == "NO_PENDING_JOURNAL"
    finally:
        app.state.engine.dispose()


def test_null_project_receipt_scope_cannot_bypass_revoked_project_grant(official):
    from sqlalchemy import select, text

    from journeon.database import transaction
    from journeon.models import AccessGrant, Receipt

    engine, client, headers, config = official
    identity, base, path = bound_instructions(official)
    with transaction(engine) as db:
        receipt = db.scalar(
            select(Receipt).where(Receipt.command == "project.instructions.bind.v1")
        )
        operation = receipt.id
        db.get(AccessGrant, "instruction-read").enabled = False
        db.get(AccessGrant, "instruction-receipt.read").enabled = False
        db.execute(text("PRAGMA ignore_check_constraints=ON"))
        db.execute(
            text("UPDATE operation_receipts SET project_id = NULL WHERE id = :id"),
            {"id": operation},
        )
    response = client.get(f"/api/v1/operations/{operation}", headers=headers)
    assert response.status_code == 403, (
        "Null retained Project scope bypassed both revoked instruction grants"
    )


def test_confirmation_surface_renders_stored_effect(official):
    from journeon.installed_instructions import candidate_manifest

    engine, client, headers, config = official
    effect = {
        "kind": "instruction.candidate.register.v1",
        "idempotency_key": "surface",
        "manifest_digest": candidate_manifest().digest,
        "expected_revision": 0,
    }
    prepared = client.post(
        "/api/v1/protected-operations/prepare", headers=headers, json={"effect": effect}
    )
    assert prepared.status_code == 200
    result = client.get(
        "/instructions/confirmation/" + prepared.json()["request_id"], headers=headers
    )
    assert result.status_code == 200
    assert "Confirm this operation" in result.text
    assert "instruction.candidate.register.v1" in result.text
    assert result.headers["x-frame-options"] == "DENY"
    assert result.headers["referrer-policy"] == "no-referrer"
    assert result.headers["cache-control"] == "no-store"


def test_release_evidence_has_owned_health_and_coherent_backup(official, tmp_path, monkeypatch):
    from test_production_instructions import (
        test_signed_installed_evidence_uses_disposable_authority_and_rejects_tampering,
    )

    from journeon import release_evidence
    from journeon.database import transaction
    from journeon.models import InstalledReleaseEvidence

    original = release_evidence.verify_release

    def verify(engine, config, actor):
        identity = original(engine, config, actor)
        with transaction(engine) as db:
            stored = db.get(InstalledReleaseEvidence, identity).snapshot
            assert stored["qualification"]["health"]["result"] == "PASS"
            assert stored["qualification"]["backup"]["trees_hash"]
        return identity

    monkeypatch.setattr(release_evidence, "verify_release", verify)
    test_signed_installed_evidence_uses_disposable_authority_and_rejects_tampering(
        official, tmp_path
    )


@pytest.mark.parametrize("table", ["operation_receipts", "outbox_events"])
def test_project_scope_constraints_reject_null(official, table):
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    from journeon.database import transaction

    engine, client, headers, config = official
    identity, base, path = bound_instructions(official)
    with pytest.raises(IntegrityError), transaction(engine) as db:
        db.execute(
            text(f"UPDATE {table} SET project_id=NULL WHERE target_kind='project_instructions'")
        )


@pytest.mark.parametrize(
    "change", ["missing", "tree_backup", "database_backup", "state", "dirty_tree"]
)
def test_release_qualification_denies_absent_or_changed_operands(official, tmp_path, change):
    from journeon.contracts import DomainError
    from journeon.database import transaction
    from journeon.instruction_config import ReleaseTrustConfiguration
    from journeon.models import ProjectInstructionBinding
    from journeon.release_qualification import produce, verify

    engine, client, headers, config = official
    identity, base, path = bound_instructions(official)
    trust = ReleaseTrustConfiguration(
        public_key_hex="00" * 32,
        manifest_path=str(tmp_path / "manifest"),
        signature_path=str(tmp_path / "signature"),
        artifact_path=str(tmp_path / "artifact"),
        backup_path=str(tmp_path / "backup"),
        channel="qualification",
        platform="linux-aarch64",
        authority="DISPOSABLE_TEST_AUTHORITY",
        revision=1,
    )
    config = config.model_copy(update={"release_trust": trust})
    from sqlalchemy import select

    from journeon.models import BrowserSession
    from journeon.permissions import AuthenticatedContext

    with transaction(engine) as db:
        session = db.scalar(select(BrowserSession))
        actor = AuthenticatedContext(session.principal_id, session.principal_epoch, session.id)
    evidence = produce(engine, config, actor)
    verify(engine, config, evidence, actor)
    if change == "missing":
        evidence = {}
    elif change == "tree_backup":
        Path(evidence["backup"]["directory"], "trees.json").write_text("{}")
    elif change == "database_backup":
        Path(evidence["backup"]["directory"], "database.sqlite").write_bytes(b"invalid")
    elif change == "state":
        with transaction(engine) as db:
            db.get(ProjectInstructionBinding, identity).generation += 1
    else:
        (path / "INDEX.md").write_text("unknown edit")
    with pytest.raises(DomainError):
        verify(engine, config, evidence, actor)


@pytest.mark.parametrize("change", ["root", "grant", "generation", "consent"])
def test_projection_recovery_rechecks_before_effect(official, monkeypatch, change):
    from journeon import project_instructions as service
    from journeon import release_evidence
    from journeon.database import transaction
    from journeon.models import (
        AccessGrant,
        InstructionRoot,
        ProjectInstructionBinding,
        ProtectedRequest,
    )

    engine, client, headers, config = official
    identity, base, path = bound_instructions(official)

    def interrupt(*args, **kwargs):
        raise OSError("local interrupted projection")

    with monkeypatch.context() as patch:
        patch.setattr(service, "replace_document", interrupt)
        response = client.post(
            f"/api/v1/projects/{identity}/instructions/projections/materialize",
            headers=headers,
            json={
                "idempotency_key": "projection-interrupted",
                "project_id": identity,
                "expected_revision": 1,
                "root_id": "environment",
                "expected_root_revision": 1,
                "filename": "AGENTS.md",
                "expected_observed_hash": None,
            },
        )
        assert response.status_code == 503
    target = client.post(
        f"/api/v1/projects/{identity}/instructions/recovery",
        headers=headers,
        json={"project_id": identity},
    ).json()
    prepared = client.post(
        "/api/v1/protected-operations/prepare",
        headers=headers,
        json={
            "effect": {
                "kind": "project.instructions.recover.v1",
                "idempotency_key": "reconcile",
                "disposition": "FINISH_TARGET",
                **target,
            }
        },
    ).json()
    preview = client.post(
        "/api/v1/protected-operations/preview", headers=headers, json=prepared
    ).json()
    observed = release_evidence.regular_bytes

    def revoke(location, limit):
        if location.endswith("/AGENTS.md"):
            with transaction(engine) as db:
                if change == "root":
                    db.get(InstructionRoot, "environment").enabled = False
                elif change == "grant":
                    db.get(AccessGrant, "instruction-projection").enabled = False
                elif change == "generation":
                    db.get(ProjectInstructionBinding, identity).generation += 1
                else:
                    db.get(ProtectedRequest, prepared["request_id"]).approval_deadline = 0
        return observed(location, limit)

    monkeypatch.setattr(release_evidence, "regular_bytes", revoke)
    result = client.post(
        "/api/v1/protected-operations/confirm",
        headers=headers,
        json={key: preview[key] for key in ("request_id", "request_hash", "nonce")},
    )
    assert result.status_code == (409 if change == "generation" else 403)
    assert not Path(config.roots[0].path, "AGENTS.md").exists()


def test_pending_accept_authorizes_before_corrupt_snapshot(official, monkeypatch):
    import test_production_instructions as fixtures
    from sqlalchemy import select, text

    from journeon import project_instructions as service
    from journeon.database import transaction
    from journeon.models import InstructionPublication, InstructionRoot

    engine, client, headers, config = official
    original_effect = fixtures.official_effect
    original_replace = service.replace_document
    checked = False

    def effect(client, headers, command):
        nonlocal checked
        if command["kind"] != "project.instructions.accept.v1":
            return original_effect(client, headers, command)
        prepared = client.post(
            "/api/v1/protected-operations/prepare", headers=headers, json={"effect": command}
        ).json()
        preview = client.post(
            "/api/v1/protected-operations/preview", headers=headers, json=prepared
        ).json()

        def interrupt(*args, **kwargs):
            raise OSError("local pending accept")

        with monkeypatch.context() as patch:
            patch.setattr(service, "replace_document", interrupt)
            assert (
                client.post(
                    "/api/v1/protected-operations/confirm",
                    headers=headers,
                    json={key: preview[key] for key in ("request_id", "request_hash", "nonce")},
                ).status_code
                == 503
            )
        accepted = {key: value for key, value in command.items() if key != "kind"}
        accepted["consent_request_id"] = prepared["request_id"]
        with transaction(engine) as db:
            row = db.scalar(
                select(InstructionPublication).where(
                    InstructionPublication.idempotency_key == command["idempotency_key"]
                )
            )
            saved = row.snapshot
            db.get(InstructionRoot, "environment").enabled = False
            db.execute(
                text("UPDATE instruction_publications SET snapshot=:bad WHERE id=:id"),
                {"bad": "{", "id": row.id},
            )
            operation = row.id
        result = client.post(
            f"/api/v1/projects/{command['project_id']}/instructions/accept",
            headers=headers,
            json=accepted,
        )
        assert result.status_code == 403
        checked = True
        with transaction(engine) as db:
            db.get(InstructionRoot, "environment").enabled = True
            db.execute(
                text("UPDATE instruction_publications SET snapshot=:saved WHERE id=:id"),
                {"saved": __import__("json").dumps(saved), "id": operation},
            )
        monkeypatch.setattr(service, "replace_document", original_replace)
        return client.post(
            "/api/v1/protected-operations/confirm",
            headers=headers,
            json={key: preview[key] for key in ("request_id", "request_hash", "nonce")},
        ).json()

    monkeypatch.setattr(fixtures, "official_effect", effect)
    fixtures.test_exact_instruction_confirmation_enforces_and_commits_same_candidate(official)
    assert checked


def test_unauthenticated_surface_has_accessible_signin_guidance(official):
    engine, client, headers, config = official
    client.cookies.clear()
    result = client.get("/instructions/confirmation/unavailable")
    assert result.status_code == 401
    assert "text/html" in result.headers["content-type"]
    assert "/instructions/authenticate" in result.text


def test_dark_focus_outline_has_nontext_contrast(official):
    import re

    engine, client, headers, config = official
    css = client.get("/instructions/surface.css").text
    colors = re.findall(r"outline:3px solid (#[0-9a-f]{6})", css)
    assert colors

    def luminance(color):
        values = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [
            value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
            for value in values
        ]
        return sum(
            value * weight for value, weight in zip(linear, (0.2126, 0.7152, 0.0722), strict=True)
        )

    outline = luminance(colors[-1])
    background = luminance("#171717")
    assert (max(outline, background) + 0.05) / (min(outline, background) + 0.05) >= 3
