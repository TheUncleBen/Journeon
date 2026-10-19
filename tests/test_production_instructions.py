# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from pydantic import ValidationError


def test_explicit_production_configuration_has_no_timing_defaults(tmp_path):
    from journeon.instruction_config import InstructionConfiguration

    with pytest.raises(ValidationError):
        InstructionConfiguration.model_validate({"roots": []})
    root = tmp_path / "environment"
    root.mkdir()
    config = InstructionConfiguration.model_validate(
        {
            "roots": [
                {
                    "key": "environment",
                    "path": str(root),
                    "role": "ENVIRONMENT",
                    "project_id": None,
                    "revision": 1,
                }
            ],
            "protected_request_seconds": 101,
            "protected_preview_seconds": 37,
        }
    )
    assert config.roots[0].path == str(root)
    assert config.protected_request_seconds == 101


def test_root_observation_rejects_symlink_and_changes(tmp_path):
    from journeon.instruction_config import RootConfiguration, observe_root

    root = tmp_path / "root"
    root.mkdir()
    configuration = RootConfiguration(
        key="root", path=str(root), role="ENVIRONMENT", project_id=None, revision=1
    )
    first = observe_root(configuration)
    (root / "existing.md").write_text("User content")
    assert observe_root(configuration).digest != first.digest
    root.rename(tmp_path / "original")
    root.symlink_to(tmp_path / "original", target_is_directory=True)
    with pytest.raises(ValueError):
        observe_root(configuration)


def test_running_package_has_real_reviewable_core_and_navigation():
    from journeon.installed_instructions import candidate_manifest

    manifest = candidate_manifest()
    assert manifest.provenance == "DEVELOPMENT_CANDIDATE"
    assert {asset.purpose for asset in manifest.assets} == {"CORE", "NAVIGATION"}
    assert all(asset.template.template for asset in manifest.assets)


@pytest.fixture
def official(tmp_path):
    import json

    from fastapi.testclient import TestClient
    from test_passkeys import Authenticator

    from journeon.api import create_app
    from journeon.browser_auth import BrowserAuth
    from journeon.database import create_database
    from journeon.instruction_config import InstructionConfiguration
    from journeon.migrate import upgrade
    from journeon.passkeys import STANDARD_PASSKEY_POLICY, PasskeyService

    engine = create_database(tmp_path / "production.db")
    upgrade(engine)
    root = tmp_path / "environment"
    root.mkdir()
    config = InstructionConfiguration.model_validate(
        {
            "roots": [
                {
                    "key": "environment",
                    "path": str(root),
                    "role": "ENVIRONMENT",
                    "project_id": None,
                    "revision": 1,
                }
            ],
            "protected_request_seconds": 101,
            "protected_preview_seconds": 37,
        }
    )
    passkeys = PasskeyService(
        engine, rp_id="example.test", origin="https://example.test", policy=STANDARD_PASSKEY_POLICY
    )
    client = TestClient(
        create_app(
            engine,
            browser_auth=BrowserAuth(passkeys.origin),
            passkeys=passkeys,
            instructions=config,
        ),
        base_url=passkeys.origin,
    )
    enrollment = passkeys.prepare_bootstrap()
    key = Authenticator()
    headers = {"Origin": passkeys.origin}
    challenge = client.post(
        "/api/v1/auth/passkeys/begin",
        headers=headers,
        json={
            "purpose": "bootstrap",
            "label": "Official test authenticator",
            "enrollment_secret": enrollment.secret,
        },
    ).json()
    authenticated = client.post(
        "/api/v1/auth/passkeys/finish",
        headers=headers,
        json={
            "purpose": "bootstrap",
            "ceremony_id": challenge["ceremony_id"],
            "credential_json": json.dumps(key.register(json.loads(challenge["options_json"]))),
        },
    )
    assert authenticated.status_code == 200, authenticated.text
    headers["X-CSRF-Token"] = authenticated.json()["csrf_token"]
    yield engine, client, headers, config
    client.close()
    engine.dispose()


def official_effect(client, headers, effect):
    prepared = client.post(
        "/api/v1/protected-operations/prepare", headers=headers, json={"effect": effect}
    )
    assert prepared.status_code == 200, prepared.text
    preview = client.post(
        "/api/v1/protected-operations/preview", headers=headers, json=prepared.json()
    )
    assert preview.status_code == 200, preview.text
    exact = {name: preview.json()[name] for name in ("request_id", "request_hash", "nonce")}
    committed = client.post("/api/v1/protected-operations/confirm", headers=headers, json=exact)
    assert committed.status_code == 200, committed.text
    assert (
        client.post("/api/v1/protected-operations/confirm", headers=headers, json=exact).json()
        == committed.json()
    )
    return committed.json()


def test_real_official_confirmation_admits_root_and_registers_package(official):
    from journeon.database import transaction
    from journeon.installed_instructions import candidate_manifest
    from journeon.models import InstructionInstallation, InstructionRoot

    engine, client, headers, config = official
    observation = client.post(
        "/api/v1/project-roots/inspect",
        headers=headers,
        json={"root_key": "environment", "config_revision": 1},
    )
    assert observation.status_code == 200, observation.text
    result = official_effect(
        client,
        headers,
        {
            "kind": "project.root.admit.v1",
            "idempotency_key": "root",
            "root_key": "environment",
            "config_revision": 1,
            "expected_revision": 0,
            "inspection_digest": observation.json()["digest"],
        },
    )
    assert result["provenance"] == "ROOT"
    result = official_effect(
        client,
        headers,
        {
            "kind": "instruction.candidate.register.v1",
            "idempotency_key": "candidate-package",
            "manifest_digest": candidate_manifest().digest,
            "expected_revision": 0,
        },
    )
    assert result["provenance"] == "DEVELOPMENT_CANDIDATE"
    with transaction(engine) as db:
        assert db.get(InstructionRoot, "environment").enabled
        assert db.get(InstructionInstallation, 1).provenance == "DEVELOPMENT_CANDIDATE"


def create_instruction_project(official):
    from sqlalchemy import select

    from journeon.database import transaction
    from journeon.models import AccessGrant, DeploymentPolicy, Principal

    engine, client, headers, config = official
    with transaction(engine) as db:
        owner = db.scalar(select(Principal).where(Principal.role == "OWNER"))
        for action in ["project.create", "project.receipt.read"]:
            db.add(
                AccessGrant(
                    id=action,
                    principal_id=owner.id,
                    capability=action,
                    resource_kind="deployment",
                    resource_id="deployment",
                    enabled=True,
                    revision=1,
                    provenance="Explicit local test deployment authority",
                )
            )
        db.add(
            DeploymentPolicy(
                id=1,
                revision=1,
                approval_id=None,
                approved_by=None,
                approved_providers=[],
                verification_policy_ref=None,
            )
        )
    response = client.post(
        "/api/v1/projects",
        headers=headers,
        json={
            "schema_version": 1,
            "idempotency_key": "project",
            "name": "Instructions",
            "expected_policy_revision": 1,
        },
    )
    assert response.status_code == 200, response.text
    identity = response.json()["project"]["project_id"]
    with transaction(engine) as db:
        owner = db.scalar(select(Principal).where(Principal.role == "OWNER"))
        for action in [
            "bind",
            "read",
            "receipt.read",
            "propose",
            "accept",
            "evaluate",
            "review",
            "projection",
        ]:
            db.add(
                AccessGrant(
                    id="instruction-" + action,
                    principal_id=owner.id,
                    capability="project.instruction." + action,
                    resource_kind="project",
                    resource_id=identity,
                    enabled=True,
                    revision=1,
                    provenance="Explicit exact Project test authority",
                )
            )
    return identity


def test_environment_tree_real_bytes_policy_and_automatic_navigation(official):
    from pathlib import Path

    from journeon.instruction_files import tree_hash
    from journeon.project_instructions import navigation

    engine, client, headers, config = official
    identity = create_instruction_project(official)
    observation = client.post(
        "/api/v1/project-roots/inspect",
        headers=headers,
        json={"root_key": "environment", "config_revision": 1},
    ).json()
    official_effect(
        client,
        headers,
        {
            "kind": "project.root.admit.v1",
            "idempotency_key": "root",
            "root_key": "environment",
            "config_revision": 1,
            "inspection_digest": observation["digest"],
            "expected_revision": 0,
        },
    )
    base = {
        "INDEX.md": (
            "# Instruction navigation\n\n- [rules.md](rules.md)\n\nRequired fragme"
            "nts:\n- rules.md\n\n"
        ),
        "rules.md": "Preserve exact Project authority.\n",
    }
    result = client.post(
        f"/api/v1/projects/{identity}/instructions/binding",
        headers=headers,
        json={
            "idempotency_key": "binding",
            "project_id": identity,
            "expected_project_revision": 1,
            "expected_binding_revision": 0,
            "root_id": "environment",
            "expected_root_revision": 1,
            "expected_tree_hash": tree_hash({}),
            "owner": "ENVIRONMENT",
            "documents": [{"path": k, "content": v} for k, v in base.items()],
            "required_fragments": ["rules.md"],
            "reason": "Initial explicit instruction tree",
        },
    )
    assert result.status_code == 200, result.text
    path = Path(config.roots[0].path) / "instructions" / "projects" / identity
    assert (path / "rules.md").read_text() == base["rules.md"]
    read = client.get(f"/api/v1/projects/{identity}/instructions", headers=headers)
    assert read.status_code == 200, read.text
    assert read.json()["revision"] == 1
    official_effect(
        client,
        headers,
        {
            "kind": "project.instructions.policy.configure.v1",
            "idempotency_key": "policy",
            "project_id": identity,
            "expected_project_revision": 1,
            "expected_binding_revision": 1,
            "expected_root_revision": 1,
            "expected_policy_revision": 1,
            "policy": {
                "authorized_categories": ["NAVIGATION_REPAIR"],
                "navigation_repairs": True,
                "independent_review": True,
                "require_confirmation": False,
                "required_evals": ["instruction-boundaries-v1"],
            },
        },
    )
    repaired = {**base, "INDEX.md": navigation(base, ["rules.md"])}
    proposed = client.post(
        f"/api/v1/projects/{identity}/instructions/candidates",
        headers=headers,
        json={
            "idempotency_key": "navigation",
            "project_id": identity,
            "expected_revision": 1,
            "expected_tree_hash": tree_hash(base),
            "documents": [{"path": k, "content": v} for k, v in repaired.items()],
            "required_fragments": ["rules.md"],
            "reason": "Rebuild index from unchanged targets",
            "source_refs": ["canonical-tree"],
            "category": "NAVIGATION_REPAIR",
        },
    )
    assert proposed.status_code == 200, proposed.text
    assert proposed.json()["automatic"]
    assert (path / "INDEX.md").read_text() == repaired["INDEX.md"]
    assert (
        client.get(f"/api/v1/projects/{identity}/instructions", headers=headers).json()["revision"]
        == 2
    )


def test_signed_installed_evidence_uses_disposable_authority_and_rejects_tampering(
    official, tmp_path
):
    import hashlib
    import json
    import sqlite3

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sqlalchemy import select

    from journeon.contracts import DomainError
    from journeon.database import SCHEMA_REVISION, transaction
    from journeon.installed_instructions import candidate_manifest
    from journeon.instruction_config import ReleaseTrustConfiguration
    from journeon.models import BrowserSession
    from journeon.permissions import AuthenticatedContext
    from journeon.release_evidence import verify_release

    engine, client, headers, config = official
    package = candidate_manifest()
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"Disposable release qualification artifact")
    backup = tmp_path / "backup.db"
    with sqlite3.connect(str(engine.url.database)) as source, sqlite3.connect(backup) as target:
        source.backup(target)
        target.execute("PRAGMA journal_mode=DELETE")
    signed = {
        "format": 1,
        "instruction_manifest_digest": package.digest,
        "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "source_digest": package.source_digest,
        "source_commit": "0" * 40,
        "version": "0.0.0.dev1",
        "channel": "qualification",
        "platform": "linux-aarch64",
        "schema_revision": SCHEMA_REVISION,
        "eval_suite": "instruction-boundaries-v1",
    }
    manifest = tmp_path / "signed.json"
    manifest.write_text(json.dumps(signed, sort_keys=True))
    key = Ed25519PrivateKey.generate()
    signature = tmp_path / "signature"
    signature.write_bytes(key.sign(manifest.read_bytes()))
    trust = ReleaseTrustConfiguration(
        public_key_hex=key.public_key().public_bytes_raw().hex(),
        manifest_path=str(manifest),
        signature_path=str(signature),
        artifact_path=str(artifact),
        backup_path=str(backup),
        channel="qualification",
        platform="linux-aarch64",
        authority="DISPOSABLE_TEST_AUTHORITY",
        revision=1,
    )
    config = config.model_copy(update={"release_trust": trust})
    from fastapi.testclient import TestClient

    from journeon.api import create_app
    from journeon.browser_auth import BrowserAuth

    restarted = TestClient(
        create_app(engine, browser_auth=BrowserAuth("https://example.test"), instructions=config),
        base_url="https://example.test",
    )
    restarted.cookies.update(client.cookies)
    client = restarted
    with transaction(engine) as db:
        session = db.scalar(select(BrowserSession))
        actor = AuthenticatedContext(session.principal_id, session.principal_epoch, session.id)
    evidence = verify_release(engine, config, actor)
    result = official_effect(
        client,
        headers,
        {
            "kind": "instruction.release.install.v1",
            "idempotency_key": "verified-install",
            "evidence_id": evidence,
            "manifest_digest": package.digest,
            "expected_revision": 0,
        },
    )
    assert result["provenance"] == "VERIFIED_RELEASE"
    signature.write_bytes(b"0" * 64)
    with pytest.raises(DomainError):
        verify_release(engine, config, actor)


def test_project_owned_partial_write_restart_reconciles_exact_journal(
    official, tmp_path, monkeypatch
):
    from pathlib import Path

    from fastapi.testclient import TestClient
    from sqlalchemy import select

    import journeon.project_instructions as service
    from journeon.api import create_app
    from journeon.browser_auth import BrowserAuth
    from journeon.database import create_database, transaction
    from journeon.instruction_config import RootConfiguration
    from journeon.instruction_files import tree_hash
    from journeon.models import InstructionPublication, ProjectInstructionBinding

    engine, client, headers, config = official
    identity = create_instruction_project(official)
    root = tmp_path / "project-root"
    root.mkdir()
    config = config.model_copy(
        update={
            "roots": [
                *config.roots,
                RootConfiguration(
                    key="project-root",
                    path=str(root),
                    role="PROJECT",
                    project_id=identity,
                    revision=1,
                ),
            ]
        }
    )
    active = TestClient(
        create_app(engine, browser_auth=BrowserAuth("https://example.test"), instructions=config),
        base_url="https://example.test",
    )
    active.cookies.update(client.cookies)
    observation = active.post(
        "/api/v1/project-roots/inspect",
        headers=headers,
        json={"root_key": "project-root", "config_revision": 1},
    ).json()
    official_effect(
        active,
        headers,
        {
            "kind": "project.root.admit.v1",
            "idempotency_key": "admit-project",
            "root_key": "project-root",
            "config_revision": 1,
            "inspection_digest": observation["digest"],
            "expected_revision": 0,
        },
    )
    command = {
        "idempotency_key": "bind-project",
        "project_id": identity,
        "expected_project_revision": 1,
        "expected_binding_revision": 0,
        "root_id": "project-root",
        "expected_root_revision": 1,
        "expected_tree_hash": tree_hash({}),
        "owner": "PROJECT",
        "documents": [
            {"path": "INDEX.md", "content": "Read [rules](rules.md).\n"},
            {"path": "rules.md", "content": "Scoped instructions.\n"},
        ],
        "required_fragments": ["rules.md"],
        "reason": "Explicit Project ownership",
    }
    original = service.replace_document
    fired = False

    def fail_after_first(path, name, expected, target, **kwargs):
        nonlocal fired
        original(path, name, expected, target, **kwargs)
        if path == root / ".journeon" / "instructions" and not fired:
            fired = True
            raise OSError("Injected storage interruption")

    with monkeypatch.context() as patch:
        patch.setattr(service, "replace_document", fail_after_first)
        failed = active.post(
            f"/api/v1/projects/{identity}/instructions/binding", headers=headers, json=command
        )
        assert failed.status_code == 503, failed.text
    assert fired
    with transaction(engine) as db:
        assert db.get(ProjectInstructionBinding, identity).revision == 0
        assert db.scalar(select(InstructionPublication)).status == "RECOVERY_NEEDED"
    assert (
        active.get(f"/api/v1/projects/{identity}/instructions", headers=headers).status_code == 503
    )
    reopened = create_database(Path(str(engine.url.database)))
    restarted = TestClient(
        create_app(reopened, browser_auth=BrowserAuth("https://example.test"), instructions=config),
        base_url="https://example.test",
    )
    restarted.cookies.update(active.cookies)
    resumed = restarted.post(
        f"/api/v1/projects/{identity}/instructions/binding", headers=headers, json=command
    )
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["status"] == "CANONICAL_COMMITTED"
    assert (
        root / ".journeon" / "instructions" / "rules.md"
    ).read_text() == "Scoped instructions.\n"
    assert (
        restarted.post(
            f"/api/v1/projects/{identity}/instructions/binding", headers=headers, json=command
        ).json()
        == resumed.json()
    )
    restarted.close()
    reopened.dispose()
    active.close()


def test_document_paths_reject_control_characters():
    from journeon.instruction_contracts import Document

    for name in ["rules\n.md", "rules\t.md", "rules\x7f.md"]:
        with pytest.raises(ValidationError):
            Document(path=name, content="rules")


def test_file_replacement_binds_actual_admitted_root(tmp_path):
    from journeon.instruction_files import replace_document

    root = tmp_path / "root"
    root.mkdir()
    original = root.stat()
    root.rename(tmp_path / "old")
    root.mkdir()
    with pytest.raises(ValueError):
        replace_document(
            root, "rules.md", None, "rules", anchor=(root, original.st_dev, original.st_ino)
        )
    assert not (root / "rules.md").exists()


def bound_instructions(official, expected_status=200, extra=None):
    from pathlib import Path

    from journeon.instruction_files import tree_hash

    engine, client, headers, config = official
    identity = create_instruction_project(official)
    observation = client.post(
        "/api/v1/project-roots/inspect",
        headers=headers,
        json={"root_key": "environment", "config_revision": 1},
    ).json()
    official_effect(
        client,
        headers,
        {
            "kind": "project.root.admit.v1",
            "idempotency_key": "root",
            "root_key": "environment",
            "config_revision": 1,
            "inspection_digest": observation["digest"],
            "expected_revision": 0,
        },
    )
    base = {
        "INDEX.md": (
            "# Instruction navigation\n\n- [rules.md](rules.md)\n\nRequired fragme"
            "nts:\n- rules.md\n\n"
        ),
        "rules.md": "Preserve exact Project authority.\n",
    }
    base.update(extra or {})
    result = client.post(
        f"/api/v1/projects/{identity}/instructions/binding",
        headers=headers,
        json={
            "idempotency_key": "binding",
            "project_id": identity,
            "expected_project_revision": 1,
            "expected_binding_revision": 0,
            "root_id": "environment",
            "expected_root_revision": 1,
            "expected_tree_hash": tree_hash({}),
            "owner": "ENVIRONMENT",
            "documents": [{"path": k, "content": v} for k, v in base.items()],
            "required_fragments": ["rules.md"],
            "reason": "Initial explicit instruction tree",
        },
    )
    assert result.status_code == expected_status, result.text
    path = Path(config.roots[0].path) / "instructions" / "projects" / identity
    if expected_status != 200:
        import json

        return identity, base, path, json.loads(result.request.content)
    assert (path / "rules.md").read_text() == base["rules.md"]
    return identity, base, path


def test_exact_instruction_confirmation_enforces_and_commits_same_candidate(official):
    from journeon.instruction_files import tree_hash

    engine, client, headers, config = official
    identity, base, path = bound_instructions(official)
    official_effect(
        client,
        headers,
        {
            "kind": "project.instructions.policy.configure.v1",
            "idempotency_key": "exact-policy",
            "project_id": identity,
            "expected_project_revision": 1,
            "expected_binding_revision": 1,
            "expected_root_revision": 1,
            "expected_policy_revision": 1,
            "policy": {
                "authorized_categories": ["ORDINARY"],
                "navigation_repairs": False,
                "independent_review": False,
                "require_confirmation": True,
                "required_evals": ["instruction-boundaries-v1"],
            },
        },
    )
    target = {**base, "rules.md": base["rules.md"] + "Keep approved boundaries.\n"}
    proposed = client.post(
        f"/api/v1/projects/{identity}/instructions/candidates",
        headers=headers,
        json={
            "idempotency_key": "exact-candidate",
            "project_id": identity,
            "expected_revision": 1,
            "expected_tree_hash": tree_hash(base),
            "documents": [{"path": k, "content": v} for k, v in target.items()],
            "required_fragments": ["rules.md"],
            "reason": "Explicit local change",
            "source_refs": ["test"],
            "category": "ORDINARY",
        },
    )
    assert proposed.status_code == 200, proposed.text
    candidate = {
        key: proposed.json()[key]
        for key in (
            "project_id",
            "candidate_id",
            "candidate_hash",
            "expected_binding_revision",
            "expected_policy_revision",
        )
    }
    evaluated = client.post(
        f"/api/v1/projects/{identity}/instructions/evals", headers=headers, json=candidate
    )
    assert evaluated.status_code == 200, evaluated.text
    accepted = {
        **candidate,
        "idempotency_key": "exact-accept",
        "review_ids": [],
        "eval_ids": [evaluated.json()["evidence_id"]],
    }
    denied = client.post(
        f"/api/v1/projects/{identity}/instructions/accept", headers=headers, json=accepted
    )
    assert denied.status_code == 403, denied.text
    assert (path / "rules.md").read_text() == base["rules.md"]
    result = official_effect(
        client, headers, {"kind": "project.instructions.accept.v1", **accepted}
    )
    assert result["revision"] == 2
    assert (path / "rules.md").read_text() == target["rules.md"]
    forbidden = client.post(
        "/api/v1/protected-operations/prepare",
        headers=headers,
        json={"effect": {"kind": "execute.raw", "approved": True}},
    )
    assert forbidden.status_code == 422
    fixture_command = client.post(
        "/api/v1/protected-operations/prepare",
        headers=headers,
        json={"effect": {"kind": "passkey.label.v1", "approved": True}},
    )
    assert fixture_command.status_code == 422


def test_projection_effect_is_journaled_before_write_and_reconciles(official, monkeypatch):
    from sqlalchemy import select

    from journeon import project_instructions as service
    from journeon.database import transaction
    from journeon.models import InstructionPublication

    engine, client, headers, config = official
    identity, base, path = bound_instructions(official)
    command = {
        "idempotency_key": "projection",
        "project_id": identity,
        "expected_revision": 1,
        "root_id": "environment",
        "expected_root_revision": 1,
        "filename": "AGENTS.md",
        "expected_observed_hash": None,
    }
    url = f"/api/v1/projects/{identity}/instructions/projections/materialize"
    original = service.replace_document

    def interrupted(root, name, expected, target, **kwargs):
        if name == "AGENTS.md":
            with transaction(engine) as db:
                rows = list(db.scalars(select(InstructionPublication)))
                assert any(
                    row.snapshot["command"] == "project.instructions.projection.v1" for row in rows
                )
            original(root, name, expected, target, **kwargs)
            raise OSError("Injected projection interruption")
        return original(root, name, expected, target, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(service, "replace_document", interrupted)
        response = client.post(url, headers=headers, json=command)
        assert response.status_code == 503, response.text
    resumed = client.post(url, headers=headers, json=command)
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["status"] == "MATCH"
    assert client.post(url, headers=headers, json=command).json() == resumed.json()


def test_tree_validation_rejects_unrenderable_selected_content_before_effect():
    from journeon.contracts import DomainError
    from journeon.project_instructions import validate_tree

    with pytest.raises(DomainError):
        validate_tree({"INDEX.md": "Use {undeclared}.\n"}, [])


def test_git_checkpoint_keeps_user_index_and_exact_subset(tmp_path):
    import subprocess

    from journeon.instruction_files import git_checkpoint

    root = tmp_path / "work"
    root.mkdir()
    subprocess.run(["git", "init", str(root)], check=True, capture_output=True)
    (root / "user.txt").write_text("Unrelated staged change")
    subprocess.run(["git", "-C", str(root), "add", "user.txt"], check=True, capture_output=True)
    before = (root / ".git" / "index").read_bytes()
    checkpoint = git_checkpoint(
        root, {"INDEX.md": "Bound instructions.\n"}, tmp_path / "private-stage"
    )
    assert checkpoint["worktree"] == str(root)
    tree = subprocess.run(
        ["git", "-C", str(root), "ls-tree", "-r", "--name-only", checkpoint["tree"]],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert tree == "INDEX.md\n"
    assert (root / ".git" / "index").read_bytes() == before
    assert not (root / "INDEX.md").exists()


def test_project_instruction_read_needs_exact_project_grant(official):
    from sqlalchemy import select

    from journeon.database import transaction
    from journeon.models import AccessGrant, Principal

    engine, client, headers, config = official
    identity, _, _ = bound_instructions(official)
    with transaction(engine) as db:
        owner = db.scalar(select(Principal).where(Principal.role == "OWNER"))
        grant = db.scalar(
            select(AccessGrant).where(AccessGrant.capability == "project.instruction.read")
        )
        grant.enabled = False
        db.add(
            AccessGrant(
                id="broad-read",
                principal_id=owner.id,
                capability="project.instruction.read",
                resource_kind="deployment",
                resource_id="deployment",
                enabled=True,
                revision=1,
                provenance="Test broad grant must not substitute exact Project authority",
            )
        )
    response = client.get(f"/api/v1/projects/{identity}/instructions", headers=headers)
    assert response.status_code == 403, response.text


def candidate_command(identity, base, *, key="change", category="ORDINARY"):
    from journeon.instruction_files import tree_hash

    return {
        "idempotency_key": key,
        "project_id": identity,
        "expected_revision": 1,
        "expected_tree_hash": tree_hash(base),
        "documents": [{"path": k, "content": v} for k, v in base.items()],
        "required_fragments": ["rules.md"],
        "reason": "Scoped candidate",
        "source_refs": ["explicit-source"],
        "category": category,
    }


def reference(view):
    return {
        key: view[key]
        for key in (
            "project_id",
            "candidate_id",
            "candidate_hash",
            "expected_binding_revision",
            "expected_policy_revision",
        )
    }


def test_missing_policy_retains_candidate_without_automatic_acceptance(official, monkeypatch):
    from journeon import project_instructions
    from journeon.project_instructions import navigation

    with monkeypatch.context() as patch:
        patch.setattr(project_instructions, "initialize_project_policy", lambda *args: None)
        identity, base, path = bound_instructions(official)
    _, client, headers, _ = official
    command = candidate_command(identity, base, category="NAVIGATION_REPAIR")
    command["documents"][0]["content"] = navigation(base, ["rules.md"])
    proposed = client.post(
        f"/api/v1/projects/{identity}/instructions/candidates", headers=headers, json=command
    )
    assert proposed.status_code == 200, proposed.text
    assert proposed.json()["expected_policy_revision"] == 0
    assert not proposed.json()["automatic"]
    assert (path / "INDEX.md").read_text() == base["INDEX.md"]
    accepted = client.post(
        f"/api/v1/projects/{identity}/instructions/accept",
        headers=headers,
        json={
            **reference(proposed.json()),
            "idempotency_key": "accept-no-policy",
            "eval_ids": [],
            "review_ids": [],
        },
    )
    assert accepted.status_code == 503, accepted.text
    assert (
        client.post(
            f"/api/v1/projects/{identity}/instructions/preview",
            headers=headers,
            json=reference(proposed.json()),
        ).status_code
        == 200
    )


def test_scoped_history_documents_preview_and_revoked_corrupt_consent(official):
    from sqlalchemy import select

    from journeon.database import transaction
    from journeon.models import AccessGrant, ProtectedRequest

    engine, client, headers, config = official
    identity, base, path = bound_instructions(official)
    history = client.post(
        f"/api/v1/projects/{identity}/instructions/history",
        headers=headers,
        json={"project_id": identity, "revision": 1},
    )
    assert history.status_code == 200, history.text
    assert "documents" not in history.json()
    document = client.post(
        f"/api/v1/projects/{identity}/instructions/document",
        headers=headers,
        json={"project_id": identity, "revision": 1, "path": "rules.md"},
    )
    assert document.status_code == 200 and document.json()["content"] == base["rules.md"]
    proposed = client.post(
        f"/api/v1/projects/{identity}/instructions/candidates",
        headers=headers,
        json=candidate_command(identity, base),
    ).json()
    effect = {
        "kind": "project.instructions.accept.v1",
        **reference(proposed),
        "idempotency_key": "pending-consent",
        "eval_ids": [],
        "review_ids": [],
    }
    prepared = client.post(
        "/api/v1/protected-operations/prepare", headers=headers, json={"effect": effect}
    )
    assert prepared.status_code == 200, prepared.text
    with transaction(engine) as db:
        db.scalar(
            select(AccessGrant).where(AccessGrant.capability == "project.instruction.read")
        ).enabled = False
        db.get(ProtectedRequest, prepared.json()["request_id"]).payload = {
            "corrupt": "must not decode"
        }
    for suffix, body in [
        ("history", {"project_id": identity, "revision": 1}),
        ("document", {"project_id": identity, "revision": 1, "path": "rules.md"}),
        ("preview", reference(proposed)),
    ]:
        denied = client.post(
            f"/api/v1/projects/{identity}/instructions/{suffix}", headers=headers, json=body
        )
        assert denied.status_code == 403, denied.text
    denied = client.post(
        "/api/v1/protected-operations/preview", headers=headers, json=prepared.json()
    )
    assert denied.status_code == 403, denied.text
    assert "corrupt" not in denied.text


@pytest.mark.parametrize("findings", [[], ["Mandatory authority rule is omitted"]])
def test_independent_review_evidence_controls_acceptance(official, findings):
    from sqlalchemy import select

    from journeon.contracts import DomainError
    from journeon.database import transaction
    from journeon.instruction_contracts import InstructionReview
    from journeon.models import AccessGrant, InstructionEvidence, Principal
    from journeon.permissions import AuthenticatedContext
    from journeon.project_instructions import ProjectInstructionService
    from journeon.sessions import issue_session

    engine, client, headers, config = official
    identity, base, path = bound_instructions(official)
    official_effect(
        client,
        headers,
        {
            "kind": "project.instructions.policy.configure.v1",
            "idempotency_key": "review-policy",
            "project_id": identity,
            "expected_project_revision": 1,
            "expected_binding_revision": 1,
            "expected_root_revision": 1,
            "expected_policy_revision": 1,
            "policy": {
                "authorized_categories": ["ORDINARY"],
                "navigation_repairs": False,
                "independent_review": True,
                "require_confirmation": False,
                "required_evals": ["instruction-boundaries-v1"],
            },
        },
    )
    proposed = client.post(
        f"/api/v1/projects/{identity}/instructions/candidates",
        headers=headers,
        json=candidate_command(identity, base),
    ).json()
    ref = reference(proposed)
    evaluation = client.post(
        f"/api/v1/projects/{identity}/instructions/evals", headers=headers, json=ref
    ).json()["evidence_id"]
    review = {
        **ref,
        "idempotency_key": "review",
        "coverage": "Scope and selected fragments",
        "limitations": "No model execution",
        "verdict": "PASS",
        "findings": findings,
    }
    self_review = client.post(
        f"/api/v1/projects/{identity}/instructions/reviews", headers=headers, json=review
    )
    assert self_review.status_code == 403, self_review.text
    with transaction(engine) as db:
        db.add(Principal(id="independent", role="SHARED_USER", enabled=True, authorization_epoch=1))
        db.flush()
        issued = issue_session(
            db,
            "independent",
            authentication_method="test-fixture",
            client_label="Local reviewer fixture",
            strong=True,
        )
        for action in ("read", "review"):
            db.add(
                AccessGrant(
                    id="reviewer-" + action,
                    principal_id="independent",
                    capability="project.instruction." + action,
                    resource_kind="project",
                    resource_id=identity,
                    enabled=True,
                    revision=1,
                    provenance="Explicit local review scope",
                )
            )
    actor = AuthenticatedContext("independent", 1, issued.session_id)
    service = ProjectInstructionService(engine, config)
    evidence = service.review(actor, InstructionReview.model_validate(review))
    assert service.review(actor, InstructionReview.model_validate(review)) == evidence
    with pytest.raises(DomainError) as collision:
        service.review(
            actor, InstructionReview.model_validate({**review, "coverage": "Different review"})
        )
    assert collision.value.code == "IDEMPOTENCY_CONFLICT"
    with transaction(engine) as db:
        assert (
            len(
                list(
                    db.scalars(
                        select(InstructionEvidence).where(InstructionEvidence.kind == "REVIEW")
                    )
                )
            )
            == 1
        )
    accepted = client.post(
        f"/api/v1/projects/{identity}/instructions/accept",
        headers=headers,
        json={
            **ref,
            "idempotency_key": "reviewed-accept",
            "review_ids": [evidence],
            "eval_ids": [evaluation],
        },
    )
    assert accepted.status_code == (403 if findings else 200), accepted.text


@pytest.mark.parametrize("boundary", ["staging", "fsync", "checkpoint", "finalize"])
def test_publication_fault_boundaries_retain_canonical_revision(official, monkeypatch, boundary):
    from journeon import instruction_files
    from journeon import project_instructions as service
    from journeon.database import transaction
    from journeon.models import ProjectInstructionBinding

    engine, client, headers, config = official
    original_write = service.replace_document
    original_record = service.record
    fired = False

    def write(root, name, expected, target, **kwargs):
        nonlocal fired
        if boundary == "staging" and ".instruction-publications" in str(root):
            fired = True
            raise OSError("Injected staging disk full")
        return original_write(root, name, expected, target, **kwargs)

    def record(*args, **kwargs):
        nonlocal fired
        if boundary == "finalize" and args[2] == "project.instructions.bind.v1":
            fired = True
            raise OSError("Injected final receipt interruption")
        return original_record(*args, **kwargs)

    def fsync(*args):
        nonlocal fired
        fired = True
        raise OSError("Injected directory sync failure")

    def checkpoint(*args):
        nonlocal fired
        fired = True
        raise OSError("Injected checkpoint storage failure")

    with monkeypatch.context() as patch:
        patch.setattr(service, "replace_document", write)
        patch.setattr(service, "record", record)
        if boundary == "fsync":
            patch.setattr(instruction_files.os, "fsync", fsync)
        if boundary == "checkpoint":
            patch.setattr(instruction_files, "git_checkpoint", checkpoint)
        identity, base, path, command = bound_instructions(official, expected_status=503)
    assert fired
    with transaction(engine) as db:
        assert db.get(ProjectInstructionBinding, identity).revision == 0
    resumed = client.post(
        f"/api/v1/projects/{identity}/instructions/binding", headers=headers, json=command
    )
    assert resumed.status_code == 200, resumed.text
    assert (path / "rules.md").read_text() == base["rules.md"]


def test_owner_transfer_preview_is_nonmutating_and_preserves_history(official, tmp_path):
    from fastapi.testclient import TestClient
    from sqlalchemy import func, select

    from journeon.api import create_app
    from journeon.browser_auth import BrowserAuth
    from journeon.database import transaction
    from journeon.instruction_config import RootConfiguration
    from journeon.instruction_files import tree_hash
    from journeon.models import (
        InstructionPublication,
        Project,
        ProjectInstructionBinding,
        ProjectInstructionRevision,
        Receipt,
    )

    engine, client, headers, config = official
    identity, base, old_path = bound_instructions(official)
    target = tmp_path / "selected-project"
    target.mkdir()
    config = config.model_copy(
        update={
            "roots": [
                *config.roots,
                RootConfiguration(
                    key="project", path=str(target), role="PROJECT", project_id=identity, revision=1
                ),
            ]
        }
    )
    with TestClient(
        create_app(engine, browser_auth=BrowserAuth("https://example.test"), instructions=config),
        base_url="https://example.test",
    ) as active:
        active.cookies.update(client.cookies)
        observation = active.post(
            "/api/v1/project-roots/inspect",
            headers=headers,
            json={"root_key": "project", "config_revision": 1},
        ).json()
        official_effect(
            active,
            headers,
            {
                "kind": "project.root.admit.v1",
                "idempotency_key": "transfer-root",
                "root_key": "project",
                "config_revision": 1,
                "expected_revision": 0,
                "inspection_digest": observation["digest"],
            },
        )
        command = {
            "idempotency_key": "transfer",
            "project_id": identity,
            "expected_project_revision": 1,
            "expected_binding_revision": 1,
            "root_id": "project",
            "expected_root_revision": 1,
            "expected_tree_hash": tree_hash({}),
            "owner": "PROJECT",
            "documents": [{"path": k, "content": v} for k, v in base.items()],
            "required_fragments": ["rules.md"],
            "reason": "Explicit ownership transfer",
        }

        def counts():
            with transaction(engine) as db:
                return tuple(
                    db.scalar(select(func.count()).select_from(model))
                    for model in (
                        ProjectInstructionBinding,
                        ProjectInstructionRevision,
                        Receipt,
                        InstructionPublication,
                    )
                )

        before = counts()
        preview = active.post(
            f"/api/v1/projects/{identity}/instructions/binding-preview",
            headers=headers,
            json=command,
        )
        assert preview.status_code == 200, preview.text
        assert counts() == before
        assert preview.json()["previous_owner"] == "ENVIRONMENT"
        assert preview.json()["proposed_owner"] == "PROJECT"
        assert str(target) not in preview.text
        accepted = active.post(
            f"/api/v1/projects/{identity}/instructions/binding", headers=headers, json=command
        )
        assert accepted.status_code == 200, accepted.text
        with transaction(engine) as db:
            assert db.get(ProjectInstructionBinding, identity).root_id == "project"
            assert db.get(Project, identity).instruction_owner == "PROJECT"
            assert db.get(Project, identity).revision == 2
            assert db.get(ProjectInstructionRevision, (identity, 1)).snapshot["documents"] == base
        assert (old_path / "rules.md").read_text() == base["rules.md"]
        assert (target / ".journeon" / "instructions" / "rules.md").read_text() == base["rules.md"]
        assert (
            active.post(
                f"/api/v1/projects/{identity}/instructions/binding", headers=headers, json=command
            ).json()
            == accepted.json()
        )


@pytest.mark.parametrize("interruption", ["dirty", "revoke", "generation"])
def test_between_file_effects_never_commits_unresolved_tree(official, monkeypatch, interruption):
    from sqlalchemy import select

    from journeon import project_instructions as service
    from journeon.database import transaction
    from journeon.models import AccessGrant, ProjectInstructionBinding

    engine, client, headers, config = official
    original = service.replace_document
    fired = False

    def replace(root, name, expected, target, **kwargs):
        nonlocal fired
        original(root, name, expected, target, **kwargs)
        if "instructions/projects" in str(root) and not fired:
            fired = True
            if interruption == "dirty":
                (root / "rules.md").write_text("Unaccepted user edit")
            else:
                with transaction(engine) as db:
                    if interruption == "revoke":
                        db.scalar(
                            select(AccessGrant).where(
                                AccessGrant.capability == "project.instruction.accept"
                            )
                        ).enabled = False
                    else:
                        db.scalar(select(ProjectInstructionBinding)).generation += 1

    with monkeypatch.context() as patch:
        patch.setattr(service, "replace_document", replace)
        identity, base, path, command = bound_instructions(
            official, expected_status={"dirty": 503, "revoke": 403, "generation": 409}[interruption]
        )
    assert fired
    with transaction(engine) as db:
        row = db.get(ProjectInstructionBinding, identity)
        assert row.revision == 0 and row.active_operation is not None
    assert (
        client.get(f"/api/v1/projects/{identity}/instructions", headers=headers).status_code == 503
    )
    if interruption == "dirty":
        assert (path / "rules.md").read_text() == "Unaccepted user edit"


def test_large_tree_selects_only_required_fragments_and_preserves_native_guidance(official):
    import hashlib
    from pathlib import Path

    _, client, headers, config = official
    identity, base, path = bound_instructions(
        official, extra={"reference.md": "Unselected reference.\n" * 2000}
    )
    read = client.get(f"/api/v1/projects/{identity}/instructions", headers=headers)
    assert read.status_code == 200, read.text
    assert {document["path"] for document in read.json()["selected_documents"]} == {
        "INDEX.md",
        "rules.md",
    }
    assert {ref["path"] for ref in read.json()["selected_refs"]} == {"INDEX.md", "rules.md"}
    assert sum(len(item["content"]) for item in read.json()["selected_documents"]) < 300
    native = Path(config.roots[0].path) / "CLAUDE.md"
    native.write_text("Existing user guidance")
    command = {
        "idempotency_key": "native",
        "project_id": identity,
        "expected_revision": 1,
        "root_id": "environment",
        "expected_root_revision": 1,
        "filename": "CLAUDE.md",
        "expected_observed_hash": hashlib.sha256(native.read_bytes()).hexdigest(),
    }
    prefix = f"/api/v1/projects/{identity}/instructions/projections/"
    preview = client.post(prefix + "preview", headers=headers, json=command)
    assert preview.status_code == 200 and preview.json()["status"] == "UNMANAGED"
    denied = client.post(prefix + "materialize", headers=headers, json=command)
    assert denied.status_code == 409 and native.read_text() == "Existing user guidance"
    command.update(idempotency_key="owned", filename="AGENTS.md", expected_observed_hash=None)
    accepted = client.post(prefix + "materialize", headers=headers, json=command)
    assert accepted.status_code == 200, accepted.text
    generated = Path(config.roots[0].path) / "AGENTS.md"
    generated.write_text("Later user edit")
    command.update(
        idempotency_key="drift",
        expected_observed_hash=hashlib.sha256(generated.read_bytes()).hexdigest(),
    )
    observed = client.post(prefix + "check", headers=headers, json=command)
    assert observed.status_code == 200 and observed.json()["status"] == "DRIFT"
    assert client.post(prefix + "materialize", headers=headers, json=command).status_code == 409
    assert generated.read_text() == "Later user edit"


@pytest.mark.parametrize("change", ["nonce", "expiry", "session", "epoch", "configuration"])
def test_protected_confirmation_rechecks_current_inputs_before_effect(official, change):
    from journeon.database import transaction
    from journeon.installed_instructions import candidate_manifest
    from journeon.models import BrowserSession, InstructionInstallation, Principal, ProtectedRequest

    engine, client, headers, config = official
    effect = {
        "kind": "instruction.candidate.register.v1",
        "idempotency_key": "guarded-install",
        "manifest_digest": candidate_manifest().digest,
        "expected_revision": 0,
    }
    assert (
        client.post(
            "/api/v1/protected-operations/prepare",
            headers={"Origin": "https://example.test"},
            json={"effect": effect},
        ).status_code
        == 401
    )
    prepared = client.post(
        "/api/v1/protected-operations/prepare", headers=headers, json={"effect": effect}
    )
    preview = client.post(
        "/api/v1/protected-operations/preview", headers=headers, json=prepared.json()
    )
    assert preview.status_code == 200 and preview.headers["cache-control"] == "no-store"
    exact = {name: preview.json()[name] for name in ("request_id", "request_hash", "nonce")}
    with transaction(engine) as db:
        request = db.get(ProtectedRequest, exact["request_id"])
        if change == "nonce":
            exact["nonce"] = "x" * 43
        elif change == "expiry":
            request.nonce_deadline = 0
        elif change == "session":
            db.get(BrowserSession, request.session_id).revoked = True
        elif change == "epoch":
            db.get(Principal, request.principal_id).authorization_epoch += 1
        elif change == "configuration":
            request.policy_hash = "a" * 64
    denied = client.post("/api/v1/protected-operations/confirm", headers=headers, json=exact)
    assert denied.status_code in {401, 403}, denied.text
    with transaction(engine) as db:
        assert db.get(InstructionInstallation, 1) is None


def test_package_update_denies_same_version_bytes_and_switches_versioned_assets(
    official, monkeypatch
):
    from journeon import instruction_admin
    from journeon.database import transaction
    from journeon.installed_instructions import CandidateManifest, candidate_manifest
    from journeon.instructions import digest
    from journeon.models import InstructionInstallation, InstructionRevision

    engine, client, headers, _ = official
    original = candidate_manifest()
    official_effect(
        client,
        headers,
        {
            "kind": "instruction.candidate.register.v1",
            "idempotency_key": "initial",
            "manifest_digest": original.digest,
            "expected_revision": 0,
        },
    )

    def changed(version):
        item = original.assets[0]
        template = item.template.model_copy(
            update={
                "template": item.template.template + "\nPreserve current instruction ownership.\n"
            }
        )
        assets = [
            item.model_copy(
                update={
                    "version": version,
                    "template": template,
                    "content_hash": digest(template.model_dump(mode="json")),
                }
            ),
            original.assets[1],
        ]
        values = {
            "assets": [asset.model_dump(mode="json") for asset in assets],
            "source_digest": original.source_digest,
        }
        return CandidateManifest(
            digest=digest(values), source_digest=original.source_digest, assets=assets
        )

    invalid = changed("1.0.0")
    with monkeypatch.context() as patch:
        patch.setattr(instruction_admin, "candidate_manifest", lambda: invalid)
        effect = {
            "kind": "instruction.candidate.register.v1",
            "idempotency_key": "invalid-update",
            "manifest_digest": invalid.digest,
            "expected_revision": 1,
        }
        prepared = client.post(
            "/api/v1/protected-operations/prepare", headers=headers, json={"effect": effect}
        ).json()
        preview = client.post(
            "/api/v1/protected-operations/preview", headers=headers, json=prepared
        ).json()
        result = client.post(
            "/api/v1/protected-operations/confirm",
            headers=headers,
            json={key: preview[key] for key in ("request_id", "request_hash", "nonce")},
        )
        assert result.status_code == 409, result.text
    valid = changed("1.0.1")
    with monkeypatch.context() as patch:
        patch.setattr(instruction_admin, "candidate_manifest", lambda: valid)
        receipt = official_effect(
            client,
            headers,
            {
                "kind": "instruction.candidate.register.v1",
                "idempotency_key": "versioned-update",
                "manifest_digest": valid.digest,
                "expected_revision": 1,
            },
        )
    assert receipt["revision"] == 2
    with transaction(engine) as db:
        assert (
            db.get(InstructionRevision, ("system-core", 1)).content_hash
            == original.assets[0].content_hash
        )
        assert (
            db.get(InstructionRevision, ("system-core", 2)).content_hash
            == valid.assets[0].content_hash
        )
        assert db.get(InstructionInstallation, 1).manifest_digest == valid.digest


def test_new_project_preset_does_not_configure_other_categories(official):
    _, client, headers, _ = official
    identity, base, _ = bound_instructions(official)
    proposed = client.post(
        f"/api/v1/projects/{identity}/instructions/candidates",
        headers=headers,
        json=candidate_command(identity, base, category="SECURITY"),
    )
    assert proposed.status_code == 200, proposed.text
    accepted = client.post(
        f"/api/v1/projects/{identity}/instructions/accept",
        headers=headers,
        json={
            **reference(proposed.json()),
            "idempotency_key": "unconfigured-security",
            "review_ids": [],
            "eval_ids": [],
        },
    )
    assert accepted.status_code == 503, accepted.text


def test_canonical_symlink_drift_is_sanitized_without_disclosure(official, tmp_path):
    _, client, headers, _ = official
    identity, base, path = bound_instructions(official)
    external = tmp_path / "external.md"
    external.write_text("Outside canonical boundary")
    (path / "rules.md").unlink()
    (path / "rules.md").symlink_to(external)
    response = client.get(f"/api/v1/projects/{identity}/instructions", headers=headers)
    assert response.status_code == 503, response.text
    assert "Outside canonical boundary" not in response.text


def test_two_principals_and_projects_require_explicit_disclosure_scope(official):
    from fastapi.testclient import TestClient

    from journeon.api import create_app
    from journeon.browser_auth import COOKIE_NAME, BrowserAuth
    from journeon.database import transaction
    from journeon.models import AccessGrant, Principal
    from journeon.sessions import issue_session

    engine, client, headers, config = official
    identity, base, _ = bound_instructions(official)
    second = client.post(
        "/api/v1/projects",
        headers=headers,
        json={
            "schema_version": 1,
            "idempotency_key": "second-project",
            "name": "Other project",
            "expected_policy_revision": 1,
        },
    )
    assert second.status_code == 200, second.text
    other_id = second.json()["project"]["project_id"]
    assert (
        client.get(f"/api/v1/projects/{other_id}/instructions", headers=headers).status_code == 403
    )
    with transaction(engine) as db:
        db.add(Principal(id="reader", role="SHARED_USER", enabled=True, authorization_epoch=1))
        db.flush()
        issued = issue_session(
            db,
            "reader",
            authentication_method="test-fixture",
            client_label="Local disclosure fixture",
            strong=True,
        )
    with TestClient(
        create_app(engine, browser_auth=BrowserAuth("https://example.test"), instructions=config),
        base_url="https://example.test",
    ) as shared:
        shared.cookies.set(COOKIE_NAME, issued.token)
        shared_headers = {"Origin": "https://example.test", "X-CSRF-Token": issued.csrf_token}
        query = {"project_id": identity, "revision": 1, "path": "rules.md"}
        url = f"/api/v1/projects/{identity}/instructions/document"
        denied = shared.post(url, headers=shared_headers, json=query)
        assert denied.status_code == 403, denied.text
        with transaction(engine) as db:
            db.add(
                AccessGrant(
                    id="shared-project-read",
                    principal_id="reader",
                    capability="project.instruction.read",
                    resource_kind="project",
                    resource_id=identity,
                    enabled=True,
                    revision=1,
                    provenance="Explicit test sharing",
                )
            )
        allowed = shared.post(url, headers=shared_headers, json=query)
        assert allowed.status_code == 200 and allowed.json()["content"] == base["rules.md"]
        cross = shared.post(
            f"/api/v1/projects/{other_id}/instructions/document",
            headers=shared_headers,
            json={**query, "project_id": other_id},
        )
        assert cross.status_code == 403, cross.text


def test_fresh_exact_recovery_preserves_pending_operation(official, monkeypatch):
    from sqlalchemy import select

    from journeon import project_instructions as service
    from journeon.database import transaction
    from journeon.instruction_files import tree_hash
    from journeon.models import InstructionPublication, ProjectInstructionBinding, Receipt

    engine, client, headers, config = official
    original = service.replace_document

    def fail(path, name, expected, content, **kwargs):
        if kwargs.get("anchor"):
            raise OSError("interrupted fixture")
        return original(path, name, expected, content, **kwargs)

    monkeypatch.setattr(service, "replace_document", fail)
    identity, base, path, command = bound_instructions(official, expected_status=503)
    monkeypatch.setattr(service, "replace_document", original)
    with transaction(engine) as db:
        journal = db.scalar(
            select(InstructionPublication).where(InstructionPublication.project_id == identity)
        )
        binding = db.get(ProjectInstructionBinding, identity)
        operation = journal.id
        effect = dict(
            kind="project.instructions.recover.v1",
            disposition="FINISH_TARGET",
            root_revisions=[{"root_id": "environment", "revision": 1}],
            idempotency_key="fresh-recovery",
            project_id=identity,
            operation_id=operation,
            expected_generation=journal.generation,
            expected_binding_revision=binding.revision,
            expected_policy_revision=binding.policy_revision,
            publication_hash=journal.payload_hash,
            target_hash=tree_hash(journal.snapshot["target"]),
        )
        journal.authentication_ref = "expired-original-session"
    result = official_effect(client, headers, effect)
    assert result["operation_id"] == operation
    assert (path / "rules.md").read_text() == base["rules.md"]
    with transaction(engine) as db:
        assert (
            len(
                list(
                    db.scalars(
                        select(InstructionPublication).where(
                            InstructionPublication.project_id == identity
                        )
                    )
                )
            )
            == 1
        )
        receipt = db.get(Receipt, operation)
        assert receipt.authentication_ref == "expired-original-session"
        assert db.get(ProjectInstructionBinding, identity).active_operation is None


def test_expired_instruction_consent_recovers_with_fresh_exact_request(official, monkeypatch):
    import sys

    from sqlalchemy import select

    from journeon import project_instructions as service
    from journeon.database import transaction
    from journeon.models import InstructionPublication, OutboxEvent, ProtectedRequest, Receipt

    engine, client, headers, config = official
    apply = official_effect
    original = service.replace_document
    old_request = None
    old_operation = None

    def interrupt(path, name, expected, content, **kwargs):
        if kwargs.get("anchor"):
            original(path, name, expected, content, **kwargs)
            raise OSError("crash after known target write")
        return original(path, name, expected, content, **kwargs)

    def recover_effect(client, headers, effect):
        nonlocal old_request, old_operation
        if effect["kind"] != "project.instructions.accept.v1":
            return apply(client, headers, effect)
        prepared = client.post(
            "/api/v1/protected-operations/prepare", headers=headers, json={"effect": effect}
        )
        assert prepared.status_code == 200
        old_request = prepared.json()["request_id"]
        preview = client.post(
            "/api/v1/protected-operations/preview",
            headers=headers,
            json={"request_id": old_request},
        ).json()
        command = {key: preview[key] for key in ("request_id", "request_hash", "nonce")}
        monkeypatch.setattr(service, "replace_document", interrupt)
        assert (
            client.post(
                "/api/v1/protected-operations/confirm", headers=headers, json=command
            ).status_code
            == 503
        )
        monkeypatch.setattr(service, "replace_document", original)
        with transaction(engine) as db:
            row = db.get(ProtectedRequest, old_request)
            row.approval_deadline = 0
            old_operation = row.operation_id
        assert (
            client.post(
                "/api/v1/protected-operations/confirm", headers=headers, json=command
            ).status_code
            == 403
        )
        inspected = client.post(
            f"/api/v1/projects/{effect['project_id']}/instructions/recovery",
            headers=headers,
            json={"project_id": effect["project_id"]},
        )
        assert inspected.status_code == 200, inspected.text
        fresh = {
            "kind": "project.instructions.recover.v1",
            "disposition": "FINISH_TARGET",
            "idempotency_key": "renew-exact",
            **inspected.json(),
        }
        result = apply(client, headers, fresh)
        assert result["operation_id"] == old_operation
        assert (
            client.post(
                "/api/v1/protected-operations/confirm", headers=headers, json=command
            ).status_code
            == 403
        )
        return result

    monkeypatch.setattr(sys.modules[__name__], "official_effect", recover_effect)
    test_exact_instruction_confirmation_enforces_and_commits_same_candidate(official)
    with transaction(engine) as db:
        assert db.get(ProtectedRequest, old_request).state == "APPROVED"
        assert len(list(db.scalars(select(Receipt).where(Receipt.id == old_operation)))) == 1
        assert (
            len(
                list(
                    db.scalars(select(OutboxEvent).where(OutboxEvent.operation_id == old_operation))
                )
            )
            == 1
        )
        assert db.get(InstructionPublication, old_operation).status == "CANONICAL_COMMITTED"


@pytest.mark.parametrize("change", ["target", "generation", "dirty", "grant"])
def test_recovery_rechecks_exact_scope_and_preserves_unknown_bytes(official, monkeypatch, change):
    from sqlalchemy import update

    from journeon import project_instructions as service
    from journeon.database import transaction
    from journeon.models import AccessGrant, InstructionPublication, Receipt

    engine, client, headers, config = official
    original = service.replace_document

    def fail(path, name, expected, content, **kwargs):
        if kwargs.get("anchor"):
            raise OSError("fixture interruption")
        return original(path, name, expected, content, **kwargs)

    monkeypatch.setattr(service, "replace_document", fail)
    identity, base, path, command = bound_instructions(official, expected_status=503)
    monkeypatch.setattr(service, "replace_document", original)
    target = client.post(
        f"/api/v1/projects/{identity}/instructions/recovery",
        headers=headers,
        json={"project_id": identity},
    ).json()
    if change == "target":
        target["target_hash"] = "0" * 64
    if change == "generation":
        target["expected_generation"] += 1
    prepared = client.post(
        "/api/v1/protected-operations/prepare",
        headers=headers,
        json={
            "effect": {
                "kind": "project.instructions.recover.v1",
                "disposition": "FINISH_TARGET",
                "idempotency_key": "negative",
                **target,
            }
        },
    )
    assert prepared.status_code == 200, prepared.text
    request = prepared.json()
    preview = client.post("/api/v1/protected-operations/preview", headers=headers, json=request)
    assert preview.status_code == 200
    if change == "dirty":
        path.mkdir(parents=True, exist_ok=True)
        (path / "rules.md").write_text("Unknown external content")
    if change == "grant":
        with transaction(engine) as db:
            db.execute(
                update(AccessGrant)
                .where(
                    AccessGrant.resource_id == identity,
                    AccessGrant.capability == "project.instruction.accept",
                )
                .values(enabled=False)
            )
            # A denied caller must not decode even damaged retained request JSON.
            from sqlalchemy import text

            db.execute(
                text("UPDATE protected_requests SET payload=:broken WHERE id=:identity"),
                {"broken": "invalid-json", "identity": request["request_id"]},
            )
    confirmed = client.post(
        "/api/v1/protected-operations/confirm",
        headers=headers,
        json={key: preview.json()[key] for key in ("request_id", "request_hash", "nonce")},
    )
    assert (
        confirmed.status_code
        == {"target": 409, "generation": 409, "dirty": 503, "grant": 403}[change]
    ), confirmed.text
    if change == "dirty":
        assert (path / "rules.md").read_text() == "Unknown external content"
    with transaction(engine) as db:
        assert db.get(Receipt, target["operation_id"]) is None
        assert (
            db.get(InstructionPublication, target["operation_id"]).status != "CANONICAL_COMMITTED"
        )


def test_restore_creates_new_candidate_under_current_gates(official):
    from sqlalchemy import select

    from journeon.database import transaction
    from journeon.models import ProjectInstructionBinding, ProjectInstructionRevision

    engine, client, headers, config = official
    test_exact_instruction_confirmation_enforces_and_commits_same_candidate(official)
    with transaction(engine) as db:
        binding = db.scalar(select(ProjectInstructionBinding))
        identity = binding.project_id
        current_hash = binding.tree_hash
        historic = db.get(ProjectInstructionRevision, (identity, 1)).snapshot
    restored = client.post(
        f"/api/v1/projects/{identity}/instructions/restore",
        headers=headers,
        json={
            "idempotency_key": "restore-old",
            "project_id": identity,
            "revision": 1,
            "expected_revision": 2,
            "expected_tree_hash": current_hash,
            "reason": "Restore recorded instructions",
        },
    )
    assert restored.status_code == 200, restored.text
    value = restored.json()
    reference = {
        key: value[key]
        for key in (
            "project_id",
            "candidate_id",
            "candidate_hash",
            "expected_binding_revision",
            "expected_policy_revision",
        )
    }
    evaluated = client.post(
        f"/api/v1/projects/{identity}/instructions/evals", headers=headers, json=reference
    )
    assert evaluated.status_code == 200
    accept = {
        **reference,
        "idempotency_key": "restore-accept",
        "review_ids": [],
        "eval_ids": [evaluated.json()["evidence_id"]],
    }
    assert (
        client.post(
            f"/api/v1/projects/{identity}/instructions/accept", headers=headers, json=accept
        ).status_code
        == 403
    )
    result = official_effect(client, headers, {"kind": "project.instructions.accept.v1", **accept})
    assert result["revision"] == 3
    with transaction(engine) as db:
        assert db.get(ProjectInstructionRevision, (identity, 1)).snapshot == historic
        assert (
            db.get(ProjectInstructionRevision, (identity, 3)).snapshot["documents"]
            == historic["documents"]
        )


def test_changed_policy_allows_exact_abandon_and_new_binding(official, monkeypatch):
    from journeon import project_instructions as service
    from journeon.database import transaction
    from journeon.models import InstructionPublication, ProjectInstructionBinding

    engine, client, headers, config = official
    original = service.replace_document

    def interrupt(path, name, expected, content, **kwargs):
        result = original(path, name, expected, content, **kwargs)
        if kwargs.get("anchor"):
            raise OSError("known partial write")
        return result

    monkeypatch.setattr(service, "replace_document", interrupt)
    identity, base, path, command = bound_instructions(official, expected_status=503)
    monkeypatch.setattr(service, "replace_document", original)
    official_effect(
        client,
        headers,
        {
            "kind": "project.instructions.policy.configure.v1",
            "idempotency_key": "changed-policy",
            "project_id": identity,
            "expected_project_revision": 1,
            "expected_binding_revision": 0,
            "expected_root_revision": 1,
            "expected_policy_revision": 1,
            "policy": {
                "authorized_categories": ["ORDINARY"],
                "navigation_repairs": False,
                "independent_review": True,
                "require_confirmation": True,
                "required_evals": ["instruction-boundaries-v1"],
            },
        },
    )
    target = client.post(
        f"/api/v1/projects/{identity}/instructions/recovery",
        headers=headers,
        json={"project_id": identity},
    ).json()
    result = official_effect(
        client,
        headers,
        {
            "kind": "project.instructions.recover.v1",
            "disposition": "RESTORE_BASE",
            "idempotency_key": "abandon-old-target",
            **target,
        },
    )
    assert result["operation_id"] == target["operation_id"]
    assert result["status"] == "ABANDONED"
    assert not (path / "INDEX.md").exists()
    with transaction(engine) as db:
        binding = db.get(ProjectInstructionBinding, identity)
        assert (
            binding.active_operation is None
            and binding.revision == 0
            and binding.policy_revision == 2
        )
        assert db.get(InstructionPublication, target["operation_id"]).status == "ABANDONED"
    response = client.post(
        f"/api/v1/projects/{identity}/instructions/binding",
        headers=headers,
        json={**command, "idempotency_key": "bind-after-abandon"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "CANONICAL_COMMITTED"


@pytest.mark.parametrize("disposition", ["FINISH_TARGET", "RESTORE_BASE", "SUBSTITUTED"])
def test_recovery_after_same_root_readmission_uses_fresh_binding(
    official, monkeypatch, disposition
):
    from journeon import project_instructions as service
    from journeon.database import transaction
    from journeon.models import ProjectInstructionBinding

    engine, client, headers, config = official
    original = service.replace_document

    def fail(path, name, expected, content, **kwargs):
        if kwargs.get("anchor"):
            raise OSError("fixture interruption")
        return original(path, name, expected, content, **kwargs)

    monkeypatch.setattr(service, "replace_document", fail)
    identity, base, path, command = bound_instructions(official, expected_status=503)
    monkeypatch.setattr(service, "replace_document", original)
    official_effect(
        client,
        headers,
        {
            "kind": "project.root.revoke.v1",
            "idempotency_key": "revoke",
            "root_id": "environment",
            "expected_revision": 1,
        },
    )
    url = f"/api/v1/projects/{identity}/instructions/recovery"
    assert client.post(url, headers=headers, json={"project_id": identity}).status_code == 403
    if disposition == "SUBSTITUTED":
        from pathlib import Path

        root_path = Path(config.roots[0].path)
        root_path.rename(root_path.with_name("retained-original-root"))
        root_path.mkdir()
        (root_path / "unknown.txt").write_text("Preserve substituted root")
    observation = client.post(
        "/api/v1/project-roots/inspect",
        headers=headers,
        json={"root_key": "environment", "config_revision": 1},
    ).json()
    official_effect(
        client,
        headers,
        {
            "kind": "project.root.admit.v1",
            "idempotency_key": "readmit",
            "root_key": "environment",
            "config_revision": 1,
            "inspection_digest": observation["digest"],
            "expected_revision": 2,
        },
    )
    target = client.post(url, headers=headers, json={"project_id": identity})
    if disposition == "SUBSTITUTED":
        assert target.status_code == 409, target.text
        assert (root_path / "unknown.txt").read_text() == "Preserve substituted root"
        return
    assert target.status_code == 200, target.text
    result = official_effect(
        client,
        headers,
        {
            "kind": "project.instructions.recover.v1",
            "idempotency_key": "recover-readmitted",
            "disposition": disposition,
            **target.json(),
        },
    )
    assert result["status"] == (
        "CANONICAL_COMMITTED" if disposition == "FINISH_TARGET" else "ABANDONED"
    )
    with transaction(engine) as db:
        binding = db.get(ProjectInstructionBinding, identity)
        assert binding.root_revision == 3 and binding.active_operation is None
    if disposition == "RESTORE_BASE":
        response = client.post(
            f"/api/v1/projects/{identity}/instructions/binding",
            headers=headers,
            json={**command, "expected_root_revision": 3, "idempotency_key": "new-current-binding"},
        )
        assert response.status_code == 200, response.text


@pytest.mark.parametrize("disposition", ["FINISH_TARGET", "RESTORE_BASE"])
def test_projection_recovery_preserves_original_effect_identity(official, monkeypatch, disposition):
    from journeon import project_instructions as service
    from journeon.database import transaction
    from journeon.models import Receipt

    engine, client, headers, config = official
    identity, base, path = bound_instructions(official)
    original = service.replace_document

    def interrupt(path, name, expected, content, **kwargs):
        original(path, name, expected, content, **kwargs)
        if kwargs.get("anchor"):
            raise OSError("projection post-effect interruption")

    monkeypatch.setattr(service, "replace_document", interrupt)
    response = client.post(
        f"/api/v1/projects/{identity}/instructions/projections/materialize",
        headers=headers,
        json={
            "idempotency_key": "projection-recovery",
            "project_id": identity,
            "expected_revision": 1,
            "root_id": "environment",
            "expected_root_revision": 1,
            "filename": "AGENTS.md",
            "expected_observed_hash": None,
        },
    )
    assert response.status_code == 503, response.text
    monkeypatch.setattr(service, "replace_document", original)
    target = client.post(
        f"/api/v1/projects/{identity}/instructions/recovery",
        headers=headers,
        json={"project_id": identity},
    )
    assert target.status_code == 200
    result = official_effect(
        client,
        headers,
        {
            "kind": "project.instructions.recover.v1",
            "idempotency_key": "recover-projection",
            "disposition": disposition,
            **target.json(),
        },
    )
    assert result["operation_id"] == target.json()["operation_id"]
    assert result["status"] == (
        "CANONICAL_COMMITTED" if disposition == "FINISH_TARGET" else "ABANDONED"
    )
    from pathlib import Path

    assert (Path(config.roots[0].path) / "AGENTS.md").exists() == (disposition == "FINISH_TARGET")
    with transaction(engine) as db:
        assert (
            db.get(Receipt, result["operation_id"]).command == "project.instructions.projection.v1"
        )


@pytest.mark.parametrize(
    "table", ["instruction_roots", "instruction_publications", "instruction_request_scopes"]
)
def test_instruction_boolean_metadata_rejects_raw_invalid_values(official, table):
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    from journeon.database import transaction

    engine, client, headers, config = official
    identity, base, path = bound_instructions(official)
    prepared = client.post(
        "/api/v1/protected-operations/prepare",
        headers=headers,
        json={
            "effect": {
                "kind": "project.instructions.accept.v1",
                "idempotency_key": "unconfirmed-scope",
                "project_id": identity,
                "candidate_id": "unconfirmed-candidate",
                "candidate_hash": "a" * 64,
                "expected_binding_revision": 1,
                "expected_policy_revision": 1,
                "review_ids": [],
                "eval_ids": [],
            }
        },
    )
    assert prepared.status_code == 200, prepared.text
    column = "enabled" if table == "instruction_roots" else "projection"
    with transaction(engine) as db:
        assert db.scalar(text(f"SELECT count(*) FROM {table}")) > 0
    for invalid in (2, -1, 0.5, "true", b"1"):
        with pytest.raises(IntegrityError), transaction(engine) as db:
            db.execute(text(f"UPDATE {table} SET {column}=:invalid"), {"invalid": invalid})
    with transaction(engine) as db:
        values = set(db.scalars(text(f"SELECT {column} FROM {table}")))
        assert values == ({1} if column == "enabled" else {0})
