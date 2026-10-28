# SPDX-License-Identifier: AGPL-3.0-only

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_attempt_snapshots import git
from test_production_instructions import bound_instructions, official, official_effect  # noqa: F401

from journeon.api import create_app
from journeon.attempt_contracts import AttemptConfiguration
from journeon.database import transaction
from journeon.installed_instructions import candidate_manifest
from journeon.models import AccessGrant, AttemptEffect, AttemptManifest, Principal


@pytest.fixture
def attempt_environment(official, tmp_path, request):  # noqa: F811
    engine, client, headers, config = official
    root = tmp_path / "project-source"
    root.mkdir()
    if getattr(request, "param", True):
        git(root, "init", "-q")
        git(root, "config", "user.name", "Fixture")
        git(root, "config", "user.email", "fixture@example.invalid")
        (root / "source.txt").write_text("base")
        git(root, "add", ".")
        git(root, "commit", "-qm", "fixture")
    else:
        (root / "source.txt").write_text("directory source")
    project, _, _ = bound_instructions(official)
    official_effect(
        client,
        headers,
        {
            "kind": "instruction.candidate.register.v1",
            "idempotency_key": "package",
            "manifest_digest": candidate_manifest().digest,
            "expected_revision": 0,
        },
    )
    with transaction(engine) as db:
        principal = db.scalar(select(Principal).where(Principal.role == "OWNER"))
        for action in (
            "project.read",
            "project.verification.configure",
            "project.verification.read",
            "task.create",
            "task.read",
            "task.receipt.read",
            "execution.admit",
            "attempt.prepare",
            "attempt.read",
            "attempt.receipt.read",
        ):
            db.add(
                AccessGrant(
                    id="attempt:" + action,
                    principal_id=principal.id,
                    capability=action,
                    resource_kind="project",
                    resource_id=project,
                    enabled=True,
                    revision=1,
                    provenance="Explicit disposable fixture authority",
                )
            )
    project_view = client.get("/api/v1/projects/" + project).json()
    response = client.post(
        "/api/v1/projects/verification",
        headers=headers,
        json={
            "schema_version": 1,
            "idempotency_key": "verification",
            "project_id": project,
            "expected_project_revision": project_view["revision"],
            "expected_policy_revision": 0,
            "enabled": True,
            "checks": [
                {
                    "check_id": "check",
                    "criterion": "Command succeeds",
                    "argv": ["/usr/bin/true"],
                    "working_directory": ".",
                    "expected_exit_code": 0,
                }
            ],
            "workflow": {
                "steps": [{"step_id": "verify", "kind": "VERIFICATION", "check_id": "check"}]
            },
        },
    )
    assert response.status_code == 200, response.text
    current = client.get("/api/v1/projects/" + project).json()
    response = client.post(
        "/api/v1/tasks",
        headers=headers,
        json={
            "schema_version": 1,
            "idempotency_key": "task",
            "project_id": project,
            "expected_project_revision": current["revision"],
            "objective": "Verify this workspace",
            "responsibility": "HUMAN",
        },
    )
    assert response.status_code == 200, response.text
    task = response.json()["task"]
    storage = tmp_path / "attempt-storage"
    storage.mkdir(mode=0o700)
    config = config.model_copy(
        update={
            "attempts": AttemptConfiguration(
                storage_path=str(storage),
                revision=1,
                snapshot_bytes=1048576,
                snapshot_files=100,
                pending_bytes=10485760,
                pending_count=10,
                lease_seconds=120,
                workspaces=[
                    {
                        "key": "fixture",
                        "revision": 1,
                        "project_id": project,
                        "root_key": "environment"
                        if getattr(request, "param", True) == "ENVIRONMENT"
                        else "project-source",
                        "root_revision": 1,
                    }
                ],
            )
        }
    )
    from journeon.instruction_config import RootConfiguration
    from journeon.passkeys import STANDARD_PASSKEY_POLICY, PasskeyService

    config = config.model_copy(
        update={
            "roots": [
                *config.roots,
                RootConfiguration(
                    key="project-source",
                    path=str(root),
                    role="PROJECT",
                    project_id=project,
                    revision=1,
                ),
            ]
        }
    )
    passkeys = PasskeyService(
        engine, rp_id="example.test", origin="https://example.test", policy=STANDARD_PASSKEY_POLICY
    )
    attempt_client = TestClient(
        create_app(
            engine,
            browser_auth=client.app.state.browser_auth,
            passkeys=passkeys,
            instructions=config,
        ),
        base_url="https://example.test",
        cookies=client.cookies,
    )
    observed_root = attempt_client.post(
        "/api/v1/project-roots/inspect",
        headers=headers,
        json={"root_key": "project-source", "config_revision": 1},
    )
    assert observed_root.status_code == 200, observed_root.text
    official_effect(
        attempt_client,
        headers,
        {
            "kind": "project.root.admit.v1",
            "idempotency_key": "project-source-root",
            "root_key": "project-source",
            "config_revision": 1,
            "expected_revision": 0,
            "inspection_digest": observed_root.json()["digest"],
        },
    )
    command = {
        "schema_version": 1,
        "idempotency_key": "attempt",
        "origin": {"kind": "TASK", "task_id": task["task_id"], "task_revision": task["revision"]},
        "project_id": project,
        "expected_policy_revision": 1,
        "workspace_key": "fixture",
        "workspace_revision": 1,
    }
    yield engine, attempt_client, headers, config, command, root, storage
    attempt_client.close()


def test_canonical_attempt_uses_real_instruction_and_workspace_producers(attempt_environment):
    engine, client, headers, config, command, root, storage = attempt_environment
    (root / "source.txt").write_text("staged")
    git(root, "add", "source.txt")
    (root / "source.txt").write_text("working")
    response = client.post("/api/v1/attempts/prepare", headers=headers, json=command)
    assert response.status_code == 200, response.text
    result = response.json()
    attempt = result["attempt"]
    manifest = attempt["manifest"]
    assert attempt["state"] == "PREPARED"
    assert not attempt["execution_authorized"]
    assert manifest["task"]["task_id"] == command["origin"]["task_id"]
    assert manifest["instruction_bundle"]["kind"] == "DETERMINISTIC"
    assert [
        item["purpose"]
        for item in __import__("json").loads(manifest["instruction_bundle"]["rendering"])
    ] == ["CORE", "NAVIGATION", "PROJECT", "TASK", "WORKFLOW"]
    target = storage / attempt["attempt_id"] / "workspace"
    assert git(target, "show", ":source.txt") == "staged"
    assert (target / "source.txt").read_text() == "working"
    assert client.post("/api/v1/attempts/prepare", headers=headers, json=command).json() == result
    assert client.get("/api/v1/attempts/" + attempt["attempt_id"]).json() == attempt
    assert client.get("/api/v1/operations/" + result["operation_id"]).json() == result
    with transaction(engine) as db:
        assert db.scalar(select(AttemptManifest)).content_hash == manifest["content_digest"]
        assert db.scalar(select(AttemptEffect)).state == "APPLIED"


def test_revoked_preparation_grant_blocks_replay_and_new_effects(attempt_environment):
    engine, client, headers, _, command, _, storage = attempt_environment
    first = client.post("/api/v1/attempts/prepare", headers=headers, json=command)
    assert first.status_code == 200, first.text
    before = sorted(path.name for path in storage.iterdir())
    with transaction(engine) as db:
        db.get(AccessGrant, "attempt:attempt.prepare").enabled = False
    response = client.post("/api/v1/attempts/prepare", headers=headers, json=command)
    assert response.status_code == 403, response.text
    assert sorted(path.name for path in storage.iterdir()) == before


def test_revocation_during_preparation_retains_uncertain_effect(attempt_environment, monkeypatch):
    from journeon import attempts
    from journeon.models import Attempt

    engine, client, headers, _, command, _, _ = attempt_environment
    original = attempts.materialize_worktree

    def revoke_after_write(*args, **kwargs):
        original(*args, **kwargs)
        with transaction(engine) as db:
            db.get(AccessGrant, "attempt:attempt.prepare").enabled = False

    monkeypatch.setattr(attempts, "materialize_worktree", revoke_after_write)
    response = client.post("/api/v1/attempts/prepare", headers=headers, json=command)
    assert response.status_code == 403, response.text
    with transaction(engine) as db:
        assert db.scalar(select(AttemptManifest)) is None
        assert db.scalar(select(AttemptEffect)).state == "UNKNOWN"
        assert db.scalar(select(Attempt)).snapshot["state"] == "RECOVERY_REQUIRED"


@pytest.mark.parametrize("attempt_environment", [False], indirect=True)
def test_non_git_attempt_uses_owned_snapshot_and_lease(attempt_environment):
    engine, client, headers, _, command, _, storage = attempt_environment
    response = client.post("/api/v1/attempts/prepare", headers=headers, json=command)
    assert response.status_code == 200, response.text
    attempt = response.json()["attempt"]
    assert attempt["manifest"]["workspace_kind"] == "DIRECTORY"
    assert (
        storage / attempt["attempt_id"] / "workspace" / "source.txt"
    ).read_text() == "directory source"
    from journeon.models import WorkspaceLease

    with transaction(engine) as db:
        assert db.scalar(select(WorkspaceLease)).attempt_id == attempt["attempt_id"]


@pytest.mark.parametrize("attempt_environment", ["ENVIRONMENT"], indirect=True)
def test_environment_instruction_root_cannot_be_a_project_workspace(attempt_environment):
    engine, client, headers, _, command, _, storage = attempt_environment
    from journeon.models import Attempt

    response = client.post("/api/v1/attempts/prepare", headers=headers, json=command)
    assert response.status_code == 403, response.text
    assert not list(storage.iterdir())
    with transaction(engine) as db:
        assert db.scalar(select(Attempt)) is None


def test_root_revocation_blocks_attempt_disclosure_and_replay(attempt_environment):
    from journeon.models import InstructionRoot

    engine, client, headers, _, command, _, _ = attempt_environment
    first = client.post("/api/v1/attempts/prepare", headers=headers, json=command)
    assert first.status_code == 200, first.text
    identity = first.json()["attempt"]["attempt_id"]
    with transaction(engine) as db:
        db.get(InstructionRoot, "project-source").enabled = False
    assert client.get("/api/v1/attempts/" + identity).status_code == 403
    assert client.post("/api/v1/attempts/prepare", headers=headers, json=command).status_code == 403
    assert client.get("/api/v1/operations/" + first.json()["operation_id"]).status_code == 403


def test_restart_reconciles_exact_completed_workspace_without_repeating_effect(
    attempt_environment, monkeypatch
):
    from journeon import attempts
    from journeon.contracts import DomainError

    _, client, headers, _, command, _, storage = attempt_environment
    original = attempts.materialize_worktree
    calls = []

    def interrupted(*args, **kwargs):
        original(*args, **kwargs)
        calls.append("effect")
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Disposable interruption after workspace write")

    monkeypatch.setattr(attempts, "materialize_worktree", interrupted)
    first = client.post("/api/v1/attempts/prepare", headers=headers, json=command)
    assert first.status_code == 503, first.text
    before = sorted(path.name for path in storage.iterdir())
    second = client.post("/api/v1/attempts/prepare", headers=headers, json=command)
    assert second.status_code == 200, second.text
    assert calls == ["effect"]
    assert sorted(path.name for path in storage.iterdir()) == before


@pytest.mark.parametrize("state", ["RUNNING", "REVIEW", "DONE", "CANCELLED", "ARCHIVED"])
def test_task_settlement_blocks_new_attempt(attempt_environment, state):
    from journeon.models import Task

    engine, client, headers, _, command, _, storage = attempt_environment
    with transaction(engine) as db:
        row = db.get(Task, command["origin"]["task_id"])
        row.snapshot = row.snapshot | {"state": state}
    response = client.post("/api/v1/attempts/prepare", headers=headers, json=command)
    assert response.status_code == 409, response.text
    assert not list(storage.iterdir())


def test_attempt_read_rejects_corrupt_manifest_after_authorization(attempt_environment):
    from journeon.models import Attempt

    engine, client, headers, _, command, _, _ = attempt_environment
    response = client.post("/api/v1/attempts/prepare", headers=headers, json=command)
    assert response.status_code == 200, response.text
    identity = response.json()["attempt"]["attempt_id"]
    with transaction(engine) as db:
        row = db.get(Attempt, identity)
        row.snapshot = row.snapshot | {
            "manifest": row.snapshot["manifest"] | {"content_digest": "0" * 64}
        }
    assert client.get("/api/v1/attempts/" + identity).status_code == 503
    with transaction(engine) as db:
        db.get(AccessGrant, "attempt:attempt.read").enabled = False
    assert client.get("/api/v1/attempts/" + identity).status_code == 403


def test_live_writer_lock_blocks_lease_takeover(attempt_environment):
    import hashlib
    import subprocess
    import sys
    from datetime import UTC, datetime, timedelta

    from journeon.models import WorkspaceLease

    engine, client, headers, _, command, _, storage = attempt_environment
    first = client.post("/api/v1/attempts/prepare", headers=headers, json=command)
    assert first.status_code == 200, first.text
    lock = storage / ("workspace-" + hashlib.sha256(b"project-source").hexdigest() + ".lock")
    script = (
        'import fcntl,sys; f=open(sys.argv[1],"r+"); fcntl.flock(f,fcntl.LOCK_EX); '
        'print("locked",flush=True); sys.stdin.read()'
    )
    holder = subprocess.Popen(
        [sys.executable, "-c", script, str(lock)], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    try:
        assert holder.stdout.readline() == b"locked\n"
        with transaction(engine) as db:
            db.scalar(select(WorkspaceLease)).deadline = (
                datetime.now(UTC) - timedelta(seconds=10)
            ).isoformat()
        response = client.post(
            "/api/v1/attempts/prepare",
            headers=headers,
            json=command | {"idempotency_key": "competing"},
        )
        assert response.status_code == 409, response.text
    finally:
        holder.stdin.close()
        assert holder.wait(timeout=10) == 0
        holder.stdout.close()


def test_changed_interrupted_workspace_is_never_overwritten(attempt_environment, monkeypatch):
    from journeon import attempts
    from journeon.contracts import DomainError

    _, client, headers, _, command, _, storage = attempt_environment
    original = attempts.materialize_worktree
    target = None

    def interrupted(source, destination, *args):
        nonlocal target
        original(source, destination, *args)
        target = destination
        (target / "source.txt").write_text("Unrecognized later work")
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Disposable interruption")

    monkeypatch.setattr(attempts, "materialize_worktree", interrupted)
    assert client.post("/api/v1/attempts/prepare", headers=headers, json=command).status_code == 503
    assert client.post("/api/v1/attempts/prepare", headers=headers, json=command).status_code == 503
    assert (target / "source.txt").read_text() == "Unrecognized later work"


def test_host_attempt_configuration_rejects_ambiguous_storage():
    from pydantic import ValidationError

    values = dict(
        storage_path="relative",
        revision=1,
        snapshot_bytes=1024,
        snapshot_files=10,
        pending_bytes=2048,
        pending_count=2,
        lease_seconds=30,
        workspaces=[
            dict(key="project", revision=1, project_id="project", root_key="root", root_revision=1)
        ],
    )
    with pytest.raises(ValidationError):
        AttemptConfiguration(**values)


def test_attempt_storage_budget_includes_retained_attempts(attempt_environment):
    from journeon.models import AttemptEffect

    engine, client, headers, configuration, command, _, storage = attempt_environment
    first = client.post("/api/v1/attempts/prepare", headers=headers, json=command)
    assert first.status_code == 200, first.text
    with transaction(engine) as db:
        effect = db.scalar(select(AttemptEffect))
        reserved = effect.snapshot.get("storage_bytes", 0)
    assert reserved > 0
    configuration = configuration.model_copy(
        update={
            "attempts": configuration.attempts.model_copy(
                update={"pending_bytes": reserved * 2 - 1}
            )
        }
    )
    before = {path.name for path in storage.iterdir()}
    with TestClient(
        create_app(engine, browser_auth=client.app.state.browser_auth, instructions=configuration),
        base_url="https://example.test",
        cookies=client.cookies,
    ) as restarted:
        second = restarted.post(
            "/api/v1/attempts/prepare",
            headers=headers,
            json=command | {"idempotency_key": "second-storage-claim"},
        )
    assert second.status_code == 503, second.text
    assert {path.name for path in storage.iterdir()} == before
