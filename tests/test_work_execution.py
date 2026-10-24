# SPDX-License-Identifier: AGPL-3.0-only
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_production_instructions import bound_instructions, official_effect
from test_production_instructions import official as _official
from test_runtime import certificate

from journeon.database import transaction
from journeon.instruction_files import tree_hash
from journeon.models import AccessGrant, BrowserSession, Job, Principal, ProjectInstructionRevision
from journeon.project_instructions import navigation
from journeon.runtime import RuntimeConfig, application


@pytest.fixture
def official(tmp_path):
    yield from _official.__wrapped__(tmp_path)


def propose(official):
    engine, client, headers, config = official
    identity, base, path = bound_instructions(official)
    target = {**base, "INDEX.md": navigation(base, ["rules.md"])}
    command = dict(
        idempotency_key="navigation",
        project_id=identity,
        expected_revision=1,
        expected_tree_hash=tree_hash(base),
        documents=[{"path": k, "content": v} for k, v in target.items()],
        required_fragments=["rules.md"],
        reason="Restore canonical navigation",
        source_refs=["canonical-tree"],
        category="NAVIGATION_REPAIR",
    )
    response = client.post(
        f"/api/v1/projects/{identity}/instructions/candidates", headers=headers, json=command
    )
    assert response.status_code == 200, response.text
    return identity, base, path, response.json(), command


def runtime_settings(official, tmp_path, database=None):
    engine, _, _, config = official
    cert, key = certificate(tmp_path, "jobs")
    return RuntimeConfig(
        host="127.0.0.1",
        port=9443,
        origin="https://example.test",
        rp_id="example.test",
        database=database or str(engine.url.database),
        tls_certificate=str(cert),
        tls_private_key=str(key),
        trusted_proxy_peers=[],
        busy_timeout_ms=5000,
        backlog=8,
        limit_concurrency=8,
        timeout_keep_alive=1,
        timeout_graceful_shutdown=2,
        instructions=config,
    )


def settle(client, headers, identity):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/jobs/{identity}", headers=headers)
        assert response.status_code == 200, response.text
        if response.json()["state"] not in {"QUEUED", "RUNNING", "RETRY_WAIT"}:
            return response.json()
        time.sleep(0.02)
    pytest.fail("Runtime did not settle the admitted Job")


def test_real_runtime_dispatch_and_deduplicated_receipts(official, tmp_path):
    engine, client, headers, _ = official
    project, base, path, candidate, command = propose(official)
    assert (path / "INDEX.md").read_text() == base["INDEX.md"]
    again = client.post(
        f"/api/v1/projects/{project}/instructions/candidates", headers=headers, json=command
    )
    assert again.json() == candidate
    with transaction(engine) as db:
        session = db.scalar(select(BrowserSession))
        last_activity = session.last_activity
    with TestClient(
        application(runtime_settings(official, tmp_path)), base_url="https://example.test"
    ) as running:
        running.cookies.update(client.cookies)
        job = settle(running, headers, candidate["job_id"])
        assert job["state"] == "SUCCEEDED", job
        assert job["effect"] == "COMMITTED"
        assert (path / "INDEX.md").read_text() == navigation(base, ["rules.md"])
        for operation in (job["admission_id"], job["operation_id"]):
            assert (
                running.get(f"/api/v1/operations/{operation}", headers=headers).status_code == 200
            )
        page = running.post("/api/v1/events/replay", headers=headers, json={"limit": 100})
        assert page.status_code == 200, page.text
        assert any(event["event_type"] == "job.admitted" for event in page.json()["events"])
    with transaction(engine) as db:
        assert db.scalar(select(BrowserSession)).last_activity == last_activity
        assert len(list(db.scalars(select(Job)))) == 1


def test_cancel_before_claim_and_revoked_original_session(official, tmp_path):
    engine, client, headers, _ = official
    _, base, path, candidate, _ = propose(official)
    response = client.post(
        f"/api/v1/jobs/{candidate['job_id']}/cancel", headers=headers, json={"expected_revision": 1}
    )
    assert response.status_code == 200
    with TestClient(
        application(runtime_settings(official, tmp_path)), base_url="https://example.test"
    ) as running:
        running.cookies.update(client.cookies)
        assert settle(running, headers, candidate["job_id"])["state"] == "CANCELLED"
    assert (path / "INDEX.md").read_text() == base["INDEX.md"]
    with transaction(engine) as db:
        assert db.get(Job, candidate["job_id"]).operation_id is None


def test_revocation_blocks_claim_without_extending_idle(official):
    from journeon.jobs import JobService

    engine, _, _, config = official
    _, base, path, candidate, _ = propose(official)
    with transaction(engine) as db:
        session = db.scalar(select(BrowserSession))
        activity = session.last_activity
        session.revoked = True
    service = JobService(engine, config)
    assert service.claim() is None
    with transaction(engine) as db:
        assert db.get(Job, candidate["job_id"]).state == "FAILED"
        assert db.scalar(select(BrowserSession)).last_activity == activity
    assert (path / "INDEX.md").read_text() == base["INDEX.md"]


@pytest.fixture
def prepared_restore(official, tmp_path):
    from journeon.api import create_app
    from journeon.browser_auth import BrowserAuth
    from journeon.instruction_config import InstructionConfiguration
    from journeon.operations import snapshot_database

    engine, client, headers, config = official
    project, _, path, candidate, _ = propose(official)
    snapshots, destinations = tmp_path / "snapshots", tmp_path / "restores"
    snapshots.mkdir()
    destinations.mkdir()
    config = InstructionConfiguration.model_validate(
        {
            **config.model_dump(),
            "restore": {"snapshot_root": str(snapshots), "destination_root": str(destinations)},
        }
    )
    configured = (engine, client, headers, config)
    from journeon.sessions import issue_session

    with transaction(engine) as db:
        principal = db.scalar(select(Principal).where(Principal.role == "OWNER"))
        retired = issue_session(
            db,
            principal.id,
            authentication_method="synthetic-revocation-boundary",
            client_label="Retired recovery session",
            strong=True,
        )
        retired_id = retired.session_id
        db.add(
            AccessGrant(
                id="retired-restore-grant",
                principal_id=principal.id,
                capability="historical.unavailable",
                resource_kind="deployment",
                resource_id="deployment",
                enabled=True,
                revision=1,
                provenance="Synthetic stale grant boundary",
            )
        )
    pending = client.post(
        "/api/v1/protected-operations/prepare",
        headers=headers,
        json={
            "effect": {
                "kind": "project.root.revoke.v1",
                "idempotency_key": "old-pending-request",
                "root_id": "environment",
                "expected_revision": 1,
            }
        },
    )
    assert pending.status_code == 200, pending.text
    snapshot_database(Path(str(engine.url.database)), snapshots / "before")
    with transaction(engine) as db:
        db.get(BrowserSession, retired_id).revoked = True
        db.get(AccessGrant, "retired-restore-grant").enabled = False
    with TestClient(
        application(runtime_settings(configured, tmp_path)), base_url="https://example.test"
    ) as running:
        running.cookies.update(client.cookies)
        assert settle(running, headers, candidate["job_id"])["state"] == "SUCCEEDED"
    client.close()
    client = TestClient(
        create_app(engine, browser_auth=BrowserAuth("https://example.test"), instructions=config),
        base_url="https://example.test",
    )
    client.cookies.update(official[1].cookies)
    with transaction(engine) as db:
        old = db.get(ProjectInstructionRevision, (project, 1))
        assert old is not None
        from sqlalchemy import text

        trigger = db.execute(
            text(
                "SELECT sql FROM sqlite_master WHERE name='immutable_project_instr"
                "uction_revisions_delete'"
            )
        ).scalar_one()
        db.execute(text("DROP TRIGGER immutable_project_instruction_revisions_delete"))
        db.delete(old)
        db.flush()
        db.execute(text(trigger))
        principal = db.scalar(select(Principal).where(Principal.role == "OWNER"))
        for capability, kind, target in [
            ("lifecycle.restore", "deployment", "deployment"),
            ("project.instruction.restore", "project", project),
        ]:
            db.add(
                AccessGrant(
                    id=capability,
                    principal_id=principal.id,
                    capability=capability,
                    resource_kind=kind,
                    resource_id=target,
                    enabled=True,
                    revision=1,
                    provenance="Explicit disposable restore authority",
                )
            )
    before = client.post("/api/v1/events/replay", headers=headers, json={"limit": 100}).json()[
        "cursor"
    ]
    planned = client.post(
        "/api/v1/lifecycle/restore-preview",
        headers=headers,
        json={
            "idempotency_key": "recover-history",
            "snapshot": "before",
            "destination": "restored",
            "data_class": "PROJECT_INSTRUCTION_HISTORY",
            "selection": [{"project_id": project, "revisions": [1]}],
        },
    )
    assert planned.status_code == 200, planned.text
    plan = planned.json()
    authorized = official_effect(client, headers, plan)
    plan_file, config_file = tmp_path / "plan.json", tmp_path / "instructions.json"
    plan_file.write_text(json.dumps(plan))
    config_file.write_text(config.model_dump_json())
    source = str(engine.url.database)
    client.close()
    engine.dispose()
    command = [
        sys.executable,
        "-m",
        "journeon.operations",
        "restore",
        source,
        plan["destination_path"],
        "--authorization",
        authorized["request_id"],
        "--plan",
        str(plan_file),
        "--instruction-config",
        str(config_file),
        "--json",
    ]
    return configured, project, path, snapshots, source, command, before, authorized


def test_real_restore_command_startup_and_replay_preserve_newer_state(
    prepared_restore, official, tmp_path
):
    configured, project, path, snapshots, source, command, before, authorized = prepared_restore
    headers = official[2]
    executed = subprocess.run(command, capture_output=True, text=True)
    assert executed.returncode == 0, executed.stdout + executed.stderr
    result = json.loads(executed.stdout)
    assert result["status"] == "RESTORED_INACTIVE"
    import sqlite3
    from contextlib import closing

    with closing(sqlite3.connect(result["database"])) as db:
        assert db.execute(
            "SELECT revoked FROM browser_sessions WHERE client_label='Retired recovery session'"
        ).fetchone() == (1,)
        assert db.execute(
            "SELECT enabled FROM access_grants WHERE id='retired-restore-grant'"
        ).fetchone() == (0,)
        assert db.execute(
            "SELECT state FROM protected_requests WHERE idempotency_key='old-pending-request'"
        ).fetchone() == ("INVALIDATED",)
    with pytest.raises(ValueError):
        application(runtime_settings(configured, tmp_path, source))

    assert Path(source).exists() and (snapshots / "before" / "database.sqlite").exists()
    with TestClient(
        application(runtime_settings(configured, tmp_path, result["database"])),
        base_url="https://example.test",
    ) as restored:
        restored.cookies.update(official[1].cookies)
        stale = restored.post(
            "/api/v1/events/replay", headers=headers, json={"limit": 100, "cursor": before}
        )
        assert stale.status_code == 200, stale.text
        assert stale.json()["status"] == "CANONICAL_REFETCH_REQUIRED"
        receipt = restored.get(f"/api/v1/operations/{authorized['operation_id']}", headers=headers)
        assert receipt.status_code == 200, receipt.text
        assert receipt.json()["restored_history_count"] == 1
        fresh = restored.post("/api/v1/events/replay", headers=headers, json={"limit": 100})
        assert fresh.json()["status"] == "AVAILABLE"
        history = restored.post(
            f"/api/v1/projects/{project}/instructions/history",
            headers=headers,
            json={"project_id": project, "revision": 1},
        )
        assert history.status_code == 200, history.text
        assert (
            restored.get(f"/api/v1/projects/{project}/instructions", headers=headers).json()[
                "revision"
            ]
            == 2
        )
    with TestClient(
        application(runtime_settings(configured, tmp_path, result["database"])),
        base_url="https://example.test",
    ) as restarted:
        restarted.cookies.update(official[1].cookies)
        assert (
            restarted.post(
                "/api/v1/events/replay",
                headers=headers,
                json={"limit": 100, "cursor": fresh.json()["cursor"]},
            ).json()["status"]
            == "AVAILABLE"
        )
    assert (path / "INDEX.md").exists()


@pytest.mark.parametrize("boundary", ["claim", "evaluation", "intent", "file", "commit"])
def test_crash_boundaries_reconcile_same_job_and_fence(official, monkeypatch, boundary):
    import journeon.project_instructions as publisher
    from journeon.jobs import JobService
    from journeon.project_instructions import ProjectInstructionService

    engine, client, headers, config = official
    project, base, path, candidate, _ = propose(official)
    service = JobService(engine, config)
    claim = service.claim()
    assert claim is not None
    assert JobService(engine, config).claim() is None
    if boundary != "claim":
        if boundary == "evaluation":
            target, name = ProjectInstructionService, "accept"
        elif boundary == "intent":
            target, name = ProjectInstructionService, "publish"
        elif boundary == "file":
            target, name = publisher, "replace_document"
        else:
            target, name = ProjectInstructionService, "accept"
        original = getattr(target, name)

        def crash(*args, **kwargs):
            if boundary in {"file", "commit"}:
                original(*args, **kwargs)
            raise SystemExit("Synthetic local interruption")

        monkeypatch.setattr(target, name, crash)
        with pytest.raises(SystemExit):
            service.execute(claim)
        monkeypatch.setattr(target, name, original)
    service.reconcile(claim.job_id, expected=claim)
    with transaction(engine) as db:
        job = db.get(Job, claim.job_id)
        assert job.fence > claim.fence
        effect, state = job.effect, job.state
    if boundary in {"claim", "evaluation"}:
        assert effect == "NONE" and state == "RETRY_WAIT"
        assert (path / "INDEX.md").read_text() == base["INDEX.md"]
        service.execute(claim)
        assert (path / "INDEX.md").read_text() == base["INDEX.md"]
    elif boundary == "commit":
        assert effect == "COMMITTED" and state == "SUCCEEDED"
    else:
        assert effect == "UNKNOWN" and state == "FAILED"
        attention = client.get(f"/api/v1/jobs/{claim.job_id}/attention", headers=headers)
        assert attention.status_code == 200 and attention.json()[0]["disposition"] == "OPEN"
        recovery = client.post(
            f"/api/v1/projects/{project}/instructions/recovery",
            headers=headers,
            json={"project_id": project},
        )
        assert recovery.status_code == 200, recovery.text
        official_effect(
            client,
            headers,
            {
                **recovery.json(),
                "kind": "project.instructions.recover.v1",
                "idempotency_key": "reconcile",
                "disposition": "FINISH_TARGET",
            },
        )
        settled = client.get(f"/api/v1/jobs/{claim.job_id}", headers=headers).json()
        assert settled["effect"] == "COMMITTED" and settled["state"] == "SUCCEEDED"
        assert (
            client.get(f"/api/v1/jobs/{claim.job_id}/attention", headers=headers).json()[0][
                "disposition"
            ]
            == "RESOLVED"
        )


def test_cancel_active_fences_next_effect_and_preserves_candidate(official):
    from journeon.jobs import JobService

    engine, client, headers, config = official
    _, base, path, candidate, _ = propose(official)
    service = JobService(engine, config)
    claim = service.claim()
    result = client.post(
        f"/api/v1/jobs/{candidate['job_id']}/cancel", headers=headers, json={"expected_revision": 2}
    )
    assert result.status_code == 200
    service.execute(claim)
    assert (
        client.get(f"/api/v1/jobs/{candidate['job_id']}", headers=headers).json()["state"]
        == "CANCELLED"
    )
    assert (path / "INDEX.md").read_text() == base["INDEX.md"]


def test_replay_corrupt_unauthorized_rows_and_invalid_cursor(official):

    from journeon.models import OutboxEvent

    engine, client, headers, _ = official
    _, _, _, candidate, _ = propose(official)
    first = client.post("/api/v1/events/replay", headers=headers, json={"limit": 1})
    assert first.status_code == 200, first.text
    cursor = first.json()["cursor"]
    invalid = {**cursor, "sequence": 2**60}
    assert (
        client.post(
            "/api/v1/events/replay", headers=headers, json={"limit": 1, "cursor": invalid}
        ).json()["status"]
        == "CANONICAL_REFETCH_REQUIRED"
    )
    with transaction(engine) as db:
        grant = db.scalar(
            select(AccessGrant).where(AccessGrant.capability == "project.instruction.read")
        )
        grant.enabled = False
        event = db.scalar(select(OutboxEvent).where(OutboxEvent.target_id == candidate["job_id"]))
        event.payload = {"corrupt": True}
    response = client.post("/api/v1/events/replay", headers=headers, json={"limit": 100})
    assert response.status_code == 200, response.text
    assert all(event["target_id"] != candidate["job_id"] for event in response.json()["events"])


@pytest.mark.parametrize(
    "failure",
    ["missing", "revoked", "expired", "destination", "snapshot", "writer", "external", "newer"],
)
def test_restore_rejects_changed_or_unauthorized_operands(prepared_restore, failure):
    from journeon.database import create_database
    from journeon.models import Project, ProtectedRequest

    configured, project, path, snapshots, source, command, _, authorized = prepared_restore
    engine = create_database(Path(source))
    held = None
    if failure == "missing":
        command[command.index("--authorization") + 1] = "missing"
    elif failure == "destination":
        command[5] += "-different"
    elif failure == "snapshot":
        with (snapshots / "before" / "database.sqlite").open("ab") as stream:
            stream.write(b"changed")
    elif failure == "external":
        (path / "rules.md").write_text("Unsent local edit remains untouched.")
    else:
        with transaction(engine) as db:
            if failure == "revoked":
                db.scalar(select(BrowserSession)).revoked = True
            elif failure == "expired":
                row = db.get(ProtectedRequest, authorized["request_id"])
                row.approval_deadline = 1
            elif failure == "newer":
                db.get(Project, project).revision += 1
        if failure == "writer":
            held = engine.connect()
    if held is None:
        engine.dispose()
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        assert result.returncode != 0, result.stdout
        assert Path(source).exists()
        assert not Path(source + ".successor.json").exists()
        assert not (
            Path(configured[3].restore.destination_root)
            / "restored"
            / "staged"
            / "database.sqlite.admission.json"
        ).exists()
        if failure == "external":
            assert (path / "rules.md").read_text() == "Unsent local edit remains untouched."
    finally:
        if held is not None:
            held.close()
        engine.dispose()


@pytest.mark.parametrize(
    "failure", ["missing", "wrong_incarnation", "incomplete", "wrong_destination"]
)
def test_restored_startup_rejects_missing_or_changed_journal(prepared_restore, tmp_path, failure):
    configured, _, _, _, _, command, _, _ = prepared_restore
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    path = json.loads(result.stdout)["database"]
    journal = Path(path + ".admission.json")
    data = json.loads(journal.read_text())
    if failure == "missing":
        journal.rename(journal.with_suffix(".retained"))
    else:
        data[
            {
                "wrong_incarnation": "incarnation",
                "incomplete": "status",
                "wrong_destination": "destination",
            }[failure]
        ] = "different"
        journal.write_text(json.dumps(data))
    with pytest.raises((ValueError, FileNotFoundError)):
        application(runtime_settings(configured, tmp_path, path))


@pytest.mark.parametrize("after_target", [False, True])
def test_interruption_between_admission_records_cannot_activate(
    prepared_restore, tmp_path, monkeypatch, after_target
):
    import journeon.restore as recovery
    from journeon.database import create_database
    from journeon.restore_contracts import RestorePlan

    configured, _, _, _, source, command, _, authorized = prepared_restore
    plan = RestorePlan.model_validate_json(Path(command[command.index("--plan") + 1]).read_bytes())
    write = recovery.write_admission
    calls = 0

    def interrupted(path, data):
        nonlocal calls
        calls += 1
        if calls == 3 and not after_target:
            raise SystemExit("Synthetic admission interruption")
        write(path, data)
        if calls == 3:
            raise SystemExit("Synthetic completed-admission interruption")

    monkeypatch.setattr(recovery, "write_admission", interrupted)
    engine = create_database(Path(source))
    try:
        with pytest.raises(SystemExit):
            recovery.restore(engine, configured[3], authorized["request_id"], plan)
    finally:
        engine.dispose()
    target = str(Path(plan.destination_path) / "staged" / "database.sqlite")
    with pytest.raises((ValueError, FileNotFoundError)):
        application(runtime_settings(configured, tmp_path, target))
    with pytest.raises(ValueError):
        application(runtime_settings(configured, tmp_path, source))
    assert Path(source).exists()


@pytest.mark.parametrize("changed", ["lease", "epoch", "grant", "root", "policy"])
def test_current_fence_and_authority_block_execution_after_claim(official, changed):
    from journeon.jobs import JobService
    from journeon.models import InstructionRoot, ProjectInstructionBinding

    engine, client, headers, config = official
    project, base, path, candidate, _ = propose(official)
    service = JobService(engine, config)
    claim = service.claim()
    assert claim is not None
    with transaction(engine) as db:
        if changed == "lease":
            db.get(Job, claim.job_id).lease_deadline = 0
        elif changed == "epoch":
            db.scalar(select(Principal).where(Principal.role == "OWNER")).authorization_epoch += 1
        elif changed == "grant":
            db.scalar(
                select(AccessGrant).where(AccessGrant.capability == "project.instruction.accept")
            ).enabled = False
        elif changed == "root":
            db.get(InstructionRoot, "environment").enabled = False
        else:
            db.get(ProjectInstructionBinding, project).policy_revision += 1
    service.execute(claim)
    with transaction(engine) as db:
        assert db.get(Job, candidate["job_id"]).operation_id is None
        assert db.get(Job, candidate["job_id"]).state in {"FAILED", "RETRY_WAIT"}
    assert (path / "INDEX.md").read_text() == base["INDEX.md"]


def test_separate_processes_claim_only_one_writer(official, tmp_path):
    engine, _, _, config = official
    _, _, _, candidate, _ = propose(official)
    config_path = tmp_path / "claim-config.json"
    config_path.write_text(config.model_dump_json())
    code = """from pathlib import Path
import sys
from journeon.database import create_database
from journeon.instruction_config import InstructionConfiguration
from journeon.jobs import JobService
engine = create_database(Path(sys.argv[1]))
try:
    config = InstructionConfiguration.model_validate_json(Path(sys.argv[2]).read_bytes())
    claim = JobService(engine, config).claim()
    print('CLAIMED' if claim is not None else 'NO_CLAIM')
finally:
    engine.dispose()
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(engine.url.database), str(config_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    outputs = []
    for process in processes:
        output, error = process.communicate(timeout=30)
        assert process.returncode == 0, error
        outputs.append(output.strip())
    assert sorted(outputs) == ["CLAIMED", "NO_CLAIM"]
    with transaction(engine) as db:
        assert db.get(Job, candidate["job_id"]).fence == 1


def test_raw_execution_booleans_cannot_assert_security_or_cancel(official):
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    engine = official[0]
    propose(official)
    for table, column in (("store_identity", "security_reconciled"), ("jobs", "cancel_requested")):
        for invalid in (2, -1, 0.5, "true", b"1"):
            with pytest.raises(IntegrityError), transaction(engine) as db:
                db.execute(text(f"UPDATE {table} SET {column}=:invalid"), {"invalid": invalid})


def test_history_restore_rejects_inconsistent_document_provenance(official):
    import sqlite3
    from contextlib import closing

    from journeon.contracts import DomainError
    from journeon.project_instructions import ProjectInstructionService
    from journeon.restore_contracts import HistorySelection

    engine, _, _, _ = official
    project, _, _, _, _ = propose(official)
    with closing(sqlite3.connect(str(engine.url.database))) as db:
        row = db.execute(
            "SELECT snapshot FROM project_instruction_revisions WHERE project_id=? AND revision=1",
            (project,),
        ).fetchone()
        data = json.loads(row[0])
        data["document_refs"]["INDEX.md"]["revision"] = 99
        db.execute("DROP TRIGGER immutable_project_instruction_revisions_update")
        db.execute(
            "UPDATE project_instruction_revisions SET snapshot=? WHERE project_id=? AND revision=1",
            (json.dumps(data), project),
        )
        db.commit()
        with pytest.raises(DomainError):
            ProjectInstructionService.validate_restore_history(
                db, HistorySelection(project_id=project, revisions=[1])
            )


@pytest.mark.parametrize("boundary", ["copy", "reconciled", "finalized"])
@pytest.mark.parametrize("remove_pending", [False, True])
def test_interrupted_staging_cannot_start_as_an_ordinary_store(
    prepared_restore, tmp_path, monkeypatch, remove_pending, boundary
):
    import journeon.restore as recovery
    from journeon.database import create_database
    from journeon.restore_contracts import RestorePlan

    configured, _, _, _, source, command, _, authorized = prepared_restore
    plan = RestorePlan.model_validate_json(Path(command[command.index("--plan") + 1]).read_bytes())
    function = "snapshot_database" if boundary == "copy" else "doctor"
    original_function = getattr(recovery, function)
    calls = 0

    def interrupt(*args, **kwargs):
        nonlocal calls
        calls += 1
        result = original_function(*args, **kwargs)
        if calls == (1 if boundary == "reconciled" else 2):
            raise SystemExit("Synthetic staged-copy interruption")
        return result

    monkeypatch.setattr(recovery, function, interrupt)
    engine = create_database(Path(source))
    try:
        with pytest.raises(SystemExit):
            recovery.restore(engine, configured[3], authorized["request_id"], plan)
    finally:
        engine.dispose()
    target = str(Path(plan.destination_path) / "staged" / "database.sqlite")
    if remove_pending:
        Path(str(Path(target).parent) + ".pending.json").unlink()
    with pytest.raises((ValueError, FileNotFoundError)):
        with create_database(Path(target)).connect():
            pytest.fail("Staged database admitted a normal writer")
    with pytest.raises((ValueError, FileNotFoundError)):
        unexpected = application(runtime_settings(configured, tmp_path, target))
        unexpected.state.engine.dispose()
    original = application(runtime_settings(configured, tmp_path, source))
    original.state.engine.dispose()


def test_copied_restored_database_and_admission_cannot_rebind(prepared_restore, tmp_path):
    import shutil

    from journeon.database import create_database
    from journeon.operations import doctor

    configured, _, _, _, _, command, _, _ = prepared_restore
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    original = Path(json.loads(result.stdout)["database"])
    copied = tmp_path / "copied.sqlite"
    shutil.copy2(original, copied)
    shutil.copy2(Path(str(original) + ".admission.json"), Path(str(copied) + ".admission.json"))
    assert doctor(copied)["schema"] == "CURRENT"
    with pytest.raises(ValueError):
        application(runtime_settings(configured, tmp_path, str(copied)))
    with pytest.raises(ValueError):
        with create_database(copied).connect():
            pytest.fail("Copied admission rebound a writable store")


def test_snapshot_inspection_does_not_authorize_store_activation(official, tmp_path):
    from journeon.database import create_database
    from journeon.operations import doctor, snapshot_database, validate_snapshot

    directory = tmp_path / "inspection"
    snapshot_database(Path(str(official[0].url.database)), directory)
    copied = directory / "database.sqlite"
    assert validate_snapshot(directory)["schema"] == "0014_review_completion"
    assert doctor(copied)["schema"] == "CURRENT"
    with pytest.raises(ValueError):
        application(runtime_settings(official, tmp_path, str(copied)))
    with pytest.raises(ValueError):
        with create_database(copied).connect():
            pytest.fail("Snapshot inspection admitted a writable store")


def test_source_fenced_after_configuration_is_denied_at_lifespan(prepared_restore, tmp_path):
    configured, _, _, _, source, command, _, _ = prepared_restore
    waiting = application(runtime_settings(configured, tmp_path, source))
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    with pytest.raises(ValueError), TestClient(waiting):
        pytest.fail("Previously configured source opened after successor activation")


@pytest.mark.parametrize("bound", ["count", "bytes"])
def test_configured_queue_pressure_rolls_back_candidate_admission(official, bound):
    from journeon.api import create_app
    from journeon.browser_auth import BrowserAuth
    from journeon.models import InstructionCandidate

    engine, client, headers, config = official
    project, _, _, candidate, command = propose(official)
    jobs = config.jobs.model_copy(
        update={"pending_count": 1}
        if bound == "count"
        else {"pending_bytes": candidate["byte_count"]}
    )
    constrained = config.model_copy(update={"jobs": jobs})
    with TestClient(
        create_app(
            engine, browser_auth=BrowserAuth("https://example.test"), instructions=constrained
        ),
        base_url="https://example.test",
    ) as other:
        other.cookies.update(client.cookies)
        response = other.post(
            f"/api/v1/projects/{project}/instructions/candidates",
            headers=headers,
            json={**command, "idempotency_key": "second-admission"},
        )
        assert response.status_code == 503, response.text
    with transaction(engine) as db:
        assert len(list(db.scalars(select(Job)))) == 1
        assert len(list(db.scalars(select(InstructionCandidate)))) == 1
