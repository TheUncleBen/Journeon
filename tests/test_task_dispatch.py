# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_attempt_execution import attempt_environment  # noqa: F401
from test_execution_route import route
from test_production_instructions import official  # noqa: F401

from journeon.api import create_app
from journeon.database import transaction
from journeon.execution_process import ExecutionConfiguration
from journeon.job_contracts import JobConfiguration
from journeon.models import AccessGrant, Principal


@pytest.fixture
def dispatch_environment(attempt_environment, tmp_path, request):  # noqa: F811
    engine, client, headers, config, prepare, root, storage = attempt_environment
    execution_storage = tmp_path / "execution-storage"
    execution_storage.mkdir(mode=0o700)
    project = prepare["project_id"]
    configured_route = route().model_copy(
        update={
            "project_id": project,
            "check_id": "check",
            "argv": ["/usr/bin/true"],
            "executable_sha256": hashlib.sha256(Path("/usr/bin/true").read_bytes()).hexdigest(),
            "artifacts": [],
        }
    )
    if hasattr(request, "param"):
        configured_route = configured_route.model_copy(
            update={
                "argv": ["/usr/bin/python3", "-I", "-S", "-c", request.param],
                "executable_sha256": hashlib.sha256(
                    Path("/usr/bin/python3").read_bytes()
                ).hexdigest(),
            }
        )
    config = config.model_copy(
        update={
            "jobs": JobConfiguration(
                pending_count=10,
                pending_bytes=10485760,
                concurrency=1,
                lease_seconds=5,
                poll_seconds=1,
                retry_seconds=1,
                max_attempts=2,
            ),
            "executions": ExecutionConfiguration(
                revision=1,
                storage_path=str(execution_storage),
                snapshot_bytes=1048576,
                snapshot_files=100,
                concurrent_executions=2,
                memory_bytes=268435456,
                storage_bytes=33554432,
                cpu_percent=50,
                core_cpu_reserve_percent=100,
                routes=[configured_route],
            ),
        }
    )
    with transaction(engine) as db:
        principal = db.scalar(select(Principal).where(Principal.role == "OWNER"))
        for capability in (
            "task.revise",
            "task.pause",
            "task.cancel",
            "task.dispatch",
            "job.read",
            "job.cancel",
            "job.receipt.read",
            "execution.start",
            "execution.read",
            "execution.stop",
            "execution.drain",
            "execution.complete",
            "execution.receipt.read",
        ):
            db.add(
                AccessGrant(
                    id="dispatch:" + capability,
                    principal_id=principal.id,
                    capability=capability,
                    resource_kind="project",
                    resource_id=project,
                    enabled=True,
                    revision=1,
                    provenance="Explicit disposable dispatch authority",
                )
            )
    command = prepare | {
        "step_id": "verify",
        "route_key": configured_route.key,
        "route_revision": 1,
    }
    with TestClient(
        create_app(engine, browser_auth=client.app.state.browser_auth, instructions=config),
        base_url="https://example.test",
        cookies=client.cookies,
    ) as configured:
        if hasattr(request, "param"):
            current = configured.get("/api/v1/projects/" + project).json()
            policy = configured.post(
                "/api/v1/projects/verification",
                headers=headers,
                json={
                    "schema_version": 1,
                    "idempotency_key": "dispatch-policy",
                    "project_id": project,
                    "expected_project_revision": current["revision"],
                    "expected_policy_revision": 1,
                    "enabled": True,
                    "checks": [
                        {
                            "check_id": "check",
                            "criterion": "Command succeeds",
                            "argv": configured_route.argv,
                            "working_directory": ".",
                            "expected_exit_code": 0,
                        }
                    ],
                    "workflow": {
                        "steps": [
                            {"step_id": "verify", "kind": "VERIFICATION", "check_id": "check"}
                        ]
                    },
                },
            )
            assert policy.status_code == 200, policy.text
            revised = configured.post(
                "/api/v1/tasks/revise",
                headers=headers,
                json={
                    "schema_version": 1,
                    "idempotency_key": "dispatch-task",
                    "task_id": command["origin"]["task_id"],
                    "expected_revision": command["origin"]["task_revision"],
                    "reason": "Bind the local verifier",
                    "expected_policy_revision": 2,
                    "success_conditions": ["Command succeeds"],
                    "workflow": policy.json()["policy"]["workflow"],
                },
            )
            assert revised.status_code == 200, revised.text
            command = command | {
                "origin": command["origin"] | {"task_revision": revised.json()["task"]["revision"]},
                "expected_policy_revision": 2,
            }
        yield engine, configured, headers, config, command, root, storage


def test_task_dispatch_produces_a_durable_task_job(dispatch_environment):
    _, client, headers, _, command, _, _ = dispatch_environment
    response = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert response.status_code == 200, response.text
    assert response.json()["kind"] == "TASK_VERIFICATION"
    assert response.json()["state"] == "QUEUED"
    assert response.json()["task_id"] == command["origin"]["task_id"]


def test_task_execution_claim_requires_a_positive_integer_fence():
    import sqlite3

    from sqlalchemy.dialects.sqlite import dialect
    from sqlalchemy.schema import CreateTable

    from journeon.models import TaskVerificationJob

    with sqlite3.connect(":memory:") as db:
        db.execute(str(CreateTable(TaskVerificationJob.__table__).compile(dialect=dialect())))
        for invalid in (None, 0, -1, 0.5, "invalid"):
            with pytest.raises(sqlite3.IntegrityError):
                db.execute(
                    "INSERT INTO task_verification_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        "job",
                        "attempt",
                        "manifest",
                        "principal",
                        "key",
                        "verify",
                        "digest",
                        1,
                        "{}",
                        "execution",
                        invalid,
                        "owner",
                        "incarnation",
                    ),
                )


def dispatch_worker(engine, config):
    from journeon.executions import ExecutionService
    from journeon.jobs import JobService

    executions = ExecutionService(engine, config)
    worker = JobService(engine, config, executions=executions)
    claim = worker.claim()
    assert claim is not None
    try:
        worker.execute(claim)
    finally:
        executions.shutdown()
    return worker, claim


def test_task_dispatch_runs_real_verification_and_publishes_exact_evidence(dispatch_environment):
    from journeon.models import Attempt, Execution, Job, TaskVerificationEvidence

    engine, client, headers, config, command, root, _ = dispatch_environment
    response = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert response.status_code == 200, response.text
    identity = response.json()["job_id"]
    (root / "source.txt").write_text("new source after admitted Attempt")
    dispatch_worker(engine, config)
    result = client.get("/api/v1/jobs/" + identity)
    assert result.status_code == 200, result.text
    assert result.json()["state"] == "SUCCEEDED", result.text
    proof = client.get("/api/v1/jobs/" + identity + "/evidence")
    assert proof.status_code == 200, proof.text
    evidence = proof.json()
    assert evidence["passed"]
    assert evidence["execution"]["origin"] == "TASK_VERIFICATION"
    assert evidence["execution"]["completion"]["exit_code"] == 0
    assert evidence["execution"]["completion"]["drained"]
    assert evidence["execution"]["invocation_id"]
    assert evidence["criterion"]["text"] == "Command succeeds"
    assert client.get("/api/v1/tasks/" + command["origin"]["task_id"]).json()["state"] != "DONE"
    with transaction(engine) as db:
        execution = db.scalar(select(Execution))
        attempt = db.scalar(select(Attempt))
        assert execution.inputs["source_snapshot"] == attempt.snapshot["manifest"]["snapshot"]
        assert db.scalar(select(TaskVerificationEvidence)).job_id == identity
        assert db.get(Job, identity).operation_id is not None
    assert (
        client.post("/api/v1/tasks/dispatch", headers=headers, json=command).json()["job_id"]
        == identity
    )


@pytest.mark.parametrize(
    "dispatch_environment",
    [
        "import subprocess as s;assert open('source.txt').read()=='working';"
        "assert [s.check_output(['git','show',x]).decode() for x in "
        "[':source.txt','HEAD:source.txt']]==['staged','base'];print('frozen')"
    ],
    indirect=True,
)
def test_task_process_reads_frozen_attempt_head_index_and_working_bytes(dispatch_environment):
    from test_attempt_snapshots import git

    engine, client, headers, config, command, root, _ = dispatch_environment
    (root / "source.txt").write_text("staged")
    git(root, "add", "source.txt")
    (root / "source.txt").write_text("working")
    response = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert response.status_code == 200, response.text
    (root / "source.txt").write_text("later source")
    git(root, "add", "source.txt")
    git(root, "commit", "-qm", "later source")
    dispatch_worker(engine, config)
    evidence = client.get("/api/v1/jobs/" + response.json()["job_id"] + "/evidence")
    assert evidence.status_code == 200, evidence.text
    assert evidence.json()["passed"], evidence.text
    import base64

    assert b"frozen" in b"".join(
        base64.b64decode(item["data"]) for item in evidence.json()["execution"]["output"]
    )


@pytest.mark.parametrize(
    "dispatch_environment", ["print('actual-failure'); raise SystemExit(7)"], indirect=True
)
def test_nonzero_exit_publishes_failed_exact_criterion_and_attention(dispatch_environment):
    engine, client, headers, config, command, _, _ = dispatch_environment
    response = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert response.status_code == 200, response.text
    identity = response.json()["job_id"]
    dispatch_worker(engine, config)
    evidence = client.get("/api/v1/jobs/" + identity + "/evidence")
    assert evidence.status_code == 200, evidence.text
    assert not evidence.json()["passed"]
    assert evidence.json()["execution"]["completion"]["exit_code"] == 7
    assert client.get("/api/v1/jobs/" + identity).json()["state"] == "FAILED"
    assert (
        client.get("/api/v1/jobs/" + identity + "/attention").json()[0]["reason"]
        == "VERIFICATION_FAILED"
    )


@pytest.mark.parametrize(
    "dispatch_environment",
    ["import time; print('started',flush=True); time.sleep(7); print('finished')"],
    indirect=True,
)
def test_healthy_task_process_renews_job_lease(dispatch_environment):
    from journeon.models import Job

    engine, client, headers, config, command, _, _ = dispatch_environment
    config = config.model_copy(update={"jobs": config.jobs.model_copy(update={"lease_seconds": 2})})
    response = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert response.status_code == 200, response.text
    dispatch_worker(engine, config)
    with transaction(engine) as db:
        job = db.get(Job, response.json()["job_id"])
        assert job.state == "SUCCEEDED", (job.state, job.reason)
        assert job.attempts == 1


@pytest.mark.parametrize(
    "dispatch_environment",
    ["import time; print('active',flush=True); time.sleep(60)"],
    indirect=True,
)
@pytest.mark.parametrize("stop", ["job", "task", "grant", "grant_corrupt", "fence"])
def test_current_stop_boundaries_drain_without_publishing(dispatch_environment, stop):
    import threading
    import time

    from journeon.executions import ExecutionService
    from journeon.jobs import JobService
    from journeon.models import Execution, Job, TaskVerificationEvidence

    engine, client, headers, config, command, _, _ = dispatch_environment
    response = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert response.status_code == 200, response.text
    identity = response.json()["job_id"]
    executions = ExecutionService(engine, config)
    worker = JobService(engine, config, executions=executions)
    claim = worker.claim()
    thread = threading.Thread(target=worker.execute, args=(claim,))
    thread.start()
    try:
        deadline = time.monotonic() + 30
        while True:
            with transaction(engine) as db:
                execution = db.scalar(select(Execution))
                active = execution is not None and execution.state == "RUNNING"
            if active:
                break
            assert time.monotonic() < deadline
            time.sleep(0.05)
        if stop == "job":
            current = client.get("/api/v1/jobs/" + identity).json()
            cancelled = client.post(
                "/api/v1/jobs/" + identity + "/cancel",
                headers=headers,
                json={"expected_revision": current["revision"]},
            )
            assert cancelled.status_code == 200, cancelled.text
        elif stop == "task":
            paused = client.post(
                "/api/v1/tasks/pause",
                headers=headers,
                json={
                    "schema_version": 1,
                    "idempotency_key": "pause-active",
                    "task_id": command["origin"]["task_id"],
                    "expected_revision": command["origin"]["task_revision"],
                    "reason": "Stop the active verifier",
                },
            )
            assert paused.status_code == 200, paused.text
        else:
            with transaction(engine) as db:
                if stop in ("grant", "grant_corrupt"):
                    db.get(AccessGrant, "dispatch:execution.start").enabled = False
                    if stop == "grant_corrupt":
                        from sqlalchemy import text

                        db.execute(text("UPDATE task_verification_jobs SET inputs='{'"))
                else:
                    db.get(Job, identity).fence += 1
        thread.join(30)
        assert not thread.is_alive()
    finally:
        executions.shutdown()
        thread.join(30)
    with transaction(engine) as db:
        execution = db.scalar(select(Execution))
        assert execution.drained
        assert execution.snapshot["completion"]["reason"] == "CANCELLED"
        assert not execution.snapshot["verification_passed"]
        assert db.scalar(select(TaskVerificationEvidence)) is None
        assert db.get(Job, identity).state in ("CANCELLED", "FAILED")


def test_unknown_completion_retains_observation_and_never_reruns(dispatch_environment, monkeypatch):
    from journeon import executions
    from journeon.execution_process import ExecutionInterrupted
    from journeon.models import Attention, Execution, Job, TaskVerificationEvidence

    engine, client, headers, config, command, _, _ = dispatch_environment
    original = executions.run_local
    calls = []

    def lose_completion(*args, **kwargs):
        actual = original(*args, **kwargs)
        calls.append(actual["invocation_id"])
        raise ExecutionInterrupted(
            {"output": actual["output"], "launcher_exit_code": actual["launcher_exit_code"]}
        )

    monkeypatch.setattr(executions, "run_local", lose_completion)
    response = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert response.status_code == 200, response.text
    identity = response.json()["job_id"]
    worker, _ = dispatch_worker(engine, config)
    worker.reconcile()
    assert worker.claim() is None
    assert (
        client.post("/api/v1/tasks/dispatch", headers=headers, json=command).json()["job_id"]
        == identity
    )
    with transaction(engine) as db:
        assert db.get(Job, identity).effect == "UNKNOWN"
        assert db.get(Job, identity).state == "FAILED"
        assert db.scalar(select(Attention)).reason == "EXECUTION_RECONCILIATION_REQUIRED"
        assert db.scalar(select(Execution)).state == "UNKNOWN"
        assert db.scalar(select(TaskVerificationEvidence)) is None
    assert len(calls) == 1


def test_task_job_reads_need_read_grants_without_instruction_accept(dispatch_environment):
    engine, client, headers, _, command, _, _ = dispatch_environment
    response = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert response.status_code == 200, response.text
    job = response.json()
    with transaction(engine) as db:
        for grant in db.scalars(select(AccessGrant)):
            if grant.capability in (
                "task.dispatch",
                "job.cancel",
                "attempt.prepare",
                "execution.start",
                "execution.stop",
                "execution.complete",
                "project.instruction.accept",
            ):
                grant.enabled = False
    assert client.get("/api/v1/jobs/" + job["job_id"]).status_code == 200
    assert client.get("/api/v1/jobs/" + job["job_id"] + "/attention").status_code == 200
    assert client.get("/api/v1/operations/" + job["admission_id"]).status_code == 200
    replay = client.post("/api/v1/events/replay", headers=headers, json={"limit": 100})
    assert replay.status_code == 200, replay.text
    assert any(item["target_id"] == job["job_id"] for item in replay.json()["events"])


@pytest.mark.parametrize("capability", ["job.read", "project.verification.read"])
def test_revoked_job_read_precedes_corrupt_binding_decode(dispatch_environment, capability):
    from journeon.models import TaskVerificationJob

    engine, client, headers, _, command, _, _ = dispatch_environment
    response = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert response.status_code == 200, response.text
    job = response.json()
    with transaction(engine) as db:
        for grant in db.scalars(select(AccessGrant).where(AccessGrant.capability == capability)):
            grant.enabled = False
        db.get(TaskVerificationJob, job["job_id"]).inputs = {"invalid": True}
    for suffix in ("", "/attention", "/evidence"):
        assert client.get("/api/v1/jobs/" + job["job_id"] + suffix).status_code == 403
    assert client.get("/api/v1/operations/" + job["admission_id"]).status_code == 403
    assert client.post("/api/v1/tasks/dispatch", headers=headers, json=command).status_code == 403


@pytest.mark.parametrize("kind", ["WORK", "REVIEW", "CONDITION", "APPROVAL"])
def test_unproduced_workflow_prerequisite_is_not_bypassed(dispatch_environment, kind):
    from journeon.models import Attempt, Job

    engine, client, headers, _, command, _, _ = dispatch_environment
    revised = client.post(
        "/api/v1/tasks/revise",
        headers=headers,
        json={
            "schema_version": 1,
            "idempotency_key": "mixed-workflow",
            "task_id": command["origin"]["task_id"],
            "expected_revision": command["origin"]["task_revision"],
            "expected_policy_revision": 1,
            "reason": "Require the workflow prerequisite",
            "success_conditions": ["Command succeeds"],
            "workflow": {
                "steps": [
                    {"step_id": "prerequisite", "kind": kind},
                    {
                        "step_id": "verify",
                        "kind": "VERIFICATION",
                        "check_id": "check",
                        "dependencies": ["prerequisite"],
                    },
                ]
            },
        },
    )
    assert revised.status_code == 200, revised.text
    command = command | {
        "origin": command["origin"] | {"task_revision": revised.json()["task"]["revision"]}
    }
    response = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert response.status_code in (403, 503), response.text
    with transaction(engine) as db:
        assert db.scalar(select(Job)) is None
        assert db.scalar(select(Attempt)) is None


def test_reused_attempt_requires_actual_prerequisite_evidence(dispatch_environment):
    from journeon.models import TaskVerificationJob

    engine, client, headers, config, command, _, _ = dispatch_environment
    revised = client.post(
        "/api/v1/tasks/revise",
        headers=headers,
        json={
            "schema_version": 1,
            "idempotency_key": "verification-dag",
            "task_id": command["origin"]["task_id"],
            "expected_revision": command["origin"]["task_revision"],
            "expected_policy_revision": 1,
            "reason": "Bind verification dependencies",
            "success_conditions": ["Command succeeds"],
            "workflow": {
                "steps": [
                    {"step_id": "first", "kind": "VERIFICATION", "check_id": "check"},
                    {
                        "step_id": "verify",
                        "kind": "VERIFICATION",
                        "check_id": "check",
                        "dependencies": ["first"],
                    },
                ]
            },
        },
    )
    assert revised.status_code == 200, revised.text
    command = command | {
        "origin": command["origin"] | {"task_revision": revised.json()["task"]["revision"]}
    }
    blocked = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert blocked.status_code == 503, blocked.text
    first = client.post(
        "/api/v1/tasks/dispatch", headers=headers, json=command | {"step_id": "first"}
    )
    assert first.status_code == 200, first.text
    with transaction(engine) as db:
        attempt = db.get(TaskVerificationJob, first.json()["job_id"]).attempt_id
    second_command = command | {"attempt_id": attempt, "idempotency_key": "second-step"}
    assert (
        client.post("/api/v1/tasks/dispatch", headers=headers, json=second_command).status_code
        == 503
    )
    dispatch_worker(engine, config)
    second = client.post("/api/v1/tasks/dispatch", headers=headers, json=second_command)
    assert second.status_code == 200, second.text
    dispatch_worker(engine, config)
    assert client.get("/api/v1/jobs/" + second.json()["job_id"]).json()["state"] == "SUCCEEDED"


def test_changed_attempt_workspace_cannot_be_used_as_verification_input(dispatch_environment):
    from journeon.models import Execution, TaskVerificationJob

    engine, client, headers, config, command, _, storage = dispatch_environment
    first = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert first.status_code == 200, first.text
    with transaction(engine) as db:
        attempt = db.get(TaskVerificationJob, first.json()["job_id"]).attempt_id
    (storage / attempt / "workspace" / "source.txt").write_text("unrecognized bytes")
    dispatch_worker(engine, config)
    with transaction(engine) as db:
        execution = db.scalar(select(Execution))
        assert execution.state == "UNKNOWN"
        assert execution.snapshot["invocation_id"] is None
    assert client.get("/api/v1/jobs/" + first.json()["job_id"] + "/evidence").status_code == 404


def test_cancel_before_claim_never_creates_execution(dispatch_environment):
    from journeon.jobs import JobService
    from journeon.models import Execution

    engine, client, headers, config, command, _, _ = dispatch_environment
    first = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert first.status_code == 200, first.text
    stopped = client.post(
        "/api/v1/jobs/" + first.json()["job_id"] + "/cancel",
        headers=headers,
        json={"expected_revision": first.json()["revision"]},
    )
    assert stopped.status_code == 200, stopped.text
    assert JobService(engine, config).claim() is None
    with transaction(engine) as db:
        assert db.scalar(select(Execution)) is None


def test_lost_admission_response_reuses_prepared_attempt(dispatch_environment, monkeypatch):
    from journeon import jobs
    from journeon.models import Attempt, Job

    engine, client, headers, _, command, _, _ = dispatch_environment
    original = jobs.record
    calls = []

    def fail_record(*args, **kwargs):
        calls.append(True)
        if len(calls) == 1:
            raise OSError("Disposable interruption before Job admission commit")
        return original(*args, **kwargs)

    monkeypatch.setattr(jobs, "record", fail_record)
    with pytest.raises(OSError):
        client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    with transaction(engine) as db:
        before = list(db.scalars(select(Attempt.id)))
        assert len(before) == 1
        assert db.scalar(select(Job)) is None
    again = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert again.status_code == 200, again.text
    with transaction(engine) as db:
        assert list(db.scalars(select(Attempt.id))) == before
        assert len(list(db.scalars(select(Job)))) == 1


def test_claim_interruption_retries_same_job_without_an_extra_attempt(dispatch_environment):
    from journeon.jobs import JobService
    from journeon.models import Attempt, Execution, Job

    engine, client, headers, config, command, _, _ = dispatch_environment
    first = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert first.status_code == 200, first.text
    worker = JobService(engine, config)
    old = worker.claim()
    assert old is not None
    assert worker.claim() is None
    with transaction(engine) as db:
        db.get(Job, old.job_id).lease_deadline = 0
    worker.reconcile()
    with transaction(engine) as db:
        job = db.get(Job, old.job_id)
        assert job.state == "RETRY_WAIT"
        job.due_at = 0
    dispatch_worker(engine, config)
    with transaction(engine) as db:
        assert len(list(db.scalars(select(Attempt)))) == 1
        assert len(list(db.scalars(select(Execution)))) == 1
        assert db.get(Job, old.job_id).state == "SUCCEEDED"


def test_completed_process_reconciles_expired_publication_lease_without_rerun(
    dispatch_environment, monkeypatch
):
    from journeon.executions import ExecutionService
    from journeon.jobs import JobService
    from journeon.models import Attempt, Execution, Job, TaskVerificationEvidence
    from journeon.task_dispatch import TaskDispatchService

    engine, client, headers, config, command, _, _ = dispatch_environment
    admitted = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert admitted.status_code == 200, admitted.text
    identity = admitted.json()["job_id"]
    executions = ExecutionService(engine, config)
    worker = JobService(engine, config, executions=executions)
    claim = worker.claim()
    original = TaskDispatchService.settle

    def interrupted(*args, **kwargs):
        raise SystemExit("Disposable crash after actual completion before publication")

    monkeypatch.setattr(TaskDispatchService, "settle", interrupted)
    try:
        with pytest.raises(SystemExit):
            worker.execute(claim)
    finally:
        executions.shutdown()
    with transaction(engine) as db:
        execution = db.scalar(select(Execution))
        assert execution.state == "COMPLETED" and execution.drained
        original_invocation = execution.snapshot["invocation_id"]
        db.get(Job, identity).lease_deadline = 0
        assert db.scalar(select(TaskVerificationEvidence)) is None
    monkeypatch.setattr(TaskDispatchService, "settle", original)
    restarted = JobService(engine, config)
    restarted.reconcile()
    assert restarted.claim() is None
    with transaction(engine) as db:
        job = db.get(Job, identity)
        assert job.state == "SUCCEEDED", (job.state, job.reason)
        assert job.fence == claim.fence
        assert len(list(db.scalars(select(Execution)))) == 1
        assert len(list(db.scalars(select(Attempt)))) == 1
        assert db.scalar(select(Execution)).snapshot["invocation_id"] == original_invocation
        assert db.scalar(select(TaskVerificationEvidence)) is not None


def test_repeated_settlement_preserves_terminal_job_and_immutable_evidence(dispatch_environment):
    from journeon.models import Job, TaskVerificationEvidence
    from journeon.task_dispatch import TaskDispatchService

    engine, client, headers, config, command, _, _ = dispatch_environment
    admitted = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert admitted.status_code == 200, admitted.text
    identity = admitted.json()["job_id"]
    dispatch_worker(engine, config)
    with transaction(engine) as db:
        job = db.get(Job, identity)
        before = job.revision
        proof = db.scalar(select(TaskVerificationEvidence)).id
        assert TaskDispatchService(engine, config).settle(db, job)
    with transaction(engine) as db:
        assert db.get(Job, identity).state == "SUCCEEDED"
        assert db.get(Job, identity).revision == before
        assert db.scalar(select(TaskVerificationEvidence)).id == proof


def test_interrupted_dispatch_keeps_full_request_identity(dispatch_environment, monkeypatch):
    from journeon import jobs

    engine, client, headers, config, command, _, _ = dispatch_environment
    original = jobs.record

    def interrupted(*args, **kwargs):
        raise OSError("Disposable interruption before Job admission commit")

    monkeypatch.setattr(jobs, "record", interrupted)
    with pytest.raises(OSError):
        client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    monkeypatch.setattr(jobs, "record", original)
    config = config.model_copy(
        update={
            "executions": config.executions.model_copy(
                update={
                    "routes": [
                        *config.executions.routes,
                        config.executions.routes[0].model_copy(update={"key": "other-route"}),
                    ]
                }
            )
        }
    )
    with TestClient(
        create_app(engine, browser_auth=client.app.state.browser_auth, instructions=config),
        base_url="https://example.test",
        cookies=client.cookies,
    ) as restarted:
        changed = restarted.post(
            "/api/v1/tasks/dispatch", headers=headers, json=command | {"route_key": "other-route"}
        )
    assert changed.status_code == 409, changed.text
    assert changed.json()["code"] == "IDEMPOTENCY_CONFLICT"


def test_runtime_uses_the_same_dispatcher_for_task_verification(dispatch_environment, tmp_path):
    import time

    from test_work_execution import runtime_settings

    from journeon.runtime import application

    engine, client, headers, config, command, _, _ = dispatch_environment
    first = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert first.status_code == 200, first.text
    identity = first.json()["job_id"]
    settings = runtime_settings((engine, client, headers, config), tmp_path)
    with TestClient(
        application(settings), base_url="https://example.test", cookies=client.cookies
    ) as running:
        deadline = time.monotonic() + 45
        while True:
            result = running.get("/api/v1/jobs/" + identity)
            assert result.status_code == 200, result.text
            if result.json()["state"] not in ("QUEUED", "RUNNING", "RETRY_WAIT"):
                break
            assert time.monotonic() < deadline
            time.sleep(0.05)
        assert result.json()["state"] == "SUCCEEDED", result.text
        assert running.get("/api/v1/jobs/" + identity + "/evidence").json()["passed"]


def test_migrated_claim_domain_and_immutable_evidence(dispatch_environment):
    from sqlalchemy.exc import IntegrityError

    from journeon.models import TaskVerificationEvidence

    engine, client, headers, config, command, _, _ = dispatch_environment
    first = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert first.status_code == 200, first.text
    dispatch_worker(engine, config)
    for invalid in (None, 0, -1, 0.5, "invalid"):
        with pytest.raises(IntegrityError, match="task_execution_claim"), engine.begin() as db:
            db.exec_driver_sql("UPDATE task_verification_jobs SET claim_fence=?", (invalid,))
    for statement in (
        "UPDATE task_verification_evidence SET content_hash='changed'",
        "DELETE FROM task_verification_evidence",
    ):
        with pytest.raises(IntegrityError, match="immutable"), engine.begin() as db:
            db.exec_driver_sql(statement)
    with transaction(engine) as db:
        assert db.scalar(select(TaskVerificationEvidence)) is not None


def test_current_read_grants_preserve_history_after_task_criteria_advance(dispatch_environment):
    engine, client, headers, config, command, _, _ = dispatch_environment
    first = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert first.status_code == 200, first.text
    identity = first.json()["job_id"]
    dispatch_worker(engine, config)
    evidence = client.get("/api/v1/jobs/" + identity + "/evidence").json()
    revised = client.post(
        "/api/v1/tasks/revise",
        headers=headers,
        json={
            "schema_version": 1,
            "idempotency_key": "later-task-criteria",
            "task_id": command["origin"]["task_id"],
            "expected_revision": command["origin"]["task_revision"],
            "expected_policy_revision": 1,
            "reason": "Advance the Task criteria",
            "success_conditions": ["A different current criterion"],
            "workflow": evidence["manifest"]["task"]["workflow"],
        },
    )
    assert revised.status_code == 200, revised.text
    historical = client.get("/api/v1/jobs/" + identity + "/evidence")
    assert historical.status_code == 200, historical.text
    assert historical.json() == evidence
    assert client.get("/api/v1/jobs/" + identity).status_code == 200
    assert client.get("/api/v1/operations/" + first.json()["admission_id"]).status_code == 200
    assert client.post("/api/v1/tasks/dispatch", headers=headers, json=command).status_code == 409


def test_authorized_corrupt_task_binding_returns_repair_error(dispatch_environment):
    from journeon.models import TaskVerificationJob

    engine, client, headers, _, command, _, _ = dispatch_environment
    first = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert first.status_code == 200, first.text
    identity = first.json()["job_id"]
    with transaction(engine) as db:
        db.get(TaskVerificationJob, identity).inputs = {"invalid": True}
    result = client.get("/api/v1/jobs/" + identity)
    assert result.status_code == 503, result.text
    assert result.json()["code"] == "DEPENDENCY_UNAVAILABLE"
