# SPDX-License-Identifier: AGPL-3.0-only
import sqlite3
import threading
import time
from pathlib import Path

import pytest
from sqlalchemy import select
from test_work_execution import official as official
from test_work_execution import prepared_restore as prepared_restore
from test_work_execution import propose

from journeon.database import create_database, transaction
from journeon.jobs import JobService
from journeon.models import AccessGrant, Job


@pytest.mark.parametrize("corrupt", [False, True])
def test_job_receipt_revocation_blocks_receipt_and_replay(official, corrupt):
    engine, client, headers, config = official
    _, _, _, candidate, _ = propose(official)
    with transaction(engine) as db:
        admission = db.get(Job, candidate["job_id"]).admission_id
        db.scalar(
            select(AccessGrant).where(AccessGrant.capability == "project.instruction.receipt.read")
        ).enabled = False
    if corrupt:
        with engine.begin() as db:
            db.exec_driver_sql(
                "UPDATE operation_receipts SET result='invalid' WHERE id=?", (admission,)
            )
            db.exec_driver_sql(
                "UPDATE outbox_events SET payload='invalid' WHERE operation_id=?", (admission,)
            )
    receipt = client.get("/api/v1/operations/" + admission, headers=headers)
    replay = client.post("/api/v1/events/replay", headers=headers, json={"limit": 100})
    exposed = any(e["operation_id"] == admission for e in replay.json()["events"])
    assert (receipt.status_code, exposed) == (403, False), (receipt.status_code, exposed)


def test_transient_database_busy_does_not_permanently_stop_worker(official):
    engine, _, _, config = official
    _, base, path, candidate, _ = propose(official)
    isolated = create_database(Path(str(engine.url.database)), busy_timeout_ms=50)
    held = sqlite3.connect(str(engine.url.database))
    held.execute("BEGIN IMMEDIATE")
    stop = threading.Event()
    errors = []

    def run():
        try:
            JobService(isolated, config).run(stop)
        except Exception as error:
            errors.append(type(error).__name__)

    thread = threading.Thread(target=run)
    thread.start()
    time.sleep(0.3)
    held.rollback()
    held.close()
    alive = thread.is_alive()
    try:
        until = time.monotonic() + 8
        state = None
        while thread.is_alive() and time.monotonic() < until:
            with transaction(engine) as db:
                state = db.get(Job, candidate["job_id"]).state
            if state == "SUCCEEDED":
                break
            time.sleep(0.02)
        assert alive and not errors, {"worker_alive_after_transient_lock": alive, "errors": errors}
        assert state == "SUCCEEDED"
        assert (path / "INDEX.md").read_text() != base["INDEX.md"]
    finally:
        stop.set()
        thread.join(5)
        isolated.dispose()
    assert not thread.is_alive()


@pytest.mark.parametrize(
    "failure", ["read", "receipt.read", "plan_hash", "disabled_root", "stale_root", "missing_scope"]
)
def test_restore_receipt_revocation_blocks_selected_scope(
    prepared_restore, official, tmp_path, failure
):
    import json
    import subprocess

    from fastapi.testclient import TestClient
    from test_work_execution import runtime_settings

    from journeon.runtime import application

    configured, _, _, _, _, command, _, authorized = prepared_restore
    executed = subprocess.run(command, capture_output=True, text=True)
    assert executed.returncode == 0
    path = json.loads(executed.stdout)["database"]
    target = create_database(Path(path))
    from journeon.api import create_app
    from journeon.browser_auth import BrowserAuth

    with TestClient(
        create_app(
            target, browser_auth=BrowserAuth("https://example.test"), instructions=configured[3]
        ),
        base_url="https://example.test",
    ) as permitted:
        permitted.cookies.update(official[1].cookies)
        positive = permitted.get(
            "/api/v1/operations/" + authorized["operation_id"], headers=official[2]
        )
        assert positive.status_code == 200
        events = permitted.post("/api/v1/events/replay", headers=official[2], json={"limit": 100})
        assert any(
            event["operation_id"] == authorized["operation_id"] for event in events.json()["events"]
        )
    with transaction(target) as db:
        from journeon.models import InstructionRoot, ProtectedRequest, RestoreRequestScope

        if failure in {"read", "receipt.read"}:
            db.scalar(
                select(AccessGrant).where(
                    AccessGrant.capability == "project.instruction." + failure
                )
            ).enabled = False
        elif failure == "plan_hash":
            db.scalar(
                select(ProtectedRequest).where(
                    ProtectedRequest.operation_id == authorized["operation_id"]
                )
            ).payload_hash = "0" * 64
        elif failure == "missing_scope":
            for scope in db.scalars(select(RestoreRequestScope)):
                db.delete(scope)
        else:
            root = db.get(InstructionRoot, "environment")
            if failure == "disabled_root":
                root.enabled = False
            else:
                root.revision += 1
    with target.begin() as db:
        db.exec_driver_sql(
            "UPDATE operation_receipts SET result='invalid' WHERE id=?",
            (authorized["operation_id"],),
        )
        db.exec_driver_sql(
            "UPDATE outbox_events SET payload='invalid' WHERE operation_id=?",
            (authorized["operation_id"],),
        )
    target.dispose()
    with TestClient(
        application(runtime_settings(configured, tmp_path, path)), base_url="https://example.test"
    ) as client:
        client.cookies.update(official[1].cookies)
        receipt = client.get(
            "/api/v1/operations/" + authorized["operation_id"], headers=official[2]
        )
        replay = client.post("/api/v1/events/replay", headers=official[2], json={"limit": 100})
        exposed = any(
            e["operation_id"] == authorized["operation_id"] for e in replay.json()["events"]
        )
        assert (receipt.status_code, exposed) == (403, False), (receipt.status_code, exposed)


def test_stale_executor_cannot_reconcile_current_claim(official):
    engine, _, _, config = official
    _, _, _, candidate, _ = propose(official)
    old = JobService(engine, config)
    stale = old.claim()
    with transaction(engine) as db:
        db.get(Job, candidate["job_id"]).lease_deadline = 0
    current = JobService(engine, config)
    current.reconcile()
    with transaction(engine) as db:
        db.get(Job, candidate["job_id"]).due_at = 0
    claim = current.claim()
    assert claim is not None and claim.fence > stale.fence
    old.execute(stale)
    with transaction(engine) as db:
        row = db.get(Job, candidate["job_id"])
        assert (row.state, row.fence, row.claim_owner) == ("RUNNING", claim.fence, claim.owner), (
            row.state,
            row.reason,
            row.fence,
        )
    current.execute(claim)
    with transaction(engine) as db:
        assert db.get(Job, claim.job_id).state == "SUCCEEDED"


@pytest.mark.parametrize("disposition", ["FINISH_TARGET", "RESTORE_BASE"])
@pytest.mark.parametrize("resume", ["retry", "restart"])
def test_retry_committed_recovery_settles_job_and_attention(
    official, monkeypatch, tmp_path, disposition, resume
):
    import journeon.jobs as jobs
    from journeon.project_instructions import ProjectInstructionService

    engine, client, headers, config = official
    project, _, _, candidate, _ = propose(official)
    service = JobService(engine, config)
    claim = service.claim()
    original = ProjectInstructionService.publish

    def stop_before_publish(*args, **kwargs):
        raise OSError("Synthetic publication interruption")

    monkeypatch.setattr(ProjectInstructionService, "publish", stop_before_publish)
    service.execute(claim)
    monkeypatch.setattr(ProjectInstructionService, "publish", original)
    recovery = client.post(
        f"/api/v1/projects/{project}/instructions/recovery",
        headers=headers,
        json={"project_id": project},
    )
    assert recovery.status_code == 200
    prepared = client.post(
        "/api/v1/protected-operations/prepare",
        headers=headers,
        json={
            "effect": {
                **recovery.json(),
                "kind": "project.instructions.recover.v1",
                "idempotency_key": "recover-interrupted-settlement",
                "disposition": disposition,
            }
        },
    )
    assert prepared.status_code == 200
    preview = client.post(
        "/api/v1/protected-operations/preview", headers=headers, json=prepared.json()
    )
    assert preview.status_code == 200
    exact = {k: preview.json()[k] for k in ("request_id", "request_hash", "nonce")}
    settle = jobs.settle_recovery

    def interrupt(*args):
        raise OSError("Synthetic failure after canonical recovery commit")

    monkeypatch.setattr(jobs, "settle_recovery", interrupt)
    failed = client.post("/api/v1/protected-operations/confirm", headers=headers, json=exact)
    assert failed.status_code == 503
    monkeypatch.setattr(jobs, "settle_recovery", settle)

    def no_publication(*args, **kwargs):
        pytest.fail("A terminal recovery was published again")

    monkeypatch.setattr(ProjectInstructionService, "publish", no_publication)
    if resume == "retry":
        retry = client.post("/api/v1/protected-operations/confirm", headers=headers, json=exact)
        assert retry.status_code == 200
    else:
        from fastapi.testclient import TestClient
        from test_work_execution import runtime_settings

        from journeon.runtime import application

        with TestClient(
            application(runtime_settings(official, tmp_path)), base_url="https://example.test"
        ):
            until = time.monotonic() + 5
            while time.monotonic() < until:
                with transaction(engine) as db:
                    if db.get(Job, claim.job_id).effect != "UNKNOWN":
                        break
                time.sleep(0.02)
    job = client.get(f"/api/v1/jobs/{candidate['job_id']}", headers=headers).json()
    attention = client.get(f"/api/v1/jobs/{candidate['job_id']}/attention", headers=headers).json()
    expected = (
        ("SUCCEEDED", "COMMITTED", "RESOLVED")
        if disposition == "FINISH_TARGET"
        else ("FAILED", "ABANDONED", "RESOLVED")
    )
    assert (job["state"], job["effect"], attention[0]["disposition"]) == expected
    from sqlalchemy import func

    from journeon.models import Attention, OutboxEvent

    def retained():
        with transaction(engine) as db:
            item = db.scalar(select(Attention).where(Attention.job_id == claim.job_id))
            return (
                db.get(Job, claim.job_id).revision,
                len(item.history),
                db.scalar(select(func.count()).select_from(OutboxEvent)),
            )

    before = retained()
    for _ in range(2):
        service.reconcile()
        assert (
            client.post(
                "/api/v1/protected-operations/confirm", headers=headers, json=exact
            ).status_code
            == 200
        )
    assert retained() == before


@pytest.mark.parametrize("field", ["owner", "incarnation"])
def test_wrong_execution_identity_cannot_settle_claim(official, field):
    from dataclasses import replace

    engine, _, _, config = official
    propose(official)
    service = JobService(engine, config)
    claim = service.claim()
    service.execute(replace(claim, **{field: "stale"}))
    with transaction(engine) as db:
        row = db.get(Job, claim.job_id)
        assert (row.state, row.fence, row.claim_owner, row.incarnation) == (
            "RUNNING",
            claim.fence,
            claim.owner,
            claim.incarnation,
        )
    service.execute(claim)
    with transaction(engine) as db:
        assert db.get(Job, claim.job_id).state == "SUCCEEDED"


def test_unexpected_worker_failure_is_visible_to_runtime(official, tmp_path, monkeypatch, capsys):
    from fastapi.testclient import TestClient
    from test_work_execution import runtime_settings

    from journeon.runtime import application

    propose(official)

    def fail(_self):
        raise RuntimeError("Synthetic unexpected worker failure")

    monkeypatch.setattr(JobService, "claim", fail)
    with TestClient(
        application(runtime_settings(official, tmp_path)), base_url="https://example.test"
    ) as running:
        until = time.monotonic() + 5
        response = None
        while time.monotonic() < until:
            response = running.get("/instructions/authenticate")
            if response.status_code == 503:
                break
            time.sleep(0.02)
        assert response.status_code == 503
        assert response.json()["code"] == "DEPENDENCY_UNAVAILABLE"
    output = capsys.readouterr().out
    assert "JOB_WORKER_FAILED" in output
    assert "Synthetic unexpected" not in output


@pytest.mark.parametrize("stop_early", [False, True])
def test_storage_pressure_is_bounded_and_shutdown_interrupts_wait(
    official, monkeypatch, capsys, stop_early
):
    from sqlalchemy.exc import OperationalError

    _, _, _, config = official
    config = config.model_copy(
        update={"jobs": config.jobs.model_copy(update={"retry_seconds": 1, "max_attempts": 2})}
    )
    service = JobService(official[0], config)
    attempted = threading.Event()
    calls = []

    def busy():
        calls.append(1)
        error = sqlite3.OperationalError("Synthetic busy store")
        error.sqlite_errorcode = sqlite3.SQLITE_BUSY
        attempted.set()
        raise OperationalError("", (), error)

    monkeypatch.setattr(service, "reconcile", busy)
    stop = threading.Event()
    thread = threading.Thread(target=service.run, args=(stop,))
    thread.start()
    assert attempted.wait(2)
    if stop_early:
        stop.set()
    thread.join(3)
    try:
        assert not thread.is_alive()
        assert len(calls) == (1 if stop_early else 2)
        assert ("JOB_WORKER_FAILED" in capsys.readouterr().out) == (not stop_early)
    finally:
        stop.set()
        thread.join(3)


def test_selected_restore_mutation_grant_is_not_receipt_read_authority(prepared_restore, official):
    import json
    import subprocess

    from fastapi.testclient import TestClient

    from journeon.api import create_app
    from journeon.browser_auth import BrowserAuth

    configured, _, _, _, _, command, _, authorization = prepared_restore
    run = subprocess.run(command, capture_output=True, text=True)
    assert run.returncode == 0
    engine = create_database(Path(json.loads(run.stdout)["database"]))
    with transaction(engine) as db:
        db.scalar(
            select(AccessGrant).where(AccessGrant.capability == "project.instruction.restore")
        ).enabled = False
    try:
        with TestClient(
            create_app(
                engine, browser_auth=BrowserAuth("https://example.test"), instructions=configured[3]
            ),
            base_url="https://example.test",
        ) as client:
            client.cookies.update(official[1].cookies)
            receipt = client.get(
                "/api/v1/operations/" + authorization["operation_id"], headers=official[2]
            )
            replay = client.post("/api/v1/events/replay", headers=official[2], json={"limit": 100})
            assert receipt.status_code == 200
            assert any(
                e["operation_id"] == authorization["operation_id"] for e in replay.json()["events"]
            )
    finally:
        engine.dispose()
