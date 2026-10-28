# SPDX-License-Identifier: AGPL-3.0-only
"""Abrupt Task execution losses preserve durable identity without replaying uncertain work."""

import hashlib
import json
import multiprocessing
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_attempt_execution import attempt_environment  # noqa: F401
from test_production_instructions import official  # noqa: F401
from test_task_dispatch import dispatch_environment  # noqa: F401
from test_work_execution import runtime_settings

from journeon.database import create_database, transaction
from journeon.models import (
    AccessGrant,
    Attempt,
    Attention,
    Execution,
    ExecutionEffect,
    Job,
    OutboxEvent,
    Receipt,
    TaskVerificationEvidence,
    TaskVerificationJob,
)


def barrier(connection, window, **observed):
    connection.send({"window": window, "controller_pid": os.getpid(), **observed})
    connection.recv()


def expect_barrier(connection, process, window):
    assert connection.poll(45), "Owned controller did not reach the requested crash boundary"
    try:
        observed = connection.recv()
    except EOFError:
        raise AssertionError("Owned controller exited without a crash boundary") from None
    assert observed["window"] == window, "Controller reached the wrong crash boundary"
    assert observed["controller_pid"] == process.pid, "Crash boundary belongs to another controller"
    return observed


def require_killed(process):
    process.join(10)
    assert not process.is_alive(), "Owned crash controller did not terminate"
    assert process.exitcode == -signal.SIGKILL, "Controller did not undergo abrupt termination"


def control_controller(connection, mode):
    if mode != "missing":
        connection.send({"window": "wrong", "controller_pid": os.getpid()})
    connection.close()


@pytest.mark.parametrize("mode", ["missing", "wrong", "normal_exit"])
def test_crash_harness_rejects_wrong_or_missing_fault(mode):
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    process = context.Process(target=control_controller, args=(child, mode))
    process.start()
    child.close()
    try:
        if mode == "normal_exit":
            with pytest.raises(AssertionError, match="abrupt termination"):
                require_killed(process)
        else:
            with pytest.raises(
                AssertionError, match="without a crash boundary|wrong crash boundary"
            ):
                expect_barrier(parent, process, "expected")
    finally:
        process.join(10)
        if process.is_alive():
            process.kill()
            process.join(10)
        parent.close()
    assert process.exitcode == 0


def crash_controller(connection, database, config, actor, command, window, helper, journal):
    from journeon import execution_helper, executions, jobs
    from journeon.execution_process import ExecutionInterrupted
    from journeon.executions import CurrentExecution, ExecutionService
    from journeon.job_contracts import TaskDispatch
    from journeon.jobs import JobService
    from journeon.task_dispatch import TaskDispatchService

    engine = create_database(database, busy_timeout_ms=5000)
    if helper is not None:
        execution_helper.__file__ = str(helper)
    original_record = jobs.record

    def record(db, row, *, admission=False, event_type=None):
        if window == "prepared" and admission and row.kind == "TASK_VERIFICATION":
            barrier(connection, window, attempt_count=len(list(db.scalars(select(Attempt.id)))))
        original_record(db, row, admission=admission, event_type=event_type)
        if (
            window == "settlement_flushed"
            and row.kind == "TASK_VERIFICATION"
            and row.state == "SUCCEEDED"
            and not admission
            and event_type is None
        ):
            db.flush()
            assert db.in_transaction() and not db.new
            barrier(
                connection,
                window,
                job_id=row.id,
                receipts=list(db.scalars(select(Receipt.id).where(Receipt.target_id == row.id))),
                events=list(
                    db.scalars(select(OutboxEvent.event_id).where(OutboxEvent.target_id == row.id))
                ),
                evidence=list(db.scalars(select(TaskVerificationEvidence.id))),
            )

    jobs.record = record
    if window in ("prepared", "admitted"):
        result = TaskDispatchService(engine, config).admit(
            actor, TaskDispatch.model_validate(command)
        )
        barrier(connection, window, job_id=result.job_id)
        return
    worker = JobService(engine, config, executions=ExecutionService(engine, config))
    claim = worker.claim()
    assert claim is not None
    if window == "claimed":
        barrier(connection, window, job_id=claim.job_id, fence=claim.fence)
    if window == "intent":

        def submit(*args, **kwargs):
            barrier(connection, window, job_id=claim.job_id)

        executions.ThreadPoolExecutor.submit = submit
    phases = {
        "preparing": ("preparing", True),
        "before_start": ("starting", True),
    }
    if window in phases:
        method, after = phases[window]
        original = getattr(CurrentExecution, method)

        def observe(self, *args, **kwargs):
            if after:
                original(self, *args, **kwargs)
            barrier(
                connection,
                window,
                job_id=claim.job_id,
                invocation=args[1],
                process_id=args[3] if method == "started" else None,
            )
            if not after:
                original(self, *args, **kwargs)

        setattr(CurrentExecution, method, observe)
    original_started = CurrentExecution.started

    def started(self, unit, invocation, containment, process_id):
        observe_physical_start(unit, invocation, config.executions.routes[0], journal)
        if window == "after_start":
            barrier(
                connection,
                window,
                job_id=claim.job_id,
                invocation=invocation,
                process_id=process_id,
            )
        original_started(self, unit, invocation, containment, process_id)
        if window == "running":
            barrier(
                connection,
                window,
                job_id=claim.job_id,
                invocation=invocation,
                process_id=process_id,
            )

    CurrentExecution.started = started
    if window in ("result_received", "drain_started", "before_result"):
        original_run = executions.run_local

        def run(*args, **kwargs):
            try:
                actual = original_run(*args, **kwargs)
            except ExecutionInterrupted as error:
                assert window in ("drain_started", "before_result")
                assert error.observation["launcher_exit_code"] == 79
                connection.send(
                    {
                        "window": window,
                        "controller_pid": os.getpid(),
                        "helper_launcher_exit": error.observation["launcher_exit_code"],
                    }
                )
                raise
            assert window == "result_received"
            assert actual["completion"]["drained"]
            assert actual["completion"]["exit_code"] == 0
            barrier(connection, window, job_id=claim.job_id, invocation=actual["invocation_id"])
            return actual

        executions.run_local = run
    if window == "completed":

        def settle(self, db, row, *, reconcile=False):
            execution = db.scalar(select(Execution))
            assert execution.state == "COMPLETED" and execution.drained
            barrier(
                connection, window, job_id=row.id, invocation=execution.snapshot["invocation_id"]
            )

        TaskDispatchService.settle = settle
    worker.execute(claim)
    if window == "settled":
        barrier(connection, window, job_id=claim.job_id)
    worker.executions.shutdown()
    engine.dispose()
    connection.close()


def authenticated_actor(engine, client, headers):
    values = headers | {"cookie": "; ".join(f"{k}={v}" for k, v in client.cookies.items())}
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "headers": [(k.lower().encode(), v.encode()) for k, v in values.items()],
        }
    )
    return client.app.state.browser_auth.resolve(engine, request)


def observation(engine):
    with transaction(engine) as db:
        executions = list(db.scalars(select(Execution)))
        job = db.scalar(select(Job).where(Job.kind == "TASK_VERIFICATION"))
        return {
            "attempts": list(db.scalars(select(Attempt.id))),
            "job_ids": list(db.scalars(select(Job.id).where(Job.kind == "TASK_VERIFICATION"))),
            "job": None
            if job is None
            else {
                "id": job.id,
                "revision": job.revision,
                "fence": job.fence,
                "owner": job.claim_owner,
                "incarnation": job.incarnation,
                "state": job.state,
                "effect": job.effect,
                "reason": job.reason,
                "operation": job.operation_id,
            },
            "executions": [
                {
                    "id": e.id,
                    "state": e.state,
                    "drained": e.drained,
                    "snapshot": e.snapshot,
                    "inputs": e.inputs,
                }
                for e in executions
            ],
            "binding": [
                (
                    b.job_id,
                    b.attempt_id,
                    b.manifest_id,
                    b.execution_id,
                    b.claim_fence,
                    b.claim_owner,
                    b.claim_incarnation,
                )
                for b in db.scalars(select(TaskVerificationJob))
            ],
            "phases": list(
                db.scalars(select(ExecutionEffect.kind).order_by(ExecutionEffect.revision))
            ),
            "proofs": [
                (e.id, e.content_hash) for e in db.scalars(select(TaskVerificationEvidence))
            ],
            "attention": [(a.id, a.reason, a.disposition) for a in db.scalars(select(Attention))],
            "receipts": {
                r.id: r.result
                for r in db.scalars(
                    select(Receipt).where(
                        Receipt.target_id.in_(
                            ([job.id] if job else []) + [e.id for e in executions]
                        )
                    )
                )
            },
            "events": {
                e.event_id: e.payload
                for e in db.scalars(
                    select(OutboxEvent).where(
                        OutboxEvent.target_id.in_(
                            ([job.id] if job else []) + [e.id for e in executions]
                        )
                    )
                )
            },
            "started": [
                (e.id, e.observation)
                for e in db.scalars(
                    select(ExecutionEffect).where(ExecutionEffect.kind == "STARTED")
                )
            ],
        }


def verifier_program(window):
    descendant = window in ("drain_started", "before_result")
    return f"""import hashlib, json, os, time
from pathlib import Path
child = None
if {descendant!r}:
    child = os.fork()
    if child == 0:
        Path("crash-descendant").write_text(str(os.getpid()))
        time.sleep(60)
        os._exit(0)
    deadline = time.monotonic() + 45
    while not Path("crash-descendant").exists():
        assert time.monotonic() < deadline
        time.sleep(0.01)
with Path("crash-invocations").open("a") as marker:
    actual = {{"namespace_pid": os.getpid(), "descendant_namespace_pid": child}}
    actual["source_sha256"] = hashlib.sha256(Path("crash_verifier.py").read_bytes()).hexdigest()
    marker.write(json.dumps(actual) + "\\n")
deadline = time.monotonic() + 45
while not Path("crash-observed").exists():
    assert time.monotonic() < deadline
    time.sleep(0.01)
if {window == "running"!r}:
    time.sleep(60)
print("actual verifier", flush=True)
"""


def observe_physical_start(unit, invocation, route, journal):
    from journeon.execution_process import unit_observation

    actual_invocation, group = unit_observation(unit, route.control_seconds)
    assert actual_invocation == invocation
    deadline = time.monotonic() + route.authority_lease_seconds
    while True:
        for pid in (group / "cgroup.procs").read_text().split():
            try:
                workspace = Path("/proc") / pid / "root/workspace"
                marker = workspace / "crash-invocations"
                if marker.exists():
                    entries = marker.read_text().splitlines()
                    if entries and entries[-1].endswith("}"):
                        break
            except FileNotFoundError:
                continue
        else:
            assert time.monotonic() < deadline, "Real verifier did not write its invocation marker"
            time.sleep(0.01)
            continue
        break
    assert len(entries) == 1, "Contained workspace records more than one verifier invocation"
    actual = json.loads(entries[0])
    # Resolve namespace identities only through this invocation's actual cgroup members.
    members = {}
    for pid in (group / "cgroup.procs").read_text().split():
        status = dict(
            line.split(":", 1) for line in (Path("/proc") / pid / "status").read_text().splitlines()
        )
        members[int(status["NSpid"].split()[-1])] = (int(pid), status["State"].strip())
    observed = {
        "unit": unit,
        "invocation": invocation,
        "marker": actual,
        "physical_count": len(entries),
    }
    for name in ("namespace_pid", "descendant_namespace_pid"):
        if actual[name] is not None:
            host_pid, state = members[actual[name]]
            assert not state.startswith("Z"), "Observed contained process has already exited"
            observed[name + "_host"] = host_pid
            observed[name + "_state"] = state
    if actual["descendant_namespace_pid"] is not None:
        assert (
            int((workspace / "crash-descendant").read_text()) == actual["descendant_namespace_pid"]
        )
    with journal.open("a") as retained:
        retained.write(json.dumps(observed, sort_keys=True) + "\n")
    (workspace / "crash-observed").touch()
    return observed


def physical_observations(journal):
    return (
        [json.loads(line) for line in journal.read_text().splitlines()] if journal.exists() else []
    )


WINDOWS = [
    "prepared",
    "admitted",
    "claimed",
    "intent",
    "preparing",
    "before_start",
    "after_start",
    "running",
    "drain_started",
    "before_result",
    "result_received",
    "completed",
    "settlement_flushed",
    "settled",
]


@pytest.mark.parametrize(
    ("window", "dispatch_environment", "revoke"),
    [
        (
            window,
            "exec(open('crash_verifier.py').read())",
            False,
        )
        for window in WINDOWS
    ]
    + [
        ("completed", "exec(open('crash_verifier.py').read())", True),
        ("settled", "exec(open('crash_verifier.py').read())", True),
    ],
    indirect=["dispatch_environment"],
)
def test_task_abrupt_crash_reconciles_durable_identity(
    dispatch_environment,  # noqa: F811
    tmp_path,
    window,
    revoke,
    request,
    monkeypatch,
):
    from journeon import execution_helper
    from journeon.runtime import application

    engine, client, headers, config, command, root, storage = dispatch_environment
    (root / "crash_verifier.py").write_text(verifier_program(window))
    actor = authenticated_actor(engine, client, headers)
    journal = tmp_path / "physical-invocations.jsonl"
    helper = None
    if window in ("drain_started", "before_result"):
        source = Path(execution_helper.__file__).read_text()
        anchor = (
            "            kill_children()\n" if window == "drain_started" else "    process.wait()\n"
        )
        assert source.count(anchor) == 1
        helper = tmp_path / "fault_helper.py"
        helper.write_text(
            source.replace(
                anchor,
                anchor
                + ("            " if window == "drain_started" else "    ")
                + "os._exit(79)\n",
            )
        )
        assert (
            hashlib.sha256(helper.read_bytes()).digest() != hashlib.sha256(source.encode()).digest()
        )
    if window not in ("prepared", "admitted"):
        response = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
        assert response.status_code == 200, response.text
    initial = observation(engine)
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    process = context.Process(
        target=crash_controller,
        args=(child, Path(engine.url.database), config, actor, command, window, helper, journal),
    )
    process.start()
    child.close()
    try:
        reached = expect_barrier(parent, process, window)
        if helper is None:
            process.kill()
            require_killed(process)
        else:
            process.join(30)
            assert not process.is_alive() and process.exitcode == 0
            assert reached["helper_launcher_exit"] == 79
    finally:
        if process.is_alive():
            process.kill()
            process.join(10)
        parent.close()
    before = observation(engine)
    physical_before = physical_observations(journal)
    assert len(physical_before) == (0 if window in WINDOWS[:6] else 1)
    assert len(before["attempts"]) == 1
    admitted_verifier = storage / before["attempts"][0] / "workspace/crash_verifier.py"
    assert admitted_verifier.read_bytes() == verifier_program(window).encode()
    verifier_hash = hashlib.sha256(admitted_verifier.read_bytes()).hexdigest()
    if window == "prepared":
        assert reached["attempt_count"] == 1
        assert before["job"] is None and not before["executions"]
    expected_phase = {
        "intent": "INTENT",
        "preparing": "PREPARING",
        "before_start": "START_REQUESTED",
        "after_start": "START_REQUESTED",
        "running": "STARTED",
        "result_received": "STARTED",
        "completed": "COMPLETED",
        "settlement_flushed": "COMPLETED",
        "settled": "COMPLETED",
    }.get(window)
    if expected_phase:
        assert before["phases"][-1] == expected_phase
    if window in ("after_start", "running"):
        assert reached["process_id"] > 1 and reached["invocation"]
    if window in ("intent", "preparing", "before_start", "after_start"):
        assert before["started"] == []
    if window in ("admitted", "claimed"):
        assert before["executions"] == []
    if window == "claimed":
        assert before["job"]["fence"] == reached["fence"]
    if window in ("prepared", "admitted"):
        response = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
        assert response.status_code == 200, response.text
        replayed_admission = observation(engine)
        assert replayed_admission["executions"] == []
        assert replayed_admission["attempts"] == before["attempts"]
        if window == "admitted":
            assert response.json()["job_id"] == reached["job_id"]
            assert replayed_admission == before
    if window == "settlement_flushed":
        assert before["proofs"] == [] and before["job"]["state"] == "RUNNING"
        assert set(reached["receipts"]) - before["receipts"].keys()
        assert set(reached["events"]) - before["events"].keys()
        assert reached["evidence"]
    if revoke:
        with transaction(engine) as db:
            db.get(
                AccessGrant,
                "dispatch:execution.start" if window == "completed" else "dispatch:execution.read",
            ).enabled = False
    from journeon.executions import CurrentExecution

    original_started = CurrentExecution.started

    def started(self, unit, invocation, containment, process_id):
        observe_physical_start(unit, invocation, config.executions.routes[0], journal)
        original_started(self, unit, invocation, containment, process_id)

    monkeypatch.setattr(CurrentExecution, "started", started)
    settings = runtime_settings((engine, client, headers, config), tmp_path)
    with TestClient(
        application(settings), base_url="https://example.test", cookies=client.cookies
    ) as running:
        deadline = time.monotonic() + 45
        while True:
            current = observation(engine)
            if current["job"]["state"] not in ("QUEUED", "RUNNING", "RETRY_WAIT"):
                break
            assert time.monotonic() < deadline, current["job"]
            time.sleep(0.05)
        identity = current["job"]["id"]
        assert current["job_ids"] == [identity] and len(current["binding"]) == 1
        receipts = list(current["receipts"].values())
        assert sum(r["command"] == "job.admitted.v1" for r in receipts) == 1
        assert sum(r["command"] == "execution.start.v1" for r in receipts) == 1
        terminal = [
            r
            for r in receipts
            if r["command"] == "job.changed.v1" and r["revision"] == current["job"]["revision"]
        ]
        assert len(terminal) == (2 if current["job"]["reason"] else 1)
        assert all(r["state"] == current["job"]["state"] for r in terminal)
        events = list(current["events"].values())
        assert sorted(e["operation_id"] for e in events) == sorted(current["receipts"])
        assert all(current["receipts"][e["operation_id"]] == e for e in events)
        if window == "settlement_flushed":
            assert (
                not (set(reached["receipts"]) - before["receipts"].keys())
                & current["receipts"].keys()
            )
            assert not (set(reached["events"]) - before["events"].keys()) & current["events"].keys()
        replay = running.post("/api/v1/tasks/dispatch", headers=headers, json=command)
        if revoke:
            assert replay.status_code == 403
        else:
            assert replay.status_code == 200 and replay.json()["job_id"] == identity
        for operation, expected in current["receipts"].items():
            retained = running.get(f"/api/v1/operations/{operation}")
            if revoke and window == "settled" and "execution" in expected:
                assert retained.status_code == 403
                assert retained.json()["code"] == "PERMISSION_DENIED"
            else:
                assert retained.status_code == 200, retained.text
                assert retained.json() == expected
        task = running.get("/api/v1/tasks/" + command["origin"]["task_id"])
        assert task.status_code == 200 and task.json()["state"] != "DONE"
        proof = running.get(f"/api/v1/jobs/{identity}/evidence")
        succeeded = window in (
            "prepared",
            "admitted",
            "claimed",
            "completed",
            "settlement_flushed",
            "settled",
        ) and not (revoke and window == "completed")
        assert current["job"]["state"] == ("SUCCEEDED" if succeeded else "FAILED")
        assert len(current["executions"]) == 1
        actual = current["executions"][0]
        assert actual["snapshot"]["origin"] == "TASK_VERIFICATION"
        assert actual["drained"]
        if succeeded:
            assert actual["state"] == "COMPLETED" and len(current["proofs"]) == 1
            assert proof.status_code == (403 if revoke else 200)
        else:
            assert current["proofs"] == [] and current["attention"]
            reason = (
                "EVIDENCE_PUBLICATION_BLOCKED" if revoke else "EXECUTION_RECONCILIATION_REQUIRED"
            )
            assert current["job"]["reason"] == reason
            assert any(a[1:] == (reason, "OPEN") for a in current["attention"])
            assert actual["state"] == ("COMPLETED" if revoke else "UNKNOWN")
            assert proof.status_code in (403, 404)
        assert current["attempts"] == before["attempts"]
        if initial["job"] is not None:
            assert identity == initial["job"]["id"]
        if before["executions"]:
            assert actual["id"] == before["executions"][0]["id"]
            assert (
                actual["snapshot"]["invocation_id"]
                == before["executions"][0]["snapshot"]["invocation_id"]
            )
            assert current["started"] == before["started"]
            assert current["binding"] == before["binding"]
        assert len(current["started"]) == (
            0 if window in ("intent", "preparing", "before_start", "after_start") else 1
        )
        binding = current["binding"][0]
        assert binding[:2] == (identity, current["attempts"][0])
        assert binding[3:] == (
            actual["id"],
            current["job"]["fence"],
            current["job"]["owner"],
            current["job"]["incarnation"],
        )
        if window == "claimed":
            assert current["job"]["fence"] > reached["fence"]
        assert all(current["receipts"][key] == value for key, value in before["receipts"].items())
        assert all(current["events"][key] == value for key, value in before["events"].items())
    after = observation(engine)
    physical_after = physical_observations(journal)
    assert len(physical_after) == (0 if window in ("intent", "preparing", "before_start") else 1)
    if physical_before:
        assert physical_after == physical_before
    for observed in physical_after:
        assert observed["marker"]["source_sha256"] == verifier_hash
        assert observed["unit"] == actual["snapshot"]["unit"]
        assert observed["invocation"] == actual["snapshot"]["invocation_id"]
        if window in ("drain_started", "before_result"):
            assert observed["marker"]["descendant_namespace_pid"] > 1
            assert observed["descendant_namespace_pid_host"] > 1
        else:
            assert observed["marker"]["descendant_namespace_pid"] is None
    assert after == current
    with TestClient(application(settings), base_url="https://example.test", cookies=client.cookies):
        assert observation(engine) == after
        assert physical_observations(journal) == physical_after
    if window == "settled":
        assert after == before
    from journeon.execution_process import control_environment

    unit = subprocess.run(
        [
            "/usr/bin/systemctl",
            "--user",
            "show",
            actual["snapshot"]["unit"],
            "--property=LoadState",
            "--property=ActiveState",
            "--property=ControlGroup",
        ],
        env=control_environment(),
        capture_output=True,
        text=True,
        timeout=config.executions.routes[0].control_seconds,
    )
    assert unit.returncode in (0, 4)
    state = dict(line.split("=", 1) for line in unit.stdout.splitlines())
    assert state["LoadState"] == "not-found" and state["ActiveState"] == "inactive"
    assert not state["ControlGroup"]
    request.node.user_properties.append(
        (
            "task_crash",
            json.dumps(
                {
                    "window": window,
                    "revoked": revoke,
                    "controller_pid": process.pid,
                    "controller_exit": process.exitcode,
                    "barrier": reached,
                    "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest()
                    if helper
                    else None,
                    "helper_source_sha256": hashlib.sha256(
                        Path(execution_helper.__file__).read_bytes()
                    ).hexdigest(),
                    "before_job": before["job"],
                    "after_job": after["job"],
                    "binding": after["binding"],
                    "attempts": after["attempts"],
                    "execution": actual["id"],
                    "invocation": actual["snapshot"]["invocation_id"],
                    "phases": after["phases"],
                    "started_count": len(after["started"]),
                    "verifier_source_sha256": verifier_hash,
                    "physical_before": physical_before,
                    "physical_after": physical_after,
                    "proofs": after["proofs"],
                    "unit_observation": state,
                    "terminal_receipt_ids": [r["operation_id"] for r in terminal],
                    "receipt_ids": sorted(after["receipts"]),
                    "event_ids": sorted(after["events"]),
                },
                sort_keys=True,
            ),
        )
    )
