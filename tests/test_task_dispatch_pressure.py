# SPDX-License-Identifier: AGPL-3.0-only
"""The shared Task driver preserves completion across real SQLite writer pressure."""

import sqlite3
import threading
import traceback
from contextlib import contextmanager

import test_task_dispatch as original_test
from sqlalchemy import event, select
from test_task_dispatch import attempt_environment, dispatch_environment, official  # noqa: F401

from journeon import executions
from journeon.database import transaction
from journeon.models import (
    Attempt,
    Execution,
    ExecutionEffect,
    Job,
    OutboxEvent,
    Receipt,
    TaskVerificationEvidence,
)


def test_task_driver_recovers_real_completed_writer_pressure(
    dispatch_environment,  # noqa: F811
    monkeypatch,
    request,
):
    engine, client, headers, config, command, _, _ = dispatch_environment
    held = threading.Event()
    admitted = threading.Event()
    release = threading.Event()
    observations = []
    launches = []
    original_transaction = executions.transaction
    original_started = executions.CurrentExecution.started
    original_start = executions.ExecutionService.start

    def start(*args, **kwargs):
        result = original_start(*args, **kwargs)
        admitted.set()
        return result

    def started(self, unit, invocation_id, containment, process_id):
        result = original_started(self, unit, invocation_id, containment, process_id)
        launches.append((unit, invocation_id, process_id))
        return result

    @contextmanager
    def completing(target_engine):
        with original_transaction(target_engine) as db:
            yield db
            row = db.scalar(select(Execution))
            if row is not None and row.state == "COMPLETED" and not held.is_set():
                assert row.drained and row.snapshot["verification_passed"]
                assert row.snapshot["completion"]["reason"] == "EXITED"
                assert row.snapshot["completion"]["exit_code"] == 0
                db.flush()
                assert db.scalar(select(ExecutionEffect).where(ExecutionEffect.kind == "COMPLETED"))
                observations.append("real_completion_flushed_before_commit")
                held.set()
                assert release.wait(30), "Expected dispatcher busy boundary was not reached"
                observations.append("holder_released")
        if held.is_set():
            observations.append("original_transaction_committed")

    def on_begin(connection, cursor, statement, parameters, context, executemany):
        if admitted.is_set() and statement == "BEGIN IMMEDIATE":
            if any(
                f.name == "execute_task" and f.filename.endswith("/jobs.py")
                for f in traceback.extract_stack()
            ):
                assert held.wait(30), (
                    "Actual completion did not reach the controlled commit boundary"
                )
                observations.append("dispatcher_begin_attempt_while_held")

    def on_error(context):
        code = getattr(context.original_exception, "sqlite_errorcode", None)
        poll = any(
            f.name == "execute_task" and f.filename.endswith("/jobs.py")
            for f in traceback.extract_stack()
        )
        if context.statement == "BEGIN IMMEDIATE" and code == sqlite3.SQLITE_BUSY and poll:
            assert held.is_set()
            observations.append("real_dispatcher_begin_busy")
            release.set()

    monkeypatch.setattr(executions, "transaction", completing)
    monkeypatch.setattr(executions.ExecutionService, "start", start)
    monkeypatch.setattr(executions.CurrentExecution, "started", started)
    event.listen(engine, "handle_error", on_error)
    event.listen(engine, "before_cursor_execute", on_begin)
    try:
        # Keep the original exact migrated-domain and immutable-evidence assertions.
        original_test.test_migrated_claim_domain_and_immutable_evidence(dispatch_environment)
        assert observations[:3] == [
            "real_completion_flushed_before_commit",
            "dispatcher_begin_attempt_while_held",
            "real_dispatcher_begin_busy",
        ]
        assert len(launches) == 1
        with transaction(engine) as db:
            assert len(db.scalars(select(Attempt)).all()) == 1
            assert len(db.scalars(select(Execution)).all()) == 1
            assert len(db.scalars(select(Job)).all()) == 1
            job = db.scalar(select(Job))
            assert job.state == "SUCCEEDED" and job.attempts == 1
            assert len(db.scalars(select(TaskVerificationEvidence)).all()) == 1
            assert (
                len(
                    db.scalars(
                        select(ExecutionEffect).where(ExecutionEffect.kind == "STARTED")
                    ).all()
                )
                == 1
            )
            receipts = db.scalars(select(Receipt)).all()
            assert len([r for r in receipts if r.command == "execution.start.v1"]) == 1
            job_receipts = [r for r in receipts if r.target_kind == "job"]
            assert len(job_receipts) == 3
            assert sorted(r.result["state"] for r in job_receipts) == [
                "QUEUED",
                "RUNNING",
                "SUCCEEDED",
            ]
            events = db.scalars(select(OutboxEvent).where(OutboxEvent.target_kind == "job")).all()
            assert {e.operation_id for e in events} == {r.id for r in job_receipts}
            before = (
                {r.id for r in receipts},
                {e.event_id for e in db.scalars(select(OutboxEvent))},
            )
        replay = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
        assert replay.status_code == 200
        assert replay.json()["job_id"] == job.id
        with transaction(engine) as db:
            assert before == (
                set(db.scalars(select(Receipt.id))),
                set(db.scalars(select(OutboxEvent.event_id))),
            )
        assert len(launches) == 1
    finally:
        release.set()
        event.remove(engine, "handle_error", on_error)
        event.remove(engine, "before_cursor_execute", on_begin)
        request.node.user_properties.append(("writer_pressure_events", observations))
        request.node.user_properties.append(
            ("actual_started_unit_invocation_namespace_pid", launches)
        )


def test_task_driver_leaves_other_queued_work_for_explicit_claim(dispatch_environment):  # noqa: F811
    engine, client, headers, config, command, _, _ = dispatch_environment
    admitted = []
    for key in ("first-queued-verification", "second-queued-verification"):
        response = client.post(
            "/api/v1/tasks/dispatch", headers=headers, json=command | {"idempotency_key": key}
        )
        assert response.status_code == 200, response.text
        admitted.append(response.json()["job_id"])
    worker, completed = original_test.dispatch_worker(engine, config)
    remaining = next(identity for identity in admitted if identity != completed.job_id)
    with transaction(engine) as db:
        assert db.get(Job, completed.job_id).state == "SUCCEEDED"
        queued = db.get(Job, remaining)
        assert (queued.state, queued.attempts, queued.claim_owner, queued.operation_id) == (
            "QUEUED",
            0,
            None,
            None,
        )
        assert len(db.scalars(select(Execution)).all()) == 1
    explicit = worker.claim()
    assert explicit is not None and explicit.job_id == remaining
    current = client.get("/api/v1/jobs/" + remaining)
    assert current.status_code == 200
    cancelled = client.post(
        "/api/v1/jobs/" + remaining + "/cancel",
        headers=headers,
        json={"expected_revision": current.json()["revision"]},
    )
    assert cancelled.status_code == 200, cancelled.text
    worker.reconcile(remaining, expected=explicit)
    with transaction(engine) as db:
        assert db.get(Job, remaining).state == "CANCELLED"
        assert len(db.scalars(select(Execution)).all()) == 1
