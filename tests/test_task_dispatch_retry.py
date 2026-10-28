# SPDX-License-Identifier: AGPL-3.0-only
import time

import pytest
from sqlalchemy import select
from test_task_dispatch import dispatch_worker
from test_workspace_discovery_work import dispatch
from workspace_durable_helpers import enrolled_owner as enrolled_owner
from workspace_durable_helpers import genuine_durable_work as genuine_durable_work
from workspace_durable_helpers import genuine_instruction_scope as genuine_instruction_scope
from workspace_durable_helpers import genuine_project_task as genuine_project_task

from journeon.contracts import DomainError
from journeon.database import transaction
from journeon.executions import ExecutionService
from journeon.jobs import JobService
from journeon.models import Attempt, Execution, Job, TaskVerificationEvidence


def test_dispatch_worker_retries_expired_start_without_duplicate_effects(
    genuine_durable_work, monkeypatch, request
):
    owner, config, _, _, _ = genuine_durable_work
    admitted = dispatch(genuine_durable_work, "expired-start-retry")
    starts = []
    interruptions = []
    original_start = ExecutionService.start
    original_reconcile = JobService.reconcile

    def delayed_start(self, *args, **kwargs):
        starts.append(kwargs["job"])
        if len(starts) == 1:
            time.sleep(config.jobs.lease_seconds + 1)
            with pytest.raises(DomainError) as denied:
                original_start(self, *args, **kwargs)
            assert denied.value.code == "PERMISSION_DENIED"
            raise denied.value
        return original_start(self, *args, **kwargs)

    def observe_reconcile(self, *args, **kwargs):
        result = original_reconcile(self, *args, **kwargs)
        if kwargs.get("expected") == (starts[0] if starts else None) and "expected" in kwargs:
            with transaction(owner.engine) as db:
                job = db.get(Job, admitted["job_id"])
                interruptions.append((job.state, job.effect, job.reason, job.attempts, job.fence))
                assert db.scalar(select(Execution)) is None
                assert db.scalar(select(TaskVerificationEvidence)) is None
        return result

    monkeypatch.setattr(ExecutionService, "start", delayed_start)
    monkeypatch.setattr(JobService, "reconcile", observe_reconcile)
    try:
        worker, first = dispatch_worker(owner.engine, config)
        assert len(starts) == 2
        assert first == starts[0]
        assert interruptions == [("RETRY_WAIT", "NONE", "EFFECT_FREE_INTERRUPTION", 1, 2)]
        assert [claim.job_id for claim in starts] == [admitted["job_id"]] * 2
        assert [claim.fence for claim in starts] == [1, 3]
        assert starts[0].owner == starts[1].owner
        assert starts[0].incarnation == starts[1].incarnation
        with transaction(owner.engine) as db:
            job = db.get(Job, admitted["job_id"])
            assert (job.state, job.attempts, job.fence) == ("SUCCEEDED", 2, 3)
            assert len(db.scalars(select(Job)).all()) == 1
            assert len(db.scalars(select(Attempt)).all()) == 1
            execution = db.scalars(select(Execution)).one()
            assert execution.job_id == job.id and execution.drained
            evidence = db.scalars(select(TaskVerificationEvidence)).one()
            assert evidence.job_id == job.id
        endpoint = f"/api/v1/jobs/{admitted['job_id']}/evidence"
        proof = owner.client.get(endpoint)
        assert proof.status_code == 200
        assert proof.json()["passed"]
        assert proof.json()["execution"]["completion"]["exit_code"] == 0
        assert proof.json()["execution"]["completion"]["drained"]
        worker.reconcile()
        assert worker.claim() is None
        assert owner.client.get(endpoint).json() == proof.json()
    finally:
        request.node.user_properties.append(("retry_claims", [claim.__dict__ for claim in starts]))
        request.node.user_properties.append(("effect_free_interruptions", interruptions))


@pytest.mark.parametrize(
    "changed", [{"job_id": "other"}, {"owner": "other"}, {"incarnation": "other"}, {"fence": 1}]
)
def test_dispatch_worker_rejects_unrelated_or_stale_retry(monkeypatch, changed):
    from contextlib import nullcontext
    from dataclasses import replace
    from types import SimpleNamespace

    import test_task_dispatch

    from journeon.jobs import JobExecutionIdentity

    first = JobExecutionIdentity("selected", 1, "owner", "incarnation")
    claims = iter((first, replace(first, **({"fence": 3} | changed))))
    executed = []
    db = SimpleNamespace(get=lambda *args: SimpleNamespace(state="RETRY_WAIT"))
    monkeypatch.setattr(test_task_dispatch, "transaction", lambda engine: nullcontext(db))
    monkeypatch.setattr(JobService, "claim", lambda self: next(claims))

    def run(self, stop):
        for _ in range(2):
            claim = self.claim()
            if claim is not None:
                executed.append(claim)

    monkeypatch.setattr(JobService, "run", run)
    with pytest.raises(AssertionError):
        dispatch_worker(None, None)
    assert executed == [first]
