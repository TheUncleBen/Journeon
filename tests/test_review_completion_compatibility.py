# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import json

from sqlalchemy import text
from test_task_admission import admitted  # noqa: F401
from test_work import work  # noqa: F401

from journeon.contracts import TaskAdmission, TaskAssign, TaskControl, TaskReceipt, TaskRevise
from journeon.database import transaction
from journeon.receipts import OperationService
from journeon.work import WorkService


def test_all_seven_prior_task_commands_keep_receipt_json_shape(admitted):  # noqa: F811
    (engine, _, actor, _, create), configure = admitted
    service = WorkService(engine)
    policy = service.configure_verification(actor, configure).policy
    results = [service.create(actor, create.model_copy(update={"expected_project_revision": 2}))]
    current = results[-1].task
    results.append(
        service.revise(
            actor,
            TaskRevise(
                schema_version=1,
                idempotency_key="legacy-revise",
                task_id=current.task_id,
                expected_revision=current.revision,
                reason="Retain prior receipt shapes",
                expected_policy_revision=1,
                success_conditions=[policy.checks[0].criterion],
                workflow=policy.workflow,
            ),
        )
    )
    current = results[-1].task
    results.append(
        service.assign(
            actor,
            TaskAssign(
                schema_version=1,
                idempotency_key="legacy-assign",
                task_id=current.task_id,
                expected_revision=current.revision,
                reason="Retain human responsibility",
                responsibility="HUMAN",
            ),
        )
    )
    current = results[-1].task
    results.append(
        service.create_or_continue_task(
            actor,
            TaskAdmission(
                schema_version=1,
                idempotency_key="legacy-admit",
                task_id=current.task_id,
                expected_revision=current.revision,
                expected_policy_revision=1,
                reason="Check current admission",
            ),
        )
    )
    for action in ("pause", "resume", "cancel"):
        current = results[-1].task
        results.append(
            service.control(
                actor,
                action,
                TaskControl(
                    schema_version=1,
                    idempotency_key="legacy-" + action,
                    task_id=current.task_id,
                    expected_revision=current.revision,
                    reason="Exercise the existing lifecycle command",
                ),
            )
        )
    assert {result.command for result in results} == {
        "task.create.v1",
        "task.revise.v1",
        "task.assign.v1",
        "task.admit.v1",
        "task.pause.v1",
        "task.resume.v1",
        "task.cancel.v1",
    }
    with transaction(engine) as db:
        original = {
            result.operation_id: db.execute(
                text("SELECT result FROM operation_receipts WHERE id=:id"),
                {"id": result.operation_id},
            ).scalar_one()
            for result in results
        }
    hashes = {
        identity: hashlib.sha256(value.encode()).hexdigest() for identity, value in original.items()
    }
    for result in results:
        stored = json.loads(original[result.operation_id])
        assert "completion" not in stored["task"]
        assert TaskReceipt.model_validate(stored).model_dump(mode="json") == stored
        assert OperationService(engine).receipt(actor, result.operation_id) == result
    with transaction(engine) as db:
        for identity, expected in hashes.items():
            retained = db.execute(
                text("SELECT result FROM operation_receipts WHERE id=:id"), {"id": identity}
            ).scalar_one()
            assert hashlib.sha256(retained.encode()).hexdigest() == expected
