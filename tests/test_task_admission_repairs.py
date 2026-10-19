# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from test_task_admission import admitted, prepared  # noqa: F401
from test_work import work  # noqa: F401

from journeon.contracts import DomainError, TaskAssign
from journeon.database import transaction
from journeon.models import AccessGrant


def test_human_assignment_replay_same_unchanged_authority(admitted):  # noqa: F811
    (engine, _, actor, _, _), configure = admitted
    service, task, _ = prepared(admitted)
    with transaction(engine) as db:
        db.get(AccessGrant, "admission:execution.admit").enabled = False
    command = TaskAssign(
        schema_version=1,
        idempotency_key="human-retry",
        task_id=task.task_id,
        expected_revision=task.revision,
        reason="Assign human",
        responsibility="HUMAN",
    )
    first = service.assign(actor, command)
    assert service.assign(actor, command) == first


def test_human_assignment_replay_without_configured_policy(admitted):  # noqa: F811
    (engine, _, actor, _, create), _ = admitted
    from journeon.work import WorkService

    service = WorkService(engine)
    task = service.create(actor, create).task
    command = TaskAssign(
        schema_version=1,
        idempotency_key="human-no-policy",
        task_id=task.task_id,
        expected_revision=task.revision,
        reason="Assign human",
        responsibility="HUMAN",
    )
    first = service.assign(actor, command)
    assert service.assign(actor, command) == first


def test_invalid_policy_check_binding_is_client_validation_error(admitted):  # noqa: F811
    from fastapi.testclient import TestClient

    from journeon.api import create_app
    from journeon.browser_auth import COOKIE_NAME, BrowserAuth

    (engine, _, _, issued, _), configure = admitted
    data = configure.model_dump()
    data["checks"][0]["check_id"] = "different-check"
    with TestClient(
        create_app(engine, browser_auth=BrowserAuth("https://testserver")),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(COOKIE_NAME, issued.token)
        response = client.post(
            "/api/v1/projects/verification",
            json=data,
            headers={"Origin": "https://testserver", "X-CSRF-Token": issued.csrf_token},
        )
        assert response.status_code == 422, (response.status_code, response.json())


def test_denied_admission_replay_same_unchanged_authority(admitted):  # noqa: F811
    (engine, _, actor, _, _), _ = admitted
    service, task, command = prepared(admitted)
    with transaction(engine) as db:
        db.get(AccessGrant, "admission:execution.admit").enabled = False
    first = service.create_or_continue_task(actor, command)
    assert first.task.admission.decision == "DENY"
    assert service.create_or_continue_task(actor, command) == first


def test_invalid_revised_workflow_binding_is_client_validation_error(admitted):  # noqa: F811
    from fastapi.testclient import TestClient

    from journeon.api import create_app
    from journeon.browser_auth import COOKIE_NAME, BrowserAuth

    (engine, _, actor, issued, _), _ = admitted
    service, task, _ = prepared(admitted)
    data = dict(
        schema_version=1,
        idempotency_key="invalid-revise",
        task_id=task.task_id,
        expected_revision=task.revision,
        expected_policy_revision=1,
        reason="Revise",
        success_conditions=["Check passes"],
        workflow={
            "steps": [{"step_id": "verify", "kind": "VERIFICATION", "check_id": "different-check"}]
        },
    )
    with TestClient(
        create_app(engine, browser_auth=BrowserAuth("https://testserver")),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(COOKIE_NAME, issued.token)
        response = client.post(
            "/api/v1/tasks/revise",
            json=data,
            headers={"Origin": "https://testserver", "X-CSRF-Token": issued.csrf_token},
        )
        assert response.status_code == 422, (response.status_code, response.json())


def test_revision_can_add_work_before_retained_verification_gate(admitted):  # noqa: F811
    from journeon.contracts import TaskRevise, TaskWorkflow

    (engine, _, actor, _, _), configure = admitted
    service, task, _ = prepared(admitted)
    workflow = TaskWorkflow(
        steps=[
            {"step_id": "work", "kind": "WORK"},
            {
                "step_id": "verify",
                "kind": "VERIFICATION",
                "check_id": "check",
                "dependencies": ["work"],
            },
        ]
    )
    command = TaskRevise(
        schema_version=1,
        idempotency_key="add-prerequisite",
        task_id=task.task_id,
        expected_revision=task.revision,
        expected_policy_revision=1,
        reason="Add work before proof",
        success_conditions=["Check passes"],
        workflow=workflow,
    )
    result = service.revise(actor, command)
    assert result.task.workflow == workflow


@pytest.mark.parametrize("responsibility", ["HUMAN", "UNASSIGNED"])
@pytest.mark.parametrize("policy_state", ["absent", "disabled", "enabled"])
def test_non_bot_replay_needs_no_execution_grant(admitted, responsibility, policy_state):  # noqa: F811
    from journeon.work import WorkService

    (engine, _, actor, _, create), configure = admitted
    service = WorkService(engine)
    if policy_state != "absent":
        service.configure_verification(
            actor, configure.model_copy(update={"enabled": policy_state == "enabled"})
        )
        create = create.model_copy(update={"expected_project_revision": 2})
    task = service.create(actor, create).task
    with transaction(engine) as db:
        db.get(AccessGrant, "admission:execution.admit").enabled = False
    command = TaskAssign(
        schema_version=1,
        idempotency_key="assignment",
        task_id=task.task_id,
        expected_revision=task.revision,
        reason="Change responsibility",
        responsibility=responsibility,
    )
    first = service.assign(actor, command)
    assert service.assign(actor, command) == first
    assert service.read(actor, task.task_id) == first.task


@pytest.mark.parametrize(
    "capability",
    ["task.assign", "task.read", "task.receipt.read", "project.verification.read", "session"],
)
def test_assignment_replay_still_requires_applicable_authority(admitted, capability):  # noqa: F811
    from sqlalchemy import select

    from journeon.models import BrowserSession

    (engine, _, actor, _, _), _ = admitted
    service, task, _ = prepared(admitted)
    command = TaskAssign(
        schema_version=1,
        idempotency_key="assignment",
        task_id=task.task_id,
        expected_revision=task.revision,
        reason="Assign human",
        responsibility="HUMAN",
    )
    service.assign(actor, command)
    with transaction(engine) as db:
        if capability == "session":
            db.get(BrowserSession, actor.authentication_ref).revoked = True
        else:
            for grant in db.scalars(
                select(AccessGrant).where(
                    AccessGrant.principal_id == actor.principal_id,
                    AccessGrant.capability == capability,
                )
            ):
                grant.enabled = False
    with pytest.raises(DomainError) as error:
        service.assign(actor, command)
    assert error.value.code == (
        "AUTHENTICATION_REQUIRED" if capability == "session" else "PERMISSION_DENIED"
    )


@pytest.mark.parametrize("mode", ["missing-policy", "disabled-policy", "unassigned", "paused"])
def test_non_admit_outcomes_replay_without_mutation(admitted, mode):  # noqa: F811
    from journeon.contracts import TaskAdmission, TaskControl
    from journeon.work import WorkService

    (engine, _, actor, _, create), configure = admitted
    service = WorkService(engine)
    if mode != "missing-policy":
        service.configure_verification(
            actor, configure.model_copy(update={"enabled": mode != "disabled-policy"})
        )
        create = create.model_copy(update={"expected_project_revision": 2})
    if mode == "unassigned":
        create = create.model_copy(update={"responsibility": "UNASSIGNED"})
    task = service.create(actor, create).task
    if mode == "paused":
        task = service.control(
            actor,
            "pause",
            TaskControl(
                schema_version=1,
                idempotency_key="pause",
                task_id=task.task_id,
                expected_revision=task.revision,
                reason="Pause",
            ),
        ).task
    command = TaskAdmission(
        schema_version=1,
        idempotency_key="admit",
        task_id=task.task_id,
        expected_revision=task.revision,
        expected_policy_revision=1,
        reason="Prepare",
    )
    first = service.create_or_continue_task(actor, command)
    assert first.task.admission.decision == (
        "QUEUE" if mode in ("paused", "unassigned") else "DENY"
    )
    assert service.create_or_continue_task(actor, command) == first
    assert not first.task.admission.execution_authorized
    assert not first.task.admission.execution_started
    assert service.read(actor, task.task_id) == first.task


def state_counts(engine):
    from sqlalchemy import func, select

    from journeon.models import (
        OutboxEvent,
        Project,
        Receipt,
        TaskRevision,
        VerificationPolicyRevision,
    )

    with transaction(engine) as db:
        return [
            db.scalar(select(func.count()).select_from(table))
            for table in (OutboxEvent, Receipt, TaskRevision, VerificationPolicyRevision)
        ] + [(p.id, p.revision) for p in db.scalars(select(Project))]


@pytest.mark.parametrize(
    "mode", ["duplicate-check", "unbound-check", "duplicate-capability", "task-binding"]
)
def test_proposed_validation_is_422_and_atomic(admitted, mode):  # noqa: F811
    from fastapi.testclient import TestClient

    from journeon.api import create_app
    from journeon.browser_auth import COOKIE_NAME, BrowserAuth

    (engine, _, _, issued, _), configure = admitted
    service, task, _ = prepared(admitted)
    data = configure.model_dump() | {
        "idempotency_key": "invalid",
        "expected_project_revision": 2,
        "expected_policy_revision": 1,
    }
    path = "/api/v1/projects/verification"
    if mode == "duplicate-check":
        data["checks"] += data["checks"]
    elif mode == "unbound-check":
        data["checks"][0]["check_id"] = "unbound"
    elif mode == "duplicate-capability":
        data["required_capabilities"] = ["task.read", "task.read"]
    else:
        path = "/api/v1/tasks/revise"
        data = dict(
            schema_version=1,
            idempotency_key="invalid",
            task_id=task.task_id,
            expected_revision=task.revision,
            expected_policy_revision=1,
            reason="Revise",
            success_conditions=["Check"],
            workflow={
                "steps": [{"step_id": "verify", "kind": "VERIFICATION", "check_id": "unbound"}]
            },
        )
    before = state_counts(engine)
    with TestClient(
        create_app(engine, browser_auth=BrowserAuth("https://testserver")),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(COOKIE_NAME, issued.token)
        response = client.post(
            path,
            json=data,
            headers={"Origin": "https://testserver", "X-CSRF-Token": issued.csrf_token},
        )
        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_FAILED"
    assert state_counts(engine) == before


@pytest.mark.parametrize("kind", ["policy", "task"])
def test_stored_binding_corruption_stays_unavailable_after_authorization(admitted, kind):  # noqa: F811
    from sqlalchemy import select

    from journeon.models import Task, VerificationPolicyRevision

    (engine, _, actor, _, _), _ = admitted
    service, task, command = prepared(admitted)
    with transaction(engine) as db:
        row = (
            db.get(Task, task.task_id)
            if kind == "task"
            else db.scalar(select(VerificationPolicyRevision))
        )
        snapshot = dict(row.snapshot)
        snapshot["workflow"] = {
            "steps": [{"step_id": "verify", "kind": "VERIFICATION", "check_id": "unknown"}]
        }
        row.snapshot = snapshot
    with pytest.raises(DomainError) as error:
        service.create_or_continue_task(actor, command)
    assert error.value.code == "DEPENDENCY_UNAVAILABLE"
    with transaction(engine) as db:
        db.get(AccessGrant, "admission:project.verification.read").enabled = False
    with pytest.raises(DomainError) as error:
        service.create_or_continue_task(actor, command)
    assert error.value.code == "PERMISSION_DENIED"


@pytest.mark.parametrize("kind", ["WORK", "REVIEW"])
def test_unconditional_prerequisite_strengthens_policy(admitted, kind):  # noqa: F811
    from journeon.contracts import TaskRevise, TaskWorkflow

    (_, _, actor, _, _), _ = admitted
    service, task, _ = prepared(admitted)
    workflow = TaskWorkflow(
        steps=[
            {"step_id": "extra", "kind": kind},
            {
                "step_id": "verify",
                "kind": "VERIFICATION",
                "check_id": "check",
                "dependencies": ["extra"],
            },
        ]
    )
    command = TaskRevise(
        schema_version=1,
        idempotency_key="strengthen",
        task_id=task.task_id,
        expected_revision=task.revision,
        expected_policy_revision=1,
        reason="Add prerequisite",
        success_conditions=["Check"],
        workflow=workflow,
    )
    result = service.revise(actor, command)
    assert result.task.workflow == workflow
    assert service.revise(actor, command) == result


@pytest.mark.parametrize("transitive", [False, True])
def test_conditional_added_prerequisite_cannot_weaken_gate(admitted, transitive):  # noqa: F811
    from journeon.contracts import TaskRevise, TaskWorkflow

    (_, _, actor, _, _), _ = admitted
    service, task, _ = prepared(admitted)
    steps = [
        {"step_id": "choice", "kind": "CONDITION"},
        {
            "step_id": "branch",
            "kind": "WORK",
            "dependencies": ["choice"],
            "condition_step": "choice",
            "condition_value": True,
        },
    ]
    if transitive:
        steps.append({"step_id": "extra", "kind": "WORK", "dependencies": ["branch"]})
    steps.append(
        {
            "step_id": "verify",
            "kind": "VERIFICATION",
            "check_id": "check",
            "dependencies": ["extra" if transitive else "branch"],
        }
    )
    command = TaskRevise(
        schema_version=1,
        idempotency_key="conditional",
        task_id=task.task_id,
        expected_revision=task.revision,
        expected_policy_revision=1,
        reason="Add prerequisite",
        success_conditions=["Check"],
        workflow=TaskWorkflow(steps=steps),
    )
    with pytest.raises(DomainError) as error:
        service.revise(actor, command)
    assert error.value.code == "VALIDATION_FAILED"


@pytest.mark.parametrize("mutation", ["kind", "condition", "check", "loop"])
def test_workflow_strengthening_preserves_original_obligations(admitted, mutation):  # noqa: F811
    from journeon.contracts import TaskRevise, TaskWorkflow

    (engine, _, actor, _, create), configure = admitted
    from journeon.work import WorkService

    service = WorkService(engine)
    original = TaskWorkflow(
        steps=[
            {"step_id": "choice", "kind": "CONDITION"},
            {
                "step_id": "verify",
                "kind": "VERIFICATION",
                "check_id": "check",
                "dependencies": ["choice"],
                "condition_step": "choice",
                "condition_value": True,
            },
        ],
        loops=[{"steps": ["verify"], "maximum_iterations": 2}],
    )
    service.configure_verification(actor, configure.model_copy(update={"workflow": original}))
    task = service.create(actor, create.model_copy(update={"expected_project_revision": 2})).task
    candidate = original.model_dump()
    if mutation == "kind":
        candidate["steps"][0]["kind"] = "WORK"
        candidate["steps"][1].update(condition_step=None, condition_value=None)
    elif mutation == "condition":
        candidate["steps"][1]["condition_value"] = False
    elif mutation == "check":
        candidate["steps"][1]["check_id"] = "other"
    else:
        candidate["loops"][0]["maximum_iterations"] = 3
    command = TaskRevise(
        schema_version=1,
        idempotency_key="weaken",
        task_id=task.task_id,
        expected_revision=task.revision,
        expected_policy_revision=1,
        reason="Revise obligations",
        success_conditions=["Check"],
        workflow=TaskWorkflow.model_validate(candidate),
    )
    with pytest.raises(DomainError) as error:
        service.revise(actor, command)
    assert error.value.code == "VALIDATION_FAILED"
    assert service.read(actor, task.task_id) == task


def test_service_proposed_policy_binding_is_validation_and_atomic(admitted):  # noqa: F811
    from journeon.work import WorkService

    (engine, _, actor, _, _), configure = admitted
    invalid = configure.model_copy(
        update={"checks": [configure.checks[0].model_copy(update={"check_id": "other"})]}
    )
    before = state_counts(engine)
    with pytest.raises(DomainError) as error:
        WorkService(engine).configure_verification(actor, invalid)
    assert error.value.code == "VALIDATION_FAILED"
    assert state_counts(engine) == before


@pytest.mark.parametrize("capability", ["task.admit", "task.read", "task.receipt.read"])
def test_denied_admission_replay_keeps_applicable_grants(admitted, capability):  # noqa: F811
    from sqlalchemy import select

    (engine, _, actor, _, _), _ = admitted
    service, task, command = prepared(admitted)
    with transaction(engine) as db:
        db.get(AccessGrant, "admission:execution.admit").enabled = False
    first = service.create_or_continue_task(actor, command)
    assert first.task.admission.decision == "DENY"
    assert service.create_or_continue_task(actor, command) == first
    with transaction(engine) as db:
        for grant in db.scalars(
            select(AccessGrant).where(
                AccessGrant.principal_id == actor.principal_id, AccessGrant.capability == capability
            )
        ):
            grant.enabled = False
    with pytest.raises(DomainError) as error:
        service.create_or_continue_task(actor, command)
    assert error.value.code == "PERMISSION_DENIED"


def test_persisted_workflow_lost_obligation_is_storage_error(admitted):  # noqa: F811
    from journeon.contracts import TaskWorkflow
    from journeon.models import Task

    work_state, configure = admitted
    engine, _, actor, _, _ = work_state
    policy_workflow = TaskWorkflow(
        steps=[
            {"step_id": "approval", "kind": "APPROVAL"},
            {
                "step_id": "verify",
                "kind": "VERIFICATION",
                "check_id": "check",
                "dependencies": ["approval"],
            },
        ]
    )
    service, task, command = prepared(
        (work_state, configure.model_copy(update={"workflow": policy_workflow}))
    )
    with transaction(engine) as db:
        row = db.get(Task, task.task_id)
        row.snapshot = row.snapshot | {
            "workflow": {
                "steps": [{"step_id": "verify", "kind": "VERIFICATION", "check_id": "check"}]
            }
        }
    with pytest.raises(DomainError) as error:
        service.create_or_continue_task(actor, command)
    assert error.value.code == "DEPENDENCY_UNAVAILABLE"


def test_new_policy_gate_requires_reconciliation_not_storage_repair(admitted):  # noqa: F811
    from journeon.contracts import TaskRevise, TaskWorkflow

    (_, _, actor, _, _), configure = admitted
    service, task, command = prepared(admitted)
    workflow = TaskWorkflow(
        steps=[
            {"step_id": "approval", "kind": "APPROVAL"},
            {
                "step_id": "verify",
                "kind": "VERIFICATION",
                "check_id": "check",
                "dependencies": ["approval"],
            },
        ]
    )
    service.configure_verification(
        actor,
        configure.model_copy(
            update={
                "idempotency_key": "new-gate",
                "expected_project_revision": 2,
                "expected_policy_revision": 1,
                "workflow": workflow,
            }
        ),
    )
    current_command = command.model_copy(update={"expected_policy_revision": 2})
    denied = service.create_or_continue_task(actor, current_command)
    assert denied.task.admission.decision == "DENY"
    assert (
        denied.task.admission.reason == "Task criteria and workflow require policy reconciliation"
    )
    assert service.create_or_continue_task(actor, current_command) == denied
    revised = service.revise(
        actor,
        TaskRevise(
            schema_version=1,
            idempotency_key="reconcile",
            task_id=task.task_id,
            expected_revision=denied.task.revision,
            expected_policy_revision=2,
            reason="Reconcile policy",
            success_conditions=["Check"],
            workflow=workflow,
        ),
    ).task
    result = service.create_or_continue_task(
        actor,
        current_command.model_copy(
            update={"idempotency_key": "reconciled", "expected_revision": revised.revision}
        ),
    )
    assert result.task.admission.decision == "REQUIRE_APPROVAL"
