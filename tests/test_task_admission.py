# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from test_work import work  # noqa: F401

from journeon.contracts import TaskAdmission, TaskWorkflow, VerificationPolicyConfigure
from journeon.database import transaction
from journeon.models import AccessGrant
from journeon.work import WorkService


@pytest.fixture
def admitted(work):  # noqa: F811
    engine, path, actor, issued, create = work
    with transaction(engine) as db:
        for capability in (
            "project.verification.configure",
            "project.verification.read",
            "task.admit",
            "task.revise",
            "task.assign",
            "execution.admit",
            "project.receipt.read",
        ):
            db.add(
                AccessGrant(
                    id="admission:" + capability,
                    principal_id=actor.principal_id,
                    capability=capability,
                    resource_kind="project",
                    resource_id=create.project_id,
                    enabled=True,
                    revision=1,
                    provenance="fixture",
                )
            )
    workflow = TaskWorkflow(
        steps=[{"step_id": "verify", "kind": "VERIFICATION", "check_id": "check"}]
    )
    configure = VerificationPolicyConfigure(
        schema_version=1,
        idempotency_key="policy",
        project_id=create.project_id,
        expected_project_revision=1,
        expected_policy_revision=0,
        enabled=True,
        checks=[
            {
                "check_id": "check",
                "criterion": "Check passes",
                "argv": ["python", "-V"],
                "working_directory": ".",
                "expected_exit_code": 0,
            }
        ],
        workflow=workflow,
    )
    return work, configure


def test_production_policy_and_current_admission(admitted):
    (engine, _, actor, _, create), configure = admitted
    service = WorkService(engine)
    policy = service.configure_verification(actor, configure)
    task = service.create(actor, create.model_copy(update={"expected_project_revision": 2})).task
    assert task.success_conditions[0].provenance == "PROJECT"
    assert task.workflow == policy.policy.workflow
    command = TaskAdmission(
        schema_version=1,
        idempotency_key="admit",
        task_id=task.task_id,
        expected_revision=task.revision,
        expected_policy_revision=1,
        reason="Continue this Task",
    )
    result = service.create_or_continue_task(actor, command)
    assert result.task.admission.decision == "ADMIT"
    assert result.task.state == "READY"
    assert not result.task.admission.execution_started
    assert service.create_or_continue_task(actor, command) == result


def prepared(admitted):
    (engine, path, actor, issued, create), configure = admitted
    service = WorkService(engine)
    service.configure_verification(actor, configure)
    task = service.create(actor, create.model_copy(update={"expected_project_revision": 2})).task
    return (
        service,
        task,
        TaskAdmission(
            schema_version=1,
            idempotency_key="admit",
            task_id=task.task_id,
            expected_revision=task.revision,
            expected_policy_revision=1,
            reason="Continue this Task",
        ),
    )


def test_authenticated_api_receipts_and_restart(admitted):
    from fastapi.testclient import TestClient

    from journeon.api import create_app
    from journeon.browser_auth import COOKIE_NAME, BrowserAuth
    from journeon.database import create_database
    from journeon.receipts import OperationService

    (engine, path, actor, issued, create), configure = admitted
    headers = {"Origin": "https://testserver", "X-CSRF-Token": issued.csrf_token}
    with TestClient(
        create_app(engine, browser_auth=BrowserAuth("https://testserver")),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(COOKIE_NAME, issued.token)
        assert (
            client.post("/api/v1/projects/verification", json=configure.model_dump()).status_code
            == 401
        )
        response = client.post(
            "/api/v1/projects/verification", json=configure.model_dump(), headers=headers
        )
        assert response.status_code == 200, response.text
        policy = response.json()
        assert client.get(f"/api/v1/operations/{policy['operation_id']}").json() == policy
        assert (
            client.get(f"/api/v1/projects/{create.project_id}/verification").json()
            == policy["policy"]
        )
        task = client.post(
            "/api/v1/tasks",
            json=create.model_dump() | {"expected_project_revision": 2},
            headers=headers,
        ).json()["task"]
        data = dict(
            schema_version=1,
            idempotency_key="api-admit",
            task_id=task["task_id"],
            expected_revision=1,
            expected_policy_revision=1,
            reason="Continue",
        )
        response = client.post("/api/v1/tasks/admit", json=data, headers=headers)
        assert response.status_code == 200, response.text
        result = response.json()
        assert result["task"]["admission"]["scope"] == "TASK_PREPARATION"
        assert result["task"]["admission"]["execution_authorized"] is False
        assert client.post("/api/v1/tasks/admit", json=data, headers=headers).json() == result
        assert (
            client.post(
                "/api/v1/tasks/admit", json=data | {"approved": True}, headers=headers
            ).status_code
            == 422
        )
    other = create_database(path)
    try:
        assert (
            WorkService(other).read(actor, task["task_id"]).model_dump(mode="json")
            == result["task"]
        )
        assert (
            OperationService(other).receipt(actor, result["operation_id"]).model_dump(mode="json")
            == result
        )
    finally:
        other.dispose()


@pytest.mark.parametrize("mode", ["grant", "policy", "session", "epoch"])
def test_revocation_rechecks_even_after_success(admitted, mode):
    from journeon.contracts import DomainError
    from journeon.models import BrowserSession, Principal

    (engine, _, actor, _, _), configure = admitted
    service, task, command = prepared(admitted)
    service.create_or_continue_task(actor, command)
    if mode == "policy":
        service.configure_verification(
            actor,
            configure.model_copy(
                update={
                    "idempotency_key": "disabled",
                    "expected_project_revision": 2,
                    "expected_policy_revision": 1,
                    "enabled": False,
                }
            ),
        )
    else:
        with transaction(engine) as db:
            if mode == "grant":
                db.get(AccessGrant, "admission:execution.admit").enabled = False
            elif mode == "session":
                db.get(BrowserSession, actor.authentication_ref).revoked = True
            else:
                db.get(Principal, actor.principal_id).authorization_epoch += 1
    with pytest.raises(DomainError):
        service.create_or_continue_task(actor, command)


@pytest.mark.parametrize(
    "state,expected",
    [
        ("paused", "QUEUE"),
        ("unassigned", "QUEUE"),
        ("approval", "REQUIRE_APPROVAL"),
        ("native", "DENY"),
        ("missing-grant", "DENY"),
    ],
)
def test_derived_decisions(admitted, state, expected):
    from journeon.contracts import TaskControl

    (engine, _, actor, _, create), configure = admitted
    if state == "approval":
        configure = configure.model_copy(
            update={
                "workflow": TaskWorkflow(
                    steps=[
                        {"step_id": "approve", "kind": "APPROVAL"},
                        {
                            "step_id": "verify",
                            "kind": "VERIFICATION",
                            "check_id": "check",
                            "dependencies": ["approve"],
                        },
                    ]
                )
            }
        )
    if state == "native":
        configure = configure.model_copy(update={"required_services": ["NATIVE"]})
    if state == "unassigned":
        create = create.model_copy(update={"responsibility": "UNASSIGNED"})
    service, task, command = prepared(((engine, None, actor, None, create), configure))
    if state == "paused":
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
        command = command.model_copy(update={"expected_revision": task.revision})
    if state == "missing-grant":
        with transaction(engine) as db:
            db.get(AccessGrant, "admission:execution.admit").enabled = False
    assert service.create_or_continue_task(actor, command).task.admission.decision == expected


def test_string_reference_is_never_admission_authority(admitted):
    from journeon.models import Project

    (engine, _, actor, _, create), _ = admitted
    with transaction(engine) as db:
        db.get(Project, create.project_id).verification_policy_ref = "arbitrary-policy"
    service = WorkService(engine)
    task = service.create(actor, create).task
    result = service.create_or_continue_task(
        actor,
        TaskAdmission(
            schema_version=1,
            idempotency_key="admit",
            task_id=task.task_id,
            expected_revision=1,
            expected_policy_revision=1,
            reason="Continue",
        ),
    )
    assert result.task.admission.decision == "DENY"
    assert result.task.state != "READY"


def test_stale_policy_reconciliation_and_retained_history(admitted):
    from sqlalchemy import select

    from journeon.contracts import DomainError, TaskRevise
    from journeon.models import TaskRevision, VerificationPolicyRevision

    (engine, _, actor, _, _), configure = admitted
    service, task, command = prepared(admitted)
    service.configure_verification(
        actor,
        configure.model_copy(
            update={
                "idempotency_key": "new-policy",
                "expected_project_revision": 2,
                "expected_policy_revision": 1,
            }
        ),
    )
    with pytest.raises(DomainError, match="changed"):
        service.create_or_continue_task(actor, command)
    result = service.create_or_continue_task(
        actor, command.model_copy(update={"expected_policy_revision": 2})
    ).task
    assert result.admission.decision == "DENY"
    revised = service.revise(
        actor,
        TaskRevise(
            schema_version=1,
            idempotency_key="revise",
            task_id=task.task_id,
            expected_revision=result.revision,
            expected_policy_revision=2,
            reason="Reconcile",
            success_conditions=["Revised check passes"],
            workflow=configure.workflow,
        ),
    ).task
    assert revised.criteria_revision == revised.workflow_revision == 2
    assert revised.task_id == task.task_id
    result = service.create_or_continue_task(
        actor,
        command.model_copy(
            update={
                "idempotency_key": "current",
                "expected_revision": revised.revision,
                "expected_policy_revision": 2,
            }
        ),
    ).task
    assert result.admission.decision == "ADMIT"
    with transaction(engine) as db:
        assert len(db.scalars(select(TaskRevision)).all()) == 4
        assert len(db.scalars(select(VerificationPolicyRevision)).all()) == 2


@pytest.mark.parametrize(
    "steps",
    [
        [{"step_id": "a", "kind": "WORK", "dependencies": ["a"]}],
        [
            {"step_id": "a", "kind": "WORK", "dependencies": ["b"]},
            {"step_id": "b", "kind": "WORK", "dependencies": ["a"]},
        ],
        [{"step_id": "a", "kind": "WORK", "dependencies": ["absent"]}],
        [{"step_id": "a", "kind": "WORK"}, {"step_id": "a", "kind": "WORK"}],
        [{"step_id": "a", "kind": "VERIFICATION"}],
        [{"step_id": "a", "kind": "WORK", "condition_step": "absent", "condition_value": True}],
    ],
)
def test_workflow_invalid_graphs(steps):
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        TaskWorkflow(steps=steps)


def test_workflow_fan_out_in_category_score_and_nested_bounded_loops():
    from pydantic import ValidationError

    data = dict(
        steps=[
            {"step_id": "decide", "kind": "CONDITION"},
            {
                "step_id": "a",
                "kind": "WORK",
                "dependencies": ["decide"],
                "condition_step": "decide",
                "condition_value": "bug",
            },
            {
                "step_id": "b",
                "kind": "WORK",
                "dependencies": ["decide"],
                "condition_step": "decide",
                "condition_value": 0.7,
                "condition_operator": "GE",
            },
            {"step_id": "join", "kind": "REVIEW", "dependencies": ["a", "b"]},
        ],
        loops=[
            {"steps": ["a", "b", "join"], "maximum_iterations": 3},
            {"steps": ["a"], "maximum_iterations": 2},
        ],
    )
    assert len(TaskWorkflow.model_validate(data).steps) == 4
    for limit in (0, -1):
        with pytest.raises(ValidationError):
            TaskWorkflow.model_validate(
                data | {"loops": [{"steps": ["a"], "maximum_iterations": limit}]}
            )


def test_bot_handoff_contributor_history_private_boundary_and_revoked_receiver(admitted, actor):
    from test_agents import setup_agents

    from journeon.contracts import DomainError, TaskAssign

    (engine, path, shared, _, _), _ = admitted
    agents, profile, first, bot_command = setup_agents((engine, path), actor)
    second = agents.bot(
        actor,
        agents.create_bot(
            actor, bot_command.model_copy(update={"idempotency_key": "second", "name": "Second"})
        ).target_id,
    )
    with transaction(engine) as db:
        for kind, identity in [
            ("profile", profile.profile_id),
            ("bot", first.bot_id),
            ("bot", second.bot_id),
        ]:
            for action in ("read", "use"):
                db.add(
                    AccessGrant(
                        id=f"{identity}:{action}",
                        principal_id=shared.principal_id,
                        capability=f"{kind}.{action}",
                        resource_kind=kind,
                        resource_id=identity,
                        enabled=True,
                        revision=1,
                        provenance="fixture",
                    )
                )
    service, task, _ = prepared(admitted)

    def assign(view, bot, key, contributor=False):
        return TaskAssign(
            schema_version=1,
            idempotency_key=key,
            task_id=view.task_id,
            expected_revision=view.revision,
            reason="Explicit assignment",
            responsibility="BOT",
            bot_id=bot.bot_id,
            expected_bot_revision=bot.revision,
            contributor=contributor,
        )

    first_task = service.assign(shared, assign(task, first, "first")).task
    contribution = service.assign(shared, assign(first_task, second, "contribute", True)).task
    assert contribution.assignment.bot_id == first.bot_id
    assert contribution.contributors[0].bot_id == second.bot_id
    handed = service.assign(shared, assign(contribution, second, "handoff")).task
    assert handed.task_id == task.task_id and handed.assignment.bot_id == second.bot_id
    assert handed.assignment_history[-1].previous_bot_id == first.bot_id
    assert handed.assignment_history[-1].kind == "HANDOFF"
    assert len(handed.assignment_history) == 3
    assert first.namespace_ref not in handed.model_dump_json()
    assert "provider-a" not in handed.model_dump_json()
    with transaction(engine) as db:
        db.get(AccessGrant, f"{first.bot_id}:use").enabled = False
    with pytest.raises(DomainError):
        service.assign(shared, assign(handed, first, "revoked"))
    assert service.read(shared, task.task_id) == handed


def test_task_revision_cannot_remove_project_approval_gate(admitted):
    from journeon.contracts import DomainError, TaskRevise

    (engine, _, actor, _, create), configure = admitted
    original = configure.workflow
    configure = configure.model_copy(
        update={
            "workflow": TaskWorkflow(
                steps=[
                    {"step_id": "approve", "kind": "APPROVAL"},
                    {
                        "step_id": "verify",
                        "kind": "VERIFICATION",
                        "check_id": "check",
                        "dependencies": ["approve"],
                    },
                ]
            )
        }
    )
    service, task, _ = prepared(((engine, None, actor, None, create), configure))
    with pytest.raises(DomainError):
        service.revise(
            actor,
            TaskRevise(
                schema_version=1,
                idempotency_key="weaken",
                task_id=task.task_id,
                expected_revision=task.revision,
                expected_policy_revision=1,
                reason="Remove gate",
                success_conditions=["Pass"],
                workflow=original,
            ),
        )
    assert service.read(actor, task.task_id) == task


def test_workflow_dependency_cannot_bypass_retained_gate(admitted):
    from journeon.contracts import DomainError, TaskRevise

    (engine, _, actor, _, create), configure = admitted
    workflow = TaskWorkflow(
        steps=[
            {"step_id": "approve", "kind": "APPROVAL"},
            {"step_id": "work", "kind": "WORK", "dependencies": ["approve"]},
            {
                "step_id": "verify",
                "kind": "VERIFICATION",
                "check_id": "check",
                "dependencies": ["work"],
            },
        ]
    )
    configure = configure.model_copy(update={"workflow": workflow})
    service, task, _ = prepared(((engine, None, actor, None, create), configure))
    data = workflow.model_dump()
    data["steps"][1]["dependencies"] = []
    with pytest.raises(DomainError):
        service.revise(
            actor,
            TaskRevise(
                schema_version=1,
                idempotency_key="bypass",
                task_id=task.task_id,
                expected_revision=task.revision,
                expected_policy_revision=1,
                reason="Bypass gate",
                success_conditions=["Pass"],
                workflow=TaskWorkflow.model_validate(data),
            ),
        )


def test_all_builtin_workflows_bind_real_policy_and_preserve_provider_neutrality(admitted):
    from journeon.contracts import VerificationPolicy
    from journeon.workflows import templates

    _, configure = admitted
    found = templates().templates
    assert len(found) == 8
    for template in found:
        policy = VerificationPolicy.model_validate(
            configure.model_dump(
                exclude={
                    "schema_version",
                    "idempotency_key",
                    "expected_project_revision",
                    "expected_policy_revision",
                }
            )
            | {
                "workflow": template.workflow.model_dump(),
                "revision": 1,
                "created_by": "fixture",
                "created_at": "2026-10-19T00:00:00Z",
            }
        )
        assert policy.workflow == template.workflow
        assert "provider" not in policy.workflow.model_dump_json()
    assert [step.step_id for step in found[-1].workflow.steps] == [
        "recon",
        "plan",
        "plan-review",
        "build",
        "verify",
        "fresh-inspection",
        "close",
    ]


@pytest.mark.parametrize(
    "boundary",
    ["INSERT INTO task_revisions", "INSERT INTO operation_receipts", "INSERT INTO outbox_events"],
)
def test_admission_transaction_rolls_back_all_records(admitted, boundary):
    from sqlalchemy import event
    from test_work import counts

    (engine, _, actor, _, _), _ = admitted
    service, task, command = prepared(admitted)
    before = counts(engine)

    def fail(conn, cursor, statement, parameters, context, many):
        if statement.startswith(boundary):
            raise RuntimeError("Fixture admission interruption")

    event.listen(engine, "after_cursor_execute", fail)
    try:
        with pytest.raises(RuntimeError):
            service.create_or_continue_task(actor, command)
    finally:
        event.remove(engine, "after_cursor_execute", fail)
    assert service.read(actor, task.task_id) == task
    assert counts(engine) == before
    assert service.create_or_continue_task(actor, command).task.admission.decision == "ADMIT"


def test_concurrent_admission_and_stale_revisions(admitted):
    from concurrent.futures import ThreadPoolExecutor

    from journeon.contracts import DomainError, TaskReceipt

    (engine, _, actor, _, _), _ = admitted
    service, task, command = prepared(admitted)

    def run(key):
        try:
            return service.create_or_continue_task(
                actor, command.model_copy(update={"idempotency_key": key})
            )
        except DomainError as exc:
            return exc.code

    with ThreadPoolExecutor(2) as pool:
        outcomes = list(pool.map(run, ["first", "second"]))
    assert sum(isinstance(result, TaskReceipt) for result in outcomes) == 1
    assert "REVISION_CONFLICT" in outcomes


def test_denied_policy_read_precedes_corrupt_snapshot(admitted):
    from sqlalchemy import text

    from journeon.contracts import DomainError

    (engine, _, actor, _, create), _ = admitted
    service, _, command = prepared(admitted)
    with transaction(engine) as db:
        db.execute(text("UPDATE verification_policy_revisions SET snapshot='not-json'"))
        db.get(AccessGrant, "admission:project.verification.read").enabled = False
    for call in (
        lambda: service.verification(actor, create.project_id),
        lambda: service.create_or_continue_task(actor, command),
    ):
        with pytest.raises(DomainError) as error:
            call()
        assert error.value.code == "PERMISSION_DENIED"


def test_policy_retry_changed_input_and_stale_revision(admitted):
    from journeon.contracts import DomainError

    (engine, _, actor, _, _), configure = admitted
    service = WorkService(engine)
    result = service.configure_verification(actor, configure)
    assert service.configure_verification(actor, configure) == result
    with pytest.raises(DomainError) as error:
        service.configure_verification(actor, configure.model_copy(update={"enabled": False}))
    assert error.value.code == "IDEMPOTENCY_CONFLICT"
    with pytest.raises(DomainError) as error:
        service.configure_verification(
            actor, configure.model_copy(update={"idempotency_key": "stale"})
        )
    assert error.value.code == "REVISION_CONFLICT"


def test_human_reassignment_is_not_a_bot_handoff(admitted, actor):
    from test_agents import setup_agents

    from journeon.contracts import TaskAssign

    (engine, path, shared, _, _), _ = admitted
    _, profile, bot, _ = setup_agents((engine, path), actor)
    with transaction(engine) as db:
        for kind, identity in [("profile", profile.profile_id), ("bot", bot.bot_id)]:
            for action in ("read", "use"):
                db.add(
                    AccessGrant(
                        id=f"{identity}:{action}",
                        principal_id=shared.principal_id,
                        capability=f"{kind}.{action}",
                        resource_kind=kind,
                        resource_id=identity,
                        enabled=True,
                        revision=1,
                        provenance="fixture",
                    )
                )
    service, task, _ = prepared(admitted)
    assigned = service.assign(
        shared,
        TaskAssign(
            schema_version=1,
            idempotency_key="bot-assignment",
            task_id=task.task_id,
            expected_revision=task.revision,
            reason="Assign Bot",
            responsibility="BOT",
            bot_id=bot.bot_id,
            expected_bot_revision=1,
        ),
    ).task
    reassigned = service.assign(
        shared,
        TaskAssign(
            schema_version=1,
            idempotency_key="human-assignment",
            task_id=task.task_id,
            expected_revision=assigned.revision,
            reason="Human resumes responsibility",
            responsibility="HUMAN",
        ),
    ).task
    assert reassigned.assignment.kind == "REASSIGN"
    assert reassigned.assignment.principal_id == shared.principal_id
    assert reassigned.assignment.previous_bot_id == bot.bot_id
