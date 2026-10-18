# SPDX-License-Identifier: AGPL-3.0-only
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, func, select, text

from journeon.api import create_app
from journeon.browser_auth import COOKIE_NAME, BrowserAuth
from journeon.contracts import DomainError, TaskControl, TaskCreate, TaskReceipt
from journeon.database import create_database, transaction
from journeon.models import (
    AccessGrant,
    BrowserSession,
    OutboxEvent,
    Principal,
    Project,
    Receipt,
    Task,
)
from journeon.permissions import AuthenticatedContext
from journeon.projects import ProjectService
from journeon.receipts import OperationService
from journeon.sessions import issue_session
from journeon.work import WorkService

CAPABILITIES = (
    "task.create",
    "task.read",
    "task.receipt.read",
    "task.pause",
    "task.resume",
    "task.cancel",
)
STATES = (
    "BACKLOG",
    "READY",
    "RUNNING",
    "WAITING",
    "REVIEW",
    "BLOCKED",
    "DONE",
    "CANCELLED",
    "ARCHIVED",
)


@pytest.fixture
def work(database, actor, command):
    engine, path = database
    project = ProjectService(engine).create(actor, command).project
    with transaction(engine) as db:
        for human in ("owner-test", "viewer-test"):
            for capability in CAPABILITIES:
                db.add(
                    AccessGrant(
                        id=f"{human}:{capability}",
                        principal_id=human,
                        capability=capability,
                        resource_kind="project",
                        resource_id=project.project_id,
                        enabled=True,
                        revision=1,
                        provenance="fixture",
                    )
                )
        issued = issue_session(
            db, "viewer-test", authentication_method="fixture", client_label="Fixture", strong=False
        )
    shared = AuthenticatedContext("viewer-test", 1, issued.session_id)
    create = TaskCreate(
        schema_version=1,
        idempotency_key="work-create",
        project_id=project.project_id,
        expected_project_revision=1,
        objective="Check the local result",
        responsibility="HUMAN",
    )
    return engine, path, shared, issued, create


def control(view, key="pause-1"):
    return TaskControl(
        schema_version=1,
        idempotency_key=key,
        task_id=view.task_id,
        expected_revision=view.revision,
        reason="Human requested control",
    )


def counts(engine):
    with transaction(engine) as db:
        return tuple(
            db.scalar(select(func.count()).select_from(model))
            for model in (Task, Receipt, OutboxEvent)
        )


def test_real_authenticated_api_create_read_control_restart(work):
    engine, path, actor, issued, command = work
    app = create_app(engine, browser_auth=BrowserAuth("https://testserver"))
    with TestClient(app, base_url="https://testserver") as client:
        client.cookies.set(COOKIE_NAME, issued.token)
        headers = {"Origin": "https://testserver", "X-CSRF-Token": issued.csrf_token}
        assert client.post("/api/v1/tasks", json=command.model_dump()).status_code == 401
        response = client.post("/api/v1/tasks", json=command.model_dump(), headers=headers)
        assert response.status_code == 200, response.text
        result = TaskReceipt.model_validate(response.json())
        view = result.task
        assert view.state == "BACKLOG" and view.success_conditions == []
        assert view.assignment.principal_id == actor.principal_id
        assert view.assignment_history == [view.assignment]
        assert view.verification_policy.policy_ref is None
        assert client.get(f"/api/v1/tasks/{view.task_id}").json() == view.model_dump()
        assert (
            client.post("/api/v1/tasks", json=command.model_dump(), headers=headers).json()
            == response.json()
        )
        for action in ("pause", "resume", "cancel"):
            response = client.post(
                f"/api/v1/tasks/{action}", json=control(view, action).model_dump(), headers=headers
            )
            assert response.status_code == 200, response.text
            result = TaskReceipt.model_validate(response.json())
            view = result.task
            if action == "resume":
                assert (
                    view.state == "BLOCKED"
                    and view.blocker == "Verification policy is not configured"
                )
        assert view.state == "CANCELLED"
        assert client.get(f"/api/v1/operations/{result.operation_id}").json() == result.model_dump()
    other = create_database(path)
    try:
        assert WorkService(other).read(actor, view.task_id) == view
        assert OperationService(other).receipt(actor, result.operation_id) == result
    finally:
        other.dispose()
    with transaction(engine) as db:
        rows = db.scalars(
            select(OutboxEvent).where(OutboxEvent.owner == "work").order_by(OutboxEvent.sequence)
        ).all()
        assert [r.target_revision for r in rows] == [1, 2, 3, 4]
        assert len({r.event_id for r in rows}) == 4
        assert all(r.payload["task"]["revision"] == r.target_revision for r in rows)
        assert rows[-1].payload == result.model_dump()


@pytest.mark.parametrize("state", STATES)
@pytest.mark.parametrize("action", ("pause", "resume", "cancel"))
def test_transition_table_preserves_terminal_active_and_blocked_states(work, state, action):
    engine, _, actor, _, command = work
    service = WorkService(engine)
    view = service.create(actor, command).task
    with transaction(engine) as db:
        row = db.get(Task, view.task_id)
        data = dict(
            row.snapshot,
            state=state,
            paused=action == "resume",
            pause_reason="Fixture pause" if action == "resume" else None,
            blocker="Fixture unresolved blocker" if state == "BLOCKED" else None,
        )
        row.snapshot = data
    before = counts(engine)
    if state in ("DONE", "CANCELLED", "ARCHIVED"):
        with pytest.raises(DomainError, match="no longer accepts"):
            service.control(actor, action, control(view))
        assert counts(engine) == before
        return
    result = service.control(actor, action, control(view)).task
    if action == "cancel":
        assert result.state == "CANCELLED"
    elif action == "pause":
        assert result.paused
        assert result.state == (state if state in ("RUNNING", "REVIEW", "BLOCKED") else "WAITING")
    else:
        assert not result.paused
        assert result.state == (state if state in ("RUNNING", "REVIEW") else "BLOCKED")
    if state == "BLOCKED":
        assert result.blocker == "Fixture unresolved blocker"
    assert result.objective_revision == result.criteria_revision == 1
    assert result.assignment_history == view.assignment_history


@pytest.mark.parametrize("action", ("create", "pause", "resume", "cancel"))
def test_command_retry_changed_input_and_stale_version(work, action):
    engine, _, actor, _, command = work
    service = WorkService(engine)
    if action == "create":

        def invoke(c):
            return service.create(actor, c)
    else:
        view = service.create(actor, command).task
        if action == "resume":
            view = service.control(actor, "pause", control(view)).task
        command = control(view, action)

        def invoke(c):
            return service.control(actor, action, c)

    result = invoke(command)
    before = counts(engine)
    assert invoke(command) == result
    changed = command.model_copy(
        update={"objective": "Changed"} if action == "create" else {"reason": "Changed"}
    )
    with pytest.raises(DomainError) as error:
        invoke(changed)
    assert error.value.code == "IDEMPOTENCY_CONFLICT"
    if action != "create":
        with pytest.raises(DomainError) as error:
            invoke(command.model_copy(update={"idempotency_key": "new-key"}))
        assert error.value.code == "REVISION_CONFLICT"
    assert counts(engine) == before


@pytest.mark.parametrize("capability", CAPABILITIES)
def test_missing_exact_action_grant_denies(work, capability):
    engine, _, actor, _, command = work
    service = WorkService(engine)
    view = service.create(actor, command).task
    if capability == "task.resume":
        view = service.control(actor, "pause", control(view)).task
    with transaction(engine) as db:
        db.get(AccessGrant, f"viewer-test:{capability}").enabled = False
    before = counts(engine)
    with pytest.raises(DomainError) as error:
        if capability in ("task.create", "task.receipt.read"):
            service.create(actor, command.model_copy(update={"idempotency_key": "new"}))
        elif capability == "task.read":
            service.read(actor, view.task_id)
        else:
            service.control(actor, capability.split(".")[1], control(view, "control"))
    assert error.value.code == "PERMISSION_DENIED"
    assert counts(engine) == before


@pytest.mark.parametrize(
    "denial",
    (
        "wrong-resource",
        "expired-grant",
        "revoked-grant",
        "revoked-session",
        "expired-session",
        "epoch",
        "other-human",
        "fake-session",
    ),
)
def test_denial_precedes_corrupt_snapshot_and_receipt_decode(work, denial):
    engine, _, actor, _, command = work
    service = WorkService(engine)
    result = service.create(actor, command)
    with transaction(engine) as db:
        db.execute(text("UPDATE tasks SET snapshot='not-json'"))
        db.execute(text("UPDATE operation_receipts SET result='not-json' WHERE owner='work'"))
        grant = db.get(AccessGrant, "viewer-test:task.read")
        if denial == "wrong-resource":
            grant.resource_id = "unrelated"
        elif denial == "expired-grant":
            grant.expires_at = "2000-01-01T00:00:00+00:00"
        elif denial == "revoked-grant":
            grant.enabled = False
        elif denial == "revoked-session":
            db.get(BrowserSession, actor.authentication_ref).revoked = True
        elif denial == "expired-session":
            row = db.get(BrowserSession, actor.authentication_ref)
            row.issued_at -= 100
            row.absolute_deadline = row.last_observed
        elif denial == "epoch":
            db.get(Principal, actor.principal_id).authorization_epoch += 1
        elif denial == "other-human":
            actor = replace(actor, principal_id="owner-test")
        elif denial == "fake-session":
            actor = replace(actor, authentication_ref="fake")
    for invoke in (
        lambda: service.read(actor, result.task.task_id),
        lambda: OperationService(engine).receipt(actor, result.operation_id),
        lambda: service.create(actor, command),
    ):
        with pytest.raises(DomainError) as error:
            invoke()
        assert error.value.code in ("AUTHENTICATION_REQUIRED", "PERMISSION_DENIED", "NOT_FOUND")


def test_other_human_cannot_get_receipt_even_with_project_grant(work, actor):
    engine, _, shared, _, command = work
    result = WorkService(engine).create(shared, command)
    assert WorkService(engine).read(actor, result.task.task_id) == result.task
    with pytest.raises(DomainError) as error:
        OperationService(engine).receipt(actor, result.operation_id)
    assert error.value.code == "NOT_FOUND"


@pytest.mark.parametrize(
    "boundary", ("INSERT INTO tasks", "INSERT INTO operation_receipts", "INSERT INTO outbox_events")
)
def test_atomic_create_rollback(work, boundary):
    engine, _, actor, _, command = work
    before = counts(engine)

    def interrupt(conn, cursor, statement, parameters, context, many):
        if statement.startswith(boundary):
            raise RuntimeError("Fixture transaction interruption")

    event.listen(engine, "after_cursor_execute", interrupt)
    try:
        with pytest.raises(RuntimeError, match="interruption"):
            WorkService(engine).create(actor, command)
    finally:
        event.remove(engine, "after_cursor_execute", interrupt)
    assert counts(engine) == before
    result = WorkService(engine).create(actor, command)
    assert result.task.revision == 1


def test_controls_serialize_and_cancel_cannot_be_revived(work):
    engine, path, actor, _, command = work
    service = WorkService(engine)
    view = service.create(actor, command).task
    view = service.control(actor, "pause", control(view)).task
    other = create_database(path)

    def run(action):
        try:
            return WorkService(other if action == "resume" else engine).control(
                actor, action, control(view, action)
            )
        except DomainError as exc:
            return exc.code

    try:
        with ThreadPoolExecutor(2) as pool:
            outcomes = list(pool.map(run, ("resume", "cancel")))
        assert sum(isinstance(item, TaskReceipt) for item in outcomes) == 1
        assert "REVISION_CONFLICT" in outcomes
        current = service.read(actor, view.task_id)
        if current.state != "CANCELLED":
            current = service.control(actor, "cancel", control(current, "final-cancel")).task
        with pytest.raises(DomainError):
            service.control(actor, "resume", control(current, "late-resume"))
        assert service.read(actor, view.task_id).state == "CANCELLED"
    finally:
        other.dispose()


def test_dependencies_and_inherited_policy_remain_pending_without_execution(work):
    engine, _, actor, _, command = work
    service = WorkService(engine)
    with transaction(engine) as db:
        db.get(Project, command.project_id).verification_policy_ref = "fixture-policy"
    parent = service.create(actor, command).task
    child = service.create(
        actor,
        command.model_copy(
            update={
                "idempotency_key": "child",
                "dependencies": [parent.task_id],
                "responsibility": "UNASSIGNED",
                "success_conditions": ["Observed result matches the objective"],
            }
        ),
    ).task
    assert child.assignment.principal_id is None
    assert child.success_conditions[0].provenance == "USER"
    assert child.verification_policy.policy_ref == "fixture-policy"
    paused = service.control(actor, "pause", control(child)).task
    resumed = service.control(actor, "resume", control(paused, "resume")).task
    assert resumed.state == "WAITING"
    assert resumed.success_conditions == child.success_conditions
    with transaction(engine) as db:
        db.get(Project, command.project_id).revision += 1
    paused = service.control(actor, "pause", control(resumed, "pause-again")).task
    resumed = service.control(actor, "resume", control(paused, "resume-again")).task
    assert resumed.state == "BLOCKED" and "reconciliation" in resumed.blocker


def test_missing_dependency_and_stale_project_create_nothing(work):
    engine, _, actor, _, command = work
    before = counts(engine)
    for update, code in (
        ({"dependencies": ["absent"]}, "NOT_FOUND"),
        ({"expected_project_revision": 2}, "REVISION_CONFLICT"),
    ):
        with pytest.raises(DomainError) as error:
            WorkService(engine).create(actor, command.model_copy(update=update))
        assert error.value.code == code
    assert counts(engine) == before


@pytest.mark.parametrize("action", ("pause", "resume", "cancel"))
def test_control_failure_rolls_back_state_receipt_and_event(work, action):
    engine, _, actor, _, command = work
    service = WorkService(engine)
    view = service.create(actor, command).task
    if action == "resume":
        view = service.control(actor, "pause", control(view)).task
    before = counts(engine)

    def fail(conn, cursor, statement, parameters, context, many):
        if statement.startswith("INSERT INTO outbox_events"):
            raise RuntimeError("Fixture control interruption")

    event.listen(engine, "after_cursor_execute", fail)
    try:
        with pytest.raises(RuntimeError, match="interruption"):
            service.control(actor, action, control(view, action))
    finally:
        event.remove(engine, "after_cursor_execute", fail)
    assert service.read(actor, view.task_id) == view
    assert counts(engine) == before


def test_no_execution_state_or_principal_can_be_injected_over_api(work):
    engine, _, _, issued, command = work
    with TestClient(
        create_app(engine, browser_auth=BrowserAuth("https://testserver")),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(COOKIE_NAME, issued.token)
        for update in (
            {"state": "DONE"},
            {"responsibility": "BOT"},
            {"principal_id": "owner-test"},
            {"objective_revision": 2},
            {"success_conditions": [{"text": "Forged", "provenance": "DERIVED"}]},
        ):
            response = client.post(
                "/api/v1/tasks",
                json=command.model_dump() | update,
                headers={"Origin": "https://testserver", "X-CSRF-Token": issued.csrf_token},
            )
            assert response.status_code == 422
    assert counts(engine) == (0, 1, 1)


def test_cancelled_dependency_blocks_and_no_dependency_never_implies_done(work):
    engine, _, actor, _, command = work
    service = WorkService(engine)
    with transaction(engine) as db:
        db.get(Project, command.project_id).verification_policy_ref = "fixture-policy"
    first = service.create(actor, command).task
    paused = service.control(actor, "pause", control(first)).task
    resumed = service.control(actor, "resume", control(paused, "resume")).task
    assert resumed.state == "BACKLOG" and not resumed.success_conditions
    dependency = service.create(
        actor,
        command.model_copy(
            update={"idempotency_key": "dependent", "dependencies": [first.task_id]}
        ),
    ).task
    service.control(actor, "cancel", control(resumed, "cancel"))
    paused = service.control(actor, "pause", control(dependency, "pause-dependent")).task
    result = service.control(actor, "resume", control(paused, "resume-dependent")).task
    assert result.state == "BLOCKED" and result.dependencies == [first.task_id]


def test_resume_rejects_unpaused_and_newer_schema(work):
    engine, _, actor, _, command = work
    service = WorkService(engine)
    view = service.create(actor, command).task
    with pytest.raises(DomainError, match="no pause or stop"):
        service.control(actor, "resume", control(view))
    with engine.begin() as db:
        db.execute(text("UPDATE alembic_version SET version_num='future-schema'"))
    for call in (
        lambda: service.read(actor, view.task_id),
        lambda: service.create(actor, command),
        lambda: service.control(actor, "cancel", control(view)),
    ):
        with pytest.raises(DomainError) as error:
            call()
        assert error.value.code == "DEPENDENCY_UNAVAILABLE"
