# SPDX-License-Identifier: AGPL-3.0-only
import json

import pytest
from sqlalchemy import text
from test_production_instructions import candidate_command, official_effect
from test_task_dispatch import dispatch_worker
from test_workspace_discovery_pages import grant, revoke
from test_workspace_durable_resolution import read_state
from test_workspace_session_controls import context
from workspace_durable_helpers import enrolled_owner as enrolled_owner
from workspace_durable_helpers import genuine_durable_work as genuine_durable_work
from workspace_durable_helpers import genuine_instruction_scope as genuine_instruction_scope
from workspace_durable_helpers import genuine_project_task as genuine_project_task

from journeon.attempts import AttemptService
from journeon.contracts import DomainError
from journeon.database import transaction
from journeon.models import BrowserSession, InstructionRoot, TaskVerificationJob
from journeon.permissions import AuthenticatedContext


def actor_for(owner):
    session_id = context(owner)["session"]["session_id"]
    with transaction(owner.engine) as db:
        row = db.get(BrowserSession, session_id)
        return AuthenticatedContext(row.principal_id, row.principal_epoch, row.id)


def dispatch(fixture, key):
    owner, _, prepare, _, route = fixture
    result = owner.client.post(
        "/api/v1/tasks/dispatch",
        headers=owner.headers,
        json=prepare
        | {
            "idempotency_key": key,
            "step_id": "verify",
            "route_key": route.key,
            "route_revision": route.revision,
        },
    )
    assert result.status_code == 200
    return result.json()


def get(owner, path, **params):
    response = owner.client.get(path, params={"limit": 1} | params)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def test_task_state_filter_tracks_real_transition_and_binds_cursor(genuine_project_task):
    owner, _, receipt, command, first, _ = genuine_project_task
    project = receipt["project"]["project_id"]
    tasks = [first["task"]]
    for index in range(2):
        created = owner.client.post(
            "/api/v1/tasks",
            headers=owner.headers,
            json=command.model_dump(mode="json") | {"idempotency_key": f"filter-task-{index}"},
        )
        assert created.status_code == 200
        tasks.append(created.json()["task"])
    tasks.sort(key=lambda task: task["task_id"])
    path = f"/api/v1/projects/{project}/tasks"
    before = get(owner, path, state="BACKLOG")
    assert before["items"][0]["task_id"] == tasks[0]["task_id"]
    grant(owner, "task.cancel", project, "cancel-for-filter")
    cancelled = owner.client.post(
        "/api/v1/tasks/cancel",
        headers=owner.headers,
        json={
            "schema_version": 1,
            "idempotency_key": "change-filter-state",
            "task_id": tasks[1]["task_id"],
            "expected_revision": tasks[1]["revision"],
            "reason": "Cancel before the next discovery page",
        },
    )
    assert cancelled.status_code == 200
    after = get(owner, path, state="BACKLOG", cursor=before["next_cursor"])
    assert [item["task_id"] for item in after["items"]] == [tasks[2]["task_id"]]
    assert not after["has_more"]
    assert get(owner, path, state="CANCELLED")["items"][0]["task_id"] == tasks[1]["task_id"]
    assert owner.client.get(path, params={"limit": 1, "state": "unknown"}).status_code == 422
    assert (
        owner.client.get(
            path, params={"limit": 1, "state": "CANCELLED", "cursor": before["next_cursor"]}
        ).status_code
        == 409
    )


@pytest.mark.parametrize("authorized", [False, True])
def test_corrupt_task_requires_current_parent_scope(genuine_project_task, authorized):
    owner, _, project, _, task, grants = genuine_project_task
    if not authorized:
        revoke(owner, grants["task.read"]["grant"])
    with transaction(owner.engine) as db:
        db.execute(
            text("UPDATE tasks SET snapshot='invalid-json' WHERE id=:id"),
            {"id": task["task"]["task_id"]},
        )
    result = owner.client.get(
        f"/api/v1/projects/{project['project']['project_id']}/tasks", params={"limit": 1}
    )
    assert result.status_code == (503 if authorized else 403)


def test_parent_task_and_attempt_keep_only_current_child_links(genuine_durable_work):
    owner, _, prepare, grants, _ = genuine_durable_work
    dispatch(genuine_durable_work, "links-dispatch")
    task_id = prepare["origin"]["task_id"]
    tasks = f"/api/v1/projects/{prepare['project_id']}/tasks"
    attempts = f"/api/v1/tasks/{task_id}/attempts"
    task = get(owner, tasks)["items"][0]
    assert task["links"] == [{"relation": "attempts", "href": attempts + "?limit=1"}]
    attempt = get(owner, attempts)["items"][0]
    assert attempt["links"] == [
        {"relation": "jobs", "href": f"/api/v1/jobs?attempt_id={attempt['attempt_id']}&limit=1"}
    ]
    revoke(owner, grants["job.read"]["grant"])
    assert get(owner, attempts)["items"][0]["links"] == []
    revoke(owner, grants["attempt.read"]["grant"])
    assert get(owner, tasks)["items"][0]["links"] == []
    assert owner.client.get(attempts, params={"limit": 1}).status_code == 403


def test_same_task_retry_keeps_old_job_evidence_and_exact_attempt_filter(genuine_durable_work):
    owner, config, prepare, _, _ = genuine_durable_work
    first = dispatch(genuine_durable_work, "first-discovery-attempt")
    dispatch_worker(owner.engine, config)
    old_evidence = owner.client.get(f"/api/v1/jobs/{first['job_id']}/evidence")
    assert old_evidence.status_code == 200
    second = dispatch(genuine_durable_work, "second-discovery-attempt")
    dispatch_worker(owner.engine, config)
    assert first["job_id"] != second["job_id"]
    path = f"/api/v1/tasks/{prepare['origin']['task_id']}/attempts"
    before = read_state(owner)
    first_page = get(owner, path)
    second_page = get(owner, path, cursor=first_page["next_cursor"])
    attempts = first_page["items"] + second_page["items"]
    assert len({item["attempt_id"] for item in attempts}) == 2
    assert not second_page["has_more"]
    jobs = []
    for attempt in attempts:
        page = get(owner, "/api/v1/jobs", attempt_id=attempt["attempt_id"])
        assert not page["has_more"]
        assert page["items"][0]["attempt_id"] == attempt["attempt_id"]
        jobs.append(page["items"][0]["job_id"])
    assert set(jobs) == {first["job_id"], second["job_id"]}
    for filters in (
        {},
        {"project_id": prepare["project_id"]},
        {"task_id": prepare["origin"]["task_id"]},
    ):
        page = get(owner, "/api/v1/jobs", **filters)
        assert page["has_more"]
        following = get(owner, "/api/v1/jobs", cursor=page["next_cursor"], **filters)
        assert not following["has_more"]
        assert [page["items"][0]["job_id"], following["items"][0]["job_id"]] == sorted(jobs)
    response = owner.client.get(
        "/api/v1/jobs",
        params={"limit": 1, "cursor": page["next_cursor"], "attempt_id": attempts[0]["attempt_id"]},
    )
    assert response.status_code == 409
    assert (
        owner.client.get(f"/api/v1/jobs/{first['job_id']}/evidence").json() == old_evidence.json()
    )
    assert read_state(owner) == before
    assert (
        owner.client.get(f"/api/v1/tasks/{prepare['origin']['task_id']}").json()["state"] != "DONE"
    )


def test_missing_global_attempt_configuration_is_unavailable(genuine_durable_work):
    owner, _, prepare, _, _ = genuine_durable_work
    with pytest.raises(DomainError) as error:
        AttemptService(owner.engine, None).list(actor_for(owner), prepare["origin"]["task_id"], 1)
    assert error.value.code == "DEPENDENCY_UNAVAILABLE"


@pytest.mark.parametrize("hidden", [False, True])
def test_attempt_root_denial_precedes_corrupt_json(genuine_durable_work, hidden):
    owner, _, prepare, _, _ = genuine_durable_work
    job = dispatch(genuine_durable_work, "corrupt-attempt-dispatch")
    with transaction(owner.engine) as db:
        attempt = db.get(TaskVerificationJob, job["job_id"]).attempt_id
        db.execute(
            text("UPDATE attempts SET snapshot='invalid-json' WHERE id=:id"), {"id": attempt}
        )
        if hidden:
            from sqlalchemy import select

            root = db.scalar(
                select(InstructionRoot).where(InstructionRoot.root_key == "durable-source")
            )
            root.enabled = False
    result = owner.client.get(
        f"/api/v1/tasks/{prepare['origin']['task_id']}/attempts", params={"limit": 1}
    )
    assert result.status_code == (200 if hidden else 503)
    if hidden:
        assert result.json()["items"] == []
        assert not result.json()["has_more"]
        assert attempt not in result.text


def test_hidden_task_job_cannot_make_instruction_page_has_more(genuine_durable_work, monkeypatch):
    owner, _, prepare, grants, _ = genuine_durable_work
    task_job = dispatch(genuine_durable_work, "hidden-task-job")
    from journeon.instruction_files import tree_hash
    from journeon.project_instructions import navigation

    created = owner.client.post(
        "/api/v1/projects",
        headers=owner.headers,
        json={
            "schema_version": 1,
            "idempotency_key": "navigation-project",
            "name": "Instruction navigation project",
            "expected_policy_revision": 1,
            "provider_mode": "LOCAL_ONLY",
        },
    )
    assert created.status_code == 200
    project = created.json()["project"]["project_id"]
    for capability in (
        "project.read",
        "project.instruction.bind",
        "project.instruction.propose",
        "project.instruction.read",
        "project.instruction.receipt.read",
        "project.instruction.evaluate",
        "project.instruction.accept",
    ):
        grant(owner, capability, project, "navigation-" + capability)
    documents = {
        "INDEX.md": (
            "# Instruction navigation\n\n- [rules.md](rules.md)\n\n"
            "Required fragments:\n- rules.md\n"
        ),
        "rules.md": "Keep exact Project authority.\n",
    }
    bound = owner.client.post(
        f"/api/v1/projects/{project}/instructions/binding",
        headers=owner.headers,
        json={
            "idempotency_key": "navigation-binding",
            "project_id": project,
            "expected_project_revision": 1,
            "expected_binding_revision": 0,
            "root_id": "durable-environment",
            "expected_root_revision": 1,
            "expected_tree_hash": tree_hash({}),
            "owner": "ENVIRONMENT",
            "documents": [{"path": key, "content": value} for key, value in documents.items()],
            "required_fragments": ["rules.md"],
            "reason": "Explicit navigation source",
        },
    )
    assert bound.status_code == 200
    official_effect(
        owner.client,
        owner.headers,
        {
            "kind": "project.instructions.policy.configure.v1",
            "idempotency_key": "navigation-policy",
            "project_id": project,
            "expected_project_revision": 1,
            "expected_binding_revision": 1,
            "expected_root_revision": 1,
            "expected_policy_revision": 1,
            "policy": {
                "authorized_categories": ["NAVIGATION_REPAIR"],
                "navigation_repairs": True,
                "independent_review": True,
                "require_confirmation": False,
                "required_evals": ["instruction-boundaries-v1"],
            },
        },
    )
    target = documents | {"INDEX.md": navigation(documents, ["rules.md"])}
    command = candidate_command(project, documents, category="NAVIGATION_REPAIR")
    command["documents"] = [{"path": key, "content": value} for key, value in target.items()]
    from uuid import UUID, uuid4

    # Control opaque producer ordering; resource IDs still come from actual route responses.
    candidate_ids = iter((uuid4(), UUID(int=1)))
    with monkeypatch.context() as ordered:
        ordered.setattr("journeon.project_instructions.uuid4", lambda: next(candidate_ids))
        candidate = owner.client.post(
            f"/api/v1/projects/{project}/instructions/candidates",
            headers=owner.headers,
            json=command,
        )
    assert candidate.status_code == 200
    assert candidate.json()["automatic"]
    instruction_id = candidate.json()["job_id"]
    assert instruction_id < task_job["job_id"]
    with transaction(owner.engine) as db:
        db.execute(
            text("UPDATE task_verification_jobs SET inputs='invalid-json' WHERE job_id=:id"),
            {"id": task_job["job_id"]},
        )
    revoke(owner, grants["job.read"]["grant"])
    result = get(owner, "/api/v1/jobs")
    assert [item["job_id"] for item in result["items"]] == [instruction_id]
    assert not result["has_more"]
    assert task_job["job_id"] not in json.dumps(result)
    with transaction(owner.engine) as db:
        db.execute(
            text("DELETE FROM task_verification_jobs WHERE job_id=:id"), {"id": task_job["job_id"]}
        )
    assert get(owner, "/api/v1/jobs")["items"] == result["items"]


def test_evidence_child_denial_preserves_job_without_decoding_corruption(genuine_durable_work):
    owner, config, _, grants, _ = genuine_durable_work
    admitted = dispatch(genuine_durable_work, "evidence-link")
    dispatch_worker(owner.engine, config)
    assert get(owner, "/api/v1/jobs")["items"][0]["links"]
    from sqlalchemy.exc import IntegrityError

    corrupt = text("UPDATE task_verification_evidence SET snapshot='invalid-json' WHERE job_id=:id")
    with pytest.raises(IntegrityError):
        with transaction(owner.engine) as db:
            db.execute(corrupt, {"id": admitted["job_id"]})
    # Negative corruption fixture in a disposable database, after proving the immutable guard.
    with transaction(owner.engine) as db:
        db.execute(text("DROP TRIGGER task_evidence_no_update"))
        db.execute(corrupt, {"id": admitted["job_id"]})
    assert owner.client.get("/api/v1/jobs", params={"limit": 1}).status_code == 503
    revoke(owner, grants["execution.read"]["grant"])
    result = get(owner, "/api/v1/jobs")
    assert result["items"][0]["job_id"] == admitted["job_id"]
    assert result["items"][0]["links"] == []


def test_sibling_attempt_configuration_and_root_are_checked_individually(
    genuine_durable_work, tmp_path
):
    from dataclasses import replace

    from fastapi.testclient import TestClient
    from sqlalchemy import select
    from workspace_durable_helpers import admit_root

    from journeon.api import create_app
    from journeon.attempt_contracts import AttemptWorkspaceConfiguration
    from journeon.instruction_config import RootConfiguration

    owner, config, prepare, _, _ = genuine_durable_work
    job = dispatch(genuine_durable_work, "first-root-dispatch")
    path = f"/api/v1/tasks/{prepare['origin']['task_id']}/attempts"
    original = get(owner, path)["items"][0]["attempt_id"]
    source = tmp_path / "second-source"
    source.mkdir()
    (source / "input.txt").write_text("Second admitted source\n")
    alternate = config.model_copy(
        update={
            "roots": [
                *config.roots,
                RootConfiguration(
                    key="second-source",
                    path=str(source),
                    role="PROJECT",
                    project_id=prepare["project_id"],
                    revision=1,
                ),
            ],
            "attempts": config.attempts.model_copy(
                update={
                    "workspaces": [
                        *config.attempts.workspaces,
                        AttemptWorkspaceConfiguration(
                            key="second-workspace",
                            revision=1,
                            project_id=prepare["project_id"],
                            root_key="second-source",
                            root_revision=1,
                        ),
                    ]
                }
            ),
        }
    )
    with TestClient(
        create_app(
            owner.engine, browser_auth=owner.client.app.state.browser_auth, instructions=alternate
        ),
        base_url="https://example.test",
        cookies=owner.client.cookies,
    ) as client:
        configured = replace(owner, client=client)
        admit_root(configured, "second-source")
        prepared = client.post(
            "/api/v1/attempts/prepare",
            headers=owner.headers,
            json=prepare
            | {"idempotency_key": "second-source-attempt", "workspace_key": "second-workspace"},
        )
        assert prepared.status_code == 200
        second = prepared.json()["attempt"]["attempt_id"]
        assert {item["attempt_id"] for item in get(configured, path, limit=100)["items"]} == {
            original,
            second,
        }
        # Original configuration omits only the second workspace; the first remains readable.
        assert [item["attempt_id"] for item in get(owner, path, limit=100)["items"]] == [original]
        with transaction(owner.engine) as db:
            db.scalar(
                select(InstructionRoot).where(InstructionRoot.root_key == "second-source")
            ).enabled = False
            db.execute(
                text("UPDATE attempts SET snapshot='invalid-json' WHERE id=:id"), {"id": second}
            )
        assert [item["attempt_id"] for item in get(configured, path, limit=100)["items"]] == [
            original
        ]
        assert get(owner, "/api/v1/jobs")["items"][0]["job_id"] == job["job_id"]


def test_wrong_project_instruction_grant_does_not_open_attempts(genuine_durable_work):
    owner, _, prepare, grants, _ = genuine_durable_work
    dispatch(genuine_durable_work, "exact-instruction-scope")
    other = owner.client.post(
        "/api/v1/projects",
        headers=owner.headers,
        json={
            "schema_version": 1,
            "idempotency_key": "other-instruction-project",
            "name": "Other instruction authority",
            "expected_policy_revision": 1,
            "provider_mode": "LOCAL_ONLY",
        },
    )
    assert other.status_code == 200
    other_id = other.json()["project"]["project_id"]
    other_grant = grant(owner, "project.instruction.read", other_id, "other-instruction-read")
    revoke(owner, grants["project.instruction.read"]["grant"])
    with transaction(owner.engine) as db:
        db.execute(
            text("UPDATE attempts SET snapshot='invalid-json' WHERE task_id=:id"),
            {"id": prepare["origin"]["task_id"]},
        )
    result = owner.client.get(
        f"/api/v1/tasks/{prepare['origin']['task_id']}/attempts", params={"limit": 1}
    )
    assert result.status_code == 403
    tasks = get(owner, f"/api/v1/projects/{prepare['project_id']}/tasks")
    assert tasks["items"][0]["links"] == []
    assert get(owner, "/api/v1/jobs")["items"] == []
    from journeon.models import AccessGrant

    # Unsupported broad scope is a negative fixture, never a provisioning path.
    with transaction(owner.engine) as db:
        broad = db.get(AccessGrant, other_grant["grant_id"])
        broad.resource_kind, broad.resource_id = "deployment", "deployment"
    assert (
        owner.client.get(
            f"/api/v1/tasks/{prepare['origin']['task_id']}/attempts", params={"limit": 1}
        ).status_code
        == 403
    )


def test_all_collection_owners_reauthenticate_after_actor_resolution(genuine_durable_work):
    from journeon.jobs import JobService
    from journeon.projects import ProjectService
    from journeon.work import WorkService

    owner, config, prepare, _, _ = genuine_durable_work
    dispatch(genuine_durable_work, "before-revocation")
    actor = actor_for(owner)
    current = context(owner)
    response = owner.client.post(
        "/api/v1/auth/logout",
        headers=owner.headers,
        json={
            "schema_version": 1,
            "idempotency_key": "end-discovery-session",
            "expected_security_version": current["session"]["security_version"],
        },
    )
    assert response.status_code == 200
    for read in (
        lambda: ProjectService(owner.engine).list(actor, 1),
        lambda: WorkService(owner.engine).list(actor, prepare["project_id"], 1),
        lambda: AttemptService(owner.engine, config).list(actor, prepare["origin"]["task_id"], 1),
        lambda: JobService(owner.engine, config).list(actor, 1),
    ):
        with pytest.raises(DomainError) as denied:
            read()
        assert denied.value.code == "AUTHENTICATION_REQUIRED"


def test_authorized_corrupt_job_binding_is_unavailable(genuine_durable_work):
    owner = genuine_durable_work[0]
    admitted = dispatch(genuine_durable_work, "corrupt-visible-job")
    with transaction(owner.engine) as db:
        db.execute(
            text("UPDATE task_verification_jobs SET inputs='invalid-json' WHERE job_id=:id"),
            {"id": admitted["job_id"]},
        )
    assert owner.client.get("/api/v1/jobs", params={"limit": 1}).status_code == 503


def test_advertised_collection_links_can_be_followed_verbatim(genuine_durable_work):
    owner, _, prepare, _, _ = genuine_durable_work
    dispatch(genuine_durable_work, "follow-discovery-links")
    project = get(owner, "/api/v1/projects")["items"][0]
    task = get(owner, f"/api/v1/projects/{prepare['project_id']}/tasks")["items"][0]
    attempt = get(owner, f"/api/v1/tasks/{prepare['origin']['task_id']}/attempts")["items"][0]
    links = [parent["links"][0]["href"] for parent in (project, task, attempt)]
    responses = [owner.client.get(href) for href in links]
    assert [response.status_code for response in responses] == [200, 200, 200]
    assert all(len(response.json()["items"]) == 1 for response in responses)


def test_all_collection_routes_enforce_limits_and_preserve_read_state(genuine_durable_work):
    owner, _, prepare, _, _ = genuine_durable_work
    paths = [
        "/api/v1/projects",
        f"/api/v1/projects/{prepare['project_id']}/tasks",
        f"/api/v1/tasks/{prepare['origin']['task_id']}/attempts",
        "/api/v1/jobs",
    ]
    before = read_state(owner)
    for path in paths:
        for params in ({}, {"limit": 0}, {"limit": 101}, {"limit": 1, "cursor": "!"}):
            assert owner.client.get(path, params=params).status_code == 422
    assert read_state(owner) == before


def test_other_originating_principal_is_hidden_before_corrupt_payloads(genuine_durable_work):
    from journeon.models import Attempt, Job, Principal

    owner, _, prepare, _, _ = genuine_durable_work
    admitted = dispatch(genuine_durable_work, "different-origin")
    with transaction(owner.engine) as db:
        # Negative isolation fixture only; this does not qualify Shared onboarding.
        db.add(
            Principal(
                id="isolated-other",
                role="SHARED_USER",
                enabled=True,
                authorization_epoch=1,
                credential_revision=1,
            )
        )
        db.flush()
        attempt_id = db.get(TaskVerificationJob, admitted["job_id"]).attempt_id
        db.get(Attempt, attempt_id).principal_id = "isolated-other"
        db.get(Job, admitted["job_id"]).principal_id = "isolated-other"
        db.flush()
        db.execute(
            text("UPDATE attempts SET snapshot='invalid-json' WHERE id=:id"), {"id": attempt_id}
        )
        db.execute(
            text("UPDATE task_verification_jobs SET inputs='invalid-json' WHERE job_id=:id"),
            {"id": admitted["job_id"]},
        )
    for path in (f"/api/v1/tasks/{prepare['origin']['task_id']}/attempts", "/api/v1/jobs"):
        result = get(owner, path)
        assert result["items"] == []
        assert not result["has_more"]
        assert attempt_id not in json.dumps(result)
        assert admitted["job_id"] not in json.dumps(result)
