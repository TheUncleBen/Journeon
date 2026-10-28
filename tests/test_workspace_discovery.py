# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from sqlalchemy import text
from test_production_instructions import official_effect
from test_task_dispatch import dispatch_worker
from workspace_durable_helpers import enrolled_owner as enrolled_owner
from workspace_durable_helpers import genuine_durable_work as genuine_durable_work
from workspace_durable_helpers import genuine_instruction_scope as genuine_instruction_scope
from workspace_durable_helpers import genuine_project_task as genuine_project_task

from journeon.database import transaction
from journeon.instructions import digest


def test_provisioned_work_is_discoverable_through_real_collection_ids(genuine_durable_work):
    owner, config, prepare, _, route = genuine_durable_work
    admitted = owner.client.post(
        "/api/v1/tasks/dispatch",
        headers=owner.headers,
        json=prepare
        | {
            "idempotency_key": "discoverable-dispatch",
            "step_id": "verify",
            "route_key": route.key,
            "route_revision": route.revision,
        },
    )
    assert admitted.status_code == 200
    dispatch_worker(owner.engine, config)
    projects = owner.client.get("/api/v1/projects", params={"limit": 1})
    assert projects.status_code == 200
    project = projects.json()["items"][0]
    assert project["project_id"] == prepare["project_id"]
    tasks = owner.client.get(f"/api/v1/projects/{project['project_id']}/tasks", params={"limit": 1})
    assert tasks.status_code == 200
    task = tasks.json()["items"][0]
    assert task["task_id"] == prepare["origin"]["task_id"]
    attempts = owner.client.get(f"/api/v1/tasks/{task['task_id']}/attempts", params={"limit": 1})
    assert attempts.status_code == 200
    attempt = attempts.json()["items"][0]
    jobs = owner.client.get(
        "/api/v1/jobs", params={"limit": 1, "attempt_id": attempt["attempt_id"]}
    )
    assert jobs.status_code == 200
    job = jobs.json()["items"][0]
    assert job["job_id"] == admitted.json()["job_id"]
    proof = owner.client.get(f"/api/v1/jobs/{job['job_id']}/evidence")
    assert proof.status_code == 200
    evidence = proof.json()
    assert evidence["attempt_id"] == attempt["attempt_id"]
    assert evidence["job_id"] == job["job_id"]
    assert evidence["passed"]
    assert evidence["execution"]["completion"]["exit_code"] == 0
    assert evidence["execution"]["completion"]["drained"]
    assert evidence["content_digest"] == digest(
        {key: value for key, value in evidence.items() if key != "content_digest"}
    )
    detail = owner.client.get(f"/api/v1/tasks/{task['task_id']}")
    assert detail.status_code == 200
    assert detail.json()["state"] != "DONE"
    for response in (projects, tasks, attempts, jobs):
        page = response.json()
        assert page["has_more"] is False
        assert page["next_cursor"] is None
        assert page["store_incarnation"]
        assert page["observed_at"]
        assert all(item["revision"] >= 1 for item in page["items"])


def test_owner_project_creation_does_not_grant_discovery(genuine_project_task):
    owner, _, receipt, _, _, _ = genuine_project_task
    response = owner.client.get("/api/v1/projects", params={"limit": 1})
    assert response.status_code == 200
    assert response.json()["items"] == []
    assert response.json()["has_more"] is False
    project_id = receipt["project"]["project_id"]
    official_effect(owner.client, owner.headers, owner.grant("project.read", project_id=project_id))
    visible = owner.client.get("/api/v1/projects", params={"limit": 1})
    assert visible.status_code == 200
    assert [item["project_id"] for item in visible.json()["items"]] == [project_id]


@pytest.mark.parametrize("authorized", [False, True])
def test_project_discovery_authorizes_before_decoding_corrupt_state(
    genuine_project_task, authorized
):
    owner, _, receipt, _, _, _ = genuine_project_task
    project_id = receipt["project"]["project_id"]
    if authorized:
        official_effect(
            owner.client, owner.headers, owner.grant("project.read", project_id=project_id)
        )
    with transaction(owner.engine) as db:
        db.execute(
            text("UPDATE projects SET provider_snapshot='invalid-json' WHERE id=:id"),
            {"id": project_id},
        )
    response = owner.client.get("/api/v1/projects", params={"limit": 1})
    assert response.status_code == (503 if authorized else 200)
    if not authorized:
        assert response.json()["items"] == []
        assert response.json()["has_more"] is False
        assert project_id not in response.text


@pytest.mark.parametrize("limit", [None, 0, 101])
def test_discovery_requires_an_explicit_bounded_limit(enrolled_owner, limit):
    parameters = {} if limit is None else {"limit": limit}
    response = enrolled_owner.client.get("/api/v1/projects", params=parameters)
    assert response.status_code == 422
