# SPDX-License-Identifier: AGPL-3.0-only
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from test_workspace_attention_boundaries import navigation_job as navigation_job
from test_workspace_discovery_pages import revoke
from workspace_durable_helpers import enrolled_owner as enrolled_owner
from workspace_durable_helpers import genuine_instruction_scope as genuine_instruction_scope
from workspace_durable_helpers import genuine_project_task as genuine_project_task

from journeon.api import create_app
from journeon.database import transaction
from journeon.jobs import JobService
from journeon.models import AccessGrant, OutboxEvent, StoreIdentity


def revoke_instruction_grant(owner, project, capability):
    with transaction(owner.engine) as db:
        row = db.scalar(
            select(AccessGrant).where(
                AccessGrant.capability == capability, AccessGrant.resource_id == project
            )
        )
        target = {"grant_id": row.id, "revision": row.revision}
    revoke(owner, target)


@pytest.fixture
def failed_navigation(navigation_job):
    owner, config, project, proposed = navigation_job
    revoke_instruction_grant(owner, project, "project.instruction.evaluate")
    assert JobService(owner.engine, config).claim() is None
    job = owner.client.get("/api/v1/jobs/" + proposed["job_id"]).json()
    assert job["state"] == "FAILED"
    return owner, config, project, job


def replayed_job_events(client, headers, identity, cursor=None):
    events = []
    while True:
        response = client.post(
            "/api/v1/events/replay",
            headers=headers,
            json={"limit": 100} | ({"cursor": cursor} if cursor else {}),
        )
        assert response.status_code == 200, response.text
        page = response.json()
        events.extend(page["events"])
        if not page["truncated"]:
            break
        cursor = page["cursor"]
    return [event for event in events if event["target_id"] == identity]


@pytest.mark.parametrize("surface", ["legacy_attention", "receipt", "replay"])
def test_legacy_instruction_job_observation_requires_current_configured_root(
    failed_navigation, surface
):
    owner, config, _, job = failed_navigation
    legacy = "/api/v1/jobs/" + job["job_id"] + "/attention"
    receipt = "/api/v1/operations/" + job["admission_id"]
    assert owner.client.get(legacy).status_code == 200
    assert owner.client.get(legacy).json()
    assert owner.client.get(receipt).status_code == 200
    assert replayed_job_events(owner.client, owner.headers, job["job_id"])
    with TestClient(
        create_app(
            owner.engine,
            browser_auth=owner.client.app.state.browser_auth,
            instructions=config.model_copy(update={"roots": []}),
        ),
        base_url="https://example.test",
        cookies=owner.client.cookies,
    ) as client:
        assert client.get("/api/v1/jobs/" + job["job_id"]).status_code == 404
        if surface in {"legacy_attention", "receipt"}:
            response = client.get(legacy if surface == "legacy_attention" else receipt)
            assert response.status_code == 404, response.text
            assert response.json()["code"] == "NOT_FOUND"
        else:
            assert not replayed_job_events(client, owner.headers, job["job_id"])


@pytest.mark.parametrize("hidden", ["configuration", "root", "revision", "device", "git", "grant"])
def test_legacy_job_source_authority_precedes_corrupt_observation_json(failed_navigation, hidden):
    owner, config, project, job = failed_navigation
    selected = config
    if hidden == "configuration":
        selected = None
    elif hidden == "root":
        selected = config.model_copy(update={"roots": []})
    elif hidden == "revision":
        selected = config.model_copy(
            update={
                "roots": [
                    root.model_copy(update={"revision": root.revision + 1}) for root in config.roots
                ]
            }
        )
    elif hidden == "device":
        root = Path(config.roots[0].path)
        root.rename(root.with_name("retained-prior-root"))
        root.mkdir()
    elif hidden == "git":
        (Path(config.roots[0].path) / ".git").mkdir()
    else:
        revoke_instruction_grant(owner, project, "project.instruction.read")
    with transaction(owner.engine) as db:
        db.execute(
            text("UPDATE attention SET history='invalid-json' WHERE job_id=:id"),
            {"id": job["job_id"]},
        )
        db.execute(
            text(
                "UPDATE operation_receipts SET result='invalid-json' "
                "WHERE owner='jobs' AND target_id=:id"
            ),
            {"id": job["job_id"]},
        )
        db.execute(
            text(
                "UPDATE outbox_events SET payload='invalid-json' "
                "WHERE owner='jobs' AND target_id=:id"
            ),
            {"id": job["job_id"]},
        )
    expected = 503 if hidden == "configuration" else 404 if hidden == "root" else 403
    code = (
        "DEPENDENCY_UNAVAILABLE"
        if expected == 503
        else "NOT_FOUND"
        if expected == 404
        else "PERMISSION_DENIED"
    )
    with TestClient(
        create_app(
            owner.engine, browser_auth=owner.client.app.state.browser_auth, instructions=selected
        ),
        base_url="https://example.test",
        cookies=owner.client.cookies,
    ) as client:
        for path in (
            f"/api/v1/jobs/{job['job_id']}/attention",
            f"/api/v1/operations/{job['admission_id']}",
        ):
            response = client.get(path)
            assert response.status_code == expected, response.text
            assert response.json()["code"] == code
            assert job["job_id"] not in response.text
        cursor = None
        if hidden == "revision":
            response = client.post(
                "/api/v1/events/replay", headers=owner.headers, json={"limit": 100}
            )
            assert response.status_code == 409
            assert response.json()["code"] == "REVISION_CONFLICT"
            assert response.json()["reason"] == "Root configuration changed"
            with transaction(owner.engine) as db:
                first = db.scalar(
                    select(func.min(OutboxEvent.sequence)).where(
                        OutboxEvent.owner == "jobs", OutboxEvent.target_id == job["job_id"]
                    )
                )
                store = db.get(StoreIdentity, 1)
                assert first is not None and store is not None
                cursor = {"incarnation": store.incarnation, "sequence": first - 1}
        assert not replayed_job_events(client, owner.headers, job["job_id"], cursor)


def test_instruction_job_stop_control_keeps_its_existing_accept_grant(navigation_job):
    owner, config, project, proposed = navigation_job
    job = owner.client.get("/api/v1/jobs/" + proposed["job_id"]).json()
    revoke_instruction_grant(owner, project, "project.instruction.read")
    with TestClient(
        create_app(
            owner.engine,
            browser_auth=owner.client.app.state.browser_auth,
            instructions=config.model_copy(update={"roots": []}),
        ),
        base_url="https://example.test",
        cookies=owner.client.cookies,
    ) as client:
        response = client.post(
            f"/api/v1/jobs/{job['job_id']}/cancel",
            headers=owner.headers,
            json={"expected_revision": job["revision"]},
        )
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "CANCELLED"
