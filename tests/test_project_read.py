# SPDX-License-Identifier: AGPL-3.0-only

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_task_admission import admitted  # noqa: F401
from test_work import work  # noqa: F401

from journeon.api import create_app
from journeon.browser_auth import COOKIE_NAME, BrowserAuth
from journeon.contracts import DomainError
from journeon.database import transaction
from journeon.models import AccessGrant, BrowserSession, Project
from journeon.projects import ProjectService


def test_current_project_revision_can_be_refreshed_after_lost_response(admitted):  # noqa: F811
    (engine, _, actor, issued, create), configure = admitted
    with transaction(engine) as db:
        db.add(
            AccessGrant(
                id="current-project-read",
                principal_id=actor.principal_id,
                capability="project.read",
                resource_kind="project",
                resource_id=create.project_id,
                enabled=True,
                revision=1,
                provenance="fixture",
            )
        )
    with TestClient(
        create_app(engine, browser_auth=BrowserAuth("https://testserver")),
        base_url="https://testserver",
    ) as client:
        client.cookies.set(COOKIE_NAME, issued.token)
        headers = {"Origin": "https://testserver", "X-CSRF-Token": issued.csrf_token}
        first = client.post(
            "/api/v1/projects/verification", json=configure.model_dump(), headers=headers
        )
        assert first.status_code == 200, first.text
        later = configure.model_dump() | {
            "idempotency_key": "other-writer",
            "expected_project_revision": 2,
            "expected_policy_revision": 1,
        }
        assert (
            client.post("/api/v1/projects/verification", json=later, headers=headers).status_code
            == 200
        )
        assert (
            client.post(
                "/api/v1/projects/verification", json=configure.model_dump(), headers=headers
            ).json()
            == first.json()
        )
        stale = client.post(
            "/api/v1/tasks",
            json=create.model_dump() | {"expected_project_revision": 2},
            headers=headers,
        )
        assert stale.status_code == 409
        current = client.get(f"/api/v1/projects/{create.project_id}")
        assert current.status_code == 200, current.text
        assert current.json()["revision"] == 3
        result = client.post(
            "/api/v1/tasks",
            json=create.model_dump() | {"expected_project_revision": current.json()["revision"]},
            headers=headers,
        )
        assert result.status_code == 200, result.text
        with transaction(engine) as db:
            db.get(AccessGrant, "current-project-read").enabled = False
        assert client.get(f"/api/v1/projects/{create.project_id}").status_code == 403


def grant_read(engine, actor, project_id):
    with transaction(engine) as db:
        db.add(
            AccessGrant(
                id="read-fixture",
                principal_id=actor.principal_id,
                capability="project.read",
                resource_kind="project",
                resource_id=project_id,
                enabled=True,
                revision=1,
                provenance="fixture",
            )
        )


@pytest.mark.parametrize("state", ["missing", "wrong-project", "disabled", "expired"])
def test_project_read_requires_current_exact_grant_before_decode(work, state):  # noqa: F811
    engine, _, actor, _, create = work
    if state != "missing":
        grant_read(
            engine, actor, create.project_id if state != "wrong-project" else "another-project"
        )
        with transaction(engine) as db:
            grant = db.get(AccessGrant, "read-fixture")
            if state == "disabled":
                grant.enabled = False
            if state == "expired":
                grant.expires_at = "2000-01-01T00:00:00+00:00"
    with transaction(engine) as db:
        db.execute(
            text("UPDATE projects SET provider_snapshot = :value WHERE id = :id"),
            {"value": "invalid-json", "id": create.project_id},
        )
    for project_id in (create.project_id, "missing-project"):
        with pytest.raises(DomainError) as error:
            ProjectService(engine).read(actor, project_id)
        assert error.value.code == "PERMISSION_DENIED"


def test_project_read_malformed_state_and_missing_target(work):  # noqa: F811
    engine, _, actor, _, create = work
    grant_read(engine, actor, create.project_id)
    with transaction(engine) as db:
        db.get(Project, create.project_id).resource_refs = {"invalid": "value"}
    with pytest.raises(DomainError) as error:
        ProjectService(engine).read(actor, create.project_id)
    assert error.value.code == "DEPENDENCY_UNAVAILABLE"
    assert error.value.reason == "Stored Project state requires repair"
    with transaction(engine) as db:
        db.get(AccessGrant, "read-fixture").resource_id = "missing-project"
    with pytest.raises(DomainError) as error:
        ProjectService(engine).read(actor, "missing-project")
    assert error.value.code == "NOT_FOUND"


def test_project_read_current_instruction_owner_and_session_revocation(work):  # noqa: F811
    engine, _, actor, _, create = work
    grant_read(engine, actor, create.project_id)
    service = ProjectService(engine)
    original = service.read(actor, create.project_id)
    assert original.revision == 1
    assert original.instruction_owner == "ENVIRONMENT"
    with transaction(engine) as db:
        project = db.get(Project, create.project_id)
        project.revision += 1
        project.instruction_owner = "PROJECT"
        project.instruction_authority_ref = "project-instructions:fixture"
    current = service.read(actor, create.project_id)
    assert current.revision == 2
    assert current.instruction_owner == "PROJECT"
    assert current.instruction_authority_ref == "project-instructions:fixture"
    assert current.provider_allowance_at_creation == original.provider_allowance_at_creation
    with transaction(engine) as db:
        db.get(BrowserSession, actor.authentication_ref).revoked = True
    with pytest.raises(DomainError) as error:
        service.read(actor, create.project_id)
    assert error.value.code == "AUTHENTICATION_REQUIRED"


def test_project_read_http_authentication_denial_and_path_validation(work):  # noqa: F811
    engine, _, _, issued, create = work
    with TestClient(
        create_app(engine, browser_auth=BrowserAuth("https://testserver")),
        base_url="https://testserver",
    ) as client:
        assert client.get(f"/api/v1/projects/{create.project_id}").status_code == 401
        client.cookies.set(COOKIE_NAME, issued.token)
        denied = client.get(f"/api/v1/projects/{create.project_id}")
        missing = client.get("/api/v1/projects/missing-project")
        assert denied.status_code == missing.status_code == 403
        assert denied.json() == missing.json()
        assert client.get("/api/v1/projects/invalid%20identifier").status_code == 422


def test_owner_creation_grants_do_not_imply_project_read(database, actor, command):
    engine, _ = database
    service = ProjectService(engine)
    project = service.create(actor, command).project
    with pytest.raises(DomainError) as error:
        service.read(actor, project.project_id)
    assert error.value.code == "PERMISSION_DENIED"
    grant_read(engine, actor, project.project_id)
    assert service.read(actor, project.project_id).revision == project.revision
