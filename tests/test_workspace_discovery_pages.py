# SPDX-License-Identifier: AGPL-3.0-only
import base64
import json
from datetime import datetime, timedelta

import pytest
from sqlalchemy import text
from test_production_instructions import official_effect
from test_workspace_durable_resolution import read_state
from test_workspace_session_controls import context
from workspace_durable_helpers import enrolled_owner as enrolled_owner
from workspace_durable_helpers import genuine_project_task as genuine_project_task

from journeon.contracts import DomainError
from journeon.database import transaction
from journeon.models import AccessGrant, BrowserSession, Principal, StoreIdentity
from journeon.permissions import AuthenticatedContext
from journeon.projects import ProjectService


def grant(owner, capability, project, identity):
    return official_effect(
        owner.client,
        owner.headers,
        owner.grant(capability, project_id=project, identity=identity),
    )["grant"]


def revoke(owner, selected):
    official_effect(
        owner.client,
        owner.headers,
        {
            "kind": "permission.grant.revoke.v1",
            "schema_version": 1,
            "idempotency_key": "remove-" + selected["grant_id"],
            "grant_id": selected["grant_id"],
            "expected_revision": selected["revision"],
        },
    )


def projects(fixture, count):
    owner, command, first, _, _, _ = fixture
    identities = [first["project"]["project_id"]]
    for index in range(count - 1):
        result = owner.client.post(
            "/api/v1/projects",
            headers=owner.headers,
            json=command.model_dump(mode="json") | {"idempotency_key": f"page-project-{index}"},
        )
        assert result.status_code == 200
        identities.append(result.json()["project"]["project_id"])
    return sorted(identities)


def page(owner, **params):
    response = owner.client.get("/api/v1/projects", params={"limit": 1} | params)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert set(body) == {"items", "next_cursor", "has_more", "observed_at", "store_incarnation"}
    assert datetime.fromisoformat(body["observed_at"]).utcoffset() == timedelta(0)
    return body


def ids(body):
    return [item["project_id"] for item in body["items"]]


@pytest.mark.parametrize("limit", [1, 2])
def test_hidden_before_between_after_never_enters_cursor_or_lookahead(genuine_project_task, limit):
    owner = genuine_project_task[0]
    identities = projects(genuine_project_task, 5)
    visible = identities[1::2]
    for index, identity in enumerate(visible):
        grant(owner, "project.read", identity, f"visible-{index}")
    hidden = set(identities) - set(visible)
    with transaction(owner.engine) as db:
        for identity in hidden:
            db.execute(
                text("UPDATE projects SET provider_snapshot='invalid-json' WHERE id=:id"),
                {"id": identity},
            )
    before = read_state(owner)
    result, found = page(owner, limit=limit), []
    while True:
        found.extend(ids(result))
        serialized = json.dumps(result)
        assert all(identity not in serialized for identity in hidden)
        if result["next_cursor"] is None:
            assert result["has_more"] is False
            break
        assert result["has_more"] is True
        cursor = json.loads(base64.urlsafe_b64decode(result["next_cursor"]))
        assert cursor["after"] == found[-1]
        assert all(identity not in json.dumps(cursor) for identity in hidden)
        result = page(owner, limit=limit, cursor=result["next_cursor"])
    assert found == visible
    assert read_state(owner) == before


def test_grants_are_live_between_pages_and_regrant_does_not_restart(genuine_project_task):
    owner = genuine_project_task[0]
    identities = projects(genuine_project_task, 4)
    grants = [
        grant(owner, "project.read", identity, f"live-{index}")
        for index, identity in enumerate(identities)
    ]
    first = page(owner)
    assert ids(first) == identities[:1]
    revoke(owner, grants[1])
    second = page(owner, cursor=first["next_cursor"])
    assert ids(second) == identities[2:3]
    old = grants[1]
    official_effect(
        owner.client,
        owner.headers,
        owner.grant("project.read", project_id=identities[1], identity="regrant-middle")
        | {"expected_revision": old["revision"] + 1},
    )
    last = page(owner, cursor=second["next_cursor"])
    assert ids(last) == identities[3:]
    assert not last["has_more"]
    assert ids(page(owner, limit=100)) == identities


@pytest.mark.parametrize("mode", ["disabled", "expired", "malformed", "naive", "wrong-scope"])
def test_invalid_grant_does_not_admit_record_or_override_valid_sibling(genuine_project_task, mode):
    owner = genuine_project_task[0]
    identity = genuine_project_task[2]["project"]["project_id"]
    selected = grant(owner, "project.read", identity, "grant-under-test")
    with transaction(owner.engine) as db:
        row = db.get(AccessGrant, selected["grant_id"])
        if mode == "disabled":
            row.enabled = False
        elif mode == "wrong-scope":
            row.resource_id = "unrelated-project"
        else:
            row.expires_at = {
                "expired": "2000-01-01T00:00:00+00:00",
                "malformed": "invalid-date",
                "naive": "2999-01-01T00:00:00",
            }[mode]
    assert ids(page(owner)) == []
    grant(owner, "project.read", None, "explicit-deployment-read")
    assert ids(page(owner)) == [identity]


@pytest.mark.parametrize("cursor", ["", "!", "a" * 4097, "e30=", "W10=", "bnVsbA=="])
def test_malformed_cursor_is_bounded_and_rejected_without_echo(enrolled_owner, cursor):
    result = enrolled_owner.client.get("/api/v1/projects", params={"limit": 1, "cursor": cursor})
    assert result.status_code == 422
    assert set(result.json()) <= {"schema_version", "code", "reason", "details"}


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("principal", "different-principal", 409),
        ("epoch", 999, 409),
        ("incarnation", "previous-store", 409),
        ("query", {"operation": "task.list.v1"}, 409),
        ("extra", "forbidden", 422),
        ("after", [], 422),
    ],
)
def test_cursor_binding_rejects_changed_context(genuine_project_task, field, value, expected):
    owner = genuine_project_task[0]
    for index, identity in enumerate(projects(genuine_project_task, 2)):
        grant(owner, "project.read", identity, f"cursor-{index}")
    first = page(owner)
    decoded = json.loads(base64.urlsafe_b64decode(first["next_cursor"]))
    decoded[field] = value
    cursor = base64.urlsafe_b64encode(json.dumps(decoded).encode()).decode()
    result = owner.client.get("/api/v1/projects", params={"limit": 1, "cursor": cursor})
    assert result.status_code == expected


def test_store_incarnation_change_invalidates_real_cursor(genuine_project_task):
    owner = genuine_project_task[0]
    for index, identity in enumerate(projects(genuine_project_task, 2)):
        grant(owner, "project.read", identity, f"incarnation-{index}")
    first = page(owner)
    with transaction(owner.engine) as db:
        db.get(StoreIdentity, 1).incarnation = "replacement-store"
    result = owner.client.get(
        "/api/v1/projects", params={"limit": 1, "cursor": first["next_cursor"]}
    )
    assert result.status_code == 409


def test_exhausted_hidden_scan_returns_unavailable_without_partial_page(
    genuine_project_task, monkeypatch
):
    from journeon import discovery

    owner = genuine_project_task[0]
    identities = projects(genuine_project_task, 3)
    grant(owner, "project.read", identities[0], "first-visible")
    monkeypatch.setattr(discovery, "SCAN_LIMIT", 2)
    result = owner.client.get("/api/v1/projects", params={"limit": 1})
    assert result.status_code == 503
    assert "items" not in result.json()
    assert all(identity not in result.text for identity in identities)


@pytest.mark.parametrize("invalid", ["revoked", "expired", "rotated", "epoch", "disabled"])
def test_resolved_actor_is_rechecked_on_empty_collection(enrolled_owner, invalid, monkeypatch):
    owner = enrolled_owner
    session_id = context(owner)["session"]["session_id"]
    with transaction(owner.engine) as db:
        session = db.get(BrowserSession, session_id)
        actor = AuthenticatedContext(session.principal_id, session.principal_epoch, session.id)
        if invalid == "revoked":
            session.revoked = True
        elif invalid == "expired":
            deadline = session.absolute_deadline
            monkeypatch.setattr("journeon.sessions.utc_seconds", lambda: deadline)
        elif invalid == "rotated":
            from journeon.sessions import rotate_session

            rotate_session(db, session.id, strong=True)
        elif invalid == "epoch":
            db.get(Principal, actor.principal_id).authorization_epoch += 1
        else:
            # Negative-only Shared identity; this does not qualify Shared onboarding.
            db.add(
                Principal(
                    id="isolated-disabled",
                    role="SHARED_USER",
                    enabled=False,
                    authorization_epoch=1,
                    credential_revision=1,
                )
            )
            db.flush()
            session.principal_id = "isolated-disabled"
            actor = AuthenticatedContext("isolated-disabled", session.principal_epoch, session.id)
    with pytest.raises(DomainError) as rejected:
        ProjectService(owner.engine).list(actor, 1)
    assert rejected.value.code in {"AUTHENTICATION_REQUIRED", "PERMISSION_DENIED"}


def test_parent_project_survives_child_grant_removal(genuine_project_task):
    owner, _, receipt, _, _, grants = genuine_project_task
    identity = receipt["project"]["project_id"]
    grant(owner, "project.read", identity, "parent-read")
    assert page(owner)["items"][0]["links"] == [
        {"relation": "tasks", "href": f"/api/v1/projects/{identity}/tasks?limit=1"}
    ]
    revoke(owner, grants["task.read"]["grant"])
    result = page(owner)
    assert ids(result) == [identity]
    assert result["items"][0]["links"] == []
    assert (
        owner.client.get(f"/api/v1/projects/{identity}/tasks", params={"limit": 1}).status_code
        == 403
    )
