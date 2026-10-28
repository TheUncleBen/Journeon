# SPDX-License-Identifier: AGPL-3.0-only
import base64
import json
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from test_production_instructions import official_effect
from test_workspace_discovery_pages import grant, projects, revoke
from test_workspace_discovery_work import dispatch
from test_workspace_durable_resolution import read_state
from test_workspace_search_attention import attention_page, dismiss, search
from test_workspace_search_attention import failed_work as failed_work
from workspace_durable_helpers import enrolled_owner as enrolled_owner
from workspace_durable_helpers import genuine_durable_work as genuine_durable_work
from workspace_durable_helpers import genuine_instruction_scope as genuine_instruction_scope
from workspace_durable_helpers import genuine_project_task as genuine_project_task

from journeon.api import create_app
from journeon.database import transaction
from journeon.models import (
    AccessGrant,
    BrowserSession,
    InstructionRoot,
    Job,
    Principal,
    TaskVerificationJob,
)


def test_all_real_kinds_share_deterministic_order_and_authorized_lookahead(genuine_durable_work):
    owner, _, prepare, grants, _ = genuine_durable_work
    admitted = dispatch(genuine_durable_work, "all-search-kinds")
    with transaction(owner.engine) as db:
        attempt_id = db.get(TaskVerificationJob, admitted["job_id"]).attempt_id
    kinds = ["TASK", "PROJECT", "JOB", "INSTRUCTION_NAVIGATION", "ATTEMPT"]
    before = read_state(owner)
    items, cursor = [], None
    while True:
        response = search(owner, "e", kinds, limit=2, **({"cursor": cursor} if cursor else {}))
        assert response.status_code == 200, response.text
        result = response.json()
        items.extend(result["items"])
        if not result["has_more"]:
            assert result["next_cursor"] is None
            break
        cursor = result["next_cursor"]
        position = json.loads(base64.urlsafe_b64decode(cursor))
        assert (position["after_kind"], position["after"]) == (
            items[-1]["kind"],
            items[-1]["entity_id"],
        )
    assert [(item["kind"], item["entity_id"]) for item in items] == [
        ("ATTEMPT", attempt_id),
        ("INSTRUCTION_NAVIGATION", prepare["project_id"]),
        ("JOB", admitted["job_id"]),
        ("PROJECT", prepare["project_id"]),
        ("TASK", prepare["origin"]["task_id"]),
    ]
    for item in items:
        assert owner.client.get(item["href"]).status_code == 200
    assert read_state(owner) == before
    revoke(owner, grants["attempt.read"]["grant"])
    with transaction(owner.engine) as db:
        db.execute(
            text("UPDATE attempts SET snapshot='invalid-json', inputs='invalid-json' WHERE id=:id"),
            {"id": attempt_id},
        )
        db.execute(
            text("UPDATE task_verification_jobs SET inputs='invalid-json' WHERE job_id=:id"),
            {"id": admitted["job_id"]},
        )
    response = search(owner, "e", kinds, limit=3)
    assert response.status_code == 200, response.text
    assert [item["kind"] for item in response.json()["items"]] == [
        "INSTRUCTION_NAVIGATION",
        "PROJECT",
        "TASK",
    ]
    assert not response.json()["has_more"]
    assert admitted["job_id"] not in response.text
    assert attempt_id not in response.text


def test_cursor_rejects_unselected_kind_and_security_rebinding(genuine_project_task):
    owner = genuine_project_task[0]
    identities = projects(genuine_project_task, 2)
    for index, identity in enumerate(identities):
        grant(owner, "project.read", identity, f"cursor-visible-{index}")
    first = search(owner, "project", ["PROJECT"], limit=1).json()
    assert first["has_more"]
    for changed, expected in (
        ({"after_kind": "TASK"}, 422),
        ({"principal": "other-human"}, 409),
        ({"epoch": 999}, 409),
        ({"incarnation": "other-store"}, 409),
    ):
        cursor = json.loads(base64.urlsafe_b64decode(first["next_cursor"])) | changed
        forged = base64.urlsafe_b64encode(json.dumps(cursor).encode()).decode()
        result = search(owner, "project", ["PROJECT"], limit=1, cursor=forged)
        assert result.status_code == expected, result.text


@pytest.mark.parametrize("hidden", ["principal", "root", "config"])
def test_other_source_authority_hides_attention_before_history(failed_work, hidden):
    fixture, _ = failed_work
    owner, config = fixture[:2]
    item = attention_page(owner)["items"][0]
    command, accepted = dismiss(owner, item)
    assert accepted.status_code == 200
    with transaction(owner.engine) as db:
        if hidden == "principal":
            db.add(
                Principal(
                    id="other-human",
                    role="SHARED_USER",
                    enabled=True,
                    authorization_epoch=1,
                    credential_revision=1,
                )
            )
            db.flush()
            db.get(Job, item["source"]["job_id"]).principal_id = "other-human"
        elif hidden == "root":
            db.get(InstructionRoot, "durable-source").enabled = False
        db.execute(
            text("UPDATE attention SET history='invalid-json' WHERE id=:id"),
            {"id": item["attention_id"]},
        )
        db.execute(
            text("UPDATE operation_receipts SET result='invalid-json' WHERE id=:id"),
            {"id": accepted.json()["operation_id"]},
        )
    selected_config = config.model_copy(update={"roots": []}) if hidden == "config" else config
    with TestClient(
        create_app(
            owner.engine,
            browser_auth=owner.client.app.state.browser_auth,
            instructions=selected_config,
        ),
        base_url="https://example.test",
        cookies=owner.client.cookies,
    ) as client:
        view = attention_page(replace(owner, client=client))
        assert view["items"] == [] and not view["has_more"]
        assert item["attention_id"] not in json.dumps(view)
        assert client.post(
            "/api/v1/notifications/dismiss", headers=owner.headers, json=command
        ).status_code in {403, 404}
        assert client.get(f"/api/v1/operations/{accepted.json()['operation_id']}").status_code in {
            403,
            404,
        }


@pytest.mark.parametrize("state", ["revoked", "expired"])
def test_global_read_authentication_does_not_refresh_idle(enrolled_owner, state, monkeypatch):
    owner = enrolled_owner
    with transaction(owner.engine) as db:
        session = db.scalar(select(BrowserSession))
        if state == "revoked":
            session.revoked = True
        else:
            expired_at = session.absolute_deadline + 1
            monkeypatch.setattr("journeon.sessions.utc_seconds", lambda: expired_at)
        before = session.last_activity
        identity = session.id
    for path, params in (
        ("/api/v1/search", {"q": "e", "kinds": "PROJECT", "limit": 1}),
        ("/api/v1/attention", {"limit": 1}),
    ):
        assert owner.client.get(path, params=params).status_code == 401
    with transaction(owner.engine) as db:
        assert db.get(BrowserSession, identity).last_activity == before


@pytest.mark.parametrize(
    "kind,capability", [("TASK", "task.read"), ("ATTEMPT", "attempt.read"), ("JOB", "job.read")]
)
def test_search_required_corruption_is_hidden_before_decode_and_explicit_when_authorized(
    genuine_durable_work, kind, capability
):
    owner, _, prepare, grants, _ = genuine_durable_work
    admitted = dispatch(genuine_durable_work, "search-corruption-acceptance")
    with transaction(owner.engine) as db:
        attempt = db.get(TaskVerificationJob, admitted["job_id"]).attempt_id
    identity = {
        "TASK": prepare["origin"]["task_id"],
        "ATTEMPT": attempt,
        "JOB": admitted["job_id"],
    }[kind]
    revoke(owner, grants[capability]["grant"])
    table, column = {
        "TASK": ("tasks", "snapshot"),
        "ATTEMPT": ("attempts", "snapshot"),
        "JOB": ("task_verification_jobs", "inputs"),
    }[kind]
    key = "job_id" if kind == "JOB" else "id"
    with transaction(owner.engine) as db:
        db.execute(
            text(f"UPDATE {table} SET {column}='invalid-json' WHERE {key}=:id"), {"id": identity}
        )
    before = read_state(owner)
    hidden = search(owner, "e", (kind,), limit=1)
    assert hidden.status_code == 200, hidden.text
    assert hidden.json()["items"] == []
    assert hidden.json()["has_more"] is False
    assert hidden.json()["next_cursor"] is None
    assert identity not in hidden.text
    assert read_state(owner) == before
    with transaction(owner.engine) as db:
        revision = db.get(AccessGrant, grants[capability]["grant"]["grant_id"]).revision
    official_effect(
        owner.client,
        owner.headers,
        owner.grant(
            capability,
            project_id=prepare["project_id"],
            identity="restore-search-authority-" + kind,
        )
        | {"expected_revision": revision},
    )
    before = read_state(owner)
    visible = search(owner, "e", (kind,), limit=1)
    assert visible.status_code == 503, visible.text
    assert visible.json()["code"] == "DEPENDENCY_UNAVAILABLE"
    assert identity not in visible.text
    assert read_state(owner) == before


@pytest.mark.parametrize("limit", [0, 101])
def test_explicit_search_limit_rejects_outside_contract(genuine_project_task, limit):
    owner = genuine_project_task[0]
    before = read_state(owner)
    response = search(owner, "e", ("PROJECT",), limit=limit)
    assert response.status_code == 422
    assert read_state(owner) == before
