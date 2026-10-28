# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from sqlalchemy import func, select
from test_production_instructions import official_effect
from test_workspace_provisioning import enrolled_owner  # noqa: F401

from journeon.database import transaction
from journeon.instructions import digest
from journeon.models import BrowserSession, OutboxEvent, ProtectedRequest, Receipt


def context(owner):
    response = owner.client.get("/api/v1/auth/context", headers=owner.headers)
    assert response.status_code == 200
    return response.json()


def test_fresh_owner_discovers_current_browser_session(enrolled_owner):  # noqa: F811
    owner = enrolled_owner
    current = context(owner)
    response = owner.client.get("/api/v1/auth/sessions?limit=1", headers=owner.headers)
    assert response.status_code == 200
    page = response.json()
    if len(page["items"]) != 1 or page["next_cursor"] is not None:
        pytest.fail("Session inventory must return the real first session")
    target = page["items"][0]
    if (
        target["session_id"] != current["session"]["session_id"]
        or target["security_version"] != current["session"]["security_version"]
        or target["principal_id"] != owner.principal_id
    ):
        pytest.fail("Session inventory must bind the current security target")
    if response.headers.get("cache-control") != "no-store":
        pytest.fail("Session inventory must not be cached")


def test_current_cookie_can_refresh_csrf_without_activity(enrolled_owner):  # noqa: F811
    owner = enrolled_owner
    before = context(owner)
    identity = before["session"]["session_id"]
    with transaction(owner.engine) as db:
        old = db.get(BrowserSession, identity)
        activity = old.last_activity
        deadline = old.absolute_deadline
        csrf_hash = old.csrf_hash
        receipt_count = db.scalar(select(func.count()).select_from(Receipt))
        event_count = db.scalar(select(func.count()).select_from(OutboxEvent))
    response = owner.client.post(
        "/api/v1/auth/context/bootstrap", headers={"Origin": owner.headers["Origin"]}, json={}
    )
    assert response.status_code == 200
    body = response.json()
    token = body.get("csrf_token")
    if not isinstance(token, str) or len(token) != 43:
        pytest.fail("Context bootstrap must return one usable CSRF token")
    if response.headers.get("cache-control") != "no-store" or "set-cookie" in response.headers:
        pytest.fail("CSRF refresh must not cache or rotate the browser session")
    with transaction(owner.engine) as db:
        current = db.get(BrowserSession, identity)
        if current.csrf_hash == csrf_hash:
            pytest.fail("CSRF refresh must replace the stored token hash")
        assert current.last_activity == activity
        assert current.absolute_deadline == deadline
        assert db.scalar(select(func.count()).select_from(Receipt)) == receipt_count
        assert db.scalar(select(func.count()).select_from(OutboxEvent)) == event_count
    after = context(owner)
    if before["session"]["security_version"] != after["session"]["security_version"]:
        pytest.fail("CSRF refresh must not change the session security version")
    old_request = owner.client.post(
        "/api/v1/protected-operations/prepare",
        headers=owner.headers,
        json={"effect": owner.grant("project.create")},
    )
    assert old_request.status_code == 401
    fresh_request = owner.client.post(
        "/api/v1/protected-operations/prepare",
        headers={"Origin": owner.headers["Origin"], "X-CSRF-Token": token},
        json={"effect": owner.grant("project.create")},
    )
    assert fresh_request.status_code == 200


@pytest.mark.parametrize("operation", ["revoke", "logout"])
def test_current_human_can_end_own_session_with_a_receipt(enrolled_owner, operation):  # noqa: F811
    owner = enrolled_owner
    current = context(owner)
    pending = owner.prepare(owner.grant("project.create"))
    command = {
        "schema_version": 1,
        "idempotency_key": "end-own-session",
        "expected_security_version": current["session"]["security_version"],
    }
    if operation == "revoke":
        command["target_session_id"] = current["session"]["session_id"]
    path = "/api/v1/auth/sessions/revoke" if operation == "revoke" else "/api/v1/auth/logout"
    response = owner.client.post(path, headers=owner.headers, json=command)
    assert response.status_code == 200
    receipt = response.json()
    with transaction(owner.engine) as db:
        assert db.get(BrowserSession, current["session"]["session_id"]).revoked
        assert db.get(ProtectedRequest, pending["request_id"]).state == "INVALIDATED"
        assert db.get(Receipt, receipt["operation_id"]) is not None
        assert (
            db.scalar(
                select(func.count())
                .select_from(OutboxEvent)
                .where(OutboxEvent.operation_id == receipt["operation_id"])
            )
            == 1
        )
    if operation == "logout" and "set-cookie" not in response.headers:
        pytest.fail("Committed logout must clear the browser cookie")
    assert owner.client.get("/api/v1/auth/context", headers=owner.headers).status_code == 401


def test_original_command_identity_resolves_a_lost_grant_response(enrolled_owner):  # noqa: F811
    owner = enrolled_owner
    current = context(owner)
    effect = owner.grant("project.create")
    accepted = official_effect(owner.client, owner.headers, effect)
    with transaction(owner.engine) as db:
        receipt_count = db.scalar(select(func.count()).select_from(Receipt))
        event_count = db.scalar(select(func.count()).select_from(OutboxEvent))
        activity = db.get(BrowserSession, current["session"]["session_id"]).last_activity
    response = owner.client.post(
        "/api/v1/operations/resolve",
        headers=owner.headers,
        json={
            "schema_version": 1,
            "command": effect["kind"],
            "idempotency_key": effect["idempotency_key"],
            "payload_digest": digest(effect),
            "scope": {
                key: effect[key]
                for key in ("principal_id", "capability", "resource_kind", "resource_id")
            },
            "store_incarnation": current["store_incarnation"],
        },
    )
    assert response.status_code == 200
    body = response.json()
    if body.get("status") != "OBSERVED_RECEIPT" or body.get("receipt") != accepted:
        pytest.fail("Original command identity must recover the retained authorized receipt")
    with transaction(owner.engine) as db:
        assert db.scalar(select(func.count()).select_from(Receipt)) == receipt_count
        assert db.scalar(select(func.count()).select_from(OutboxEvent)) == event_count
        assert db.get(BrowserSession, current["session"]["session_id"]).last_activity == activity
