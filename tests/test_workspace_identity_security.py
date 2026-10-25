# SPDX-License-Identifier: AGPL-3.0-only
import json

import pytest
from sqlalchemy import func, select, text
from test_production_instructions import official_effect
from test_workspace_provisioning import enrolled_owner  # noqa: F401
from test_workspace_session_controls import context

from journeon.database import transaction
from journeon.instructions import digest
from journeon.models import BrowserSession, OutboxEvent, Principal, Receipt, StoreIdentity
from journeon.sessions import security_version


def login_again(owner, *, count=1):
    begun = owner.client.post(
        "/api/v1/auth/passkeys/begin",
        headers={"Origin": owner.headers["Origin"]},
        json={"purpose": "login", "label": "Session control test"},
    )
    assert begun.status_code == 200
    challenge = begun.json()
    credential = owner.authenticator.assert_key(json.loads(challenge["options_json"]), count=count)
    finished = owner.client.post(
        "/api/v1/auth/passkeys/finish",
        headers={"Origin": owner.headers["Origin"]},
        json={
            "purpose": "login",
            "ceremony_id": challenge["ceremony_id"],
            "credential_json": json.dumps(credential),
        },
    )
    assert finished.status_code == 200
    owner.headers["X-CSRF-Token"] = finished.json()["csrf_token"]


def resolve_request(effect, current, scope):
    return {
        "schema_version": 1,
        "command": effect["kind"],
        "idempotency_key": effect["idempotency_key"],
        "payload_digest": digest(effect),
        "scope": scope,
        "store_incarnation": current["store_incarnation"],
    }


def test_fresh_same_principal_login_recovers_own_logout_without_retry(enrolled_owner):  # noqa: F811
    owner = enrolled_owner
    before = context(owner)
    effect = {
        "kind": "identity.session.logout.v1",
        "schema_version": 1,
        "idempotency_key": "lost-logout",
        "expected_security_version": before["session"]["security_version"],
    }
    query = resolve_request(effect, before, {"target_session_id": before["session"]["session_id"]})
    logout = owner.client.post("/api/v1/auth/logout", headers=owner.headers, json=effect)
    assert logout.status_code == 200
    assert (
        owner.client.post(
            "/api/v1/operations/resolve", headers=owner.headers, json=query
        ).status_code
        == 401
    )
    login_again(owner)
    resolved = owner.client.post("/api/v1/operations/resolve", headers=owner.headers, json=query)
    assert resolved.status_code == 200
    if resolved.json().get("receipt") != logout.json():
        pytest.fail("A fresh login must recover the same historical logout receipt")
    with transaction(owner.engine) as db:
        assert (
            db.scalar(
                select(func.count())
                .select_from(Receipt)
                .where(Receipt.command == "identity.session.logout.v1")
            )
            == 1
        )


def test_current_human_revokes_an_older_genuine_session(enrolled_owner):  # noqa: F811
    owner = enrolled_owner
    older = context(owner)
    login_again(owner)
    current = context(owner)
    page = owner.client.get("/api/v1/auth/sessions?limit=1", headers=owner.headers)
    assert page.status_code == 200
    pages = [page.json()]
    while pages[-1]["next_cursor"] is not None:
        response = owner.client.get(
            "/api/v1/auth/sessions",
            headers=owner.headers,
            params={"limit": 1, "cursor": pages[-1]["next_cursor"]},
        )
        assert response.status_code == 200
        pages.append(response.json())
    identities = {item["session_id"] for page in pages for item in page["items"]}
    if identities != {older["session"]["session_id"], current["session"]["session_id"]}:
        pytest.fail("Paged inventory must include both genuinely issued sessions exactly once")
    command = {
        "schema_version": 1,
        "idempotency_key": "revoke-older",
        "target_session_id": older["session"]["session_id"],
        "expected_security_version": older["session"]["security_version"],
    }
    response = owner.client.post(
        "/api/v1/auth/sessions/revoke", headers=owner.headers, json=command
    )
    assert response.status_code == 200
    replay = owner.client.post("/api/v1/auth/sessions/revoke", headers=owner.headers, json=command)
    assert replay.status_code == 200
    if replay.json() != response.json():
        pytest.fail("An unchanged session command must replay the retained receipt")
    assert owner.client.get("/api/v1/auth/context", headers=owner.headers).status_code == 200


@pytest.mark.parametrize(
    "change", ["origin", "missing-origin", "missing-cookie", "unexpected-body"]
)
def test_context_bootstrap_rejects_invalid_boundary_without_effect(enrolled_owner, change):  # noqa: F811
    owner = enrolled_owner
    current = context(owner)
    with transaction(owner.engine) as db:
        old = db.get(BrowserSession, current["session"]["session_id"])
        before = (old.csrf_hash, old.last_activity, old.absolute_deadline)
    headers = {"Origin": owner.headers["Origin"]}
    payload = {}
    if change == "origin":
        headers["Origin"] = "https://untrusted.test"
    if change == "missing-origin":
        headers = {}
    if change == "missing-cookie":
        owner.client.cookies.clear()
    if change == "unexpected-body":
        payload = {"grant": "project.create"}
    response = owner.client.post("/api/v1/auth/context/bootstrap", headers=headers, json=payload)
    assert response.status_code == (422 if change == "unexpected-body" else 401)
    with transaction(owner.engine) as db:
        row = db.get(BrowserSession, current["session"]["session_id"])
        if (row.csrf_hash, row.last_activity, row.absolute_deadline) != before:
            pytest.fail("Rejected context bootstrap must not alter authentication or deadlines")


@pytest.mark.parametrize("change", ["revoked", "disabled", "epoch", "expired"])
def test_context_rechecks_current_authority(enrolled_owner, change, monkeypatch):  # noqa: F811
    owner = enrolled_owner
    current = context(owner)
    with transaction(owner.engine) as db:
        row = db.get(BrowserSession, current["session"]["session_id"])
        principal = db.get(Principal, owner.principal_id)
        if change == "revoked":
            row.revoked = True
        elif change == "disabled":
            # Isolated authority corruption fixture, not a supported Owner-disable producer.
            db.execute(text("DROP TRIGGER preserve_initialized_owner"))
            principal.enabled = False
        elif change == "epoch":
            principal.authorization_epoch += 1
        else:
            deadline = row.absolute_deadline
            monkeypatch.setattr("journeon.sessions.utc_seconds", lambda: deadline)
    assert owner.client.get("/api/v1/auth/context", headers=owner.headers).status_code == 401


@pytest.mark.parametrize(
    "field",
    [
        "credential_revision",
        "authorization_epoch",
        "role",
        "enabled",
        "audience",
        "authentication_method",
        "absolute_deadline",
        "inactivity_seconds",
        "strong_authenticated_at",
        "strong_freshness_seconds",
        "revoked",
        "incarnation",
    ],
)
def test_security_version_binds_security_writers(enrolled_owner, field):  # noqa: F811
    # Isolated metadata mutation checks the digest inputs, not production provisioning.
    owner = enrolled_owner
    current = context(owner)
    with transaction(owner.engine) as db:
        row = db.get(BrowserSession, current["session"]["session_id"])
        principal = db.get(Principal, owner.principal_id)
        incarnation = db.get(StoreIdentity, 1).incarnation
        before = security_version(row, principal, incarnation)
        with db.no_autoflush:
            if field == "incarnation":
                incarnation = "changed-incarnation"
            elif field in {"credential_revision", "authorization_epoch"}:
                setattr(principal, field, getattr(principal, field) + 1)
            elif field == "role":
                principal.role = "SHARED_USER"
            elif field == "enabled":
                principal.enabled = False
            elif field == "audience":
                row.audience = "unknown"
            elif field == "authentication_method":
                row.authentication_method = "changed-method"
            elif field == "revoked":
                row.revoked = True
            else:
                setattr(row, field, getattr(row, field) + 1)
            changed = security_version(row, principal, incarnation)
        db.expire_all()
        assert before != changed


@pytest.mark.parametrize("operation", ["logout", "revoke"])
def test_stale_session_version_cannot_end_current_session(enrolled_owner, operation):  # noqa: F811
    owner = enrolled_owner
    current = context(owner)
    with transaction(owner.engine) as db:
        db.get(Principal, owner.principal_id).credential_revision += 1
    command = {
        "schema_version": 1,
        "idempotency_key": "stale-end",
        "expected_security_version": current["session"]["security_version"],
    }
    if operation == "revoke":
        command["target_session_id"] = current["session"]["session_id"]
    path = "/api/v1/auth/logout" if operation == "logout" else "/api/v1/auth/sessions/revoke"
    assert owner.client.post(path, headers=owner.headers, json=command).status_code == 409
    with transaction(owner.engine) as db:
        assert not db.get(BrowserSession, current["session"]["session_id"]).revoked
        assert (
            db.scalar(
                select(func.count())
                .select_from(Receipt)
                .where(Receipt.idempotency_key == "stale-end")
            )
            == 0
        )


@pytest.mark.parametrize("state", ["absent", "pending", "committed", "different-digest", "restore"])
def test_resolver_reports_only_observed_authorized_state(enrolled_owner, state):  # noqa: F811
    owner = enrolled_owner
    current = context(owner)
    effect = owner.grant("project.create")
    query = resolve_request(
        effect,
        current,
        {
            key: effect[key]
            for key in ("principal_id", "capability", "resource_kind", "resource_id")
        },
    )
    if state == "pending":
        owner.prepare(effect)
    elif state in {"committed", "different-digest", "restore"}:
        official_effect(owner.client, owner.headers, effect)
    if state == "different-digest":
        query["payload_digest"] = "a" * 64
    if state == "restore":
        query["store_incarnation"] = "previous-incarnation"
    response = owner.client.post("/api/v1/operations/resolve", headers=owner.headers, json=query)
    assert response.status_code == (409 if state == "different-digest" else 200)
    if state != "different-digest":
        assert (
            response.json()["status"]
            == {
                "absent": "NOT_OBSERVED",
                "pending": "OBSERVED_PENDING",
                "committed": "OBSERVED_RECEIPT",
                "restore": "RECONCILIATION_REQUIRED",
            }[state]
        )
        assert response.json()["absence_is_final"] is False


def test_denied_resolver_does_not_decode_corrupt_receipt(enrolled_owner):  # noqa: F811
    owner = enrolled_owner
    current = context(owner)
    effect = owner.grant("project.create")
    accepted = official_effect(owner.client, owner.headers, effect)
    query = resolve_request(
        effect,
        current,
        {
            key: effect[key]
            for key in ("principal_id", "capability", "resource_kind", "resource_id")
        },
    )
    with transaction(owner.engine) as db:
        db.execute(text("DROP TRIGGER preserve_initialized_owner"))
        db.get(Principal, owner.principal_id).role = "SHARED_USER"
        db.execute(
            text("UPDATE operation_receipts SET result='invalid-json' WHERE id=:id"),
            {"id": accepted["operation_id"]},
        )
    assert (
        owner.client.post(
            "/api/v1/operations/resolve", headers=owner.headers, json=query
        ).status_code
        == 403
    )


def test_competing_logout_requests_commit_one_receipt(enrolled_owner):  # noqa: F811
    from concurrent.futures import ThreadPoolExecutor

    from fastapi.testclient import TestClient

    owner = enrolled_owner
    current = context(owner)
    command = {
        "schema_version": 1,
        "idempotency_key": "competing-logout",
        "expected_security_version": current["session"]["security_version"],
    }
    clients = [TestClient(owner.client.app, base_url=owner.headers["Origin"]) for _ in range(2)]
    try:
        for client in clients:
            client.cookies.update(owner.client.cookies)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(client.post, "/api/v1/auth/logout", headers=owner.headers, json=command)
                for client in clients
            ]
            statuses = [future.result().status_code for future in futures]
        assert sorted(statuses) == [200, 401]
        with transaction(owner.engine) as db:
            receipts = list(
                db.scalars(
                    select(Receipt).where(
                        Receipt.command == "identity.session.logout.v1",
                        Receipt.idempotency_key == "competing-logout",
                    )
                )
            )
            assert len(receipts) == 1
            assert (
                db.scalar(
                    select(func.count())
                    .select_from(OutboxEvent)
                    .where(OutboxEvent.operation_id == receipts[0].id)
                )
                == 1
            )
            assert db.get(BrowserSession, current["session"]["session_id"]).revoked
    finally:
        for client in clients:
            client.close()
