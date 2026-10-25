# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from sqlalchemy import select, text
from test_production_instructions import official_effect
from test_workspace_provisioning import enrolled_owner  # noqa: F401

from journeon.database import transaction
from journeon.models import (
    AccessGrant,
    BrowserSession,
    DeploymentPolicy,
    IdentityState,
    Principal,
    ProtectedRequest,
    Receipt,
    StoreIdentity,
)


@pytest.fixture(params=["set", "revoke", "policy"])
def prepared_administration(enrolled_owner, request):  # noqa: F811
    owner = enrolled_owner
    if request.param == "set":
        effect = owner.grant("project.create", identity="pending-set")
        path = "/api/v1/permissions/grants/set"
    elif request.param == "revoke":
        accepted = official_effect(owner.client, owner.headers, owner.grant("project.create"))
        effect = {
            "kind": "permission.grant.revoke.v1",
            "schema_version": 1,
            "idempotency_key": "pending-revoke",
            "grant_id": accepted["grant"]["grant_id"],
            "expected_revision": accepted["grant"]["revision"],
        }
        path = "/api/v1/permissions/grants/revoke"
    else:
        effect = {
            "kind": "egress.policy.initialize.v1",
            "schema_version": 1,
            "idempotency_key": "pending-policy",
            "expected_revision": 0,
            "provider_mode": "LOCAL_ONLY",
        }
        path = "/api/v1/egress/policy/initialize"
    preview = owner.preview(owner.prepare(effect))
    exact = {key: preview[key] for key in ("request_id", "request_hash", "nonce")}
    return owner, effect, exact, path


def retained_effect_state(owner):
    with transaction(owner.engine) as db:
        return (
            list(db.execute(select(AccessGrant.id, AccessGrant.revision, AccessGrant.enabled))),
            list(db.execute(select(DeploymentPolicy.id, DeploymentPolicy.revision))),
            list(db.scalars(select(Receipt.id))),
        )


def test_explicit_administration_routes_commit_and_replay_one_effect(prepared_administration):
    owner, effect, exact, path = prepared_administration
    response = owner.client.post(path, headers=owner.headers, json={**effect, **exact})
    assert response.status_code == 200
    accepted = response.json()
    before = retained_effect_state(owner)
    replay = owner.client.post(path, headers=owner.headers, json={**effect, **exact})
    assert replay.status_code == 200
    assert replay.json() == accepted
    assert retained_effect_state(owner) == before
    receipt = owner.client.get(
        f"/api/v1/operations/{accepted['operation_id']}", headers=owner.headers
    )
    assert receipt.status_code == 200
    assert receipt.json() == accepted
    if effect["kind"] == "permission.grant.revoke.v1":
        assert accepted["grant"]["enabled"] is False
        assert accepted["grant"]["revision"] == effect["expected_revision"] + 1


@pytest.mark.parametrize(
    "change",
    [
        "shared",
        "nonofficial",
        "no-strong",
        "stale-strong",
        "revoked",
        "epoch",
        "credential",
        "policy",
        "incarnation",
        "cancelled",
        "expired",
        "wrong-nonce",
    ],
)
def test_administration_rechecks_authority_before_corrupt_payload(
    prepared_administration, change, monkeypatch
):
    owner, _, exact, _ = prepared_administration
    before = retained_effect_state(owner)
    with transaction(owner.engine) as db:
        row = db.get(ProtectedRequest, exact["request_id"])
        session = db.get(BrowserSession, row.session_id)
        principal = db.get(Principal, row.principal_id)
        if change == "shared":
            # Isolated corruption fixture; initialized Owner protection is otherwise immutable.
            db.execute(text("DROP TRIGGER preserve_initialized_owner"))
            principal.role = "SHARED_USER"
        elif change == "nonofficial":
            session.audience = "unknown"
            session.client_label = "Official browser"
        elif change == "no-strong":
            session.strong_authenticated_at = None
        elif change == "stale-strong":
            expired = session.strong_authenticated_at + session.strong_freshness_seconds
            monkeypatch.setattr("journeon.sessions.utc_seconds", lambda: expired)
        elif change == "revoked":
            session.revoked = True
        elif change == "epoch":
            principal.authorization_epoch += 1
        elif change == "credential":
            principal.credential_revision += 1
        elif change == "policy":
            state = db.get(IdentityState, 1)
            state.rate_policy = {**state.rate_policy, "starts_per_window": 1}
        elif change == "incarnation":
            db.get(StoreIdentity, 1).incarnation = "changed-incarnation"
        elif change == "cancelled":
            row.state = "CANCELLED"
        elif change == "expired":
            row.nonce_deadline = 0
        else:
            exact["nonce"] = "x" * 43
        if change not in {"expired", "wrong-nonce"}:
            db.execute(
                text("UPDATE protected_requests SET payload='invalid-json' WHERE id=:id"),
                {"id": row.id},
            )
    response = owner.client.post(
        "/api/v1/protected-operations/confirm",
        headers={**owner.headers, "X-Official-Client": "true"},
        json=exact,
    )
    assert response.status_code in {401, 403}
    assert retained_effect_state(owner) == before


@pytest.mark.parametrize("field", ["idempotency_key", "expected_revision", "subject", "scope"])
def test_direct_administration_cannot_change_confirmed_operands(prepared_administration, field):
    owner, effect, exact, path = prepared_administration
    changed = dict(effect)
    if field == "idempotency_key":
        changed[field] = "different-key"
    elif field == "expected_revision":
        changed[field] += 1
    elif effect["kind"] == "permission.grant.set.v1":
        changed["principal_id" if field == "subject" else "resource_id"] = "different-target"
    elif effect["kind"] == "permission.grant.revoke.v1":
        changed["grant_id"] = "different-target"
    else:
        changed["provider_mode"] = "APPROVED_PROVIDERS"
    before = retained_effect_state(owner)
    response = owner.client.post(path, headers=owner.headers, json={**changed, **exact})
    assert response.status_code in {403, 422}
    assert retained_effect_state(owner) == before


def test_current_owner_gets_repair_error_for_corrupt_request(prepared_administration):
    owner, _, exact, _ = prepared_administration
    before = retained_effect_state(owner)
    with transaction(owner.engine) as db:
        db.execute(
            text("UPDATE protected_requests SET payload='invalid-json' WHERE id=:id"),
            {"id": exact["request_id"]},
        )
    response = owner.client.post(
        "/api/v1/protected-operations/confirm", headers=owner.headers, json=exact
    )
    assert response.status_code == 503
    assert retained_effect_state(owner) == before


def test_current_target_revision_is_rechecked_before_effect(prepared_administration):
    owner, effect, exact, _ = prepared_administration
    if effect["kind"] == "permission.grant.revoke.v1":
        with transaction(owner.engine) as db:
            row = db.get(AccessGrant, effect["grant_id"])
            replacement = owner.grant(row.capability, identity="changed-revision")
            replacement["expected_revision"] = row.revision
    else:
        replacement = {**effect, "idempotency_key": "changed-revision"}
    official_effect(owner.client, owner.headers, replacement)
    before = retained_effect_state(owner)
    response = owner.client.post(
        "/api/v1/protected-operations/confirm", headers=owner.headers, json=exact
    )
    assert response.status_code == 409
    assert retained_effect_state(owner) == before


def test_grant_catalog_has_real_scopes_and_inventory_rechecks_owner(enrolled_owner):  # noqa: F811
    owner = enrolled_owner
    catalog = owner.client.get("/api/v1/permissions/catalog", headers=owner.headers)
    assert catalog.status_code == 200
    scopes = {row["capability"]: row["resource_kinds"] for row in catalog.json()["capabilities"]}
    assert scopes["project.create"] == ["deployment"]
    assert scopes["project.instruction.read"] == ["project"]
    assert "passkey.self.manage" not in scopes
    assert "operation.receipt.read" not in scopes
    assert catalog.json()["unavailable_new_resource_kinds"] == ["legacy_collection"]
    for capability in ("project.create", "project.receipt.read"):
        official_effect(owner.client, owner.headers, owner.grant(capability))
    first = owner.client.get(
        "/api/v1/permissions/grants", params={"limit": 1}, headers=owner.headers
    )
    assert first.status_code == 200
    assert first.json()["has_more"] is True
    second = owner.client.get(
        "/api/v1/permissions/grants",
        params={"limit": 1, "cursor": first.json()["next_cursor"]},
        headers=owner.headers,
    )
    assert second.status_code == 200
    assert second.json()["has_more"] is False
    assert first.json()["items"][0]["grant_id"] != second.json()["items"][0]["grant_id"]
