# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from sqlalchemy import func, select, text
from test_workspace_identity_security import login_again
from test_workspace_provisioning import enrolled_owner  # noqa: F401
from test_workspace_session_controls import context

from journeon.database import transaction
from journeon.models import (
    BrowserSession,
    IdentityState,
    Principal,
    ProtectedRequest,
    Receipt,
    StoreIdentity,
)


@pytest.fixture
def isolated_cross_principal_request(enrolled_owner):  # noqa: F811
    owner = enrolled_owner
    original = context(owner)
    login_again(owner)
    # Negative-only isolated target ownership fixture. It does not qualify Shared onboarding.
    with transaction(owner.engine) as db:
        db.add(
            Principal(
                id="isolated-shared",
                role="SHARED_USER",
                enabled=True,
                authorization_epoch=1,
                credential_revision=1,
            )
        )
        db.flush()
        old = db.get(BrowserSession, original["session"]["session_id"])
        old.principal_id = "isolated-shared"
    page = owner.client.get("/api/v1/auth/sessions?limit=100", headers=owner.headers)
    assert page.status_code == 200
    target = next(
        item for item in page.json()["items"] if item["principal_id"] == "isolated-shared"
    )
    effect = {
        "kind": "identity.session.revoke.v1",
        "schema_version": 1,
        "idempotency_key": "isolated-cross-revoke",
        "target_session_id": target["session_id"],
        "expected_security_version": target["security_version"],
    }
    preview = owner.preview(owner.prepare(effect))
    exact = {key: preview[key] for key in ("request_id", "request_hash", "nonce")}
    return owner, effect, exact


@pytest.mark.parametrize(
    "change",
    [
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
        "shared",
    ],
)
def test_cross_session_confirmation_rechecks_authority_before_corrupt_payload(
    isolated_cross_principal_request,
    change,
    monkeypatch,
):
    owner, effect, exact = isolated_cross_principal_request
    with transaction(owner.engine) as db:
        pending = db.get(ProtectedRequest, exact["request_id"])
        row = db.get(BrowserSession, pending.session_id)
        principal = db.get(Principal, owner.principal_id)
        if change == "nonofficial":
            row.audience = "unknown"
            row.client_label = "Official browser"
        elif change == "no-strong":
            row.strong_authenticated_at = None
        elif change == "stale-strong":
            expired = row.strong_authenticated_at + row.strong_freshness_seconds
            monkeypatch.setattr("journeon.sessions.utc_seconds", lambda: expired)
        elif change == "revoked":
            row.revoked = True
        elif change == "epoch":
            principal.authorization_epoch += 1
        elif change == "credential":
            principal.credential_revision += 1
        elif change == "policy":
            state = db.get(IdentityState, 1)
            state.rate_policy = {**state.rate_policy, "starts_per_window": 1}
        elif change == "incarnation":
            db.get(StoreIdentity, 1).incarnation = "other-incarnation"
        elif change == "cancelled":
            pending.state = "CANCELLED"
        elif change == "expired":
            pending.nonce_deadline = 0
        elif change == "wrong-nonce":
            exact["nonce"] = "x" * 43
        elif change == "shared":
            db.execute(text("DROP TRIGGER preserve_initialized_owner"))
            principal.role = "SHARED_USER"
        if change not in {"expired", "wrong-nonce"}:
            db.execute(
                text("UPDATE protected_requests SET payload='invalid-json' WHERE id=:id"),
                {"id": pending.id},
            )
    response = owner.client.post(
        "/api/v1/protected-operations/confirm",
        headers={**owner.headers, "X-Official-Client": "true"},
        json=exact,
    )
    assert response.status_code in {401, 403}
    with transaction(owner.engine) as db:
        assert not db.get(BrowserSession, effect["target_session_id"]).revoked
        assert (
            db.scalar(
                select(func.count()).select_from(Receipt).where(Receipt.command == effect["kind"])
            )
            == 0
        )


@pytest.mark.parametrize("change", ["target", "version", "key", "missing-confirmation"])
def test_cross_session_route_rejects_changed_exact_operands(
    isolated_cross_principal_request, change
):
    owner, effect, exact = isolated_cross_principal_request
    payload = {**effect, **exact}
    if change == "target":
        payload["target_session_id"] = "unavailable-target"
    elif change == "version":
        payload["expected_security_version"] = "a" * 64
    elif change == "key":
        payload["idempotency_key"] = "changed-key"
    else:
        payload = effect
    response = owner.client.post(
        "/api/v1/auth/sessions/revoke", headers=owner.headers, json=payload
    )
    assert response.status_code in {403, 404}
    with transaction(owner.engine) as db:
        assert not db.get(BrowserSession, effect["target_session_id"]).revoked
