# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from sqlalchemy import text
from test_production_instructions import official_effect
from test_workspace_administration import prepared_administration  # noqa: F401
from test_workspace_provisioning import enrolled_owner  # noqa: F401

from journeon.database import transaction
from journeon.models import Principal, Receipt


def policy_effect():
    return {
        "kind": "egress.policy.initialize.v1",
        "schema_version": 1,
        "idempotency_key": "receipt-integrity-policy",
        "expected_revision": 0,
        "provider_mode": "LOCAL_ONLY",
    }


def fetch(owner, operation_id):
    return owner.client.get(f"/api/v1/operations/{operation_id}", headers=owner.headers)


@pytest.mark.parametrize("change", ["unconfigured", "revision", "approval", "providers"])
def test_committed_policy_receipt_rejects_impossible_initialized_result(
    enrolled_owner,  # noqa: F811
    change,
):
    owner = enrolled_owner
    accepted = official_effect(owner.client, owner.headers, policy_effect())
    assert fetch(owner, accepted["operation_id"]).status_code == 200
    with transaction(owner.engine) as db:
        row = db.get(Receipt, accepted["operation_id"])
        result = dict(row.result)
        policy = dict(result["policy"])
        if change == "unconfigured":
            policy.update(status="UNCONFIGURED", revision=0, approval_id=None, approved_by=None)
        elif change == "revision":
            policy["revision"] += 1
        elif change == "approval":
            policy["approval_id"] = "different-operation"
        else:
            policy["approved_providers"] = ["unapproved-provider"]
        row.result = {**result, "policy": policy}
    assert fetch(owner, accepted["operation_id"]).status_code == 503


@pytest.mark.parametrize("kind", ["set", "revoke"])
@pytest.mark.parametrize(
    "field", ["capability", "resource_id", "principal_id", "revision", "provenance", "enabled"]
)
def test_committed_grant_receipt_binds_original_effect_operands(
    enrolled_owner,  # noqa: F811
    kind,
    field,
):
    owner = enrolled_owner
    accepted = official_effect(owner.client, owner.headers, owner.grant("project.create"))
    if kind == "revoke":
        accepted = official_effect(
            owner.client,
            owner.headers,
            {
                "kind": "permission.grant.revoke.v1",
                "schema_version": 1,
                "idempotency_key": "receipt-integrity-revoke",
                "grant_id": accepted["grant"]["grant_id"],
                "expected_revision": accepted["grant"]["revision"],
            },
        )
    assert fetch(owner, accepted["operation_id"]).status_code == 200
    with transaction(owner.engine) as db:
        row = db.get(Receipt, accepted["operation_id"])
        result = dict(row.result)
        grant = dict(result["grant"])
        if field == "revision":
            grant[field] += 1
        elif field == "enabled":
            grant[field] = not grant[field]
        elif field == "capability":
            grant[field] = "project.read"
        else:
            grant[field] = "different-value"
        row.result = {**result, "grant": grant}
    assert fetch(owner, accepted["operation_id"]).status_code == 503


@pytest.mark.parametrize("field", ["payload_hash", "idempotency_key"])
def test_administration_receipt_metadata_matches_accepted_confirmation(
    prepared_administration,  # noqa: F811
    field,
):
    owner, effect, exact, path = prepared_administration
    response = owner.client.post(path, headers=owner.headers, json={**effect, **exact})
    assert response.status_code == 200
    operation_id = response.json()["operation_id"]
    assert fetch(owner, operation_id).status_code == 200
    with transaction(owner.engine) as db:
        row = db.get(Receipt, operation_id)
        value = "different-key" if field == "idempotency_key" else "0" * 64
        if getattr(row, field) == value:
            value = "1" * 64
        setattr(row, field, value)
    assert fetch(owner, operation_id).status_code == 503


@pytest.mark.parametrize("denial", ["owner", "principal"])
def test_administration_receipt_authorizes_before_corrupt_json(
    prepared_administration,  # noqa: F811
    denial,
):
    owner, effect, exact, path = prepared_administration
    response = owner.client.post(path, headers=owner.headers, json={**effect, **exact})
    assert response.status_code == 200
    operation_id = response.json()["operation_id"]
    with transaction(owner.engine) as db:
        # Isolated negative fixture; no fixture authority participates in the positive producer.
        if denial == "owner":
            db.execute(text("DROP TRIGGER preserve_initialized_owner"))
            db.get(Principal, owner.principal_id).role = "SHARED_USER"
        else:
            db.add(
                Principal(
                    id="other-principal",
                    role="SHARED_USER",
                    enabled=True,
                    authorization_epoch=1,
                    credential_revision=1,
                )
            )
            db.flush()
            db.get(Receipt, operation_id).principal_id = "other-principal"
        db.execute(
            text("UPDATE operation_receipts SET result='invalid-json' WHERE id=:id"),
            {"id": operation_id},
        )
    assert fetch(owner, operation_id).status_code == (403 if denial == "owner" else 404)
