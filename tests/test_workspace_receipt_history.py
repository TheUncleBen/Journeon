# SPDX-License-Identifier: AGPL-3.0-only
from test_production_instructions import official_effect
from test_workspace_provisioning import enrolled_owner  # noqa: F401


def test_grant_receipts_survive_later_real_revoke_and_revision(enrolled_owner):  # noqa: F811
    owner = enrolled_owner
    first = official_effect(owner.client, owner.headers, owner.grant("project.create"))
    revoked = official_effect(
        owner.client,
        owner.headers,
        {
            "kind": "permission.grant.revoke.v1",
            "schema_version": 1,
            "idempotency_key": "history-revoke",
            "grant_id": first["grant"]["grant_id"],
            "expected_revision": first["grant"]["revision"],
        },
    )
    replacement = owner.grant("project.create", identity="history-reenable")
    replacement.update(
        expected_revision=revoked["grant"]["revision"], expires_at="2999-01-01T00:00:00+00:00"
    )
    current = official_effect(owner.client, owner.headers, replacement)
    assert current["grant"]["revision"] == 3
    assert current["grant"]["enabled"] is True
    assert current["grant"]["expires_at"] == replacement["expires_at"]
    for historical in (first, revoked, current):
        response = owner.client.get(
            f"/api/v1/operations/{historical['operation_id']}", headers=owner.headers
        )
        assert response.status_code == 200
        assert response.json() == historical
