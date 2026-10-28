# SPDX-License-Identifier: AGPL-3.0-only
from html.parser import HTMLParser

import pytest
from test_production_instructions import official_effect
from test_workspace_provisioning import enrolled_owner  # noqa: F401


class ConfirmationFields(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = {}

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        identity = values.get("id")
        if tag == "input" and identity in {"request_id", "request_hash", "nonce"}:
            if identity in self.fields:
                pytest.fail("Confirmation page contains duplicate protected operands")
            self.fields[identity] = values.get("value")


@pytest.mark.parametrize("kind", ["grant_set", "grant_revoke", "policy_initialize"])
def test_real_owner_can_open_administration_confirmation(enrolled_owner, kind):  # noqa: F811
    owner = enrolled_owner
    effect = owner.grant("project.create")
    if kind == "grant_revoke":
        committed = official_effect(owner.client, owner.headers, effect)
        effect = {
            "kind": "permission.grant.revoke.v1",
            "schema_version": 1,
            "idempotency_key": "surface-revoke",
            "grant_id": committed["grant"]["grant_id"],
            "expected_revision": committed["grant"]["revision"],
        }
    elif kind == "policy_initialize":
        effect = {
            "kind": "egress.policy.initialize.v1",
            "schema_version": 1,
            "idempotency_key": "surface-policy",
            "expected_revision": 0,
            "provider_mode": "LOCAL_ONLY",
        }
    prepared = owner.prepare(effect)
    try:
        page = owner.client.get(
            "/instructions/confirmation/" + prepared["request_id"], headers=owner.headers
        )
    except KeyError:
        pytest.fail("Official confirmation page cannot describe the prepared administration effect")
    assert page.status_code == 200
    if effect["kind"] not in page.text:
        pytest.fail("Official confirmation page must disclose the exact prepared effect")
    parsed = ConfirmationFields()
    parsed.feed(page.text)
    if set(parsed.fields) != {"request_id", "request_hash", "nonce"}:
        pytest.fail("Confirmation page must contain one complete exact preview")
    confirmed = owner.client.post(
        "/api/v1/protected-operations/confirm", headers=owner.headers, json=parsed.fields
    )
    assert confirmed.status_code == 200
