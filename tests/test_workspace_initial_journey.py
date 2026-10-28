# SPDX-License-Identifier: AGPL-3.0-only
import json
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from test_enrollment_delivery import empty_store, invoke  # noqa: F401
from test_passkeys import Authenticator
from test_workspace_confirmation_surface import ConfirmationFields
from test_workspace_provisioning import EnrolledOwner, grant_count

from journeon.api import create_app
from journeon.browser_auth import BrowserAuth
from journeon.database import transaction
from journeon.instruction_config import InstructionConfiguration
from journeon.models import DeploymentPolicy, Principal
from journeon.passkeys import STANDARD_PASSKEY_POLICY, PasskeyService


def test_protected_cli_to_real_owner_official_consent_and_first_project(
    empty_store,  # noqa: F811
    monkeypatch,
    capsys,
):
    engine, path = empty_store
    reader, writer = os.pipe()
    try:
        assert invoke(monkeypatch, path, writer) == 0
        os.set_blocking(reader, False)
        secret = os.read(reader, 128).decode().strip()
        if len(secret) != 43:
            pytest.fail("Integrated enrollment did not receive its protected secret")
        captured = capsys.readouterr()
        if secret in captured.out or secret in captured.err:
            pytest.fail("Integrated enrollment disclosed its protected secret")
    finally:
        os.close(reader)
        os.close(writer)
    passkeys = PasskeyService(
        engine,
        rp_id="example.test",
        origin="https://example.test",
        policy=STANDARD_PASSKEY_POLICY,
    )
    instructions = InstructionConfiguration(
        roots=[], protected_request_seconds=101, protected_preview_seconds=37
    )
    # HTTP production chain with synthetic WebAuthn cryptography; no hardware/browser claim.
    with TestClient(
        create_app(
            engine,
            browser_auth=BrowserAuth(passkeys.origin),
            passkeys=passkeys,
            instructions=instructions,
        ),
        base_url=passkeys.origin,
    ) as client:
        authenticator = Authenticator()
        headers = {"Origin": passkeys.origin}
        begun = client.post(
            "/api/v1/auth/passkeys/begin",
            headers=headers,
            json={
                "purpose": "bootstrap",
                "label": "Integrated enrollment authenticator",
                "enrollment_secret": secret,
            },
        )
        assert begun.status_code == 200
        challenge = begun.json()
        finished = client.post(
            "/api/v1/auth/passkeys/finish",
            headers=headers,
            json={
                "purpose": "bootstrap",
                "ceremony_id": challenge["ceremony_id"],
                "credential_json": json.dumps(
                    authenticator.register(json.loads(challenge["options_json"]))
                ),
            },
        )
        assert finished.status_code == 200
        headers["X-CSRF-Token"] = finished.json()["csrf_token"]
        owner = EnrolledOwner(
            engine, client, headers, authenticator.user_handle.decode(), authenticator
        )
        with transaction(engine) as db:
            assert db.scalar(select(func.count()).select_from(Principal)) == 1
            assert db.get(Principal, owner.principal_id).role == "OWNER"
            assert db.get(DeploymentPolicy, 1) is None
        assert grant_count(engine) == 0

        def confirm_page(effect):
            prepared = owner.prepare(effect)
            page = client.get(
                "/instructions/confirmation/" + prepared["request_id"], headers=headers
            )
            assert page.status_code == 200
            parsed = ConfirmationFields()
            parsed.feed(page.text)
            if set(parsed.fields) != {"request_id", "request_hash", "nonce"}:
                pytest.fail("Integrated confirmation page lacks its exact preview")
            response = client.post(
                "/api/v1/protected-operations/confirm", headers=headers, json=parsed.fields
            )
            assert response.status_code == 200
            return response.json()

        for capability in ("project.create", "project.receipt.read"):
            confirm_page(owner.grant(capability))
        policy = confirm_page(
            {
                "kind": "egress.policy.initialize.v1",
                "schema_version": 1,
                "idempotency_key": "integrated-local-policy",
                "expected_revision": 0,
                "provider_mode": "LOCAL_ONLY",
            }
        )["policy"]
        created = client.post(
            "/api/v1/projects",
            headers=headers,
            json={
                "schema_version": 1,
                "idempotency_key": "integrated-first-project",
                "name": "Integrated local project",
                "expected_policy_revision": policy["revision"],
                "provider_mode": "LOCAL_ONLY",
            },
        )
        assert created.status_code == 200
        project = created.json()["project"]
        assert project["provider_allowance_at_creation"]["providers"] == []
        route = "/api/v1/projects/" + project["project_id"]
        assert client.get(route, headers=headers).status_code == 403
        confirm_page(owner.grant("project.read", project_id=project["project_id"]))
        readable = client.get(route, headers=headers)
        assert readable.status_code == 200
        assert readable.json()["project_id"] == project["project_id"]
        assert grant_count(engine) == 3
