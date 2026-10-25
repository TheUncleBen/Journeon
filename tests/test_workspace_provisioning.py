# SPDX-License-Identifier: AGPL-3.0-only
import json
from dataclasses import dataclass, field

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from test_passkeys import Authenticator
from test_production_instructions import official_effect

from journeon.api import create_app
from journeon.browser_auth import BrowserAuth
from journeon.database import create_database, transaction
from journeon.instruction_config import InstructionConfiguration
from journeon.migrate import upgrade
from journeon.models import AccessGrant, DeploymentPolicy, OutboxEvent, Principal, Receipt
from journeon.passkeys import STANDARD_PASSKEY_POLICY, PasskeyService


@dataclass(repr=False)
class EnrolledOwner:
    engine: object
    client: TestClient
    headers: dict[str, str] = field(repr=False)
    principal_id: str
    authenticator: Authenticator = field(repr=False)

    def grant(self, capability, *, project_id=None, identity=None):
        return {
            "kind": "permission.grant.set.v1",
            "schema_version": 1,
            "idempotency_key": identity or capability,
            "expected_revision": 0,
            "principal_id": self.principal_id,
            "capability": capability,
            "resource_kind": "project" if project_id else "deployment",
            "resource_id": project_id or "deployment",
            "enabled": True,
            "expires_at": None,
        }

    def prepare(self, effect):
        response = self.client.post(
            "/api/v1/protected-operations/prepare",
            headers=self.headers,
            json={"effect": effect},
        )
        assert response.status_code == 200
        return response.json()

    def preview(self, request):
        response = self.client.post(
            "/api/v1/protected-operations/preview", headers=self.headers, json=request
        )
        assert response.status_code == 200
        return response.json()


def grant_count(engine):
    with transaction(engine) as db:
        return db.scalar(select(func.count()).select_from(AccessGrant))


@pytest.fixture
def enrolled_owner(tmp_path):
    engine = create_database(tmp_path / "provisioning.db")
    upgrade(engine)
    configuration = InstructionConfiguration(
        roots=[], protected_request_seconds=101, protected_preview_seconds=37
    )
    passkeys = PasskeyService(
        engine,
        rp_id="example.test",
        origin="https://example.test",
        policy=STANDARD_PASSKEY_POLICY,
    )
    client = TestClient(
        create_app(
            engine,
            browser_auth=BrowserAuth(passkeys.origin),
            passkeys=passkeys,
            instructions=configuration,
        ),
        base_url=passkeys.origin,
    )
    try:
        enrollment = passkeys.prepare_bootstrap()
        authenticator = Authenticator()
        headers = {"Origin": passkeys.origin}
        begun = client.post(
            "/api/v1/auth/passkeys/begin",
            headers=headers,
            json={
                "purpose": "bootstrap",
                "label": "Provisioning test authenticator",
                "enrollment_secret": enrollment.secret,
            },
        )
        assert begun.status_code == 200
        challenge = begun.json()
        registration = authenticator.register(json.loads(challenge["options_json"]))
        finished = client.post(
            "/api/v1/auth/passkeys/finish",
            headers=headers,
            json={
                "purpose": "bootstrap",
                "ceremony_id": challenge["ceremony_id"],
                "credential_json": json.dumps(registration),
            },
        )
        assert finished.status_code == 200
        headers["X-CSRF-Token"] = finished.json()["csrf_token"]
        principal_id = authenticator.user_handle.decode()
        with transaction(engine) as db:
            assert db.get(Principal, principal_id).role == "OWNER"
            assert db.scalar(select(func.count()).select_from(Principal)) == 1
            assert db.scalar(select(func.count()).select_from(AccessGrant)) == 0
            assert db.get(DeploymentPolicy, 1) is None
        yield EnrolledOwner(engine, client, headers, principal_id, authenticator)
    finally:
        client.close()
        engine.dispose()


def test_fresh_owner_can_provision_one_explicit_grant_with_confirmation(enrolled_owner):
    owner = enrolled_owner
    effect = owner.grant("project.create")
    request = owner.prepare(effect)
    assert grant_count(owner.engine) == 0
    preview = owner.preview(request)
    assert preview["effect"] == effect
    assert grant_count(owner.engine) == 0
    confirmation = {key: preview[key] for key in ("request_id", "request_hash", "nonce")}
    result = owner.client.post(
        "/api/v1/protected-operations/confirm", headers=owner.headers, json=confirmation
    )
    assert result.status_code == 200
    receipt = result.json()
    with transaction(owner.engine) as db:
        grants = list(db.scalars(select(AccessGrant)))
        assert len(grants) == 1
        assert grants[0].principal_id == owner.principal_id
        assert grants[0].capability == "project.create"
        assert (grants[0].resource_kind, grants[0].resource_id) == ("deployment", "deployment")
        assert db.get(Receipt, receipt["operation_id"]) is not None
        events = list(
            db.scalars(
                select(OutboxEvent).where(OutboxEvent.operation_id == receipt["operation_id"])
            )
        )
        assert len(events) == 1
    repeated = owner.client.post(
        "/api/v1/protected-operations/confirm", headers=owner.headers, json=confirmation
    )
    assert repeated.status_code == 200
    assert repeated.json() == receipt
    assert grant_count(owner.engine) == 1


def test_fresh_owner_can_create_project_after_explicit_local_provisioning(enrolled_owner):
    owner = enrolled_owner
    for capability in ("project.create", "project.receipt.read"):
        official_effect(owner.client, owner.headers, owner.grant(capability))
    official_effect(
        owner.client,
        owner.headers,
        {
            "kind": "egress.policy.initialize.v1",
            "schema_version": 1,
            "idempotency_key": "initial-local-policy",
            "expected_revision": 0,
            "provider_mode": "LOCAL_ONLY",
        },
    )
    policy_response = owner.client.get("/api/v1/egress/policy", headers=owner.headers)
    assert policy_response.status_code == 200
    policy = policy_response.json()
    assert policy["approved_providers"] == []
    created = owner.client.post(
        "/api/v1/projects",
        headers=owner.headers,
        json={
            "schema_version": 1,
            "idempotency_key": "first-project",
            "name": "Local workspace",
            "expected_policy_revision": policy["revision"],
            "provider_mode": "LOCAL_ONLY",
        },
    )
    assert created.status_code == 200
    project = created.json()["project"]
    assert project["provider_allowance_at_creation"]["providers"] == []
    denied = owner.client.get(f"/api/v1/projects/{project['project_id']}", headers=owner.headers)
    assert denied.status_code == 403
    official_effect(
        owner.client,
        owner.headers,
        owner.grant("project.read", project_id=project["project_id"]),
    )
    readable = owner.client.get(f"/api/v1/projects/{project['project_id']}", headers=owner.headers)
    assert readable.status_code == 200
    assert readable.json()["project_id"] == project["project_id"]
    assert grant_count(owner.engine) == 3


@pytest.mark.parametrize("changed", ["request_hash", "nonce"])
def test_new_grant_effect_rejects_changed_confirmation(enrolled_owner, changed):
    owner = enrolled_owner
    request = owner.prepare(owner.grant("project.create"))
    preview = owner.preview(request)
    confirmation = {key: preview[key] for key in ("request_id", "request_hash", "nonce")}
    confirmation[changed] = "a" * (64 if changed == "request_hash" else 43)
    if confirmation[changed] == preview[changed]:
        confirmation[changed] = "b" * len(confirmation[changed])
    result = owner.client.post(
        "/api/v1/protected-operations/confirm", headers=owner.headers, json=confirmation
    )
    assert result.status_code == 403
    assert grant_count(owner.engine) == 0


def test_new_grant_effect_cancellation_cannot_install_permission(enrolled_owner):
    owner = enrolled_owner
    request = owner.prepare(owner.grant("project.create"))
    preview = owner.preview(request)
    cancelled = owner.client.post(
        "/api/v1/protected-operations/cancel", headers=owner.headers, json=request
    )
    assert cancelled.status_code == 200
    result = owner.client.post(
        "/api/v1/protected-operations/confirm",
        headers=owner.headers,
        json={key: preview[key] for key in ("request_id", "request_hash", "nonce")},
    )
    assert result.status_code == 403
    assert grant_count(owner.engine) == 0
