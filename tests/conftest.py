# SPDX-License-Identifier: AGPL-3.0-only
from pathlib import Path

import pytest

from journeon.contracts import ProjectCreate
from journeon.database import create_database, transaction
from journeon.migrate import upgrade
from journeon.models import AccessGrant, DeploymentPolicy, Principal
from journeon.permissions import AuthenticatedContext


@pytest.fixture
def database(tmp_path: Path):
    path = tmp_path / "test.db"
    engine = create_database(path)
    upgrade(engine)
    with transaction(engine) as session:
        session.add(Principal(id="owner-test", role="OWNER", enabled=True, authorization_epoch=1))
        session.add(
            Principal(id="viewer-test", role="SHARED_USER", enabled=True, authorization_epoch=1)
        )
        session.flush()
        for capability in ("project.create", "project.receipt.read"):
            session.add(
                AccessGrant(
                    id=capability,
                    principal_id="owner-test",
                    capability=capability,
                    resource_kind="deployment",
                    resource_id="deployment",
                    enabled=True,
                    revision=1,
                    expires_at=None,
                    provenance="synthetic-test-grant",
                )
            )
        session.add(
            DeploymentPolicy(
                id=1,
                revision=1,
                approval_id="synthetic-consent",
                approved_by="owner-test",
                approved_providers=["provider-a", "provider-b"],
                verification_policy_ref=None,
            )
        )
    yield engine, path
    engine.dispose()


@pytest.fixture
def actor():
    return AuthenticatedContext("owner-test", 1, "synthetic-authentication")


@pytest.fixture
def command():
    return ProjectCreate(
        schema_version=1,
        idempotency_key="create-1",
        name="Example project",
        expected_policy_revision=1,
    )
