# SPDX-License-Identifier: AGPL-3.0-only
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import text

from journeon.api import authenticated_context, create_app
from journeon.contracts import DomainError, ProjectCreate
from journeon.database import transaction
from journeon.health import schema_and_database
from journeon.models import AccessGrant, Principal
from journeon.projects import ProjectService


@pytest.mark.parametrize("version", [True, 1.0, "1"])
def test_schema_version_is_a_strict_integer(command, version):
    with pytest.raises(ValidationError):
        ProjectCreate.model_validate({**command.model_dump(), "schema_version": version})


def test_exact_project_receipt_grant_does_not_authorize_new_creation(database, actor, command):
    engine, _ = database
    service = ProjectService(engine)
    accepted = service.create(actor, command)
    with transaction(engine) as session:
        grant = session.get(AccessGrant, "project.receipt.read")
        grant.resource_kind = "project"
        grant.resource_id = accepted.project.project_id
    assert service.receipt(actor, accepted.operation_id) == accepted
    assert service.create(actor, command) == accepted
    with pytest.raises(DomainError):
        service.create(actor, command.model_copy(update={"idempotency_key": "next-project"}))
    with transaction(engine) as session:
        session.get(AccessGrant, "project.receipt.read").resource_id = "wrong-project"
    with pytest.raises(DomainError):
        service.receipt(actor, accepted.operation_id)


@pytest.mark.parametrize("corrupt_receipt", [False, True])
def test_owner_transfer_does_not_disclose_original_actor_receipts(
    database, actor, command, corrupt_receipt
):
    engine, _ = database
    accepted = ProjectService(engine).create(actor, command)
    with transaction(engine) as session:
        if corrupt_receipt:
            session.execute(text("UPDATE operation_receipts SET result = '{'"))
        session.get(Principal, actor.principal_id).enabled = False
        session.flush()
        session.get(Principal, "viewer-test").role = "OWNER"
        session.add(
            AccessGrant(
                id="new-owner-receipt",
                principal_id="viewer-test",
                capability="project.receipt.read",
                resource_kind="deployment",
                resource_id="deployment",
                enabled=True,
                revision=1,
                expires_at=None,
                provenance="synthetic-test-grant",
            )
        )
    new_actor = replace(actor, principal_id="viewer-test")
    with pytest.raises(DomainError) as error:
        ProjectService(engine).receipt(new_actor, accepted.operation_id)
    assert error.value.code == "NOT_FOUND"


@pytest.mark.parametrize("entry_point", ["lookup", "retry"])
@pytest.mark.parametrize("grant_state", ["revoked", "wrong_project", "expired"])
def test_receipt_denial_precedes_result_decoding(
    database, actor, command, entry_point, grant_state
):
    engine, _ = database
    service = ProjectService(engine)
    accepted = service.create(actor, command)
    with transaction(engine) as session:
        grant = session.get(AccessGrant, "project.receipt.read")
        if grant_state == "revoked":
            grant.enabled = False
        elif grant_state == "wrong_project":
            grant.resource_kind = "project"
            grant.resource_id = "other-project"
        else:
            grant.expires_at = "2000-01-01T00:00:00+00:00"

    for corrupt_receipt in (False, True):
        if corrupt_receipt:
            with transaction(engine) as session:
                session.execute(text("UPDATE operation_receipts SET result = '{'"))
        with pytest.raises(DomainError) as error:
            if entry_point == "lookup":
                service.receipt(actor, accepted.operation_id)
            else:
                service.create(actor, command)
        assert error.value.code == "PERMISSION_DENIED"


@pytest.mark.parametrize("head", ["future_schema", None])
def test_incompatible_schema_denies_mutation_replay_and_receipt(database, actor, command, head):
    engine, _ = database
    service = ProjectService(engine)
    accepted = service.create(actor, command)
    with transaction(engine) as session:
        session.execute(text("DELETE FROM alembic_version"))
        if head:
            session.execute(text("INSERT INTO alembic_version VALUES (:head)"), {"head": head})
    assert schema_and_database(engine).schema_state == "MISSING_OR_INCOMPATIBLE"
    next_command = command.model_copy(update={"idempotency_key": "next-project"})
    for operation in (
        lambda: service.create(actor, command),
        lambda: service.create(actor, next_command),
        lambda: service.receipt(actor, accepted.operation_id),
    ):
        with pytest.raises(DomainError) as error:
            operation()
        assert error.value.code == "DEPENDENCY_UNAVAILABLE"


def test_unsupported_version_has_stable_compatibility_error(database, actor, command):
    app = create_app(database[0])
    app.dependency_overrides[authenticated_context] = lambda: actor
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/projects", json={**command.model_dump(), "schema_version": 2}
        )
        assert response.status_code == 422
        assert response.json()["code"] == "SCHEMA_UNSUPPORTED"
