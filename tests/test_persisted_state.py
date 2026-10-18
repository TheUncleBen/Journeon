# SPDX-License-Identifier: AGPL-3.0-only
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Boolean, func, inspect, select, text
from sqlalchemy.exc import IntegrityError

from journeon.api import authenticated_context, create_app
from journeon.contracts import DomainError
from journeon.database import transaction
from journeon.models import Base, OutboxEvent, Project, Receipt
from journeon.projects import ProjectService

BOOLEAN_DOMAINS = {
    ("browser_sessions", "revoked"): "session_revoked_boolean",
    ("principals", "enabled"): "principal_enabled_boolean",
    ("access_grants", "enabled"): "grant_enabled_boolean",
}


def counts(engine):
    with transaction(engine) as session:
        return tuple(
            session.scalar(select(func.count()).select_from(model))
            for model in (Project, Receipt, OutboxEvent)
        )


def test_every_canonical_boolean_has_a_database_domain_constraint(database):
    booleans = {
        (table.name, column.name)
        for table in Base.metadata.tables.values()
        for column in table.columns
        if isinstance(column.type, Boolean)
    }
    assert booleans == set(BOOLEAN_DOMAINS)
    inspector = inspect(database[0])
    for (table, column), constraint in BOOLEAN_DOMAINS.items():
        checks = {item["name"]: item["sqltext"] for item in inspector.get_check_constraints(table)}
        assert checks[constraint] == f"{column} IN (0, 1)"


@pytest.mark.parametrize("table", ["principals", "access_grants"])
@pytest.mark.parametrize("invalid", [2, -1, 0.5, "true", b"1"])
def test_raw_nonboolean_values_are_rejected_for_all_enabled_columns(database, table, invalid):
    with pytest.raises(IntegrityError), transaction(database[0]) as session:
        session.execute(text(f"UPDATE {table} SET enabled = :invalid"), {"invalid": invalid})
    with transaction(database[0]) as session:
        values = session.execute(text(f"SELECT DISTINCT enabled FROM {table}")).scalars().all()
        assert values == [1]


def test_raw_second_owner_cannot_bypass_partial_index_with_enabled_two(database):
    with pytest.raises(IntegrityError, match="principal_enabled_boolean"):
        with transaction(database[0]) as session:
            session.execute(
                text(
                    "INSERT INTO principals (id, role, enabled, authorization_epoch) "
                    "VALUES ('second-owner', 'OWNER', 2, 1)"
                )
            )
    with transaction(database[0]) as session:
        assert session.scalar(text("SELECT count(*) FROM principals WHERE role='OWNER'")) == 1


MALFORMED_PROVIDER_LISTS = [
    {"provider-a": "private-malformed-policy"},
    "private-malformed-policy",
    None,
    True,
    7,
    ["provider-a", 4],
    [["provider-a"]],
    ["invalid provider id"],
    ["provider-a", "provider-a"],
    "not-json",
]


@pytest.mark.parametrize("stored", MALFORMED_PROVIDER_LISTS)
def test_malformed_policy_returns_sanitized_dependency_error_without_mutation(
    database,
    actor,
    command,
    stored,
):
    engine, _ = database
    encoded = stored if stored == "not-json" else json.dumps(stored)
    with transaction(engine) as session:
        session.execute(
            text("UPDATE deployment_policy SET approved_providers = :value"), {"value": encoded}
        )
        persisted = session.scalar(text("SELECT approved_providers FROM deployment_policy"))
    app = create_app(engine)
    app.dependency_overrides[authenticated_context] = lambda: actor
    with TestClient(app) as client:
        response = client.post("/api/v1/projects", json=command.model_dump())
        assert response.status_code == 503
        assert response.json() == {
            "schema_version": 1,
            "code": "DEPENDENCY_UNAVAILABLE",
            "reason": "Stored operation state requires repair",
        }
    assert counts(engine) == (0, 0, 0)
    with transaction(engine) as session:
        assert session.scalar(text("SELECT approved_providers FROM deployment_policy")) == persisted


@pytest.mark.parametrize(
    "column,value",
    [
        ("revision", "malformed-revision"),
        ("approval_id", "invalid approval identifier"),
        ("verification_policy_ref", "invalid verification identifier"),
    ],
)
def test_other_malformed_required_policy_fields_fail_closed(
    database, actor, command, column, value
):
    engine, _ = database
    with transaction(engine) as session:
        session.execute(text(f"UPDATE deployment_policy SET {column} = :value"), {"value": value})
    with pytest.raises(DomainError) as error:
        ProjectService(engine).create(actor, command)
    assert error.value.code == "DEPENDENCY_UNAVAILABLE"
    assert counts(engine) == (0, 0, 0)


@pytest.mark.parametrize(
    "damage", ["missing_fields", "scalar", "invalid_json", "operation", "project"]
)
def test_damaged_receipt_never_discloses_rewrites_or_duplicates_result(
    database,
    actor,
    command,
    damage,
):
    engine, _ = database
    service = ProjectService(engine)
    accepted = service.create(actor, command)
    result = accepted.model_dump(mode="json")
    if damage == "missing_fields":
        result = {"private-malformed-receipt": True}
    elif damage == "scalar":
        result = "private-malformed-receipt"
    elif damage == "operation":
        result["operation_id"] = "different-operation"
    elif damage == "project":
        result["project"]["project_id"] = "different-project"
    encoded = "not-json" if damage == "invalid_json" else json.dumps(result)
    with transaction(engine) as session:
        session.execute(text("UPDATE operation_receipts SET result = :value"), {"value": encoded})
    app = create_app(engine)
    app.dependency_overrides[authenticated_context] = lambda: actor
    with TestClient(app) as client:
        for response in (
            client.post("/api/v1/projects", json=command.model_dump()),
            client.get(f"/api/v1/operations/{accepted.operation_id}"),
        ):
            assert response.status_code == 503
            assert response.json() == {
                "schema_version": 1,
                "code": "DEPENDENCY_UNAVAILABLE",
                "reason": "Stored operation state requires repair",
            }
    assert counts(engine) == (1, 1, 1)
    with transaction(engine) as session:
        assert session.scalar(text("SELECT result FROM operation_receipts")) == encoded
