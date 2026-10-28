# SPDX-License-Identifier: AGPL-3.0-only
import asyncio
import json
import runpy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import journeon.api as api
from journeon.api import authenticated_context, create_app
from journeon.body_limit import MAX_COMMAND_BYTES, BodyLimitMiddleware
from journeon.contracts import OperationReceipt
from journeon.database import transaction
from journeon.models import AccessGrant


def test_api_and_generated_versions_follow_project_metadata(database, tmp_path, monkeypatch):
    (tmp_path / "src" / "journeon").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.0.0.dev2"\n')
    monkeypatch.setattr(api, "__file__", str(tmp_path / "src" / "journeon" / "api.py"))
    assert create_app(database[0]).openapi()["info"]["version"] == "0.0.0.dev2"
    generator = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "tools/generate_contracts.py")
    )
    assert json.loads(generator["artifacts"]()["openapi.json"])["info"]["version"] == "0.0.0.dev2"


def test_production_binding_fails_closed_despite_forged_actor_headers(database, command):
    with TestClient(create_app(database[0])) as client:
        response = client.post(
            "/api/v1/projects",
            json=command.model_dump(),
            headers={
                "Authorization": "Bearer fake",
                "X-Principal-ID": "owner-test",
                "X-Owner": "true",
            },
        )
        assert response.status_code == 401
        assert response.json()["code"] == "AUTHENTICATION_REQUIRED"
        assert client.get("/api/v1/operations/unknown").status_code == 401


def test_fixture_authentication_lives_only_in_test_wiring(database, actor, command):
    app = create_app(database[0])
    app.dependency_overrides[authenticated_context] = lambda: actor
    with TestClient(app) as client:
        response = client.post("/api/v1/projects", json=command.model_dump())
        assert response.status_code == 200
        created = OperationReceipt.model_validate(response.json())
        assert client.get(f"/api/v1/operations/{created.operation_id}").json() == response.json()
        with transaction(database[0]) as session:
            session.get(AccessGrant, "project.receipt.read").enabled = False
        denied = client.get(f"/api/v1/operations/{created.operation_id}")
        assert denied.status_code == 403
        assert created.project.name not in denied.text


@pytest.mark.parametrize("payload", [b"{broken-private-input", b'{"name":"private-input"}'])
def test_validation_errors_do_not_reflect_input_or_validator_details(database, actor, payload):
    app = create_app(database[0])
    app.dependency_overrides[authenticated_context] = lambda: actor
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/projects", content=payload, headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422
        assert response.json() == {
            "schema_version": 1,
            "code": "VALIDATION_FAILED",
            "reason": "Request does not match the operation schema",
        }


def test_body_limit_applies_before_json_or_authentication(database):
    with TestClient(create_app(database[0])) as client:
        response = client.post("/api/v1/projects", content=b"X" * (MAX_COMMAND_BYTES + 1))
        assert response.status_code == 413
        assert response.json()["code"] == "VALIDATION_FAILED"


def test_chunked_body_limit_never_calls_application():
    called = False
    messages = iter(
        [
            {"type": "http.request", "body": b"X" * MAX_COMMAND_BYTES, "more_body": True},
            {"type": "http.request", "body": b"Y", "more_body": False},
        ]
    )
    sent = []

    async def application(scope, receive, send):
        nonlocal called
        called = True

    async def receive():
        return next(messages)

    async def send(message):
        sent.append(message)

    asyncio.run(BodyLimitMiddleware(application)({"type": "http"}, receive, send))
    assert not called
    assert sent[0]["status"] == 413
    assert json.loads(sent[1]["body"])["code"] == "VALIDATION_FAILED"
