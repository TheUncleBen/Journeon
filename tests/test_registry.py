# SPDX-License-Identifier: AGPL-3.0-only
import runpy
from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import create_engine

from journeon.api import create_app
from journeon.contracts import ErrorEnvelope
from journeon.registry import COMMANDS, MODULES, PROJECT_CREATE, QUERIES, registry_manifest


def generated_registry():
    generate = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "tools/generate_contracts.py")
    )
    return generate["artifacts"]()


@pytest.mark.parametrize(
    "field,value",
    [
        ("tables", ("principals", "projects")),
        ("backup_class", "UNKNOWN"),
        ("health", "missing_health_check"),
        ("migration", "future_schema"),
        ("permissions", ()),
        ("api_prefixes", ()),
    ],
)
def test_generation_rejects_module_drift(monkeypatch, field, value):
    monkeypatch.setitem(MODULES, "projects", {**MODULES["projects"], field: value})
    with pytest.raises(ValueError):
        generated_registry()


def test_generation_rejects_missing_command(monkeypatch):
    monkeypatch.delitem(COMMANDS, PROJECT_CREATE.name)
    with pytest.raises(ValueError):
        generated_registry()


def test_generation_rejects_command_response_drift(monkeypatch):
    monkeypatch.setitem(
        COMMANDS, PROJECT_CREATE.name, replace(PROJECT_CREATE, result_model=ErrorEnvelope)
    )
    with pytest.raises(ValueError):
        generated_registry()


def test_generation_rejects_unbound_command(monkeypatch):
    monkeypatch.setitem(COMMANDS, "orphan", replace(PROJECT_CREATE, name="orphan"))
    with pytest.raises(ValueError):
        generated_registry()


def test_generation_includes_actual_registry():
    import json

    manifest = json.loads(generated_registry()["registry.json"])
    assert {item["module_id"] for item in manifest["modules"]} == set(MODULES)
    assert {item["name"] for item in manifest["commands"]} == set(COMMANDS)
    assert {item["name"] for item in manifest["authentication"]} == {
        "passkey.begin.v1",
        "passkey.finish.v1",
    }
    assert {item["authentication"] for item in manifest["api_operations"]} == {
        None,
        "passkey.begin.v1",
        "passkey.finish.v1",
    }
    assert {item["operation_id"] for item in manifest["api_operations"]} == {
        "createProject",
        "getOperationReceipt",
        "beginPasskey",
        "finishPasskey",
    }
    engine = create_engine("sqlite://")
    try:
        assert all(item["version"] == create_app(engine).version for item in manifest["modules"])
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "field,value",
    [
        ("owner", "identity"),
        ("permissions", ()),
        ("result_model", ErrorEnvelope),
    ],
)
def test_generation_rejects_query_drift(monkeypatch, field, value):
    name = "operation.receipt.read.v1"
    monkeypatch.setitem(QUERIES, name, {**QUERIES[name], field: value})
    with pytest.raises(ValueError):
        generated_registry()


def test_generation_rejects_unregistered_mutation():
    engine = create_engine("sqlite://")
    try:
        app = create_app(engine)

        @app.post(
            "/api/v1/projects/unregistered",
            operation_id="unregistered",
            openapi_extra={
                "x-journeon-owner": "projects",
                "x-journeon-permissions": ["project.create"],
            },
        )
        def unregistered():
            return {}

        with pytest.raises(ValueError, match="exactly one command or query"):
            registry_manifest(app)
    finally:
        engine.dispose()


def test_generation_rejects_command_input_drift(monkeypatch):
    monkeypatch.setitem(
        COMMANDS, PROJECT_CREATE.name, replace(PROJECT_CREATE, input_model=ErrorEnvelope)
    )
    with pytest.raises(ValueError):
        generated_registry()


def test_generation_rejects_missing_verification_contract(monkeypatch):
    monkeypatch.setitem(COMMANDS, PROJECT_CREATE.name, replace(PROJECT_CREATE, verification=""))
    with pytest.raises(ValueError, match="metadata is incomplete"):
        generated_registry()


def test_generation_rejects_missing_http_methods():
    from fastapi.routing import APIRoute

    engine = create_engine("sqlite://")
    try:
        app = create_app(engine)
        route = next(route for route in app.routes if isinstance(route, APIRoute))
        route.methods = None
        with pytest.raises(ValueError, match="requires an HTTP method"):
            registry_manifest(app)
    finally:
        engine.dispose()


@pytest.fixture
def authentication_app():
    from fastapi.routing import iter_route_contexts

    engine = create_engine("sqlite://")
    app = create_app(engine)
    app.router.routes = [context.original_route for context in iter_route_contexts(app.routes)]
    try:
        yield app
    finally:
        engine.dispose()


@pytest.mark.parametrize("name", ["passkey.begin.v1", "passkey.finish.v1"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("name", "renamed"),
        ("owner", "projects"),
        ("input_model", ErrorEnvelope),
        ("result_model", ErrorEnvelope),
    ],
)
def test_generation_rejects_authentication_definition_drift(monkeypatch, name, field, value):
    from journeon.registry import AUTHENTICATION

    monkeypatch.setitem(AUTHENTICATION, name, replace(AUTHENTICATION[name], **{field: value}))
    with pytest.raises(ValueError, match="Authentication registration"):
        generated_registry()


@pytest.mark.parametrize("name", ["passkey.begin.v1", "passkey.finish.v1"])
def test_generation_rejects_missing_authentication(monkeypatch, name):
    from journeon.registry import AUTHENTICATION

    monkeypatch.delitem(AUTHENTICATION, name)
    with pytest.raises(ValueError, match="Authentication registration"):
        generated_registry()


def test_generation_rejects_orphan_authentication(monkeypatch):
    from journeon.registry import AUTHENTICATION

    monkeypatch.setitem(
        AUTHENTICATION, "orphan", replace(AUTHENTICATION["passkey.begin.v1"], name="orphan")
    )
    with pytest.raises(ValueError, match="must have actual API bindings"):
        generated_registry()


@pytest.mark.parametrize(
    "change",
    ["missing", "duplicate", "method", "owner", "prefix", "permission", "command", "query"],
)
def test_generation_rejects_authentication_route_drift(authentication_app, change):
    from copy import copy

    app = authentication_app
    route = next(
        route for route in app.routes if getattr(route, "operation_id", None) == "beginPasskey"
    )
    if change == "missing":
        app.router.routes.remove(route)
    elif change == "duplicate":
        duplicate = copy(route)
        duplicate.operation_id = "duplicateBegin"
        app.router.routes.append(duplicate)
    elif change == "method":
        route.methods = {"GET"}
    elif change == "owner":
        route.openapi_extra["x-journeon-owner"] = "projects"
    elif change == "prefix":
        route.path = "/api/v1/auth/passkeys-imposter/begin"
    elif change == "permission":
        route.openapi_extra["x-journeon-permissions"] = []
    else:
        route.openapi_extra[f"x-journeon-{change}"] = "project.create.v1"
    with pytest.raises(ValueError):
        registry_manifest(app)


@pytest.mark.parametrize("operation_id", ["createProject", "getOperationReceipt"])
@pytest.mark.parametrize("authentication", [None, "passkey.begin.v1"])
def test_authentication_cannot_waive_ordinary_grants(
    authentication_app, operation_id, authentication
):
    route = next(
        route
        for route in authentication_app.routes
        if getattr(route, "operation_id", None) == operation_id
    )
    del route.openapi_extra["x-journeon-permissions"]
    if authentication:
        route.openapi_extra["x-journeon-authentication"] = authentication
    with pytest.raises(ValueError):
        registry_manifest(authentication_app)


def test_generation_checks_effective_included_prefix():
    from fastapi import FastAPI

    engine = create_engine("sqlite://")
    try:
        app = FastAPI()
        app.include_router(create_app(engine).router, prefix="/moved")
        with pytest.raises(ValueError, match="owning module prefix"):
            registry_manifest(app)
    finally:
        engine.dispose()
