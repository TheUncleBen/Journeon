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
    assert {item["operation_id"] for item in manifest["api_operations"]} == {
        "createProject",
        "getOperationReceipt",
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
