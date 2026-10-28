# SPDX-License-Identifier: AGPL-3.0-only
import json
import os
import runpy
import subprocess
from pathlib import Path

import pytest
from test_production_instructions import official_effect
from test_workspace_provisioning import enrolled_owner  # noqa: F401
from test_workspace_session_controls import context

from journeon import contracts, instruction_contracts, job_contracts, restore_contracts
from journeon.contracts import ProjectCreate
from journeon.instructions import digest
from journeon.projects import payload_hash

ROOT = Path(__file__).resolve().parents[1]


def workflow_payload(value):
    from copy import deepcopy

    payload = deepcopy(next(row["payload"] for row in VECTORS if row["model"] == "TaskRevise"))
    payload["workflow"]["steps"] = [
        {"step_id": "condition", "kind": "CONDITION"},
        {
            "step_id": "work",
            "kind": "WORK",
            "dependencies": ["condition"],
            "condition_step": "condition",
            "condition_value": value,
        },
    ]
    return payload


@pytest.mark.parametrize(
    "value",
    [
        -0.0,
        0.0,
        1.0,
        -1.5,
        1e-7,
        1e-6,
        1e-5,
        1e-4,
        1e15,
        1e16,
        1e20,
        1e21,
        5e-324,
        1.7976931348623157e308,
        True,
        False,
        "  café 🧭  ",
    ],
)
def test_generated_nested_numeric_and_union_wire_identity(digest_client, value):
    from journeon.work import payload_hash as task_hash

    result = digest_client(
        [{"helper": "digestTaskRevise", "payload": workflow_payload(value), "wire": True}]
    )[0]
    assert "error" not in result
    normalized = contracts.TaskRevise.model_validate_json(result["wire"])
    assert result["digest"] == task_hash(normalized)


@pytest.mark.parametrize("value", [1, 2**53 - 1, 2**53, 2**60, 1e20])
def test_generated_integer_uses_the_actual_json_wire_token(digest_client, value):
    payload = next(row["payload"] for row in VECTORS if row["model"] == "ProjectCreate").copy()
    payload["expected_policy_revision"] = value
    result = digest_client([{"helper": "digestProjectCreate", "payload": payload, "wire": True}])[0]
    assert "error" not in result
    assert result["digest"] == payload_hash(ProjectCreate.model_validate_json(result["wire"]))


@pytest.mark.parametrize(
    "name",
    [
        "\u0085 café \u0085",
        "\ufeffcafé\ufeff",
        "\u001ccafé\u001c",
        "\u2000café\u3000",
        "café",
        "cafe\u0301",
        "🧭\ue000",
        'a\\b"c\n',
    ],
)
def test_generated_unicode_matches_owner_normalization(digest_client, name):
    payload = next(row["payload"] for row in VECTORS if row["model"] == "ProjectCreate").copy()
    payload["name"] = name
    result = digest_client([{"helper": "digestProjectCreate", "payload": payload, "wire": True}])[0]
    assert "error" not in result
    assert result["digest"] == payload_hash(ProjectCreate.model_validate_json(result["wire"]))


@pytest.mark.parametrize(
    "change",
    [
        {"name": "\ud800"},
        {"name": "\udfff"},
        {"name": 123},
        {"expected_policy_revision": 1.5},
        {"expected_policy_revision": 1e21},
        {"expected_policy_revision": True},
        {"schema_version": True},
        {"schema_version": 2},
        {"unrecognized": "field"},
    ],
)
def test_generated_digest_rejects_nonrepresentable_owner_inputs(digest_client, change):
    payload = next(row["payload"] for row in VECTORS if row["model"] == "ProjectCreate") | change
    result = digest_client([{"helper": "digestProjectCreate", "payload": payload}])[0]
    assert "error" in result
    with pytest.raises(ValueError):
        ProjectCreate.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize("number", ["NaN", "Infinity", "-Infinity"])
def test_generated_digest_rejects_nonfinite_nested_numbers(digest_client, number):
    result = digest_client(
        [{"helper": "digestTaskRevise", "payload": workflow_payload(1), "number": number}]
    )[0]
    assert "error" in result


def test_generated_task_dependency_sort_is_owner_specific(digest_client):
    from journeon.work import payload_hash as task_hash

    payload = next(row["payload"] for row in VECTORS if row["model"] == "TaskCreate").copy()
    payload["dependencies"] = ["z", "a"]
    result = digest_client([{"helper": "digestTaskCreate", "payload": payload, "wire": True}])[0]
    assert result["digest"] == task_hash(contracts.TaskCreate.model_validate_json(result["wire"]))


def test_generated_digest_rejects_sparse_arrays(digest_client):
    payload = next(row["payload"] for row in VECTORS if row["model"] == "TaskCreate").copy()
    payload["dependencies"] = ["a", "b"]
    result = digest_client([{"helper": "digestTaskCreate", "payload": payload, "sparse": True}])[0]
    assert "error" in result


def test_generated_digest_rejects_sparse_nested_arrays(digest_client):
    result = digest_client(
        [{"helper": "digestTaskRevise", "payload": workflow_payload(1), "sparseNested": True}]
    )[0]
    assert "error" in result


@pytest.fixture(scope="session")
def digest_client(tmp_path_factory):
    target = tmp_path_factory.mktemp("client-digests")
    node = os.environ.get("JOURNEON_NODE_BINARY", "node")
    subprocess.run(
        [
            node,
            str(ROOT / "node_modules/typescript/bin/tsc"),
            "--strict",
            "--target",
            "ES2022",
            "--module",
            "NodeNext",
            "--moduleResolution",
            "NodeNext",
            "--outDir",
            str(target),
            str(ROOT / "generated/client.ts"),
        ],
        check=True,
        text=True,
    )

    def run(rows):
        result = subprocess.run(
            [node, str(ROOT / "tests/client-digests.cjs"), str(target / "client.js")],
            input=json.dumps(rows),
            text=True,
            capture_output=True,
            check=True,
        )
        return json.loads(result.stdout)

    return run


def test_generated_project_digest_matches_canonical_owner(digest_client):
    payload = {
        "schema_version": 1,
        "idempotency_key": "original-project",
        "name": "  Café 🧭  ",
        "expected_policy_revision": 1,
        "provider_mode": "NARROW",
        "selected_providers": ["z", "a"],
    }
    result = digest_client([{"helper": "digestProjectCreate", "payload": payload}])
    assert result == [{"digest": payload_hash(ProjectCreate.model_validate(payload))}]


def input_model(name):
    return next(
        getattr(module, name)
        for module in (contracts, instruction_contracts, job_contracts, restore_contracts)
        if hasattr(module, name)
    )


VECTORS = json.loads((ROOT / "tests/digest-vectors.json").read_text())


@pytest.mark.parametrize("vector", VECTORS, ids=lambda row: row["model"])
def test_generated_digest_all_owner_inputs(digest_client, vector):
    model = input_model(vector["model"])
    canonical = input_model(vector["canonical_model"])
    original = model.model_validate(vector["payload"])
    variants = [vector["payload"], original.model_dump(mode="json")]
    results = digest_client(
        [
            {"helper": "digest" + vector["model"], "payload": payload, "wire": True}
            for payload in variants
        ]
    )
    for result in results:
        assert "error" not in result
        validated = model.model_validate_json(result["wire"])
        normalized = canonical.model_validate(
            validated.model_dump(mode="json", include=canonical.model_fields.keys())
        )
        data = normalized.model_dump(
            mode="json", exclude={"idempotency_key"} if vector["exclude_key"] else set()
        )
        if vector["model"] == "ProjectCreate" and data["selected_providers"] is not None:
            data["selected_providers"] = sorted(data["selected_providers"])
        if vector["model"] == "TaskCreate":
            data["dependencies"] = sorted(data["dependencies"])
        assert result["digest"] == digest(data)
    assert results[0]["digest"] == results[1]["digest"]


def test_every_generated_digest_has_an_owner_vector():
    generator = runpy.run_path(str(ROOT / "tools/generate_contracts.py"))
    assert set(generator["bindings"]()) == {row["model"] for row in VECTORS}


def test_generated_digest_reconciles_real_project_without_its_response_id(
    enrolled_owner,  # noqa: F811
    digest_client,
):
    owner = enrolled_owner
    for capability in ("project.create", "project.receipt.read"):
        official_effect(owner.client, owner.headers, owner.grant(capability))
    policy = official_effect(
        owner.client,
        owner.headers,
        {
            "kind": "egress.policy.initialize.v1",
            "schema_version": 1,
            "idempotency_key": "digest-policy",
            "expected_revision": 0,
            "provider_mode": "LOCAL_ONLY",
        },
    )
    payload = {
        "schema_version": 1,
        "idempotency_key": "digest-project",
        "name": "  Project café 🧭  ",
        "expected_policy_revision": policy["policy"]["revision"],
        "provider_mode": "LOCAL_ONLY",
    }
    computed = digest_client([{"helper": "digestProjectCreate", "payload": payload}])[0]
    query = {
        "schema_version": 1,
        "command": "project.create.v1",
        "idempotency_key": payload["idempotency_key"],
        "payload_digest": computed["digest"],
        "scope": {},
        "store_incarnation": context(owner)["store_incarnation"],
    }
    assert (
        owner.client.post("/api/v1/projects", headers=owner.headers, json=payload).status_code
        == 200
    )
    observed = owner.client.post("/api/v1/operations/resolve", headers=owner.headers, json=query)
    assert observed.status_code == 200
    receipt = observed.json()["receipt"]
    assert observed.json()["status"] == "OBSERVED_RECEIPT"
    assert receipt["project"]["name"] == "Project café 🧭"
    assert (
        owner.client.get(
            "/api/v1/operations/" + receipt["operation_id"], headers=owner.headers
        ).json()
        == receipt
    )
