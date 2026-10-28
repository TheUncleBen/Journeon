# SPDX-License-Identifier: AGPL-3.0-only
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from test_workspace_attention_boundaries import effects
from test_workspace_search_attention import attention_page, dismiss
from test_workspace_search_attention import failed_work as failed_work
from workspace_durable_helpers import enrolled_owner as enrolled_owner
from workspace_durable_helpers import genuine_durable_work as genuine_durable_work
from workspace_durable_helpers import genuine_instruction_scope as genuine_instruction_scope
from workspace_durable_helpers import genuine_project_task as genuine_project_task

from journeon.api import create_app
from journeon.database import transaction
from journeon.instructions import digest
from journeon.models import OutboxEvent, Receipt, TaskVerificationJob


def observe_source(owner, config, job, execution_receipt, cursor, command, receipt, query):
    with TestClient(
        create_app(
            owner.engine, browser_auth=owner.client.app.state.browser_auth, instructions=config
        ),
        base_url="https://example.test",
        cookies=owner.client.cookies,
    ) as client:
        responses = {
            "search": client.get(
                "/api/v1/search", params={"q": "FAILED", "kinds": "JOB", "limit": 100}
            ),
            "jobs": client.get("/api/v1/jobs", params={"limit": 100}),
            "attention": client.get("/api/v1/attention", params={"limit": 100}),
            "direct": client.get(f"/api/v1/jobs/{job['job_id']}"),
            "legacy": client.get(f"/api/v1/jobs/{job['job_id']}/attention"),
            "evidence": client.get(f"/api/v1/jobs/{job['job_id']}/evidence"),
            "execution_receipt": client.get(f"/api/v1/operations/{execution_receipt}"),
            "job_receipt": client.get(f"/api/v1/operations/{job['admission_id']}"),
            "presentation_receipt": client.get(f"/api/v1/operations/{receipt['operation_id']}"),
            "resolve": client.post("/api/v1/operations/resolve", headers=owner.headers, json=query),
            "acknowledgement_replay": client.post(
                "/api/v1/notifications/dismiss", headers=owner.headers, json=command
            ),
            "events": client.post(
                "/api/v1/events/replay",
                headers=owner.headers,
                json={"limit": 100, "cursor": cursor},
            ),
        }
    return responses


@pytest.mark.parametrize("payload", ["inputs", "task", "attempt"])
def test_task_job_configuration_and_bound_route_precede_required_json(failed_work, payload):
    fixture, job = failed_work
    owner, config, prepare, _, route = fixture
    page = attention_page(owner)
    item = page["items"][0]
    command, accepted = dismiss(owner, item)
    assert accepted.status_code == 200
    receipt = accepted.json()
    query = {
        "schema_version": 1,
        "command": "notification.dismiss.v1",
        "idempotency_key": command["idempotency_key"],
        "payload_digest": digest(
            {key: value for key, value in command.items() if key != "idempotency_key"}
        ),
        "scope": {"attention_id": item["attention_id"]},
        "store_incarnation": page["store_incarnation"],
    }
    with transaction(owner.engine) as db:
        binding = db.get(TaskVerificationJob, job["job_id"])
        assert binding is not None and binding.execution_id is not None
        execution, attempt = binding.execution_id, binding.attempt_id
        execution_receipt = db.scalar(
            select(Receipt.id)
            .where(
                Receipt.owner == "work",
                Receipt.target_kind == "execution",
                Receipt.target_id == execution,
            )
            .order_by(Receipt.id)
            .limit(1)
        )
        assert execution_receipt is not None
        first = db.scalar(
            select(func.min(OutboxEvent.sequence)).where(
                OutboxEvent.owner == "jobs", OutboxEvent.target_id == job["job_id"]
            )
        )
        assert first is not None
    cursor = {"incarnation": page["store_incarnation"], "sequence": first - 1}
    assert config.executions is not None
    variants = {
        "unchanged": config,
        "configuration_revision": config.model_copy(
            update={
                "executions": config.executions.model_copy(
                    update={"revision": config.executions.revision + 1}
                )
            }
        ),
    }
    variants["missing_configuration"] = config.model_copy(update={"executions": None})
    variants["route_content"] = config.model_copy(
        update={
            "executions": config.executions.model_copy(
                update={"routes": [route.model_copy(update={"environment": {"MODE": "changed"}})]}
            )
        }
    )
    if payload == "inputs":
        for label, update in (
            ("route_key", {"key": route.key + "-replacement"}),
            ("route_revision", {"revision": route.revision + 1}),
            ("route_project", {"project_id": "different-project"}),
        ):
            variants[label] = config.model_copy(
                update={
                    "executions": config.executions.model_copy(
                        update={"routes": [route.model_copy(update=update)]}
                    )
                }
            )
    table, column, identity_column, identity = {
        "inputs": ("task_verification_jobs", "inputs", "job_id", job["job_id"]),
        "task": ("tasks", "snapshot", "id", prepare["origin"]["task_id"]),
        "attempt": ("attempts", "snapshot", "id", attempt),
    }[payload]
    update = text(f"UPDATE {table} SET {column}=:value WHERE {identity_column}=:id")
    with transaction(owner.engine) as db:
        original = db.scalar(
            text(f"SELECT {column} FROM {table} WHERE {identity_column}=:id"), {"id": identity}
        )
    before = effects(owner)
    observed, expected, failures = {}, {}, []
    try:
        for corrupt in (False, True):
            if corrupt:
                with transaction(owner.engine) as db:
                    db.execute(update, {"value": "invalid-json", "id": identity})
            for label, configuration in variants.items():
                responses = observe_source(
                    owner, configuration, job, execution_receipt, cursor, command, receipt, query
                )
                key = f"{label}:corrupt={corrupt}"
                observed[key], expected[key] = {}, {}
                for surface, response in responses.items():
                    body = response.json()
                    observed[key][surface] = (
                        (response.status_code, body.get("code"))
                        if isinstance(body, dict)
                        else (response.status_code, None)
                    )
                    if label == "unchanged":
                        status = 503 if corrupt else 200
                    elif surface == "events":
                        status = 200
                    elif label == "missing_configuration":
                        status = 503
                    else:
                        status = 200 if surface in {"search", "jobs", "attention"} else 403
                    code = (
                        "DEPENDENCY_UNAVAILABLE"
                        if status == 503
                        else "PERMISSION_DENIED"
                        if status == 403
                        else None
                    )
                    expected[key][surface] = (status, code)
                    if label == "missing_configuration" and surface == "direct":
                        if body.get("reason") != "Local execution routes are not configured":
                            failures.append(
                                (key, surface, "Missing configuration must precede stored data")
                            )
                    if label != "unchanged" and response.status_code == 200:
                        if surface in {"search", "jobs", "attention"} and body["items"]:
                            failures.append((key, surface, "Hidden source remained visible"))
                        if surface == "events" and any(
                            event["target_id"] in {job["job_id"], execution}
                            for event in body["events"]
                        ):
                            failures.append((key, surface, "Hidden source event remained visible"))
                if label == "unchanged" and not corrupt:
                    assert responses["presentation_receipt"].json() == receipt
                    assert responses["acknowledgement_replay"].json() == receipt
                    assert responses["resolve"].json()["receipt"] == receipt
                    assert (
                        responses["attention"].json()["items"][0]["attention_id"]
                        == item["attention_id"]
                    )
    finally:
        with transaction(owner.engine) as db:
            db.execute(update, {"value": original, "id": identity})
    assert effects(owner) == before
    print(json.dumps(observed, sort_keys=True))
    assert observed == expected
    assert not failures
