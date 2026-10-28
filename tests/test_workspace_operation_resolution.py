# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from sqlalchemy import text
from test_production_instructions import official_effect
from test_workspace_provisioning import enrolled_owner  # noqa: F401
from test_workspace_session_controls import context

from journeon.contracts import ProjectCreate, TaskCreate
from journeon.database import transaction
from journeon.projects import payload_hash as project_hash
from journeon.work import payload_hash as task_hash


@pytest.fixture
def genuine_project_task(enrolled_owner):  # noqa: F811
    owner = enrolled_owner
    for capability in ("project.create", "project.receipt.read"):
        official_effect(owner.client, owner.headers, owner.grant(capability))
    policy = official_effect(
        owner.client,
        owner.headers,
        {
            "kind": "egress.policy.initialize.v1",
            "schema_version": 1,
            "idempotency_key": "resolver-local-policy",
            "expected_revision": 0,
            "provider_mode": "LOCAL_ONLY",
        },
    )
    project_command = ProjectCreate(
        schema_version=1,
        idempotency_key="resolver-project",
        name="Receipt reconciliation project",
        expected_policy_revision=policy["policy"]["revision"],
        provider_mode="LOCAL_ONLY",
    )
    created = owner.client.post(
        "/api/v1/projects", headers=owner.headers, json=project_command.model_dump(mode="json")
    )
    assert created.status_code == 200
    project_receipt = created.json()
    project = project_receipt["project"]
    grants = {}
    for capability in ("task.create", "task.read", "task.receipt.read"):
        grants[capability] = official_effect(
            owner.client, owner.headers, owner.grant(capability, project_id=project["project_id"])
        )
    task_command = TaskCreate(
        schema_version=1,
        idempotency_key="resolver-task",
        project_id=project["project_id"],
        expected_project_revision=project["revision"],
        objective="Recover the original Task receipt",
        responsibility="HUMAN",
    )
    created_task = owner.client.post(
        "/api/v1/tasks", headers=owner.headers, json=task_command.model_dump(mode="json")
    )
    assert created_task.status_code == 200
    return owner, project_command, project_receipt, task_command, created_task.json(), grants


@pytest.mark.parametrize("kind", ["project", "task"])
def test_original_identity_resolves_real_project_and_work_receipts(genuine_project_task, kind):
    owner, project_command, project_receipt, task_command, task_receipt, _ = genuine_project_task
    if kind == "project":
        command, accepted, digest, scope = (
            project_command,
            project_receipt,
            project_hash(project_command),
            {},
        )
    else:
        command, accepted, digest, scope = (
            task_command,
            task_receipt,
            task_hash(task_command),
            {"project_id": task_command.project_id},
        )
    query = {
        "schema_version": 1,
        "command": kind + ".create.v1",
        "idempotency_key": command.idempotency_key,
        "payload_digest": digest,
        "scope": scope,
        "store_incarnation": context(owner)["store_incarnation"],
    }
    response = owner.client.post("/api/v1/operations/resolve", headers=owner.headers, json=query)
    assert response.status_code == 200
    if response.json().get("receipt") != accepted:
        pytest.fail("Original request identity must recover its canonical owner receipt")


def test_revoked_task_scope_denies_before_corrupt_receipt_decode(genuine_project_task):
    owner, _, _, command, receipt, grants = genuine_project_task
    selected = grants["task.receipt.read"]["grant"]
    official_effect(
        owner.client,
        owner.headers,
        {
            "kind": "permission.grant.revoke.v1",
            "schema_version": 1,
            "idempotency_key": "remove-task-receipt-scope",
            "grant_id": selected["grant_id"],
            "expected_revision": selected["revision"],
        },
    )
    with transaction(owner.engine) as db:
        db.execute(
            text("UPDATE operation_receipts SET result='invalid-json' WHERE id=:id"),
            {"id": receipt["operation_id"]},
        )
    response = owner.client.post(
        "/api/v1/operations/resolve",
        headers=owner.headers,
        json={
            "schema_version": 1,
            "command": "task.create.v1",
            "idempotency_key": command.idempotency_key,
            "payload_digest": task_hash(command),
            "scope": {"project_id": command.project_id},
            "store_incarnation": context(owner)["store_incarnation"],
        },
    )
    assert response.status_code == 403
