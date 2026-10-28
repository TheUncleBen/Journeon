# SPDX-License-Identifier: AGPL-3.0-only
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from test_execution_route import route
from test_production_instructions import official_effect
from test_workspace_operation_resolution import genuine_project_task as genuine_project_task
from test_workspace_provisioning import enrolled_owner as enrolled_owner

from journeon.api import create_app
from journeon.attempt_contracts import AttemptConfiguration
from journeon.execution_process import ExecutionConfiguration
from journeon.instruction_config import InstructionConfiguration, RootConfiguration
from journeon.instruction_contracts import InstructionBind
from journeon.instruction_files import tree_hash
from journeon.job_contracts import JobConfiguration
from journeon.passkeys import STANDARD_PASSKEY_POLICY, PasskeyService


@pytest.fixture
def genuine_instruction_scope(genuine_project_task, tmp_path):
    owner, _, project_receipt, _, task_receipt, prior_grants = genuine_project_task
    project = project_receipt["project"]["project_id"]
    grants = dict(prior_grants)
    for capability in (
        "project.read",
        "project.instruction.bind",
        "project.instruction.read",
        "project.instruction.receipt.read",
        "project.instruction.accept",
        "project.instruction.projection",
        "project.instruction.propose",
    ):
        grants[capability] = official_effect(
            owner.client, owner.headers, owner.grant(capability, project_id=project)
        )
    environment = tmp_path / "durable-environment"
    environment.mkdir()
    config = InstructionConfiguration(
        roots=[
            RootConfiguration(
                key="durable-environment",
                path=str(environment),
                role="ENVIRONMENT",
                project_id=None,
                revision=1,
            )
        ],
        protected_request_seconds=101,
        protected_preview_seconds=37,
    )
    with TestClient(
        create_app(
            owner.engine,
            browser_auth=owner.client.app.state.browser_auth,
            instructions=config,
            passkeys=PasskeyService(
                owner.engine,
                rp_id="example.test",
                origin="https://example.test",
                policy=STANDARD_PASSKEY_POLICY,
            ),
        ),
        base_url="https://example.test",
        cookies=owner.client.cookies,
    ) as client:
        configured = replace(owner, client=client)
        admit_root(configured, "durable-environment")
        current = client.get("/api/v1/projects/" + project, headers=owner.headers)
        assert current.status_code == 200
        documents = {
            "INDEX.md": (
                "# Navigation\n\n- [rules.md](rules.md)\n\nRequired fragments:\n- rules.md\n"
            ),
            "rules.md": "Keep exact Project authority.\n",
        }
        binding = InstructionBind(
            idempotency_key="durable-binding",
            project_id=project,
            expected_project_revision=current.json()["revision"],
            expected_binding_revision=0,
            root_id="durable-environment",
            expected_root_revision=1,
            expected_tree_hash=tree_hash({}),
            owner="ENVIRONMENT",
            documents=[{"path": name, "content": body} for name, body in documents.items()],
            required_fragments=["rules.md"],
            reason="Explicit durable observation fixture",
        )
        bound = client.post(
            f"/api/v1/projects/{project}/instructions/binding",
            headers=owner.headers,
            json=binding.model_dump(mode="json"),
        )
        assert bound.status_code == 200
        yield configured, config, project, task_receipt["task"], grants, documents


def admit_root(owner, key):
    inspected = owner.client.post(
        "/api/v1/project-roots/inspect",
        headers=owner.headers,
        json={"root_key": key, "config_revision": 1},
    )
    assert inspected.status_code == 200
    official_effect(
        owner.client,
        owner.headers,
        {
            "kind": "project.root.admit.v1",
            "idempotency_key": "admit-" + key,
            "root_key": key,
            "config_revision": 1,
            "inspection_digest": inspected.json()["digest"],
            "expected_revision": 0,
        },
    )


@pytest.fixture
def genuine_durable_work(genuine_instruction_scope, tmp_path):
    owner, config, project, task, grants, _ = genuine_instruction_scope
    for capability in (
        "project.verification.configure",
        "project.verification.read",
        "task.revise",
        "task.dispatch",
        "execution.admit",
        "attempt.prepare",
        "attempt.read",
        "attempt.receipt.read",
        "job.read",
        "job.cancel",
        "job.receipt.read",
        "execution.start",
        "execution.read",
        "execution.stop",
        "execution.drain",
        "execution.complete",
        "execution.receipt.read",
    ):
        grants[capability] = official_effect(
            owner.client, owner.headers, owner.grant(capability, project_id=project)
        )
    from journeon.installed_instructions import candidate_manifest

    official_effect(
        owner.client,
        owner.headers,
        {
            "kind": "instruction.candidate.register.v1",
            "idempotency_key": "durable-package",
            "manifest_digest": candidate_manifest().digest,
            "expected_revision": 0,
        },
    )
    source = tmp_path / "durable-source"
    source.mkdir()
    (source / "input.txt").write_text("Durable input\n")
    attempt_storage = tmp_path / "durable-attempts"
    execution_storage = tmp_path / "durable-executions"
    for storage in (attempt_storage, execution_storage):
        storage.mkdir(mode=0o700)
    local_route = route().model_copy(update={"project_id": project, "check_id": "durable-check"})
    config = config.model_copy(
        update={
            "roots": [
                *config.roots,
                RootConfiguration(
                    key="durable-source",
                    path=str(source),
                    role="PROJECT",
                    project_id=project,
                    revision=1,
                ),
            ],
            "attempts": AttemptConfiguration(
                revision=1,
                storage_path=str(attempt_storage),
                snapshot_bytes=1048576,
                snapshot_files=100,
                pending_bytes=10485760,
                pending_count=10,
                lease_seconds=120,
                workspaces=[
                    {
                        "key": "durable-workspace",
                        "revision": 1,
                        "project_id": project,
                        "root_key": "durable-source",
                        "root_revision": 1,
                    }
                ],
            ),
            "executions": ExecutionConfiguration(
                revision=1,
                storage_path=str(execution_storage),
                snapshot_bytes=1048576,
                snapshot_files=100,
                concurrent_executions=2,
                memory_bytes=268435456,
                storage_bytes=33554432,
                cpu_percent=50,
                core_cpu_reserve_percent=100,
                routes=[local_route],
            ),
            "jobs": JobConfiguration(
                pending_count=10,
                pending_bytes=10485760,
                concurrency=1,
                lease_seconds=5,
                poll_seconds=1,
                retry_seconds=1,
                max_attempts=2,
            ),
        }
    )
    with TestClient(
        create_app(
            owner.engine, browser_auth=owner.client.app.state.browser_auth, instructions=config
        ),
        base_url="https://example.test",
        cookies=owner.client.cookies,
    ) as client:
        configured = replace(owner, client=client)
        admit_root(configured, "durable-source")
        current = client.get("/api/v1/projects/" + project, headers=owner.headers)
        assert current.status_code == 200
        policy = client.post(
            "/api/v1/projects/verification",
            headers=owner.headers,
            json={
                "schema_version": 1,
                "idempotency_key": "durable-verification",
                "project_id": project,
                "expected_project_revision": current.json()["revision"],
                "expected_policy_revision": 0,
                "enabled": True,
                "checks": [
                    {
                        "check_id": "durable-check",
                        "criterion": "Local command succeeds",
                        "argv": local_route.argv,
                        "working_directory": ".",
                        "expected_exit_code": 0,
                    }
                ],
                "workflow": {
                    "steps": [
                        {"step_id": "verify", "kind": "VERIFICATION", "check_id": "durable-check"}
                    ]
                },
            },
        )
        assert policy.status_code == 200
        revised = client.post(
            "/api/v1/tasks/revise",
            headers=owner.headers,
            json={
                "schema_version": 1,
                "idempotency_key": "durable-task-policy",
                "task_id": task["task_id"],
                "expected_revision": task["revision"],
                "reason": "Bind the exact local verification policy",
                "expected_policy_revision": 1,
                "success_conditions": ["Local command succeeds"],
                "workflow": policy.json()["policy"]["workflow"],
            },
        )
        assert revised.status_code == 200
        task = revised.json()["task"]
        prepare = {
            "schema_version": 1,
            "idempotency_key": "durable-attempt",
            "project_id": project,
            "expected_policy_revision": 1,
            "origin": {
                "kind": "TASK",
                "task_id": task["task_id"],
                "task_revision": task["revision"],
            },
            "workspace_key": "durable-workspace",
            "workspace_revision": 1,
        }
        yield configured, config, prepare, grants, local_route
