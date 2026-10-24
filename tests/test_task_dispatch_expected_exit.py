# SPDX-License-Identifier: AGPL-3.0-only
import base64

import pytest
from test_attempt_execution import attempt_environment  # noqa: F401
from test_production_instructions import official  # noqa: F401
from test_task_dispatch import dispatch_environment, dispatch_worker  # noqa: F401


@pytest.mark.parametrize(
    "dispatch_environment", ["print('configured-seven'); raise SystemExit(7)"], indirect=True
)
def test_expected_nonzero_exit_is_passing_real_task_evidence(dispatch_environment):  # noqa: F811
    engine, client, headers, config, command, _, _ = dispatch_environment
    project_id = command["project_id"]
    project = client.get("/api/v1/projects/" + project_id).json()
    policy = client.get("/api/v1/projects/" + project_id + "/verification").json()
    check = policy["checks"][0] | {"expected_exit_code": 7}
    configured = client.post(
        "/api/v1/projects/verification",
        headers=headers,
        json=dict(
            schema_version=1,
            idempotency_key="expected-seven",
            project_id=project_id,
            expected_project_revision=project["revision"],
            expected_policy_revision=policy["revision"],
            enabled=True,
            checks=[check],
            workflow=policy["workflow"],
        ),
    )
    assert configured.status_code == 200, configured.text
    revision = configured.json()["policy"]["revision"]
    revised = client.post(
        "/api/v1/tasks/revise",
        headers=headers,
        json=dict(
            schema_version=1,
            idempotency_key="task-expects-seven",
            task_id=command["origin"]["task_id"],
            expected_revision=command["origin"]["task_revision"],
            expected_policy_revision=revision,
            reason="Bind the configured nonzero expected exit",
            success_conditions=[check["criterion"]],
            workflow=policy["workflow"],
        ),
    )
    assert revised.status_code == 200, revised.text
    command = command | {
        "expected_policy_revision": revision,
        "origin": command["origin"] | {"task_revision": revised.json()["task"]["revision"]},
    }
    admitted = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert admitted.status_code == 200, admitted.text
    identity = admitted.json()["job_id"]
    dispatch_worker(engine, config)
    job = client.get("/api/v1/jobs/" + identity)
    assert job.status_code == 200, job.text
    assert job.json()["state"] == "SUCCEEDED", job.text
    result = client.get("/api/v1/jobs/" + identity + "/evidence")
    assert result.status_code == 200, result.text
    proof = result.json()
    assert proof["passed"] is True
    assert proof["execution"]["origin"] == "TASK_VERIFICATION"
    assert proof["execution"]["completion"]["exit_code"] == 7
    assert proof["execution"]["completion"]["reason"] == "EXITED"
    assert proof["execution"]["completion"]["drained"] is True
    assert proof["manifest"]["verification_policy"]["checks"][0]["expected_exit_code"] == 7
    assert b"configured-seven" in b"".join(
        base64.b64decode(item["data"], validate=True) for item in proof["execution"]["output"]
    )
    assert client.get("/api/v1/tasks/" + command["origin"]["task_id"]).json()["state"] != "DONE"
