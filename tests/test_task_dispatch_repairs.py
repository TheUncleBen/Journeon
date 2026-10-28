# SPDX-License-Identifier: AGPL-3.0-only
import base64
import hashlib

import pytest
from sqlalchemy import select
from test_attempt_snapshots import git
from test_task_dispatch import attempt_environment, dispatch_environment, dispatch_worker, official  # noqa: F401

from journeon.database import transaction
from journeon.executions import ExecutionService
from journeon.models import AccessGrant, Execution
from journeon.permissions import AuthenticatedContext


def completed_task(environment):
    database, browser, csrf, configuration, request, _, _ = environment
    admitted = browser.post("/api/v1/tasks/dispatch", headers=csrf, json=request)
    assert admitted.status_code == 200
    endpoint = "/api/v1/jobs/" + admitted.json()["job_id"] + "/evidence"
    dispatch_worker(database, configuration)
    result = browser.get(endpoint)
    assert result.status_code == 200
    assert result.json()["passed"]
    return endpoint, result.json()


@pytest.mark.parametrize("missing", ["execution.read", "project.read"])
@pytest.mark.parametrize("malformed", [False, True])
def test_evidence_read_requires_owning_execution_permissions(
    dispatch_environment,  # noqa: F811
    missing,
    malformed,
):
    endpoint, proof = completed_task(dispatch_environment)
    database, browser, _, _, request, _, _ = dispatch_environment
    with transaction(database) as session:
        grants = session.scalars(
            select(AccessGrant).where(
                AccessGrant.resource_id == request["project_id"],
                AccessGrant.capability == missing,
            )
        ).all()
        assert grants
        for grant in grants:
            grant.enabled = False
    if malformed:
        with database.begin() as connection:
            connection.exec_driver_sql(
                "UPDATE task_verification_jobs SET inputs='{' WHERE job_id=?", (proof["job_id"],)
            )
    denied = browser.get(endpoint)
    assert denied.status_code == 403
    assert denied.json()["code"] == "PERMISSION_DENIED"
    assert "execution" not in denied.json()


def test_doctor_scope_matches_persisted_task_origin(dispatch_environment):  # noqa: F811
    _, proof = completed_task(dispatch_environment)
    database, _, _, configuration, _, _, _ = dispatch_environment
    with transaction(database) as session:
        persisted = session.get(Execution, proof["execution"]["execution_id"])
        assert persisted.job_id == proof["job_id"]
        context = AuthenticatedContext(
            persisted.principal_id, persisted.principal_epoch, persisted.authentication_ref
        )
    result = ExecutionService(database, configuration).doctor(context, persisted.id)
    assert proof["execution"]["origin"] == "TASK_VERIFICATION"
    assert result["execution_id"] == persisted.id
    assert result["scope"] == "CURRENT_TASK_VERIFICATION_ROUTE"
    assert result["qualified"] is True


PAYLOAD = b"post-admission-object-not-in-attempt"
OID = hashlib.sha1(b"blob " + str(len(PAYLOAD)).encode() + b"\0" + PAYLOAD).hexdigest()
PROGRAM = (
    "import subprocess as s;r=s.run(['git','cat-file','-e','"
    + OID
    + "'],stderr=s.DEVNULL);print(r.returncode);assert r.returncode"
)


@pytest.mark.parametrize("dispatch_environment", [PROGRAM], indirect=True)
def test_verifier_cannot_read_post_admission_git_blob(dispatch_environment):  # noqa: F811
    engine, client, headers, config, command, root, storage = dispatch_environment
    response = client.post("/api/v1/tasks/dispatch", headers=headers, json=command)
    assert response.status_code == 200, response.text
    identity = response.json()["job_id"]
    (root / "post-admission.txt").write_bytes(PAYLOAD)
    assert git(root, "hash-object", "post-admission.txt").strip() == OID
    git(root, "add", "post-admission.txt")
    git(root, "commit", "-qm", "Post-admission fixture object")
    dispatch_worker(engine, config)
    response = client.get("/api/v1/jobs/" + identity + "/evidence")
    assert response.status_code == 200, response.text
    proof = response.json()
    stdout = b"".join(
        base64.b64decode(row["data"])
        for row in proof["execution"]["output"]
        if row["stream"] == "stdout"
    )
    assert proof["passed"], {
        "observed_stdout": stdout.decode(),
        "exit": proof["execution"]["completion"]["exit_code"],
        "later_blob": OID,
    }


@pytest.mark.parametrize("column", ["snapshot", "inputs"])
def test_attempt_prepare_replay_checks_original_project_before_json(
    attempt_environment,  # noqa: F811
    column,
):
    database, browser, csrf, _, request, _, _ = attempt_environment
    prepared = browser.post("/api/v1/attempts/prepare", headers=csrf, json=request)
    assert prepared.status_code == 200
    other_project = browser.post(
        "/api/v1/projects",
        headers=csrf,
        json={
            "schema_version": 1,
            "idempotency_key": "replay-project",
            "name": "Replay authorization fixture",
            "expected_policy_revision": 1,
        },
    )
    assert other_project.status_code == 200
    destination = other_project.json()["project"]["project_id"]
    with transaction(database) as session:
        original = session.scalar(
            select(AccessGrant).where(
                AccessGrant.resource_id == request["project_id"],
                AccessGrant.capability == "attempt.prepare",
            )
        )
        assert original is not None
        original.enabled = False
        for suffix, permission in enumerate(
            ("attempt.prepare", "attempt.read", "attempt.receipt.read")
        ):
            session.add(
                AccessGrant(
                    id="replay-destination-" + str(suffix),
                    principal_id=original.principal_id,
                    capability=permission,
                    resource_kind="project",
                    resource_id=destination,
                    enabled=True,
                    revision=1,
                    provenance="Explicit replay destination authority",
                )
            )
    payload = request | {"project_id": destination}
    assert browser.post("/api/v1/attempts/prepare", headers=csrf, json=payload).status_code == 403
    with database.begin() as connection:
        connection.exec_driver_sql("UPDATE attempts SET " + column + "='{' ")
    rejected = browser.post("/api/v1/attempts/prepare", headers=csrf, json=payload)
    assert rejected.status_code == 403
    assert rejected.json()["code"] == "PERMISSION_DENIED"


def test_legacy_snapshot_receipts_keep_hashes_without_inventing_history(dispatch_environment):  # noqa: F811
    from journeon.contracts import AttemptPrepare, ChangeSetSnapshot
    from journeon.instructions import digest
    from journeon.models import Attempt, AttemptManifest, Job, Receipt

    engine, client, headers, _, command, _, _ = dispatch_environment
    prepare = {key: value for key, value in command.items() if key in AttemptPrepare.model_fields}
    response = client.post("/api/v1/attempts/prepare", headers=headers, json=prepare)
    assert response.status_code == 200
    legacy = response.json()
    manifest = legacy["attempt"]["manifest"]
    source = manifest["snapshot"]
    assert source.pop("git_history") == {"shallow": False, "boundaries": []}
    source["snapshot_hash"] = digest(
        {key: value for key, value in source.items() if key != "snapshot_hash"}
    )
    manifest["content_digest"] = digest(
        {key: value for key, value in manifest.items() if key != "content_digest"}
    )
    decoded = ChangeSetSnapshot.model_validate(source)
    assert decoded.git_history is None
    assert decoded.model_dump(mode="json") == source
    with transaction(engine) as db:
        db.get(Attempt, legacy["attempt"]["attempt_id"]).snapshot = legacy["attempt"]
        retained = db.get(AttemptManifest, manifest["manifest_id"])
        retained.snapshot = manifest
        retained.content_hash = manifest["content_digest"]
        db.get(Receipt, legacy["operation_id"]).result = legacy
    read = client.get("/api/v1/attempts/" + legacy["attempt"]["attempt_id"])
    assert read.status_code == 200 and read.json() == legacy["attempt"]
    replay = client.post("/api/v1/attempts/prepare", headers=headers, json=prepare)
    assert replay.status_code == 200 and replay.json() == legacy
    receipt = client.get("/api/v1/operations/" + legacy["operation_id"])
    assert receipt.status_code == 200 and receipt.json() == legacy
    dispatch = client.post(
        "/api/v1/tasks/dispatch",
        headers=headers,
        json=command
        | {
            "attempt_id": legacy["attempt"]["attempt_id"],
            "idempotency_key": "legacy-history-dispatch",
        },
    )
    assert dispatch.status_code == 503
    assert dispatch.json()["code"] == "DEPENDENCY_UNAVAILABLE"
    with transaction(engine) as db:
        assert db.scalar(select(Job)) is None
