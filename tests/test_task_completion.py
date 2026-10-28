# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from sqlalchemy import select
from test_attempt_execution import attempt_environment  # noqa: F401
from test_production_instructions import official  # noqa: F401
from test_task_dispatch import dispatch_environment, dispatch_worker  # noqa: F401

from journeon.database import transaction
from journeon.models import AccessGrant, Principal


@pytest.fixture
def completion_environment(dispatch_environment, request):  # noqa: F811
    engine, client, headers, config, dispatch, root, storage = dispatch_environment
    review_required = getattr(request, "param", False)
    project_id = dispatch["project_id"]
    task_id = dispatch["origin"]["task_id"]
    with transaction(engine) as db:
        principal = db.scalar(select(Principal).where(Principal.role == "OWNER"))
        for capability in (
            "project.review.configure",
            "project.review.read",
            "task.review.select",
            "task.review.read",
            "task.complete",
            "task.admit",
        ):
            db.add(
                AccessGrant(
                    id="complete:" + capability,
                    principal_id=principal.id,
                    capability=capability,
                    resource_kind="project",
                    resource_id=project_id,
                    enabled=True,
                    revision=1,
                    provenance="Explicit disposable completion authority",
                )
            )
    project = client.get("/api/v1/projects/" + project_id).json()
    configured = client.post(
        "/api/v1/projects/review-policy",
        headers=headers,
        json=dict(
            schema_version=1,
            idempotency_key="deterministic-completion-policy",
            project_id=project_id,
            expected_project_revision=project["revision"],
            expected_policy_revision=0,
            independent_review_required=review_required,
            minimum_independence=["FRESH_SESSION"] if review_required else [],
            preferred_diversity=[],
            required_coverage=["source"] if review_required else [],
            material_severities=[],
            owner_override_severities=[],
            automatic_round_limit=None,
            stop_on_cycle=True,
            stop_on_unchanged_target=True,
        ),
    )
    assert configured.status_code == 200, configured.text
    current = client.get("/api/v1/tasks/" + task_id).json()
    revised = client.post(
        "/api/v1/tasks/revise",
        headers=headers,
        json=dict(
            schema_version=1,
            idempotency_key="bind-completion-policy",
            task_id=task_id,
            expected_revision=current["revision"],
            reason="Bind the explicit completion policy",
            expected_policy_revision=dispatch["expected_policy_revision"],
            success_conditions=[item["text"] for item in current["success_conditions"]],
            workflow=current["workflow"],
        ),
    )
    assert revised.status_code == 200, revised.text
    admitted = client.post(
        "/api/v1/tasks/admit",
        headers=headers,
        json=dict(
            schema_version=1,
            idempotency_key="admit-completion-task",
            task_id=task_id,
            expected_revision=revised.json()["task"]["revision"],
            reason="Admit the configured proof",
            expected_policy_revision=dispatch["expected_policy_revision"],
        ),
    )
    assert admitted.status_code == 200, admitted.text
    assert admitted.json()["task"]["state"] == "READY"
    dispatch = dispatch | {
        "origin": dispatch["origin"] | {"task_revision": admitted.json()["task"]["revision"]}
    }
    return engine, client, headers, config, dispatch, root, storage


def selected_candidate(environment):
    engine, client, headers, config, dispatch, root, _ = environment
    admitted = client.post("/api/v1/tasks/dispatch", headers=headers, json=dispatch)
    assert admitted.status_code == 200, admitted.text
    dispatch_worker(engine, config)
    proof = client.get("/api/v1/jobs/" + admitted.json()["job_id"] + "/evidence")
    assert proof.status_code == 200, proof.text
    evidence = proof.json()
    target = client.post(
        "/api/v1/tasks/review-targets",
        headers=headers,
        json=dict(
            schema_version=1,
            idempotency_key="selected-candidate",
            task_id=dispatch["origin"]["task_id"],
            expected_revision=dispatch["origin"]["task_revision"],
            attempt_id=evidence["attempt_id"],
            expected_review_policy_revision=1,
        ),
    )
    assert target.status_code == 200, target.text
    selected = target.json()["target"]
    command = dict(
        schema_version=1,
        idempotency_key="complete-candidate",
        task_id=dispatch["origin"]["task_id"],
        expected_revision=dispatch["origin"]["task_revision"],
        reason="Recorded proof passed",
        target_id=selected["target_id"],
        target_digest=selected["content_digest"],
    )
    return selected, evidence, command


def test_real_verifier_completion_is_exact_candidate_and_idempotent(completion_environment):
    engine, client, headers, config, dispatch, root, _ = completion_environment
    selected, evidence, command = selected_candidate(completion_environment)
    (root / "source.txt").write_text("Later source is not the selected candidate")
    response = client.post("/api/v1/tasks/complete", headers=headers, json=command)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["task"]["state"] == "DONE"
    assert result["task"]["completion"]["target_id"] == selected["target_id"]
    assert (
        result["task"]["completion"]["snapshot_hash"]
        == evidence["manifest"]["snapshot"]["snapshot_hash"]
    )
    assert result["task"]["completion"]["evidence_ids"] == [evidence["evidence_id"]]
    assert client.post("/api/v1/tasks/complete", headers=headers, json=command).json() == result
    assert client.get("/api/v1/operations/" + result["operation_id"]).json() == result

    from pathlib import Path

    from fastapi.testclient import TestClient
    from sqlalchemy import func

    from journeon.api import create_app
    from journeon.database import create_database
    from journeon.models import OutboxEvent, Receipt, TaskRevision

    with transaction(engine) as db:
        assert (
            db.scalar(
                select(func.count())
                .select_from(Receipt)
                .where(Receipt.command == "task.complete.v1")
            )
            == 1
        )
        assert (
            db.scalar(
                select(func.count())
                .select_from(OutboxEvent)
                .where(OutboxEvent.event_type == "task.completed")
            )
            == 1
        )
        assert (
            db.scalar(
                select(func.count())
                .select_from(TaskRevision)
                .where(TaskRevision.task_id == command["task_id"])
            )
            == result["task"]["revision"]
        )
    restarted = create_database(Path(engine.url.database))
    try:
        with TestClient(
            create_app(restarted, browser_auth=client.app.state.browser_auth, instructions=config),
            base_url="https://example.test",
            cookies=client.cookies,
        ) as again:
            assert (
                again.post("/api/v1/tasks/complete", headers=headers, json=command).json() == result
            )
            assert again.get("/api/v1/operations/" + result["operation_id"]).json() == result
            assert again.get("/api/v1/review-targets/" + selected["target_id"]).json() == selected
    finally:
        restarted.dispose()


@pytest.mark.parametrize("completion_environment", [True], indirect=True)
def test_required_independent_review_cannot_be_replaced_by_verifier(completion_environment):
    _, client, headers, _, _, _, _ = completion_environment
    target, proof, command = selected_candidate(completion_environment)
    assert proof["passed"]
    assert target["authorship_status"] == "UNAVAILABLE"
    response = client.post("/api/v1/tasks/complete", headers=headers, json=command)
    assert response.status_code == 503, response.text
    assert response.json()["reason"] == "Qualified independent review evidence is unavailable"
    assert client.get("/api/v1/tasks/" + command["task_id"]).json()["state"] == "READY"


@pytest.mark.parametrize(
    "change", ["review-policy", "verification-policy", "criteria", "pause", "cancel"]
)
def test_completion_rejects_stale_or_stopped_candidate(completion_environment, change):
    _, client, headers, _, dispatch, _, _ = completion_environment
    target, _, command = selected_candidate(completion_environment)
    project_id = dispatch["project_id"]
    if change in ("pause", "cancel"):
        changed = client.post(
            "/api/v1/tasks/" + change,
            headers=headers,
            json=dict(
                schema_version=1,
                idempotency_key="stop-before-completion",
                task_id=command["task_id"],
                expected_revision=command["expected_revision"],
                reason="Stop before completion",
            ),
        )
    elif change == "criteria":
        changed = client.post(
            "/api/v1/tasks/revise",
            headers=headers,
            json=dict(
                schema_version=1,
                idempotency_key="new-criteria",
                task_id=command["task_id"],
                expected_revision=command["expected_revision"],
                reason="Require additional proof",
                expected_policy_revision=dispatch["expected_policy_revision"],
                success_conditions=["Command succeeds", "Additional required criterion"],
                workflow=target["manifest"]["task"]["workflow"],
            ),
        )
    else:
        project = client.get("/api/v1/projects/" + project_id).json()
        field = "review_policy" if change == "review-policy" else "verification_policy"
        policy = target[field] if field == "review_policy" else target["manifest"][field]
        data = {
            key: value
            for key, value in policy.items()
            if key not in ("revision", "created_by", "created_at")
        }
        data.update(
            schema_version=1,
            idempotency_key="new-policy",
            expected_project_revision=project["revision"],
            expected_policy_revision=policy["revision"],
        )
        route = "review-policy" if change == "review-policy" else "verification"
        changed = client.post("/api/v1/projects/" + route, headers=headers, json=data)
    assert changed.status_code == 200, changed.text
    response = client.post("/api/v1/tasks/complete", headers=headers, json=command)
    assert response.status_code == 409, response.text
    assert client.get("/api/v1/tasks/" + command["task_id"]).json()["state"] != "DONE"
    assert client.get("/api/v1/review-targets/" + target["target_id"]).json() == target


@pytest.mark.parametrize(
    "capability,table,trigger",
    [
        ("task.review.read", "review_targets", "review_target_no_update"),
        ("execution.read", "task_verification_evidence", "task_evidence_no_update"),
    ],
)
def test_completion_authorizes_before_corrupt_payload(
    completion_environment, capability, table, trigger
):
    from sqlalchemy import text

    engine, client, headers, _, _, _, _ = completion_environment
    target, _, command = selected_candidate(completion_environment)
    with transaction(engine) as db:
        for grant in db.scalars(select(AccessGrant).where(AccessGrant.capability == capability)):
            grant.enabled = False
        db.execute(text("DROP TRIGGER " + trigger))
        db.execute(text("UPDATE " + table + " SET snapshot='not-json'"))
    response = client.post("/api/v1/tasks/complete", headers=headers, json=command)
    assert response.status_code == 403, response.text
    if capability == "task.review.read":
        assert client.get("/api/v1/review-targets/" + target["target_id"]).status_code == 403


@pytest.mark.parametrize("dispatch_environment", ["raise SystemExit(7)"], indirect=True)
def test_failed_actual_verification_cannot_complete(completion_environment):
    _, client, headers, _, _, _, _ = completion_environment
    _, proof, command = selected_candidate(completion_environment)
    assert proof["passed"] is False
    response = client.post("/api/v1/tasks/complete", headers=headers, json=command)
    assert response.status_code == 503, response.text
    assert client.get("/api/v1/tasks/" + command["task_id"]).json()["state"] == "READY"


def test_forged_digest_valid_evidence_cannot_replace_process_provenance(completion_environment):
    import json

    from sqlalchemy import text

    from journeon.instructions import digest

    engine, client, headers, _, _, _, _ = completion_environment
    _, proof, command = selected_candidate(completion_environment)
    proof["process_id"] += 1
    proof["content_digest"] = digest(
        {key: value for key, value in proof.items() if key != "content_digest"}
    )
    with transaction(engine) as db:
        db.execute(text("DROP TRIGGER task_evidence_no_update"))
        db.execute(
            text(
                "UPDATE task_verification_evidence SET snapshot=:snapshot, "
                "content_hash=:digest WHERE id=:id"
            ),
            {
                "snapshot": json.dumps(proof),
                "digest": proof["content_digest"],
                "id": proof["evidence_id"],
            },
        )
    response = client.post("/api/v1/tasks/complete", headers=headers, json=command)
    assert response.status_code == 503, response.text
    assert client.get("/api/v1/tasks/" + command["task_id"]).json()["state"] == "READY"


@pytest.mark.parametrize("damage", ["result", "target_kind", "authentication_ref", "receipt_grant"])
def test_completion_requires_canonical_execution_receipt(completion_environment, damage):
    from sqlalchemy import text

    engine, client, headers, _, _, _, _ = completion_environment
    _, proof, command = selected_candidate(completion_environment)
    operation_id = proof["execution_operation_id"]
    with transaction(engine) as db:
        if damage in ("result", "receipt_grant"):
            db.execute(
                text("UPDATE operation_receipts SET result='not-json' WHERE id=:id"),
                {"id": operation_id},
            )
        elif damage == "target_kind":
            db.execute(
                text("UPDATE operation_receipts SET target_kind='task' WHERE id=:id"),
                {"id": operation_id},
            )
        else:
            db.execute(
                text(
                    "UPDATE operation_receipts SET authentication_ref='unrelated-session' "
                    "WHERE id=:id"
                ),
                {"id": operation_id},
            )
        if damage == "receipt_grant":
            for grant in db.scalars(
                select(AccessGrant).where(AccessGrant.capability == "execution.receipt.read")
            ):
                grant.enabled = False
    response = client.post("/api/v1/tasks/complete", headers=headers, json=command)
    assert response.status_code == (403 if damage == "receipt_grant" else 503), response.text
    assert client.get("/api/v1/tasks/" + command["task_id"]).json()["state"] == "READY"


def test_target_configuration_authorizes_before_corrupt_target(completion_environment):
    from fastapi.testclient import TestClient
    from sqlalchemy import text

    from journeon.api import create_app
    from journeon.models import Receipt

    engine, client, headers, config, dispatch, _, _ = completion_environment
    target, _, command = selected_candidate(completion_environment)
    with transaction(engine) as db:
        operation_id = db.scalar(
            select(Receipt.id).where(Receipt.command == "task.review.select.v1")
        )
        db.execute(text("DROP TRIGGER review_target_no_update"))
        db.execute(text("UPDATE review_targets SET snapshot='not-json'"))
    changed = config.model_copy(
        update={
            "roots": [
                root.model_copy(update={"revision": root.revision + 1})
                if root.project_id == dispatch["project_id"]
                else root
                for root in config.roots
            ]
        }
    )
    with TestClient(
        create_app(engine, browser_auth=client.app.state.browser_auth, instructions=changed),
        base_url="https://example.test",
        cookies=client.cookies,
    ) as current:
        statuses = [
            current.get("/api/v1/review-targets/" + target["target_id"]).status_code,
            current.get("/api/v1/operations/" + operation_id).status_code,
            current.post("/api/v1/tasks/complete", headers=headers, json=command).status_code,
        ]
    assert statuses == [403, 403, 403]


def test_candidate_selection_requires_explicit_review_policy(attempt_environment):  # noqa: F811
    engine, client, headers, _, prepare, _, _ = attempt_environment
    with transaction(engine) as db:
        owner = db.scalar(select(Principal).where(Principal.role == "OWNER"))
        for capability in ("task.review.select", "task.review.read", "project.review.read"):
            db.add(
                AccessGrant(
                    id="missing-policy:" + capability,
                    principal_id=owner.id,
                    capability=capability,
                    resource_kind="project",
                    resource_id=prepare["project_id"],
                    enabled=True,
                    revision=1,
                    provenance="Explicit target selection authority",
                )
            )
    prepared = client.post("/api/v1/attempts/prepare", headers=headers, json=prepare)
    assert prepared.status_code == 200, prepared.text
    response = client.post(
        "/api/v1/tasks/review-targets",
        headers=headers,
        json=dict(
            schema_version=1,
            idempotency_key="no-review-policy",
            task_id=prepare["origin"]["task_id"],
            expected_revision=prepare["origin"]["task_revision"],
            attempt_id=prepared.json()["attempt"]["attempt_id"],
            expected_review_policy_revision=1,
        ),
    )
    assert response.status_code == 503, response.text
    assert response.json()["reason"] == "Review policy is not configured"


@pytest.mark.parametrize("missing", ["criterion", "review-step"])
def test_completion_does_not_infer_unproduced_gates(completion_environment, missing):
    engine, client, headers, config, dispatch, root, storage = completion_environment
    task_id = dispatch["origin"]["task_id"]
    current = client.get("/api/v1/tasks/" + task_id).json()
    criteria = [item["text"] for item in current["success_conditions"]]
    workflow = current["workflow"]
    if missing == "criterion":
        criteria.append("A separate condition still needs proof")
    else:
        workflow["steps"].append(
            {"step_id": "independent-inspection", "kind": "REVIEW", "dependencies": ["verify"]}
        )
    revised = client.post(
        "/api/v1/tasks/revise",
        headers=headers,
        json=dict(
            schema_version=1,
            idempotency_key="additional-gate",
            task_id=task_id,
            expected_revision=current["revision"],
            expected_policy_revision=dispatch["expected_policy_revision"],
            reason="Retain every required gate",
            success_conditions=criteria,
            workflow=workflow,
        ),
    )
    assert revised.status_code == 200, revised.text
    admitted = client.post(
        "/api/v1/tasks/admit",
        headers=headers,
        json=dict(
            schema_version=1,
            idempotency_key="additional-gate-admit",
            task_id=task_id,
            expected_revision=revised.json()["task"]["revision"],
            expected_policy_revision=dispatch["expected_policy_revision"],
            reason="Admit deterministic proof with the remaining gate",
        ),
    )
    assert admitted.status_code == 200, admitted.text
    dispatch = dispatch | {
        "origin": dispatch["origin"] | {"task_revision": admitted.json()["task"]["revision"]}
    }
    environment = engine, client, headers, config, dispatch, root, storage
    _, proof, command = selected_candidate(environment)
    assert proof["passed"]
    response = client.post("/api/v1/tasks/complete", headers=headers, json=command)
    assert response.status_code == 503, response.text
    assert client.get("/api/v1/tasks/" + task_id).json()["state"] == "READY"


def test_completion_rollback_keeps_same_candidate_and_operation_identity(
    completion_environment, monkeypatch
):
    from sqlalchemy import func

    from journeon import work_completion
    from journeon.models import OutboxEvent, Receipt, TaskRevision

    engine, client, headers, _, _, _, _ = completion_environment
    _, _, command = selected_candidate(completion_environment)
    actual = work_completion.commit_task

    def interrupt_after_receipt(*args, **kwargs):
        actual(*args, **kwargs)
        raise RuntimeError("Disposable interruption before completion commit")

    with transaction(engine) as db:
        before = [
            db.scalar(select(func.count()).select_from(model))
            for model in (TaskRevision, Receipt, OutboxEvent)
        ]
    with monkeypatch.context() as patch:
        patch.setattr(work_completion, "commit_task", interrupt_after_receipt)
        with pytest.raises(RuntimeError, match="Disposable interruption before completion commit"):
            client.post("/api/v1/tasks/complete", headers=headers, json=command)
    assert client.get("/api/v1/tasks/" + command["task_id"]).json()["state"] == "READY"
    with transaction(engine) as db:
        assert [
            db.scalar(select(func.count()).select_from(model))
            for model in (TaskRevision, Receipt, OutboxEvent)
        ] == before
    response = client.post("/api/v1/tasks/complete", headers=headers, json=command)
    assert response.status_code == 200, response.text
    assert (
        client.post("/api/v1/tasks/complete", headers=headers, json=command).json()
        == response.json()
    )


def test_target_and_completion_replays_authorize_prior_receipt_before_decoding(
    completion_environment,
):
    import json

    from sqlalchemy import text

    from journeon.models import Receipt

    engine, client, headers, _, _, _, _ = completion_environment
    target, _, command = selected_candidate(completion_environment)
    select_command = dict(
        schema_version=1,
        idempotency_key="selected-candidate",
        task_id="another-task",
        expected_revision=target["manifest"]["task"]["revision"],
        attempt_id=target["manifest"]["attempt_id"],
        expected_review_policy_revision=1,
    )
    with transaction(engine) as db:
        receipt = db.scalar(select(Receipt).where(Receipt.command == "task.review.select.v1"))
        original = receipt.result
        identity = receipt.id
        db.execute(
            text("UPDATE operation_receipts SET result='not-json' WHERE id=:id"), {"id": identity}
        )
        db.get(AccessGrant, "complete:task.review.select").enabled = False
    denied = client.post("/api/v1/tasks/review-targets", headers=headers, json=select_command)
    assert denied.status_code == 403, denied.text
    with transaction(engine) as db:
        db.execute(
            text("UPDATE operation_receipts SET result=:result WHERE id=:id"),
            {"id": identity, "result": json.dumps(original)},
        )
        db.get(AccessGrant, "complete:task.review.select").enabled = True
    completed = client.post("/api/v1/tasks/complete", headers=headers, json=command)
    assert completed.status_code == 200, completed.text
    with transaction(engine) as db:
        db.execute(
            text("UPDATE operation_receipts SET result='not-json' WHERE id=:id"),
            {"id": completed.json()["operation_id"]},
        )
        db.get(AccessGrant, "complete:task.complete").enabled = False
    replay = client.post(
        "/api/v1/tasks/complete", headers=headers, json=command | {"task_id": "another-task"}
    )
    assert replay.status_code == 403, replay.text


def test_completed_candidate_backup_retains_history_without_activation(
    completion_environment, tmp_path
):
    import sqlite3
    from pathlib import Path

    from journeon.database import create_database
    from journeon.operations import doctor, snapshot_database, validate_snapshot

    engine, client, headers, _, _, _, _ = completion_environment
    _, _, command = selected_candidate(completion_environment)
    response = client.post("/api/v1/tasks/complete", headers=headers, json=command)
    assert response.status_code == 200, response.text
    tables = (
        "review_policy_revisions",
        "review_targets",
        "tasks",
        "task_revisions",
        "operation_receipts",
        "outbox_events",
    )
    with engine.connect() as db:
        original = {
            name: db.exec_driver_sql('SELECT * FROM "' + name + '"').all() for name in tables
        }
    destination = tmp_path / "completion-snapshot"
    snapshot_database(Path(engine.url.database), destination)
    assert validate_snapshot(destination)["schema"] == "0016_identity_sessions"
    copy = destination / "database.sqlite"
    assert doctor(copy)["schema"] == "CURRENT"
    with sqlite3.connect("file:" + str(copy) + "?mode=ro", uri=True) as retained:
        for name, rows in original.items():
            assert retained.execute('SELECT * FROM "' + name + '"').fetchall() == [
                tuple(row) for row in rows
            ]
    with pytest.raises(ValueError):
        with create_database(copy).connect():
            pytest.fail("Snapshot inspection admitted a writable completion store")
