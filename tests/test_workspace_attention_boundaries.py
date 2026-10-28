# SPDX-License-Identifier: AGPL-3.0-only
import json
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from test_production_instructions import official_effect
from test_workspace_discovery_pages import grant, revoke
from test_workspace_discovery_work import actor_for
from test_workspace_durable_resolution import read_state
from test_workspace_search_attention import attention_page, dismiss, search
from test_workspace_search_attention import failed_work as failed_work
from workspace_durable_helpers import enrolled_owner as enrolled_owner
from workspace_durable_helpers import genuine_durable_work as genuine_durable_work
from workspace_durable_helpers import genuine_instruction_scope as genuine_instruction_scope
from workspace_durable_helpers import genuine_project_task as genuine_project_task

from journeon.api import create_app
from journeon.contracts import DomainError, NotificationDismiss
from journeon.database import transaction
from journeon.job_contracts import JobConfiguration
from journeon.jobs import JobService
from journeon.models import Attention, Job, NotificationPresentation, OutboxEvent, Receipt
from journeon.notification_presentation import NotificationPresentationService
from journeon.project_instructions import ProjectInstructionService, navigation


def effects(owner):
    with transaction(owner.engine) as db:
        return tuple(
            db.scalar(select(func.count()).select_from(model))
            for model in (NotificationPresentation, Receipt, OutboxEvent)
        )


def test_presentation_stale_inputs_recurring_owner_source_and_historical_receipt(failed_work):
    fixture, admitted = failed_work
    owner = fixture[0]
    original = attention_page(owner)["items"][0]
    command, accepted = dismiss(owner, original)
    assert accepted.status_code == 200
    before = effects(owner)
    for changes in (
        {"expected_revision": 0},
        {"expected_revision": 1, "expected_source_revision": original["source_revision"] - 1},
    ):
        _, rejected = dismiss(owner, original, key="stale-command", **changes)
        assert rejected.status_code == 409
    _, changed = dismiss(owner, original, expected_source_revision=original["source_revision"] + 1)
    assert changed.status_code == 409
    assert changed.json()["code"] == "IDEMPOTENCY_CONFLICT"
    assert effects(owner) == before
    from journeon.jobs import attention

    # Owner-level recurrence contract with the existing caller version precondition.
    # This is not a public retry of a terminal Job.
    with transaction(owner.engine) as db:
        job = db.get(Job, admitted["job_id"])
        job.revision += 1
        attention(db, job, original["reason"])
    repeated = attention_page(owner)["items"][0]
    assert repeated["attention_id"] == original["attention_id"]
    assert repeated["occurrences"] == original["occurrences"] + 1
    assert repeated["source_revision"] > original["source_revision"]
    assert repeated["canonical_disposition"] == "OPEN"
    assert repeated["presentation_disposition"] == "DISMISSED"
    assert repeated["presentation_source_revision"] == original["source_revision"]
    before = effects(owner)
    _, stale = dismiss(
        owner, repeated, key="stale-source", expected_source_revision=original["source_revision"]
    )
    assert stale.status_code == 409
    assert effects(owner) == before
    replay = owner.client.post("/api/v1/notifications/dismiss", headers=owner.headers, json=command)
    assert replay.status_code == 200
    assert replay.json() == accepted.json()
    _, second = dismiss(owner, repeated, key="current-source")
    assert second.status_code == 200
    for receipt in (accepted.json(), second.json()):
        assert owner.client.get(f"/api/v1/operations/{receipt['operation_id']}").json() == receipt
    with pytest.raises(IntegrityError):
        with transaction(owner.engine) as db:
            db.execute(text("UPDATE notification_presentations SET source_revision=999"))
    with pytest.raises(IntegrityError):
        with transaction(owner.engine) as db:
            db.execute(text("DELETE FROM notification_presentations"))


@pytest.mark.parametrize("change", ["source", "grant", "root", "session"])
def test_commit_boundary_race_rolls_back_presentation_receipt_and_event(
    failed_work, monkeypatch, change
):
    fixture, _ = failed_work
    owner, config = fixture[:2]
    item = attention_page(owner)["items"][0]
    actor = actor_for(owner)
    command = NotificationDismiss(
        idempotency_key="race-dismissal",
        attention_id=item["attention_id"],
        expected_revision=0,
        expected_source_revision=item["source_revision"],
    )
    before = effects(owner)
    import journeon.notification_presentation as presentation
    from journeon.models import AccessGrant, BrowserSession, InstructionRoot

    source = presentation.source_in
    calls = 0

    def raced(db, current, identity, engine, configuration):
        nonlocal calls
        calls += 1
        if calls == 2:
            if change == "source":
                db.get(Job, item["source"]["job_id"]).revision += 1
            elif change == "grant":
                db.get(AccessGrant, fixture[3]["job.read"]["grant"]["grant_id"]).enabled = False
            elif change == "root":
                db.get(InstructionRoot, "durable-source").enabled = False
            else:
                db.get(BrowserSession, actor.authentication_ref).revoked = True
            db.flush()
        return source(db, current, identity, engine, configuration)

    monkeypatch.setattr(presentation, "source_in", raced)
    with pytest.raises(DomainError) as denied:
        NotificationPresentationService(owner.engine, config).dismiss(actor, command)
    assert denied.value.code in {
        "REVISION_CONFLICT",
        "PERMISSION_DENIED",
        "AUTHENTICATION_REQUIRED",
    }
    assert effects(owner) == before
    assert attention_page(owner)["items"][0] == item


def test_hidden_history_receipts_and_actions_do_not_decode_or_leak(failed_work):
    fixture, _ = failed_work
    owner, _, _, grants, _ = fixture
    item = attention_page(owner)["items"][0]
    command, accepted = dismiss(owner, item)
    assert accepted.status_code == 200
    receipt = accepted.json()
    before_reads = read_state(owner)
    events = owner.client.post("/api/v1/events/replay", headers=owner.headers, json={"limit": 100})
    assert events.status_code == 200
    while events.json()["truncated"]:
        events = owner.client.post(
            "/api/v1/events/replay",
            headers=owner.headers,
            json={"limit": 100, "cursor": events.json()["cursor"]},
        )
        assert events.status_code == 200
    assert read_state(owner) == before_reads
    revoke(owner, grants["job.read"]["grant"])
    with transaction(owner.engine) as db:
        db.execute(
            text("UPDATE attention SET history='invalid-json' WHERE id=:id"),
            {"id": item["attention_id"]},
        )
        db.execute(
            text("UPDATE operation_receipts SET result='invalid-json' WHERE id=:id"),
            {"id": receipt["operation_id"]},
        )
    before = effects(owner)
    view = attention_page(owner)
    assert view["items"] == [] and not view["has_more"]
    assert item["attention_id"] not in json.dumps(view)
    assert search(owner, "FAILED", ("JOB",)).json()["items"] == []
    denied = owner.client.post(
        "/api/v1/notifications/dismiss",
        headers=owner.headers,
        json=command | {"expected_source_revision": 999},
    )
    assert denied.status_code == 403
    assert owner.client.get(f"/api/v1/operations/{receipt['operation_id']}").status_code == 403
    assert effects(owner) == before


@pytest.fixture
def navigation_job(genuine_instruction_scope):
    owner, config, _, _, _, original_base = genuine_instruction_scope
    created = owner.client.post(
        "/api/v1/projects",
        headers=owner.headers,
        json={
            "schema_version": 1,
            "idempotency_key": "navigation-source-project",
            "name": "Navigation recovery project",
            "expected_policy_revision": 1,
            "provider_mode": "LOCAL_ONLY",
        },
    )
    assert created.status_code == 200
    project = created.json()["project"]["project_id"]
    base = original_base | {
        "INDEX.md": original_base["INDEX.md"].replace("# Navigation", "# Instruction navigation")
    }
    for capability in (
        "project.read",
        "project.instruction.bind",
        "project.instruction.read",
        "project.instruction.propose",
        "project.instruction.accept",
        "project.instruction.receipt.read",
        "project.instruction.evaluate",
        "project.instruction.restore",
    ):
        grant(owner, capability, project, "navigation-" + capability)
    config = config.model_copy(
        update={
            "jobs": JobConfiguration(
                pending_count=10,
                pending_bytes=1048576,
                concurrency=1,
                lease_seconds=5,
                poll_seconds=1,
                retry_seconds=1,
                max_attempts=2,
            )
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
        from journeon.instruction_files import tree_hash

        rebound = client.post(
            f"/api/v1/projects/{project}/instructions/binding",
            headers=owner.headers,
            json={
                "idempotency_key": "navigation-base",
                "project_id": project,
                "expected_project_revision": 1,
                "expected_binding_revision": 0,
                "root_id": "durable-environment",
                "expected_root_revision": 1,
                "expected_tree_hash": tree_hash({}),
                "owner": "ENVIRONMENT",
                "documents": [{"path": key, "content": value} for key, value in base.items()],
                "required_fragments": ["rules.md"],
                "reason": "Bind canonical navigation metadata",
            },
        )
        assert rebound.status_code == 200, rebound.text
        official_effect(
            client,
            owner.headers,
            {
                "kind": "project.instructions.policy.configure.v1",
                "idempotency_key": "navigation-policy",
                "project_id": project,
                "expected_project_revision": 1,
                "expected_binding_revision": 1,
                "expected_root_revision": 1,
                "expected_policy_revision": 1,
                "policy": {
                    "authorized_categories": ["NAVIGATION_REPAIR"],
                    "navigation_repairs": True,
                    "independent_review": True,
                    "require_confirmation": False,
                    "required_evals": ["instruction-boundaries-v1"],
                },
            },
        )
        from journeon.instruction_files import tree_hash

        target = base | {"INDEX.md": navigation(base, ["rules.md"])}
        proposed = client.post(
            f"/api/v1/projects/{project}/instructions/candidates",
            headers=owner.headers,
            json={
                "idempotency_key": "attention-navigation",
                "project_id": project,
                "expected_revision": 1,
                "expected_tree_hash": tree_hash(base),
                "documents": [{"path": key, "content": value} for key, value in target.items()],
                "required_fragments": ["rules.md"],
                "reason": "Restore canonical navigation",
                "source_refs": ["canonical-tree"],
                "category": "NAVIGATION_REPAIR",
            },
        )
        assert proposed.status_code == 200, proposed.text
        assert proposed.json()["automatic"]
        yield configured, config, project, proposed.json()


def test_instruction_job_search_hides_changed_configuration_before_match(navigation_job):
    owner, config, _, proposed = navigation_job
    assert search(owner, "QUEUED", ("JOB",)).json()["items"]
    with TestClient(
        create_app(
            owner.engine,
            browser_auth=owner.client.app.state.browser_auth,
            instructions=config.model_copy(update={"roots": []}),
        ),
        base_url="https://example.test",
        cookies=owner.client.cookies,
    ) as client:
        denied = client.get(f"/api/v1/jobs/{proposed['job_id']}")
        assert denied.status_code == 404
        assert denied.json()["code"] == "NOT_FOUND"
        response = search(replace(owner, client=client), "QUEUED", ("JOB",))
    assert response.status_code == 200
    assert response.json()["items"] == []


def test_actual_publication_recovery_resolves_source_and_preserves_old_presentation(
    navigation_job, monkeypatch
):
    owner, config, project, proposed = navigation_job
    service = JobService(owner.engine, config)
    claim = service.claim()
    assert claim is not None

    def interrupted(*args, **kwargs):
        raise OSError("Synthetic publication interruption")

    with monkeypatch.context() as interrupted_publication:
        interrupted_publication.setattr(ProjectInstructionService, "publish", interrupted)
        service.execute(claim)
    item = attention_page(owner)["items"][0]
    assert item["source"]["effect"] == "UNKNOWN"
    assert item["canonical_disposition"] == "OPEN"
    command, accepted = dismiss(owner, item)
    assert accepted.status_code == 200
    recovery = owner.client.post(
        f"/api/v1/projects/{project}/instructions/recovery",
        headers=owner.headers,
        json={"project_id": project},
    )
    assert recovery.status_code == 200
    official_effect(
        owner.client,
        owner.headers,
        recovery.json()
        | {
            "kind": "project.instructions.recover.v1",
            "idempotency_key": "settle-attention",
            "disposition": "FINISH_TARGET",
        },
    )
    settled = attention_page(owner)["items"][0]
    assert settled["canonical_disposition"] == "RESOLVED"
    assert settled["source"]["effect"] == "COMMITTED"
    assert settled["source_revision"] > item["source_revision"]
    assert settled["presentation_disposition"] == "DISMISSED"
    assert settled["presentation_source_revision"] == item["source_revision"]
    assert settled["actions"] == []
    assert attention_page(owner, canonical_disposition="OPEN")["items"] == []
    before = effects(owner)
    _, stale = dismiss(
        owner,
        settled,
        key="stale-after-resolution",
        expected_source_revision=item["source_revision"],
    )
    assert stale.status_code == 409
    assert effects(owner) == before
    replayed = owner.client.post(
        "/api/v1/notifications/dismiss", headers=owner.headers, json=command
    )
    assert replayed.status_code == 200
    assert replayed.json() == accepted.json()


def test_two_concurrent_duplicates_create_one_presentation_version(failed_work):
    from concurrent.futures import ThreadPoolExecutor

    fixture, _ = failed_work
    owner, config = fixture[:2]
    item = attention_page(owner)["items"][0]
    actor = actor_for(owner)
    command = NotificationDismiss(
        idempotency_key="concurrent-dismissal",
        attention_id=item["attention_id"],
        expected_revision=0,
        expected_source_revision=item["source_revision"],
    )
    service = NotificationPresentationService(owner.engine, config)
    before = effects(owner)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: service.dismiss(actor, command), range(2)))
    assert results[0] == results[1]
    assert effects(owner) == tuple(count + 1 for count in before)


def test_receipt_foreign_inner_identity_fails_after_current_authority(failed_work):
    fixture, _ = failed_work
    owner = fixture[0]
    item = attention_page(owner)["items"][0]
    _, accepted = dismiss(owner, item)
    assert accepted.status_code == 200
    receipt = accepted.json()
    for field, value in (
        ("attention_id", "foreign-attention"),
        ("principal_id", "foreign-human"),
        ("target_id", "foreign-job"),
        ("revision", 999),
        ("source_revision", 999),
    ):
        with transaction(owner.engine) as db:
            db.get(Receipt, receipt["operation_id"]).result = receipt | {field: value}
        response = owner.client.get(f"/api/v1/operations/{receipt['operation_id']}")
        assert response.status_code == 503, response.text
        if isinstance(value, str):
            assert value not in response.text
    with transaction(owner.engine) as db:
        db.get(Receipt, receipt["operation_id"]).result = receipt
    revoke(owner, fixture[3]["job.read"]["grant"])
    with transaction(owner.engine) as db:
        db.get(Receipt, receipt["operation_id"]).result = receipt | {
            "attention_id": "foreign-attention"
        }
    assert owner.client.get(f"/api/v1/operations/{receipt['operation_id']}").status_code == 403


@pytest.mark.parametrize("transition", ["authority", "exhausted"])
def test_actual_claim_and_reconcile_failures_advance_attention_source(
    navigation_job, transition, monkeypatch
):
    owner, config, project, proposed = navigation_job
    before = owner.client.get(f"/api/v1/jobs/{proposed['job_id']}").json()
    service = JobService(owner.engine, config)
    if transition == "authority":
        from journeon.models import AccessGrant

        with transaction(owner.engine) as db:
            grant_row = db.scalar(
                select(AccessGrant).where(
                    AccessGrant.capability == "project.instruction.evaluate",
                    AccessGrant.resource_id == project,
                )
            )
            selected = {"grant_id": grant_row.id, "revision": grant_row.revision}
        revoke(owner, selected)
        assert service.claim() is None
    else:
        first = service.claim()
        assert first is not None
        service.reconcile(first.job_id, expected=first)
        from journeon.sessions import utc_seconds

        later = utc_seconds() + config.jobs.retry_seconds + 1
        monkeypatch.setattr("journeon.jobs.utc_seconds", lambda: later)
        second = service.claim()
        assert second is not None
        service.reconcile(second.job_id, expected=second)
    item = attention_page(owner)["items"][0]
    assert item["source_revision"] > before["revision"]
    assert item["reason"] == (
        "CURRENT_AUTHORITY_REQUIRED" if transition == "authority" else "RETRIES_EXHAUSTED"
    )
    with transaction(owner.engine) as db:
        assert (
            db.get(Attention, item["attention_id"]).history[-1]["revision"]
            == item["source_revision"]
        )


def test_fresh_same_human_login_reconciles_original_presentation_without_retry(failed_work):
    from test_workspace_identity_security import login_again
    from test_workspace_session_controls import context

    from journeon.instructions import digest
    from journeon.passkeys import STANDARD_PASSKEY_POLICY, PasskeyService

    fixture, _ = failed_work
    owner, config = fixture[:2]
    item = attention_page(owner)["items"][0]
    command, accepted = dismiss(owner, item)
    assert accepted.status_code == 200
    original_session = context(owner)["session"]["session_id"]
    before = effects(owner)
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
    ) as client:
        fresh = replace(owner, client=client, headers=dict(owner.headers))
        login_again(fresh)
        current = context(fresh)
        assert current["session"]["session_id"] != original_session
        resolved = client.post(
            "/api/v1/operations/resolve",
            headers=fresh.headers,
            json={
                "schema_version": 1,
                "command": "notification.dismiss.v1",
                "idempotency_key": command["idempotency_key"],
                "payload_digest": digest(
                    {key: value for key, value in command.items() if key != "idempotency_key"}
                ),
                "scope": {"attention_id": item["attention_id"]},
                "store_incarnation": current["store_incarnation"],
            },
        )
        assert resolved.status_code == 200, resolved.text
        assert resolved.json()["status"] == "OBSERVED_RECEIPT"
        assert resolved.json()["receipt"] == accepted.json()
        assert attention_page(fresh)["items"][0]["presentation_revision"] == 1
    assert effects(owner) == before


@pytest.mark.parametrize("outcome", ["unknown", "evidence_denied"])
def test_actual_task_settlement_advances_attention_source(
    genuine_durable_work, monkeypatch, outcome
):
    from test_workspace_discovery_work import dispatch

    from journeon import executions
    from journeon.execution_process import ExecutionInterrupted
    from journeon.executions import ExecutionService
    from journeon.task_dispatch import TaskDispatchService

    owner, config, _, grants, _ = genuine_durable_work
    admitted = dispatch(genuine_durable_work, "settlement-source-version")
    if outcome == "unknown":
        original = executions.run_local

        def lose_completion(*args, **kwargs):
            actual = original(*args, **kwargs)
            raise ExecutionInterrupted(
                {"output": actual["output"], "launcher_exit_code": actual["launcher_exit_code"]}
            )

        monkeypatch.setattr(executions, "run_local", lose_completion)
    service = ExecutionService(owner.engine, config)
    worker = JobService(owner.engine, config, executions=service)
    claim = worker.claim()
    assert claim is not None
    with transaction(owner.engine) as db:
        revision = db.get(Job, admitted["job_id"]).revision
    original_settle = TaskDispatchService.settle
    if outcome == "evidence_denied":
        # Retain a completed execution at the existing settlement interruption boundary.
        monkeypatch.setattr(TaskDispatchService, "settle", lambda *args, **kwargs: False)
    try:
        worker.execute(claim)
    finally:
        service.shutdown()
    if outcome == "evidence_denied":
        monkeypatch.setattr(TaskDispatchService, "settle", original_settle)
        revoke(owner, grants["execution.start"]["grant"])
        worker.reconcile(claim.job_id, expected=claim)
    item = attention_page(owner)["items"][0]
    assert item["source_revision"] > revision
    assert item["reason"] == (
        "EXECUTION_RECONCILIATION_REQUIRED"
        if outcome == "unknown"
        else "EVIDENCE_PUBLICATION_BLOCKED"
    )
    with transaction(owner.engine) as db:
        assert (
            db.get(Attention, item["attention_id"]).history[-1]["revision"]
            == item["source_revision"]
        )


def test_actual_running_execution_reconciliation_advances_attention_source(
    genuine_durable_work, monkeypatch
):
    import threading

    from test_workspace_discovery_work import dispatch

    from journeon import executions
    from journeon.executions import ExecutionService

    owner, config = genuine_durable_work[:2]
    admitted = dispatch(genuine_durable_work, "running-reconciliation-source")
    entered, release = threading.Event(), threading.Event()
    original = executions.run_local

    def interrupted_owner_boundary(*args, **kwargs):
        entered.set()
        assert release.wait(45), "Reconciliation boundary was not released"
        return original(*args, **kwargs)

    monkeypatch.setattr(executions, "run_local", interrupted_owner_boundary)
    service = ExecutionService(owner.engine, config)
    worker = JobService(owner.engine, config, executions=service)
    claim = worker.claim()
    assert claim is not None
    with transaction(owner.engine) as db:
        revision = db.get(Job, admitted["job_id"]).revision
    running = threading.Thread(target=worker.execute, args=(claim,))
    running.start()
    try:
        assert entered.wait(45), "Execution did not reach the reconciliation boundary"
        worker.reconcile(claim.job_id, expected=claim)
    finally:
        release.set()
        running.join(45)
        service.shutdown()
    assert not running.is_alive()
    item = attention_page(owner)["items"][0]
    assert item["reason"] == "EXECUTION_RECONCILIATION_REQUIRED"
    assert item["source_revision"] > revision
    with transaction(owner.engine) as db:
        assert (
            db.get(Attention, item["attention_id"]).history[-1]["revision"]
            == item["source_revision"]
        )


def test_advertised_presentation_action_invokes_owner_and_tracks_current_grant(failed_work):
    from journeon.registry import COMMANDS

    fixture, _ = failed_work
    owner = fixture[0]
    item = attention_page(owner)["items"][0]
    assert item["source"]["state"] == "FAILED"
    assert len(item["actions"]) == 1
    action = item["actions"][0]
    assert action == {
        "operation": "notification.dismiss.v1",
        "target_id": item["attention_id"],
        "arguments": {
            "attention_id": item["attention_id"],
            "expected_revision": 0,
            "expected_source_revision": item["source_revision"],
        },
    }
    registered = COMMANDS[action["operation"]]
    assert registered.owner == "jobs"
    command = registered.input_model.model_validate(
        {"schema_version": 1, "idempotency_key": "follow-advertised-action"} | action["arguments"]
    )
    response = owner.client.post(
        "/api/v1/notifications/dismiss",
        headers=owner.headers,
        json=command.model_dump(mode="json"),
    )
    assert response.status_code == 200, response.text
    assert response.json()["command"] == action["operation"]
    assert response.json()["attention_id"] == action["target_id"]
    assert attention_page(owner)["items"][0]["canonical_disposition"] == "OPEN"
    revoke(owner, fixture[3]["job.receipt.read"]["grant"])
    remaining = attention_page(owner)["items"][0]
    assert remaining["attention_id"] == item["attention_id"]
    assert remaining["actions"] == []
    before = effects(owner)
    denied = owner.client.post(
        "/api/v1/notifications/dismiss",
        headers=owner.headers,
        json=command.model_dump(mode="json"),
    )
    assert denied.status_code == 403
    assert denied.json()["code"] == "PERMISSION_DENIED"
    assert effects(owner) == before


@pytest.mark.parametrize("same_key", [True, False])
def test_real_fresh_session_presentation_race_keeps_one_immutable_version(failed_work, same_key):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from test_workspace_identity_security import login_again

    from journeon.passkeys import STANDARD_PASSKEY_POLICY, PasskeyService

    fixture, _ = failed_work
    owner, config = fixture[:2]
    item = attention_page(owner)["items"][0]
    original_actor = actor_for(owner)
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
    ) as client:
        fresh = replace(owner, client=client, headers=dict(owner.headers))
        login_again(fresh)
        fresh_actor = actor_for(fresh)
        assert original_actor.authentication_ref != fresh_actor.authentication_ref
        assert original_actor.principal_id == fresh_actor.principal_id
        commands = [
            NotificationDismiss(
                idempotency_key="session-race" if same_key else f"session-race-{index}",
                attention_id=item["attention_id"],
                expected_revision=0,
                expected_source_revision=item["source_revision"],
            )
            for index in range(2)
        ]
        start = threading.Barrier(2)
        service = NotificationPresentationService(owner.engine, config)
        before = effects(owner)

        def invoke(pair):
            actor, command = pair
            start.wait(timeout=45)
            try:
                return service.dismiss(actor, command)
            except DomainError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(invoke, zip([original_actor, fresh_actor], commands, strict=True))
            )
        if same_key:
            assert results[0] == results[1]
            assert not isinstance(results[0], str)
        else:
            assert sum(result == "REVISION_CONFLICT" for result in results) == 1
            assert sum(not isinstance(result, str) for result in results) == 1
        assert effects(owner) == tuple(value + 1 for value in before)
        current = attention_page(fresh)["items"][0]
        assert current["presentation_revision"] == 1
        assert current["canonical_disposition"] == "OPEN"
        assert current["source"] == item["source"]
