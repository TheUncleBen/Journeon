# SPDX-License-Identifier: AGPL-3.0-only
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import Request
from sqlalchemy import func, select, text
from test_production_instructions import candidate_command, official_effect
from test_workspace_session_controls import context
from workspace_durable_helpers import (
    enrolled_owner as enrolled_owner,
)
from workspace_durable_helpers import (
    genuine_durable_work as genuine_durable_work,
)
from workspace_durable_helpers import (
    genuine_instruction_scope as genuine_instruction_scope,
)
from workspace_durable_helpers import (
    genuine_project_task as genuine_project_task,
)

from journeon.contracts import AttemptPrepare, ExecutionStart
from journeon.database import transaction
from journeon.instruction_contracts import InstructionPropose, ProjectionCommand
from journeon.instructions import digest
from journeon.job_contracts import TaskDispatch
from journeon.models import (
    Attempt,
    BrowserSession,
    Execution,
    InstructionCandidate,
    InstructionPublication,
    Job,
    OutboxEvent,
    Receipt,
)


def original_query(owner, name, command, scope, *, include_key=False):
    return {
        "schema_version": 1,
        "command": name,
        "idempotency_key": command.idempotency_key,
        "payload_digest": digest(
            command.model_dump(mode="json", exclude=set() if include_key else {"idempotency_key"})
        ),
        "scope": scope,
        "store_incarnation": context(owner)["store_incarnation"],
    }


def read_state(owner):
    session_id = context(owner)["session"]["session_id"]
    with transaction(owner.engine) as db:
        session = db.get(BrowserSession, session_id)
        counts = tuple(
            db.scalar(select(func.count()).select_from(model))
            for model in (Receipt, OutboxEvent, Attempt, Execution, Job, InstructionPublication)
        )
        return counts, session.last_activity, session.absolute_deadline


def resolve_without_effect(owner, query, expected=200):
    before = read_state(owner)
    response = owner.client.post("/api/v1/operations/resolve", headers=owner.headers, json=query)
    assert response.status_code == expected
    assert read_state(owner) == before
    if expected == 200:
        assert response.json()["absence_is_final"] is False
    return response


def check_original_binding(owner, query):
    resolve_without_effect(owner, query | {"payload_digest": "a" * 64}, 409)
    changed = resolve_without_effect(owner, query | {"store_incarnation": "prior-incarnation"})
    assert changed.json()["status"] == "RECONCILIATION_REQUIRED"


def revoke(owner, grant):
    official_effect(
        owner.client,
        owner.headers,
        {
            "kind": "permission.grant.revoke.v1",
            "schema_version": 1,
            "idempotency_key": "remove-" + grant["capability"],
            "grant_id": grant["grant_id"],
            "expected_revision": grant["revision"],
        },
    )


def test_original_candidate_requires_current_instruction_configuration(genuine_instruction_scope):
    from journeon.contracts import DomainError, OperationIdentityResolve
    from journeon.permissions import AuthenticatedContext
    from journeon.receipts import OperationService

    owner, _, project, _, _, documents = genuine_instruction_scope
    command = InstructionPropose.model_validate(candidate_command(project, documents))
    query = original_query(
        owner, "project.instructions.propose.v1", command, {"project_id": project}, include_key=True
    )
    admitted = owner.client.post(
        f"/api/v1/projects/{project}/instructions/candidates",
        headers=owner.headers,
        json=command.model_dump(mode="json"),
    )
    assert admitted.status_code == 200
    assert resolve_without_effect(owner, query).json()["status"] == "OBSERVED_UNKNOWN"
    session_id = context(owner)["session"]["session_id"]
    with transaction(owner.engine) as db:
        session = db.get(BrowserSession, session_id)
        actor = AuthenticatedContext(session.principal_id, session.principal_epoch, session.id)
    with pytest.raises(DomainError) as rejected:
        OperationService(owner.engine).resolve(
            actor, OperationIdentityResolve.model_validate(query)
        )
    assert rejected.value.code == "DEPENDENCY_UNAVAILABLE"


@pytest.mark.parametrize("state", ["current", "legacy", "corrupt", "denied"])
def test_original_restore_identity_observes_its_real_candidate(genuine_instruction_scope, state):
    from journeon.instruction_contracts import InstructionRestore
    from journeon.instruction_files import tree_hash

    owner, _, project, _, _, documents = genuine_instruction_scope
    command = InstructionRestore(
        idempotency_key="original-restore",
        project_id=project,
        revision=1,
        expected_revision=1,
        expected_tree_hash=tree_hash(documents),
        reason="Restore retained instructions",
    )
    query = original_query(
        owner, "project.instructions.restore.v1", command, {"project_id": project}, include_key=True
    )
    response = owner.client.post(
        f"/api/v1/projects/{project}/instructions/restore",
        headers=owner.headers,
        json=command.model_dump(mode="json"),
    )
    assert response.status_code == 200
    result = resolve_without_effect(owner, query).json()
    assert result["status"] == "OBSERVED_UNKNOWN"
    assert result["evidence_id"] == response.json()["candidate_id"]
    check_original_binding(owner, query)
    replay = owner.client.post(
        f"/api/v1/projects/{project}/instructions/restore",
        headers=owner.headers,
        json=command.model_dump(mode="json"),
    )
    assert replay.status_code == 200
    assert replay.json() == response.json()
    from journeon.project_instructions import restored_proposal

    collision = owner.client.post(
        f"/api/v1/projects/{project}/instructions/candidates",
        headers=owner.headers,
        json=restored_proposal(command, documents, ["rules.md"]).model_dump(mode="json"),
    )
    assert collision.status_code == 409
    if state != "current":
        if state == "denied":
            revoke(owner, genuine_instruction_scope[4]["project.instruction.receipt.read"]["grant"])
        with transaction(owner.engine) as db:
            row = db.get(InstructionCandidate, result["evidence_id"])
            trigger_sql = db.scalar(
                text(
                    "SELECT sql FROM sqlite_master "
                    "WHERE name='immutable_instruction_candidates_update'"
                )
            )
            db.execute(text("DROP TRIGGER immutable_instruction_candidates_update"))
            altered = dict(row.snapshot)
            if state == "legacy":
                altered.pop("original_command")
                altered.pop("original_restore")
            else:
                altered["original_restore"] = {
                    **altered["original_restore"],
                    "reason": "Changed origin",
                }
            row.snapshot = altered
            db.flush()
            db.execute(text(trigger_sql))
            assert (
                db.scalar(
                    text(
                        "SELECT sql FROM sqlite_master "
                        "WHERE name='immutable_instruction_candidates_update'"
                    )
                )
                == trigger_sql
            )
        observed = resolve_without_effect(
            owner, query, {"legacy": 200, "corrupt": 503, "denied": 403}[state]
        )
        if state == "legacy":
            assert observed.json()["status"] == "NOT_OBSERVED"


def test_normal_proposal_does_not_prove_original_restore(genuine_instruction_scope):
    owner, _, project, _, _, documents = genuine_instruction_scope
    command = InstructionPropose.model_validate(candidate_command(project, documents))
    response = owner.client.post(
        f"/api/v1/projects/{project}/instructions/candidates",
        headers=owner.headers,
        json=command.model_dump(mode="json"),
    )
    assert response.status_code == 200
    query = original_query(
        owner, "project.instructions.restore.v1", command, {"project_id": project}, include_key=True
    )
    assert resolve_without_effect(owner, query).json()["status"] == "NOT_OBSERVED"


@pytest.mark.parametrize("origin", ["restore", "legacy-proposal"])
def test_candidate_requires_its_exact_recorded_original_command(genuine_instruction_scope, origin):
    from journeon.instruction_contracts import InstructionRestore
    from journeon.instruction_files import tree_hash
    from journeon.project_instructions import restored_proposal

    owner, _, project, _, _, documents = genuine_instruction_scope
    if origin == "restore":
        restored = InstructionRestore(
            idempotency_key="exact-original",
            project_id=project,
            revision=1,
            expected_revision=1,
            expected_tree_hash=tree_hash(documents),
            reason="Recorded revision",
        )
        route, payload = "restore", restored.model_dump(mode="json")
        proposed = restored_proposal(restored, documents, ["rules.md"])
    else:
        proposed = InstructionPropose.model_validate(candidate_command(project, documents))
        route, payload = "candidates", proposed.model_dump(mode="json")
    response = owner.client.post(
        f"/api/v1/projects/{project}/instructions/{route}",
        headers=owner.headers,
        json=payload,
    )
    assert response.status_code == 200
    if origin == "legacy-proposal":
        with transaction(owner.engine) as db:
            row = db.get(InstructionCandidate, response.json()["candidate_id"])
            trigger_sql = db.scalar(
                text(
                    "SELECT sql FROM sqlite_master "
                    "WHERE name='immutable_instruction_candidates_update'"
                )
            )
            db.execute(text("DROP TRIGGER immutable_instruction_candidates_update"))
            legacy = dict(row.snapshot)
            legacy.pop("original_command")
            row.snapshot = legacy
            db.flush()
            db.execute(text(trigger_sql))
            assert (
                db.scalar(
                    text(
                        "SELECT sql FROM sqlite_master "
                        "WHERE name='immutable_instruction_candidates_update'"
                    )
                )
                == trigger_sql
            )
    query = original_query(
        owner,
        "project.instructions.propose.v1",
        proposed,
        {"project_id": project},
        include_key=True,
    )
    assert resolve_without_effect(owner, query).json()["status"] == "NOT_OBSERVED"


@pytest.mark.parametrize(
    "state", ["current", "corrupt", "denied", "operation-id", "denied-operation-id"]
)
def test_original_protected_accept_identity_survives_commit(genuine_instruction_scope, state):
    from journeon.instruction_contracts import InstructionChangeConsent

    owner, _, project, _, _, documents = genuine_instruction_scope
    official_effect(
        owner.client, owner.headers, owner.grant("project.instruction.evaluate", project_id=project)
    )
    official_effect(
        owner.client,
        owner.headers,
        {
            "kind": "project.instructions.policy.configure.v1",
            "idempotency_key": "original-accept-policy",
            "project_id": project,
            "expected_project_revision": 1,
            "expected_binding_revision": 1,
            "expected_root_revision": 1,
            "expected_policy_revision": 1,
            "policy": {
                "authorized_categories": ["ORDINARY"],
                "navigation_repairs": False,
                "independent_review": False,
                "require_confirmation": True,
                "required_evals": ["instruction-boundaries-v1"],
            },
        },
    )
    proposed = owner.client.post(
        f"/api/v1/projects/{project}/instructions/candidates",
        headers=owner.headers,
        json=candidate_command(project, documents),
    )
    assert proposed.status_code == 200
    reference = {
        key: proposed.json()[key]
        for key in (
            "project_id",
            "candidate_id",
            "candidate_hash",
            "expected_binding_revision",
            "expected_policy_revision",
        )
    }
    evaluated = owner.client.post(
        f"/api/v1/projects/{project}/instructions/evals", headers=owner.headers, json=reference
    )
    assert evaluated.status_code == 200
    effect = InstructionChangeConsent(
        **reference,
        idempotency_key="original-protected-accept",
        review_ids=[],
        eval_ids=[evaluated.json()["evidence_id"]],
    )
    query = original_query(owner, effect.kind, effect, {"project_id": project}, include_key=True)
    request = owner.prepare(effect.model_dump(mode="json"))
    assert resolve_without_effect(owner, query).json()["status"] == "OBSERVED_PENDING"
    preview = owner.preview(request)
    committed = owner.client.post(
        "/api/v1/protected-operations/confirm",
        headers=owner.headers,
        json={key: preview[key] for key in ("request_id", "request_hash", "nonce")},
    )
    assert committed.status_code == 200
    observed = resolve_without_effect(owner, query).json()
    assert observed["status"] == "OBSERVED_RECEIPT"
    assert observed["receipt"] == committed.json()
    check_original_binding(owner, query)
    if state != "current":
        if state.startswith("denied"):
            revoke(owner, genuine_instruction_scope[4]["project.instruction.receipt.read"]["grant"])
        with transaction(owner.engine) as db:
            statement = (
                "UPDATE protected_requests SET operation_id='different-operation' "
                "WHERE id=:identity"
                if state.endswith("operation-id")
                else "UPDATE protected_requests SET payload='invalid-json' WHERE id=:identity"
            )
            db.execute(text(statement), {"identity": request["request_id"]})
        resolve_without_effect(owner, query, 403 if state.startswith("denied") else 503)


def test_dispatch_original_key_resolves_real_job_admission(genuine_durable_work):
    owner, _, prepare, _, local_route = genuine_durable_work
    command = TaskDispatch.model_validate(
        prepare
        | {
            "idempotency_key": "lost-dispatch",
            "step_id": "verify",
            "route_key": local_route.key,
            "route_revision": local_route.revision,
        }
    )
    query = original_query(
        owner,
        "task.dispatch.v1",
        command,
        {"project_id": command.project_id, "task_id": command.origin.task_id},
    )
    # Construct the entire lookup before the producer exposes any server operation UUID.
    admitted = owner.client.post(
        "/api/v1/tasks/dispatch", headers=owner.headers, json=command.model_dump(mode="json")
    )
    assert admitted.status_code == 200
    resolved = resolve_without_effect(owner, query).json()
    assert resolved["status"] == "OBSERVED_RECEIPT"
    assert resolved["receipt"]["operation_id"] == admitted.json()["admission_id"]
    assert resolved["receipt"]["command"] == "job.admitted.v1"
    check_original_binding(owner, query)


def test_attempt_real_pending_then_uncertain_effect_is_read_only(
    genuine_durable_work,
    monkeypatch,
):
    from journeon import attempts

    owner, _, prepare, grants, _ = genuine_durable_work
    command = AttemptPrepare.model_validate(prepare)
    query = original_query(
        owner,
        "attempt.prepare.v1",
        command,
        {"project_id": command.project_id, "task_id": command.origin.task_id},
    )
    entered, release = threading.Event(), threading.Event()
    original = attempts.materialize_directory

    def interrupt_after_real_write(*args, **kwargs):
        entered.set()
        if not release.wait(30):
            raise RuntimeError("Resolver observation did not release the local effect")
        original(*args, **kwargs)
        raise OSError("Injected interruption after real workspace materialization")

    with monkeypatch.context() as patch, ThreadPoolExecutor(max_workers=1) as pool:
        patch.setattr(attempts, "materialize_directory", interrupt_after_real_write)
        future = pool.submit(
            owner.client.post,
            "/api/v1/attempts/prepare",
            headers=owner.headers,
            json=command.model_dump(mode="json"),
        )
        try:
            assert entered.wait(30)
            pending = resolve_without_effect(owner, query).json()
            assert pending["status"] == "OBSERVED_PENDING"
            assert pending["observed_state"] == "PREPARING"
            check_original_binding(owner, query)
        finally:
            release.set()
        assert future.result(timeout=30).status_code == 503
    uncertain = resolve_without_effect(owner, query).json()
    assert uncertain["status"] == "OBSERVED_UNKNOWN"
    assert uncertain["observed_state"] == "RECOVERY_REQUIRED"
    assert uncertain["evidence_id"] == pending["evidence_id"]
    revoke(owner, grants["attempt.receipt.read"]["grant"])
    with transaction(owner.engine) as db:
        db.execute(
            text("UPDATE attempts SET snapshot='invalid-json' WHERE id=:id"),
            {"id": uncertain["evidence_id"]},
        )
    resolve_without_effect(owner, query, 403)


def test_execution_submission_loss_retains_real_admission_receipt(
    genuine_durable_work, monkeypatch
):
    from journeon import executions
    from journeon.executions import ExecutionService

    owner, config, prepare, grants, local_route = genuine_durable_work
    command = ExecutionStart(
        idempotency_key="lost-execution",
        project_id=prepare["project_id"],
        expected_policy_revision=1,
        root_key="durable-source",
        root_revision=1,
        route_key=local_route.key,
        route_revision=local_route.revision,
        check_id=local_route.check_id,
    )
    query = original_query(owner, "execution.start.v1", command, {"project_id": command.project_id})
    headers = dict(owner.headers) | {
        "cookie": "; ".join(key + "=" + value for key, value in owner.client.cookies.items())
    }
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()],
        }
    )
    actor = owner.client.app.state.browser_auth.resolve(owner.engine, request)
    service = ExecutionService(owner.engine, config)

    def reject_submission(*args, **kwargs):
        raise RuntimeError("Injected executor submission failure after durable admission")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(executions.ThreadPoolExecutor, "submit", reject_submission)
            with pytest.raises(RuntimeError, match="Injected executor submission failure"):
                service.start(actor, command)
        first = resolve_without_effect(owner, query).json()
        assert first["status"] == "OBSERVED_RECEIPT"
        identity = first["receipt"]["execution"]["execution_id"]
        assert service.read(actor, identity).state == "STARTING"
        check_original_binding(owner, query)
        # Real owner reconciliation may inspect systemd; no submitted workload ran.
        service.reconcile()
        assert service.read(actor, identity).state == "UNKNOWN"
        assert resolve_without_effect(owner, query).json()["receipt"] == first["receipt"]
        revoke(owner, grants["execution.receipt.read"]["grant"])
        with transaction(owner.engine) as db:
            db.execute(
                text(
                    "UPDATE executions SET inputs='invalid-json',snapshot='invalid-json' "
                    "WHERE id=:id"
                ),
                {"id": identity},
            )
        resolve_without_effect(owner, query, 403)
    finally:
        service.shutdown()


def projection_query(owner, project):
    command = ProjectionCommand(
        idempotency_key="pending-projection",
        project_id=project,
        expected_revision=1,
        root_id="durable-environment",
        expected_root_revision=1,
        filename="AGENTS.md",
        expected_observed_hash=None,
    )
    query = original_query(
        owner,
        "project.instructions.projection.v1",
        command,
        {"project_id": project},
        include_key=True,
    )
    return command, query


def test_publication_real_pending_then_uncertain_effect_is_read_only(
    genuine_instruction_scope,
    monkeypatch,
):
    from journeon import project_instructions

    owner, _, project, _, _, _ = genuine_instruction_scope
    command, query = projection_query(owner, project)
    entered, release = threading.Event(), threading.Event()
    original = project_instructions.replace_document

    def interrupt_projection(root, name, *args, **kwargs):
        if name == "AGENTS.md":
            entered.set()
            if not release.wait(30):
                raise RuntimeError("Resolver observation did not release the local projection")
            original(root, name, *args, **kwargs)
            raise OSError("Injected interruption after real projection materialization")
        return original(root, name, *args, **kwargs)

    with monkeypatch.context() as patch, ThreadPoolExecutor(max_workers=1) as pool:
        patch.setattr(project_instructions, "replace_document", interrupt_projection)
        future = pool.submit(
            owner.client.post,
            f"/api/v1/projects/{project}/instructions/projections/materialize",
            headers=owner.headers,
            json=command.model_dump(mode="json"),
        )
        try:
            assert entered.wait(30)
            pending = resolve_without_effect(owner, query).json()
            assert pending["status"] == "OBSERVED_PENDING"
            assert pending["observed_state"] == "PENDING"
            check_original_binding(owner, query)
        finally:
            release.set()
        assert future.result(timeout=30).status_code == 503
    uncertain = resolve_without_effect(owner, query).json()
    assert uncertain["status"] == "OBSERVED_UNKNOWN"
    assert uncertain["observed_state"] == "RECOVERY_NEEDED"
    assert uncertain["evidence_id"] == pending["evidence_id"]


@pytest.mark.parametrize("kind", ["publication", "candidate"])
@pytest.mark.parametrize("shape", ["list", "missing"])
@pytest.mark.parametrize("denied", [False, True])
def test_actual_instruction_admission_wrong_shape_is_repair_or_hidden(
    genuine_instruction_scope,
    monkeypatch,
    kind,
    shape,
    denied,
):
    from journeon import project_instructions

    owner, _, project, _, grants, documents = genuine_instruction_scope
    if kind == "publication":
        command, query = projection_query(owner, project)

        def interrupted(*args, **kwargs):
            raise OSError("Injected projection write interruption")

        with monkeypatch.context() as patch:
            patch.setattr(project_instructions, "replace_document", interrupted)
            admitted = owner.client.post(
                f"/api/v1/projects/{project}/instructions/projections/materialize",
                headers=owner.headers,
                json=command.model_dump(mode="json"),
            )
            assert admitted.status_code == 503
        model = InstructionPublication
    else:
        command = InstructionPropose.model_validate(candidate_command(project, documents))
        query = original_query(
            owner,
            "project.instructions.propose.v1",
            command,
            {"project_id": project},
            include_key=True,
        )
        admitted = owner.client.post(
            f"/api/v1/projects/{project}/instructions/candidates",
            headers=owner.headers,
            json=command.model_dump(mode="json"),
        )
        assert admitted.status_code == 200
        model = InstructionCandidate
    observed = resolve_without_effect(owner, query).json()
    assert observed["status"] == "OBSERVED_UNKNOWN"
    check_original_binding(owner, query)
    if denied:
        revoke(owner, grants["project.instruction.receipt.read"]["grant"])
    with transaction(owner.engine) as db:
        row = db.scalar(
            select(model).where(
                model.idempotency_key == command.idempotency_key,
                model.principal_id == owner.principal_id,
            )
        )
        assert row is not None
        # Negative-only corruption of a real admitted record; never a positive producer.
        if kind == "candidate":
            trigger_query = text(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' ORDER BY name"
            )
            triggers_before = [(name, sql) for name, sql in db.execute(trigger_query)]
            trigger_hash = digest(triggers_before)
            trigger_sql = dict(triggers_before)["immutable_instruction_candidates_update"]
            db.execute(text("DROP TRIGGER immutable_instruction_candidates_update"))
        if shape == "list":
            row.snapshot = []
        else:
            altered = dict(row.snapshot)
            altered.pop("view" if kind == "candidate" else "payload")
            row.snapshot = altered
        if kind == "candidate":
            db.flush()
            db.execute(text(trigger_sql))
            triggers_after = [(name, sql) for name, sql in db.execute(trigger_query)]
            assert triggers_after == triggers_before
            assert digest(triggers_after) == trigger_hash
    try:
        resolve_without_effect(owner, query, 403 if denied else 503)
    except (AttributeError, KeyError, TypeError):
        pytest.fail("Authorized retained shape failure escaped the repair response")


def test_dispatch_denies_before_corrupt_real_admission_json(genuine_durable_work):
    owner, _, prepare, grants, local_route = genuine_durable_work
    command = TaskDispatch.model_validate(
        prepare
        | {
            "idempotency_key": "hidden-dispatch",
            "step_id": "verify",
            "route_key": local_route.key,
            "route_revision": local_route.revision,
        }
    )
    query = original_query(
        owner,
        "task.dispatch.v1",
        command,
        {"project_id": command.project_id, "task_id": command.origin.task_id},
    )
    admitted = owner.client.post(
        "/api/v1/tasks/dispatch", headers=owner.headers, json=command.model_dump(mode="json")
    )
    assert admitted.status_code == 200
    revoke(owner, grants["job.receipt.read"]["grant"])
    with transaction(owner.engine) as db:
        db.execute(
            text("UPDATE task_verification_jobs SET inputs='invalid-json' WHERE job_id=:id"),
            {"id": admitted.json()["job_id"]},
        )
        db.execute(
            text("UPDATE operation_receipts SET result='invalid-json' WHERE id=:id"),
            {"id": admitted.json()["admission_id"]},
        )
    resolve_without_effect(owner, query, 403)
