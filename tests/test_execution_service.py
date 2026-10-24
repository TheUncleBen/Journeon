# SPDX-License-Identifier: AGPL-3.0-only
import time

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_execution_route import route
from test_production_instructions import bound_instructions, official, official_effect  # noqa: F401

from journeon.api import create_app
from journeon.contracts import DomainError, ExecutionStart, ExecutionStop
from journeon.database import transaction
from journeon.execution_process import ExecutionConfiguration
from journeon.executions import ExecutionService
from journeon.instruction_config import RootConfiguration
from journeon.models import AccessGrant, Principal
from journeon.passkeys import STANDARD_PASSKEY_POLICY, PasskeyService


@pytest.fixture
def direct_execution(official, tmp_path, request):  # noqa: F811
    engine, client, headers, configuration = official
    project, _, _ = bound_instructions(official)
    source = tmp_path / "verification-source"
    source.mkdir()
    (source / "input.txt").write_text("input")
    storage = tmp_path / "execution-evidence"
    storage.mkdir(mode=0o700)
    configured_route = route().model_copy(update={"project_id": project, "check_id": "check"})
    if hasattr(request, "param") and isinstance(request.param, dict):
        from test_attempt_snapshots import git

        git(source, "init", "-q")
        git(source, "config", "user.name", "Fixture")
        git(source, "config", "user.email", "fixture@example.invalid")
        git(source, "add", ".")
        git(source, "commit", "-qm", "fixture")
        (source / "input.txt").write_text("staged")
        git(source, "add", ".")
        (source / "input.txt").write_text("working")
        request.param = request.param["command"]
    if hasattr(request, "param"):
        configured_route = configured_route.model_copy(
            update={
                "argv": ["/usr/bin/python3", "-I", "-S", "-c", request.param],
                "artifacts": [],
            }
        )
    configuration = configuration.model_copy(
        update={
            "roots": [
                *configuration.roots,
                RootConfiguration(
                    key="verification-source",
                    path=str(source),
                    role="PROJECT",
                    project_id=project,
                    revision=1,
                ),
            ],
            "executions": ExecutionConfiguration(
                revision=1,
                storage_path=str(storage),
                snapshot_bytes=1048576,
                snapshot_files=100,
                concurrent_executions=2,
                memory_bytes=268435456,
                storage_bytes=16777216,
                cpu_percent=50,
                core_cpu_reserve_percent=100,
                routes=[configured_route],
            ),
        }
    )
    with transaction(engine) as db:
        principal = db.scalar(select(Principal).where(Principal.role == "OWNER"))
        for capability in (
            "project.read",
            "project.verification.configure",
            "project.verification.read",
            "execution.start",
            "execution.read",
            "execution.stop",
            "execution.drain",
            "execution.complete",
            "execution.receipt.read",
        ):
            db.add(
                AccessGrant(
                    id="direct:" + capability,
                    principal_id=principal.id,
                    capability=capability,
                    resource_kind="project",
                    resource_id=project,
                    enabled=True,
                    revision=1,
                    provenance="Explicit disposable local qualification authority",
                )
            )
    with TestClient(
        create_app(
            engine,
            browser_auth=client.app.state.browser_auth,
            instructions=configuration,
            passkeys=PasskeyService(
                engine,
                rp_id="example.test",
                origin="https://example.test",
                policy=STANDARD_PASSKEY_POLICY,
            ),
        ),
        base_url="https://example.test",
        cookies=client.cookies,
    ) as configured:
        inspected = configured.post(
            "/api/v1/project-roots/inspect",
            headers=headers,
            json={"root_key": "verification-source", "config_revision": 1},
        )
        assert inspected.status_code == 200, inspected.text
        official_effect(
            configured,
            headers,
            {
                "kind": "project.root.admit.v1",
                "idempotency_key": "verification-root",
                "root_key": "verification-source",
                "config_revision": 1,
                "expected_revision": 0,
                "inspection_digest": inspected.json()["digest"],
            },
        )
        current = configured.get("/api/v1/projects/" + project).json()
        policy = configured.post(
            "/api/v1/projects/verification",
            headers=headers,
            json={
                "schema_version": 1,
                "idempotency_key": "direct-policy",
                "project_id": project,
                "expected_project_revision": current["revision"],
                "expected_policy_revision": 0,
                "enabled": True,
                "checks": [
                    {
                        "check_id": "check",
                        "criterion": "Build succeeds",
                        "argv": configured_route.argv,
                        "working_directory": ".",
                        "expected_exit_code": 0,
                    }
                ],
                "workflow": {
                    "steps": [{"step_id": "verify", "kind": "VERIFICATION", "check_id": "check"}]
                },
            },
        )
        assert policy.status_code == 200, policy.text
        request_headers = dict(headers) | {
            "cookie": "; ".join(f"{key}={value}" for key, value in configured.cookies.items())
        }
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "headers": [
                    (key.lower().encode(), value.encode()) for key, value in request_headers.items()
                ],
            }
        )
        actor = configured.app.state.browser_auth.resolve(engine, request)
        command = ExecutionStart(
            idempotency_key="direct-verification",
            project_id=project,
            expected_policy_revision=1,
            root_key="verification-source",
            root_revision=1,
            route_key=configured_route.key,
            route_revision=1,
            check_id="check",
        )
        service = ExecutionService(engine, configuration)
        try:
            yield service, actor, command, source
        finally:
            service.shutdown()


def test_direct_service_real_execution_has_no_task_or_attempt(direct_execution):
    service, actor, command, source = direct_execution
    receipt = service.start(actor, command)
    deadline = time.monotonic() + 15
    while True:
        result = service.read(actor, receipt.execution.execution_id)
        if result.state not in ("STARTING", "RUNNING"):
            break
        assert time.monotonic() < deadline
        time.sleep(0.05)
    assert result.state == "COMPLETED", result
    assert result.origin == "DIRECT_VERIFICATION"
    assert result.verification_passed
    assert result.completion.drained
    assert result.completion.artifacts[0].path == "result.txt"
    assert not (source / "result.txt").exists()
    assert service.start(actor, command) == receipt
    from journeon.models import ExecutionEffect

    with transaction(service.engine) as db:
        effects = list(
            db.scalars(
                select(ExecutionEffect)
                .where(ExecutionEffect.execution_id == result.execution_id)
                .order_by(ExecutionEffect.revision)
            )
        )
        assert [effect.kind for effect in effects] == [
            "INTENT",
            "INPUT_BOUND",
            "PREPARING",
            "START_REQUESTED",
            "STARTED",
            "COMPLETED",
        ]
        assert effects[-2].observation["process_id"] > 1


def wait_for(service, actor, identity, states):
    deadline = time.monotonic() + 15
    while True:
        result = service.read(actor, identity)
        if result.state in states:
            return result
        assert result.state not in ("UNKNOWN", "COMPLETED", "CANCELLED"), result
        assert time.monotonic() < deadline
        time.sleep(0.05)


@pytest.mark.parametrize("direct_execution", ["import time; time.sleep(60)"], indirect=True)
def test_direct_service_stop_has_current_receipt_and_drains(direct_execution):
    service, actor, command, _ = direct_execution
    started = service.start(actor, command)
    current = wait_for(service, actor, started.execution.execution_id, {"RUNNING"})
    stop = ExecutionStop(
        idempotency_key="stop",
        execution_id=current.execution_id,
        expected_revision=current.revision,
    )
    stopped = service.stop(actor, stop)
    assert stopped.execution.stop_requested
    result = wait_for(service, actor, current.execution_id, {"CANCELLED"})
    assert result.completion.drained
    assert not result.verification_passed
    assert service.stop(actor, stop) == stopped


@pytest.mark.parametrize("direct_execution", ["import time; time.sleep(60)"], indirect=True)
def test_direct_service_changed_route_bytes_revoke_running_authority(direct_execution):
    service, actor, command, _ = direct_execution
    started = service.start(actor, command)
    current = wait_for(service, actor, started.execution.execution_id, {"RUNNING"})
    original = service.configuration
    config = original.executions
    service.configuration = original.model_copy(
        update={
            "executions": config.model_copy(
                update={
                    "routes": [config.routes[0].model_copy(update={"environment": {"LANG": "C"}})],
                }
            )
        }
    )
    try:
        deadline = time.monotonic() + 3
        from journeon.models import Execution

        while True:
            with transaction(service.engine) as db:
                row = db.get(Execution, current.execution_id)
                state = row.state
            if state == "CANCELLED":
                break
            assert time.monotonic() < deadline, state
            time.sleep(0.05)
    finally:
        service.configuration = original


def test_direct_service_revoked_start_has_no_execution_effect(direct_execution):
    service, actor, command, source = direct_execution
    with transaction(service.engine) as db:
        db.get(AccessGrant, "direct:execution.start").enabled = False
    with pytest.raises(DomainError) as denied:
        service.start(actor, command)
    assert denied.value.code == "PERMISSION_DENIED"
    assert not (source / "result.txt").exists()


def run_controller(connection, database, configuration, actor, command, helper_path=None):
    from journeon.database import create_database
    from journeon.executions import ExecutionService

    if helper_path is not None:
        from journeon import execution_helper

        execution_helper.__file__ = str(helper_path)
    engine = create_database(database, busy_timeout_ms=5000)
    service = ExecutionService(engine, configuration)
    receipt = service.start(actor, command)
    connection.send(receipt.execution.execution_id)
    connection.recv()


@pytest.mark.parametrize("direct_execution", ["import time; time.sleep(60)"], indirect=True)
@pytest.mark.parametrize("preparing", [False, True])
def test_direct_service_restart_reconciles_without_reexecution(
    direct_execution, preparing, tmp_path
):
    import multiprocessing
    from pathlib import Path

    from journeon.models import Execution

    service, actor, command, _ = direct_execution
    helper_path = None
    if preparing:
        from journeon import execution_helper

        helper_path = tmp_path / "slow_helper.py"
        helper_path.write_text(
            Path(execution_helper.__file__)
            .read_text()
            .replace("    shutil.copytree(", "    time.sleep(5)\n    shutil.copytree(")
        )
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    process = context.Process(
        target=run_controller,
        args=(
            child,
            Path(service.engine.url.database),
            service.configuration,
            actor,
            command,
            helper_path,
        ),
    )
    process.start()
    try:
        assert parent.poll(15)
        identity = parent.recv()
        if preparing:
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                running = service.read(actor, identity)
                if running.invocation_id:
                    break
                time.sleep(0.05)
            assert running.state == "STARTING"
            assert running.invocation_id
            assert running.containment["memory.max"]
        else:
            running = wait_for(service, actor, identity, {"RUNNING"})
        process.kill()
        process.join(10)
        assert not process.is_alive()
        service.reconcile()
        observed = service.read(actor, identity)
        assert observed.state == "UNKNOWN"
        assert not observed.verification_passed
        assert observed.invocation_id == running.invocation_id
        assert service.start(actor, command).execution.execution_id == identity
        with transaction(service.engine) as db:
            assert len(list(db.scalars(select(Execution)))) == 1
    finally:
        if process.is_alive():
            process.kill()
            process.join(10)
        parent.close()
        child.close()


@pytest.mark.parametrize(
    "direct_execution",
    [
        {
            "command": "from subprocess import check_output as c; "
            "assert c(['git','show','HEAD:input.txt'])==b'input'; "
            "assert c(['git','show',':input.txt'])==b'staged'; "
            "assert open('input.txt').read()=='working'"
        }
    ],
    indirect=True,
)
def test_direct_service_binds_immutable_git_source_view(direct_execution):
    from journeon.models import ExecutionManifest

    service, actor, command, source = direct_execution
    receipt = service.start(actor, command)
    deadline = time.monotonic() + 15
    while True:
        result = service.read(actor, receipt.execution.execution_id)
        if result.state not in ("STARTING", "RUNNING"):
            break
        assert time.monotonic() < deadline
        time.sleep(0.05)
    assert result.state == "COMPLETED", result
    assert result.verification_passed, result
    with transaction(service.engine) as db:
        manifest = db.get(ExecutionManifest, result.manifest_id)
        assert manifest.snapshot["git_objects"]
        assert manifest.snapshot["git_objects"][0]["projection"]["snapshot_hash"]


def test_direct_execution_uses_canonical_current_authority_receipt(direct_execution):
    from journeon.receipts import OperationService

    service, actor, command, _ = direct_execution
    receipt = service.start(actor, command)
    operations = OperationService(service.engine, service.configuration)
    assert operations.receipt(actor, receipt.operation_id) == receipt
    with transaction(service.engine) as db:
        grant = db.get(AccessGrant, "direct:execution.receipt.read")
        grant.enabled = False
    with pytest.raises(DomainError) as error:
        operations.receipt(actor, receipt.operation_id)
    assert error.value.code == "PERMISSION_DENIED"


def test_execution_doctor_requires_real_current_qualified_operation(direct_execution):
    service, actor, command, _ = direct_execution
    receipt = service.start(actor, command)
    deadline = time.monotonic() + 15
    while True:
        result = service.read(actor, receipt.execution.execution_id)
        if result.state not in ("STARTING", "RUNNING"):
            break
        assert time.monotonic() < deadline
        time.sleep(0.05)
    observed = service.doctor(actor, result.execution_id)
    assert observed["qualified"]
    assert observed["execution_id"] == result.execution_id
    assert observed["installation"]["files"]["/usr/bin/bwrap"]
    with transaction(service.engine) as db:
        grant = db.get(AccessGrant, "direct:execution.read")
        grant.enabled = False
    with pytest.raises(DomainError) as error:
        service.doctor(actor, result.execution_id)
    assert error.value.code == "PERMISSION_DENIED"


def test_execution_replay_requires_current_host_configuration(direct_execution):
    from journeon.job_api import replay
    from journeon.job_contracts import ReplayQuery

    service, actor, command, _ = direct_execution
    receipt = service.start(actor, command)
    page = replay(service.engine, actor, ReplayQuery(limit=100))
    assert all(event.operation_id != receipt.operation_id for event in page.events)
    current = replay(service.engine, actor, ReplayQuery(limit=100), service.configuration)
    assert any(event.operation_id == receipt.operation_id for event in current.events)


@pytest.mark.parametrize(
    "direct_execution",
    [
        "import time; print('before-allocation',flush=True); "
        "time.sleep(.1); x=bytearray(400*1024*1024)"
    ],
    indirect=True,
)
def test_direct_service_retains_unknown_memory_limit_evidence(direct_execution):
    service, actor, command, _ = direct_execution
    receipt = service.start(actor, command)
    deadline = time.monotonic() + 15
    while True:
        result = service.read(actor, receipt.execution.execution_id)
        if result.state not in ("STARTING", "RUNNING"):
            break
        assert time.monotonic() < deadline
        time.sleep(0.05)
    assert result.state == "UNKNOWN"
    assert result.launcher_exit_code != 0
    assert result.output
    assert result.evidence_digest
    assert not service.doctor(actor, result.execution_id)["qualified"]
    service.reconcile()
    recovered = service.read(actor, result.execution_id)
    assert recovered.state == "UNKNOWN"
    assert recovered.drained
    assert recovered.output == result.output


def test_failed_start_control_does_not_claim_process_started(direct_execution, monkeypatch):
    from journeon import execution_process
    from journeon.models import ExecutionEffect

    service, actor, command, _ = direct_execution
    original = execution_process.subprocess.Popen

    class RejectStart:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def write(self, data):
            if data == b'{"action":"START"}\n':
                raise BrokenPipeError("Injected interruption before START delivery")
            return self.stream.write(data)

    def launch(argv, *args, **kwargs):
        process = original(argv, *args, **kwargs)
        if argv[0] == "/usr/bin/systemd-run":
            process.stdin = RejectStart(process.stdin)
        return process

    monkeypatch.setattr(execution_process.subprocess, "Popen", launch)
    receipt = service.start(actor, command)
    view = wait_for(service, actor, receipt.execution.execution_id, {"UNKNOWN"})
    with transaction(service.engine) as db:
        kinds = list(
            db.scalars(
                select(ExecutionEffect.kind).where(
                    ExecutionEffect.execution_id == view.execution_id
                )
            )
        )
    assert "START_REQUESTED" in kinds
    assert "STARTED" not in kinds
    assert not view.verification_passed


@pytest.mark.parametrize("model_created", [False, True])
def test_execution_drained_database_domain(direct_execution, model_created):
    from sqlalchemy import create_engine
    from sqlalchemy.exc import IntegrityError

    from journeon.models import Base

    service, actor, command, _ = direct_execution
    receipt = service.start(actor, command)
    current = wait_for(service, actor, receipt.execution.execution_id, {"COMPLETED"})
    engine = service.engine
    if model_created:
        model_engine = create_engine("sqlite://")
        Base.metadata.create_all(model_engine)
        with engine.connect() as connection:
            row = (
                connection.exec_driver_sql(
                    "SELECT * FROM executions WHERE id=?", (current.execution_id,)
                )
                .mappings()
                .one()
            )
        with model_engine.begin() as connection:
            columns = ",".join(row.keys())
            placeholders = ",".join("?" for _ in row)
            connection.exec_driver_sql(
                f"INSERT INTO executions ({columns}) VALUES ({placeholders})", tuple(row.values())
            )
        engine = model_engine
    try:
        for invalid in (2, -1, 0.5, "true", b"1"):
            with (
                pytest.raises(IntegrityError, match="execution_drained_boolean"),
                engine.begin() as db,
            ):
                db.exec_driver_sql(
                    "UPDATE executions SET drained=? WHERE id=?", (invalid, current.execution_id)
                )
        with engine.connect() as db:
            assert (
                db.exec_driver_sql(
                    "SELECT drained FROM executions WHERE id=?", (current.execution_id,)
                ).scalar()
                == 1
            )
    finally:
        if model_created:
            engine.dispose()


@pytest.mark.parametrize("reserve_metadata", [False, True])
def test_execution_storage_reserves_snapshot_metadata_before_writes(
    direct_execution, reserve_metadata
):
    from pathlib import Path

    from journeon.attempt_snapshots import capture_snapshot
    from journeon.attempts import snapshot_storage_bytes
    from journeon.models import Execution

    service, actor, command, source = direct_execution
    for index in range(100):
        (source / (str(index).zfill(3) + "x" * 180)).touch()
    config = service.configuration.executions
    route = config.routes[0].model_copy(update={"workspace_bytes": 4096})
    original_reservation = (
        route.output_bytes + route.artifact_bytes + 16 * 4 + route.workspace_bytes
    )
    captured = capture_snapshot(source, max_bytes=16, max_files=200)
    metadata = snapshot_storage_bytes(captured, metadata_only=True)
    config = config.model_copy(
        update={
            "snapshot_bytes": 16,
            "snapshot_files": 200,
            "storage_bytes": original_reservation + (metadata if reserve_metadata else 0),
            "routes": [route],
        }
    )
    service.configuration = service.configuration.model_copy(update={"executions": config})
    receipt = service.start(actor, command)
    result = wait_for(service, actor, receipt.execution.execution_id, {"UNKNOWN", "COMPLETED"})
    assert result.state == ("COMPLETED" if reserve_metadata else "UNKNOWN")
    with transaction(service.engine) as db:
        reserved = db.get(Execution, result.execution_id).storage_bytes
    actual = sum(
        path.stat().st_size for path in Path(config.storage_path).rglob("*") if path.is_file()
    )
    assert actual <= reserved <= config.storage_bytes
    if reserve_metadata:
        assert reserved == original_reservation + metadata
        assert actual > original_reservation
    else:
        assert actual == 0
    assert service.start(actor, command) == receipt


def test_execution_retry_does_not_create_unowned_lock_files(direct_execution):
    service, actor, command, _ = direct_execution
    receipt = service.start(actor, command)
    deadline = time.monotonic() + 20
    while service.read(actor, receipt.execution.execution_id).state in ("STARTING", "RUNNING"):
        assert time.monotonic() < deadline
        time.sleep(0.05)
    from pathlib import Path

    storage = Path(service.configuration.executions.storage_path)
    before = {p.name for p in storage.glob("execution-*.lock")}
    for _ in range(3):
        assert service.start(actor, command) == receipt
    after = {p.name for p in storage.glob("execution-*.lock")}
    from sqlalchemy import func

    from journeon.models import Execution

    with transaction(service.engine) as db:
        count = db.scalar(select(func.count()).select_from(Execution))
    assert count == 1
    assert after == before, {
        "before": sorted(before),
        "after": sorted(after),
        "execution_rows": count,
    }


def test_shutdown_cannot_be_followed_by_new_execution_admission(direct_execution, monkeypatch):
    import threading

    from journeon import executions
    from journeon.contracts import DomainError

    service, actor, command, _ = direct_execution
    entered = threading.Event()
    released = threading.Event()
    original = executions.resource_observation
    results = []

    def blocked_observation(path):
        entered.set()
        assert released.wait(5)
        return original(path)

    monkeypatch.setattr(executions, "resource_observation", blocked_observation)

    def start():
        try:
            results.append(service.start(actor, command))
        except Exception as error:
            results.append(error)

    thread = threading.Thread(target=start)
    thread.start()
    try:
        assert entered.wait(5)
        service.shutdown()
    finally:
        released.set()
        thread.join(10)
        service.shutdown()
    assert not thread.is_alive()
    from sqlalchemy import func

    from journeon.models import Execution

    with transaction(service.engine) as db:
        count = db.scalar(select(func.count()).select_from(Execution))
    assert len(results) == 1
    assert isinstance(results[0], DomainError), {
        "admission_after_shutdown": type(results[0]).__name__,
        "execution_rows": count,
    }
    assert count == 0


@pytest.mark.parametrize("failure", ["capacity", "receipt"])
def test_failed_admission_does_not_retain_unowned_lock(direct_execution, monkeypatch, failure):
    from pathlib import Path

    from sqlalchemy import func

    from journeon.models import Execution

    service, actor, command, _ = direct_execution
    if failure == "capacity":
        service.configuration = service.configuration.model_copy(
            update={
                "executions": service.configuration.executions.model_copy(
                    update={"memory_bytes": 1}
                )
            }
        )
        expected = DomainError
    else:

        def reject_receipt(*args, **kwargs):
            raise ValueError("fixture admission rollback")

        monkeypatch.setattr(service, "receipt", reject_receipt)
        expected = ValueError
    for _ in range(3):
        with pytest.raises(expected):
            service.start(actor, command)
    with transaction(service.engine) as db:
        assert db.scalar(select(func.count()).select_from(Execution)) == 0
    assert not list(Path(service.configuration.executions.storage_path).glob("execution-*.lock"))


def test_failed_submission_keeps_committed_lock_for_reconciliation(direct_execution, monkeypatch):
    from pathlib import Path

    from journeon import executions
    from journeon.models import Execution

    service, actor, command, _ = direct_execution

    def reject_submission(*args, **kwargs):
        raise RuntimeError("fixture submission failure")

    monkeypatch.setattr(executions.ThreadPoolExecutor, "submit", reject_submission)
    with pytest.raises(RuntimeError, match="fixture submission failure"):
        service.start(actor, command)
    with transaction(service.engine) as db:
        row = db.scalar(select(Execution))
        identity = row.id
        assert row.state == "STARTING"
    storage = Path(service.configuration.executions.storage_path)
    assert (storage / ("execution-" + identity + ".lock")).is_file()
    service.reconcile()
    assert service.read(actor, identity).state == "UNKNOWN"
    assert service.read(actor, identity).drained
    assert (storage / ("execution-" + identity + ".lock")).is_file()
