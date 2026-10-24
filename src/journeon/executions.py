# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical deterministic process ownership and authenticated local completion."""

import fcntl
import hashlib
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, defer

from journeon.attempt_snapshots import capture_snapshot, materialize_projection
from journeon.attempts import (
    snapshot_storage_bytes,
    verify_snapshot_evidence,
    workspace_root,
    write_snapshot,
)
from journeon.contracts import (
    DomainError,
    ExecutionReceipt,
    ExecutionStart,
    ExecutionStop,
    ExecutionView,
    VerificationPolicy,
)
from journeon.database import transaction
from journeon.execution_git import project_git_view
from journeon.execution_process import (
    ExecutionInterrupted,
    LocalRoute,
    installation_observation,
    reconcile_unit,
    resource_observation,
    run_local,
)
from journeon.instruction_config import (
    InstructionConfiguration,
    RootConfiguration,
    git_identity,
    open_directory,
)
from journeon.instructions import digest
from journeon.jobs import JobExecutionIdentity, JobService
from journeon.models import (
    Execution,
    ExecutionEffect,
    ExecutionManifest,
    InstructionRoot,
    OutboxEvent,
    Receipt,
    TaskVerificationJob,
)
from journeon.permissions import AuthenticatedContext, require_grant
from journeon.verification import current_policy
from journeon.work import work_transaction


def authorized_execution(
    db: Session, actor: AuthenticatedContext, identity: str, action: str = "read"
) -> Execution:
    row = db.get(Execution, identity, options=[defer(Execution.snapshot), defer(Execution.inputs)])
    if row is None:
        raise DomainError("NOT_FOUND", "Execution is unavailable")
    require_grant(db, actor, "execution." + action, project_id=row.project_id)
    require_grant(db, actor, "project.read", project_id=row.project_id)
    workspace_root(db, row.project_id, row.root_id, row.root_revision)
    if row.principal_id != actor.principal_id:
        raise DomainError("NOT_FOUND", "Execution is unavailable")
    return row


def execution_view(db: Session, row: Execution) -> ExecutionView:
    view = ExecutionView.model_validate(row.snapshot)
    if view.job_id != row.job_id:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored Execution origin requires repair")
    if row.job_id is not None:
        binding = db.get(
            TaskVerificationJob, row.job_id, options=[defer(TaskVerificationJob.inputs)]
        )
        if (
            binding is None
            or (binding.execution_id, binding.attempt_id, binding.manifest_id)
            != (row.id, view.attempt_id, view.attempt_manifest_id)
            or row.inputs.get("origin")
            != {
                "kind": "TASK_VERIFICATION",
                "attempt_id": view.attempt_id,
                "manifest_id": view.attempt_manifest_id,
            }
        ):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Stored Execution Task binding requires repair"
            )
    if view.manifest_digest != digest(row.inputs) or view.drained != row.drained:
        raise DomainError(
            "DEPENDENCY_UNAVAILABLE", "Stored Execution input binding requires repair"
        )
    if view.manifest_id is not None:
        manifest = db.get(ExecutionManifest, view.manifest_id)
        if (
            view.manifest_id != row.id
            or manifest is None
            or manifest.content_hash != view.manifest_digest
            or manifest.snapshot != row.inputs
        ):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored Execution manifest requires repair")
    if (
        view.execution_id,
        view.root_key,
        view.project_id,
        view.initiating_principal_id,
        view.revision,
        view.state,
        view.authentication_ref,
        view.principal_epoch,
    ) != (
        row.id,
        row.root_id,
        row.project_id,
        row.principal_id,
        row.revision,
        row.state,
        row.authentication_ref,
        row.principal_epoch,
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored Execution scope requires repair")
    if view.completion is not None and view.evidence_digest != digest(
        {
            "completion": view.completion.model_dump(mode="json"),
            "output": [item.model_dump(mode="json") for item in view.output],
            "invocation_id": view.invocation_id,
            "containment": view.containment,
            "launcher_exit_code": view.launcher_exit_code,
        }
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored Execution evidence requires repair")
    if view.completion is None and view.evidence_digest is not None:
        effect = db.scalar(
            select(ExecutionEffect)
            .where(
                ExecutionEffect.execution_id == row.id,
                ExecutionEffect.kind == "UNKNOWN",
            )
            .order_by(ExecutionEffect.revision.desc())
        )
        if (
            effect is None
            or digest(effect.observation) != view.evidence_digest
            or effect.observation.get("process_observation", {}).get("output")
            != [item.model_dump(mode="json") for item in view.output]
            or effect.observation.get("process_observation", {}).get("launcher_exit_code")
            != view.launcher_exit_code
        ):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Interrupted Execution evidence requires repair"
            )
    return view


def execution_receipt(db: Session, actor: AuthenticatedContext, row: Receipt) -> ExecutionReceipt:
    execution = authorized_execution(db, actor, row.target_id)
    require_grant(db, actor, "execution.receipt.read", project_id=execution.project_id)
    if (row.principal_id, row.project_id, row.target_kind) != (
        actor.principal_id,
        execution.project_id,
        "execution",
    ):
        raise DomainError("PERMISSION_DENIED", "Execution receipt scope is unavailable")
    result = ExecutionReceipt.model_validate(row.result)
    if (result.operation_id, result.command, result.execution.execution_id) != (
        row.id,
        row.command,
        execution.id,
    ):
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Stored Execution receipt requires repair")
    execution_view(db, execution)
    return result


def store_view(row: Execution, view: ExecutionView) -> None:
    row.revision, row.state, row.snapshot = view.revision, view.state, view.model_dump(mode="json")
    row.drained = view.drained


class CurrentExecution:
    def __init__(self, service: "ExecutionService", actor: AuthenticatedContext, identity: str):
        self.service, self.actor, self.identity = service, actor, identity

    def current(self) -> bool:
        if self.service.stopping.is_set():
            return False
        try:
            with work_transaction(self.service.engine, self.actor) as db:
                row = authorized_execution(db, self.actor, self.identity, "start")
                self.service.check_job(db, self.actor, row, renew=True)
                view = execution_view(db, row)
                self.service.check_configuration(db, self.actor, row)
                if view.stop_requested or view.state not in ("STARTING", "RUNNING"):
                    return False
                command = ExecutionStart.model_validate(row.inputs["command"])
                self.service.inputs(db, self.actor, command)
                return True
        except (DomainError, ValueError, KeyError):
            return False

    def preparing(self, unit: str, invocation_id: str, containment: dict[str, str]) -> None:
        self.observe_process(unit, invocation_id, containment, phase="PREPARING")

    def starting(self, unit: str, invocation_id: str, containment: dict[str, str]) -> None:
        self.observe_process(unit, invocation_id, containment, phase="START_REQUESTED")

    def started(
        self, unit: str, invocation_id: str, containment: dict[str, str], process_id: int
    ) -> None:
        self.observe_process(
            unit, invocation_id, containment, phase="STARTED", process_id=process_id
        )

    def observe_process(
        self,
        unit: str,
        invocation_id: str,
        containment: dict[str, str],
        *,
        phase: str,
        process_id: int | None = None,
    ) -> None:
        if not self.current():
            raise PermissionError("Current execution authority is unavailable")
        with work_transaction(self.service.engine, self.actor) as db:
            row = authorized_execution(db, self.actor, self.identity, "start")
            self.service.check_job(db, self.actor, row, renew=True)
            view = execution_view(db, row)
            if (
                view.state != "STARTING"
                or view.unit != unit
                or view.stop_requested
                or (phase != "PREPARING" and view.invocation_id != invocation_id)
                or (phase == "PREPARING" and view.invocation_id is not None)
            ):
                raise PermissionError("Execution start identity is stale")
            self.service.inputs(
                db, self.actor, ExecutionStart.model_validate(row.inputs["command"])
            )
            store_view(
                row,
                view.model_copy(
                    update={
                        "revision": view.revision + 1,
                        "state": "RUNNING" if phase == "STARTED" else "STARTING",
                        "invocation_id": invocation_id,
                        "containment": containment,
                    }
                ),
            )
            db.add(
                ExecutionEffect(
                    id=str(uuid4()),
                    execution_id=row.id,
                    revision=row.revision,
                    kind=phase,
                    observation=row.snapshot | ({"process_id": process_id} if process_id else {}),
                )
            )


class ExecutionService:
    def __init__(self, engine: Engine, configuration: InstructionConfiguration | None):
        self.engine, self.configuration = engine, configuration
        self.stopping = threading.Event()
        self.pool: ThreadPoolExecutor | None = None
        self.pool_lock = threading.Lock()

    def check_job(
        self, db: Session, actor: AuthenticatedContext, row: Execution, *, renew: bool = False
    ) -> None:
        if row.job_id is None:
            return
        binding = db.get(
            TaskVerificationJob, row.job_id, options=[defer(TaskVerificationJob.inputs)]
        )
        if (
            binding is None
            or binding.execution_id != row.id
            or binding.claim_fence is None
            or binding.claim_owner is None
            or binding.claim_incarnation is None
        ):
            raise DomainError("PERMISSION_DENIED", "Execution Job claim binding is unavailable")
        identity = JobExecutionIdentity(
            row.job_id, binding.claim_fence, binding.claim_owner, binding.claim_incarnation
        )
        assert self.configuration is not None
        job, admitted = JobService(self.engine, self.configuration).check(db, identity, renew=renew)
        if admitted != actor or row.inputs.get("job") != {
            "job_id": job.id,
            "fence": identity.fence,
            "owner": identity.owner,
            "incarnation": identity.incarnation,
        }:
            raise DomainError("PERMISSION_DENIED", "Execution Job identity changed")

    def route(self, key: str, revision: int) -> LocalRoute:
        if self.configuration is None or self.configuration.executions is None:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Local execution routes are not configured")
        route = next(
            (route for route in self.configuration.executions.routes if route.key == key), None
        )
        if route is None or route.revision != revision:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Exact local execution route is unavailable"
            )
        return route

    def check_configuration(self, db: Session, actor: AuthenticatedContext, row: Execution) -> None:
        if row.job_id is not None:
            from journeon.models import Job
            from journeon.task_dispatch import TaskDispatchService

            job = db.get(Job, row.job_id)
            if job is None or self.configuration is None:
                raise DomainError("PERMISSION_DENIED", "Execution Task origin is unavailable")
            TaskDispatchService(self.engine, self.configuration).bound(db, actor, job)
        root = workspace_root(db, row.project_id, row.root_id, row.root_revision)
        root_config = self.root_configuration(root)
        view = execution_view(db, row)
        route = self.route(view.route_key, view.route_revision)
        if (
            route.project_id != row.project_id
            or digest(route.model_dump(mode="json")) != view.route_digest
        ):
            raise DomainError("PERMISSION_DENIED", "Current Execution route binding changed")
        if (
            self.configuration is None
            or self.configuration.executions is None
            or self.configuration.executions.revision != row.inputs["configuration_revision"]
            or root_config.model_dump(mode="json") != row.inputs["root"]
        ):
            raise DomainError(
                "PERMISSION_DENIED", "Current Execution configuration binding changed"
            )

        for binding in row.inputs.get("git_roots", []):
            admitted = workspace_root(db, row.project_id, binding["key"], binding["revision"])
            current = self.root_configuration(admitted)
            if (
                current.model_dump(mode="json") != binding["configuration"]
                or [admitted.device, admitted.inode, admitted.git_identity] != binding["identity"]
            ):
                raise DomainError("PERMISSION_DENIED", "Git object root authority changed")

    def root_configuration(self, root: InstructionRoot) -> RootConfiguration:
        if self.configuration is None:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Execution roots are not configured")
        config = next(
            (item for item in self.configuration.roots if item.key == root.root_key), None
        )
        if config is None or (config.role, config.project_id, config.revision) != (
            "PROJECT",
            root.project_id,
            root.config_revision,
        ):
            raise DomainError("PERMISSION_DENIED", "Current Execution root configuration changed")
        return config

    def inputs(
        self, db: Session, actor: AuthenticatedContext, command: ExecutionStart
    ) -> tuple[InstructionRoot, VerificationPolicy, LocalRoute]:
        require_grant(db, actor, "project.read", project_id=command.project_id)
        for action in ("start", "read", "stop", "drain", "complete", "receipt.read"):
            require_grant(db, actor, "execution." + action, project_id=command.project_id)
        root = workspace_root(db, command.project_id, command.root_key, command.root_revision)
        self.root_configuration(root)
        policy = current_policy(db, actor, command.project_id)
        if (
            policy is None
            or policy.revision != command.expected_policy_revision
            or not policy.enabled
        ):
            raise DomainError("REVISION_CONFLICT", "Execution requires the current enabled policy")
        for capability in policy.required_capabilities:
            require_grant(db, actor, capability, project_id=command.project_id)
        if policy.required_services:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Required execution service producers are unavailable"
            )
        route = self.route(command.route_key, command.route_revision)
        check = next((check for check in policy.checks if check.check_id == command.check_id), None)
        if (
            route.project_id != command.project_id
            or route.check_id != command.check_id
            or check is None
            or route.argv != check.argv
            or route.cwd != check.working_directory
        ):
            raise DomainError(
                "PERMISSION_DENIED", "Command differs from the exact policy and route"
            )
        return root, policy, route

    def read(self, actor: AuthenticatedContext, identity: str) -> ExecutionView:
        with work_transaction(self.engine, actor) as db:
            row = authorized_execution(db, actor, identity)
            self.check_configuration(db, actor, row)
            return execution_view(db, row)

    def receipt(
        self,
        db: Session,
        actor: AuthenticatedContext,
        command: ExecutionStart | ExecutionStop,
        name: Literal["execution.start.v1", "execution.stop.v1"],
        view: ExecutionView,
    ) -> ExecutionReceipt:
        result = ExecutionReceipt(
            operation_id=str(uuid4()),
            command=name,
            committed_at=datetime.now(UTC).isoformat(),
            execution=view,
        )
        db.add(
            Receipt(
                id=result.operation_id,
                principal_id=actor.principal_id,
                command=name,
                idempotency_key=command.idempotency_key,
                payload_hash=digest(command.model_dump(mode="json", exclude={"idempotency_key"})),
                project_id=view.project_id,
                owner="work",
                target_kind="execution",
                target_id=view.execution_id,
                authentication_ref=actor.authentication_ref,
                result=result.model_dump(mode="json"),
            )
        )
        db.flush()
        db.add(
            OutboxEvent(
                event_id=str(uuid4()),
                operation_id=result.operation_id,
                event_type="execution."
                + ("admitted" if name == "execution.start.v1" else "stop_requested"),
                schema_version=1,
                principal_id=actor.principal_id,
                project_id=view.project_id,
                owner="work",
                target_kind="execution",
                target_id=view.execution_id,
                target_revision=view.revision,
                payload=result.model_dump(mode="json"),
                committed_at=result.committed_at,
            )
        )
        return result

    def start(
        self,
        actor: AuthenticatedContext,
        command: ExecutionStart,
        *,
        job: JobExecutionIdentity | None = None,
    ) -> ExecutionReceipt:
        if self.stopping.is_set():
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Execution service is draining")
        with work_transaction(self.engine, actor) as db:
            self.inputs(db, actor, command)
            if job is not None:
                assert self.configuration is not None
                _, admitted = JobService(self.engine, self.configuration).check(db, job, renew=True)
                if admitted != actor:
                    raise DomainError("PERMISSION_DENIED", "Execution Job actor differs")
        assert self.configuration is not None and self.configuration.executions is not None
        config = self.configuration.executions
        resources = resource_observation(Path(config.storage_path))
        if (
            resources["memory_available"]
            < max(route.core_memory_reserve_bytes for route in config.routes)
            or resources["storage_available"]
            < max(route.disk_reserve_bytes for route in config.routes)
            or config.cpu_percent + config.core_cpu_reserve_percent > resources["cpu_percent"]
        ):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Execution admission would consume the core reserve"
            )
        with self.pool_lock:
            if self.stopping.is_set():
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Execution service is draining")
            identity = str(uuid4())
            directory = open_directory(Path(config.storage_path))
            lock = None
            committed = False
            try:
                host = hashlib.sha256(
                    Path("/etc/machine-id").read_bytes() + str(os.getuid()).encode()
                ).hexdigest()
                with work_transaction(self.engine, actor) as db:
                    prior = db.scalar(
                        select(Receipt)
                        .options(defer(Receipt.result))
                        .where(
                            Receipt.principal_id == actor.principal_id,
                            Receipt.command == "execution.start.v1",
                            Receipt.idempotency_key == command.idempotency_key,
                        )
                    )
                    if prior is not None:
                        row = authorized_execution(db, actor, prior.target_id, "start")
                        self.check_configuration(db, actor, row)
                        if row.job_id != (job.job_id if job else None):
                            raise DomainError("IDEMPOTENCY_CONFLICT", "Execution origin differs")
                        if job is not None:
                            self.check_job(db, actor, row, renew=True)
                        if prior.payload_hash != digest(
                            command.model_dump(mode="json", exclude={"idempotency_key"})
                        ):
                            raise DomainError(
                                "IDEMPOTENCY_CONFLICT", "Execution identity has different input"
                            )
                        return execution_receipt(db, actor, prior)
                    root, policy, route = self.inputs(db, actor, command)
                    task_binding = None
                    if job is not None:
                        from journeon.task_dispatch import TaskDispatchService, execution_command

                        job_row, admitted = JobService(self.engine, self.configuration).check(
                            db, job, renew=True
                        )
                        task_binding, dispatch, manifest = TaskDispatchService(
                            self.engine, self.configuration
                        ).bound(db, actor, job_row, execution=True)
                        if (
                            admitted != actor
                            or command != execution_command(dispatch, manifest, job.job_id)
                            or task_binding.execution_id is not None
                        ):
                            raise DomainError(
                                "REVISION_CONFLICT", "Execution differs from its admitted Task Job"
                            )
                    retained = list(db.scalars(select(Execution)))
                    active = [row for row in retained if not row.drained]
                    storage_bytes = (
                        route.output_bytes
                        + route.artifact_bytes
                        + config.snapshot_bytes * 4
                        + route.workspace_bytes
                    )
                    memory_claim = sum(row.memory_bytes for row in active) + route.memory_bytes
                    storage_claim = sum(row.storage_bytes for row in retained) + storage_bytes
                    cpu_claim = (
                        sum(
                            LocalRoute.model_validate(row.inputs["route"]).cpu_percent
                            for row in active
                        )
                        + route.cpu_percent
                    )
                    if (
                        len(active) >= config.concurrent_executions
                        or memory_claim > config.memory_bytes
                        or storage_claim > config.storage_bytes
                        or cpu_claim > config.cpu_percent
                        or memory_claim
                        + max(item.core_memory_reserve_bytes for item in config.routes)
                        > resources["memory_available"]
                        or storage_claim + max(item.disk_reserve_bytes for item in config.routes)
                        > resources["storage_available"]
                    ):
                        raise DomainError(
                            "DEPENDENCY_UNAVAILABLE", "Execution resource admission is full"
                        )
                    lock = os.open(
                        "execution-" + identity + ".lock",
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=directory,
                    )
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    inputs = {
                        "command": command.model_dump(mode="json"),
                        "policy": policy.model_dump(mode="json"),
                        "route": route.model_dump(mode="json"),
                        "root": self.root_configuration(root).model_dump(mode="json"),
                        "root_identity": [root.device, root.inode, root.git_identity],
                        "configuration_revision": config.revision,
                        "origin": {
                            "kind": "DIRECT_VERIFICATION",
                            "execution_id": identity,
                            "principal_id": actor.principal_id,
                            "authentication_ref": actor.authentication_ref,
                            "principal_epoch": actor.principal_epoch,
                        },
                        "host_fingerprint": host,
                        "resource_admission": resources,
                    }
                    if job is not None:
                        assert task_binding is not None
                        inputs["job"] = {
                            "job_id": job.job_id,
                            "fence": job.fence,
                            "owner": job.owner,
                            "incarnation": job.incarnation,
                        }
                        inputs["origin"] = {
                            "kind": "TASK_VERIFICATION",
                            "attempt_id": task_binding.attempt_id,
                            "manifest_id": task_binding.manifest_id,
                        }
                    view = ExecutionView(
                        execution_id=identity,
                        origin="TASK_VERIFICATION" if job else "DIRECT_VERIFICATION",
                        job_id=job.job_id if job else None,
                        attempt_id=task_binding.attempt_id if task_binding else None,
                        attempt_manifest_id=task_binding.manifest_id if task_binding else None,
                        project_id=command.project_id,
                        root_key=command.root_key,
                        root_revision=command.root_revision,
                        policy_revision=policy.revision,
                        revision=1,
                        state="STARTING",
                        manifest_digest=digest(inputs),
                        route_key=route.key,
                        route_revision=route.revision,
                        route_digest=digest(route.model_dump(mode="json")),
                        check_id=command.check_id,
                        initiating_principal_id=actor.principal_id,
                        authentication_ref=actor.authentication_ref,
                        principal_epoch=actor.principal_epoch,
                        host_fingerprint=host,
                        created_at=datetime.now(UTC).isoformat(),
                        unit="journeon-execution-" + identity + ".service",
                    )
                    db.add(
                        Execution(
                            id=identity,
                            job_id=job.job_id if job else None,
                            root_id=root.id,
                            root_revision=root.revision,
                            project_id=command.project_id,
                            principal_id=actor.principal_id,
                            authentication_ref=actor.authentication_ref,
                            principal_epoch=actor.principal_epoch,
                            idempotency_key=command.idempotency_key,
                            payload_hash=digest(
                                command.model_dump(mode="json", exclude={"idempotency_key"})
                            ),
                            revision=1,
                            state="STARTING",
                            drained=False,
                            memory_bytes=route.memory_bytes,
                            storage_bytes=storage_bytes,
                            snapshot=view.model_dump(mode="json"),
                            inputs=inputs,
                        )
                    )
                    db.flush()
                    if job is not None:
                        assert task_binding is not None
                        task_binding.execution_id = identity
                        (
                            task_binding.claim_fence,
                            task_binding.claim_owner,
                            task_binding.claim_incarnation,
                        ) = job.fence, job.owner, job.incarnation
                    result = self.receipt(db, actor, command, "execution.start.v1", view)
                    if job is not None:
                        job_row.operation_id = result.operation_id
                    db.add(
                        ExecutionEffect(
                            id=str(uuid4()),
                            execution_id=identity,
                            revision=1,
                            kind="INTENT",
                            observation=view.model_dump(mode="json"),
                        )
                    )
                committed = True
                if self.pool is None:
                    self.pool = ThreadPoolExecutor(
                        max_workers=config.concurrent_executions,
                        thread_name_prefix="local-execution",
                    )
                self.pool.submit(self.execute, actor, identity, lock)
                lock = None
                return result
            finally:
                if lock is not None:
                    if not committed:
                        os.unlink("execution-" + identity + ".lock", dir_fd=directory)
                    os.close(lock)
                os.close(directory)

    def execute(self, actor: AuthenticatedContext, identity: str, lock: int) -> None:
        workspace_lock = None
        try:
            with work_transaction(self.engine, actor) as db:
                row = authorized_execution(db, actor, identity, "start")
                self.check_job(db, actor, row, renew=True)
                command = ExecutionStart.model_validate(row.inputs["command"])
                root, policy, route = self.inputs(db, actor, command)
                source = Path(self.root_configuration(root).path)
                root_identity = [root.device, root.inode, root.git_identity]
                git_roots: list[dict[str, Any]] = []
                for candidate in db.scalars(
                    select(InstructionRoot).where(
                        InstructionRoot.project_id == command.project_id,
                        InstructionRoot.role == "PROJECT",
                        InstructionRoot.enabled.is_(True),
                    )
                ):
                    try:
                        configured = self.root_configuration(candidate)
                    except DomainError:
                        continue
                    git_roots.append(
                        {
                            "key": candidate.id,
                            "revision": candidate.revision,
                            "configuration": configured.model_dump(mode="json"),
                            "identity": [candidate.device, candidate.inode, candidate.git_identity],
                        }
                    )
                view = execution_view(db, row)
                manifest = None
                if row.job_id is not None:
                    from journeon.models import Job
                    from journeon.task_dispatch import TaskDispatchService

                    job_row = db.get(Job, row.job_id)
                    assert job_row is not None and self.configuration is not None
                    _, _, manifest = TaskDispatchService(self.engine, self.configuration).bound(
                        db, actor, job_row, execution=True
                    )
            assert self.configuration is not None and self.configuration.executions is not None
            config = self.configuration.executions
            installation = installation_observation()
            descriptor = open_directory(source)
            try:
                observed = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            if [observed.st_dev, observed.st_ino, git_identity(source)] != root_identity:
                raise PermissionError("Admitted execution root identity changed")
            if manifest is not None:
                assert self.configuration.attempts is not None
                attempt_directory = (
                    Path(self.configuration.attempts.storage_path) / manifest.attempt_id
                )
                workspace_lock = os.open(
                    attempt_directory / "execution.lock",
                    os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                    0o600,
                )
                fcntl.flock(workspace_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                source = attempt_directory / "workspace"
            captured = capture_snapshot(
                source, max_bytes=config.snapshot_bytes, max_files=config.snapshot_files
            )
            if manifest is not None:
                if captured.snapshot != manifest.snapshot:
                    raise DomainError(
                        "REVISION_CONFLICT", "Attempt workspace differs from its immutable manifest"
                    )
                verify_snapshot_evidence(attempt_directory / "evidence", captured)
            authority = CurrentExecution(self, actor, identity)
            if not authority.current():
                raise PermissionError("Execution preparation authority was revoked")
            metadata_bytes = snapshot_storage_bytes(captured, metadata_only=True)
            resources = resource_observation(Path(config.storage_path))
            with work_transaction(self.engine, actor) as db:
                row = authorized_execution(db, actor, identity, "start")
                self.check_job(db, actor, row, renew=True)
                self.check_configuration(db, actor, row)
                self.inputs(db, actor, command)
                storage_claim = sum(db.scalars(select(Execution.storage_bytes))) + metadata_bytes
                if (
                    storage_claim > config.storage_bytes
                    or storage_claim + max(item.disk_reserve_bytes for item in config.routes)
                    > resources["storage_available"]
                ):
                    raise DomainError(
                        "DEPENDENCY_UNAVAILABLE",
                        "Execution snapshot metadata exceeds storage admission",
                    )
                row.storage_bytes += metadata_bytes
            evidence_directory = Path(config.storage_path) / identity
            write_snapshot(evidence_directory, captured)
            projection = evidence_directory / "input"
            materialize_projection(projection, captured)
            for binding in git_roots:
                root_path = Path(binding["configuration"]["path"])
                root_descriptor = open_directory(root_path)
                try:
                    root_stat = os.fstat(root_descriptor)
                finally:
                    os.close(root_descriptor)
                if [root_stat.st_dev, root_stat.st_ino, git_identity(root_path)] != binding[
                    "identity"
                ]:
                    raise PermissionError("Git object root identity changed")
            git_view = project_git_view(
                source,
                projection,
                captured,
                admitted_roots=[Path(binding["configuration"]["path"]) for binding in git_roots],
                max_bytes=config.snapshot_bytes - captured.snapshot.byte_count,
                max_files=config.snapshot_files - len(captured.snapshot.working),
            )
            used_roots = [
                binding
                for binding in git_roots
                if any(
                    Path(item["source"]).is_relative_to(Path(binding["configuration"]["path"]))
                    for item in git_view.observations
                )
            ]
            if (
                capture_snapshot(
                    source, max_bytes=config.snapshot_bytes, max_files=config.snapshot_files
                ).snapshot
                != captured.snapshot
            ):
                raise ValueError("Execution source changed during preparation")
            with work_transaction(self.engine, actor) as db:
                row = authorized_execution(db, actor, identity, "start")
                self.check_job(db, actor, row, renew=True)
                self.inputs(db, actor, command)
                view = execution_view(db, row)
                row.inputs = row.inputs | {
                    "source_snapshot": captured.snapshot.model_dump(mode="json"),
                    "git_objects": git_view.observations,
                    "git_roots": used_roots,
                    "installation": installation,
                }
                store_view(
                    row,
                    view.model_copy(
                        update={
                            "revision": view.revision + 1,
                            "manifest_digest": digest(row.inputs),
                            "manifest_id": identity,
                        }
                    ),
                )
                db.add(
                    ExecutionManifest(
                        execution_id=identity, content_hash=digest(row.inputs), snapshot=row.inputs
                    )
                )
                db.add(
                    ExecutionEffect(
                        id=str(uuid4()),
                        execution_id=identity,
                        revision=row.revision,
                        kind="INPUT_BOUND",
                        observation=row.snapshot,
                    )
                )
            if installation_observation() != installation:
                raise OSError("Execution installation changed before process start")
            actual = run_local(
                route, projection, authority, unit=view.unit, object_mounts=git_view.mounts
            )
            permitted = authority.current()
            with transaction(self.engine) as db:
                found = db.get(Execution, identity)
                assert found is not None
                row = found
                view = execution_view(db, row)
                try:
                    self.check_job(db, actor, row, renew=True)
                    self.check_configuration(db, actor, row)
                    self.inputs(db, actor, command)
                    permitted = permitted and not view.stop_requested and not self.stopping.is_set()
                except DomainError:
                    permitted = False
                evidence = {
                    key: actual[key]
                    for key in (
                        "completion",
                        "output",
                        "invocation_id",
                        "containment",
                        "launcher_exit_code",
                    )
                }
                check = next(check for check in policy.checks if check.check_id == view.check_id)
                passed = (
                    permitted
                    and actual["completion"]["reason"] == "EXITED"
                    and actual["completion"]["exit_code"] == check.expected_exit_code
                    and actual["completion"]["drained"]
                )
                completed = ExecutionView.model_validate(
                    view.model_dump(mode="json")
                    | evidence
                    | {
                        "revision": view.revision + 1,
                        "state": "COMPLETED" if permitted else "CANCELLED",
                        "verification_passed": passed,
                        "evidence_digest": digest(evidence),
                        "drained": actual["completion"]["drained"],
                        "launcher_exit_code": actual["launcher_exit_code"],
                    }
                )
                store_view(row, completed)
                db.add(
                    ExecutionEffect(
                        id=str(uuid4()),
                        execution_id=identity,
                        revision=row.revision,
                        kind="COMPLETED",
                        observation=row.snapshot,
                    )
                )
        except Exception as exc:
            logging.getLogger(__name__).error(
                "Local execution requires reconciliation (%s)", type(exc).__name__
            )
            with transaction(self.engine) as db:
                found = db.get(Execution, identity)
                if found is not None:
                    row = found
                    view = execution_view(db, row)
                    observation: dict[str, Any] = {"failure_type": type(exc).__name__}
                    update: dict[str, Any] = {"revision": view.revision + 1, "state": "UNKNOWN"}
                    if isinstance(exc, ExecutionInterrupted):
                        observation["process_observation"] = exc.observation
                        update.update(
                            {
                                "output": exc.observation["output"],
                                "launcher_exit_code": exc.observation["launcher_exit_code"],
                                "evidence_digest": digest(observation),
                            }
                        )
                    store_view(
                        row, ExecutionView.model_validate(view.model_dump(mode="json") | update)
                    )
                    db.add(
                        ExecutionEffect(
                            id=str(uuid4()),
                            execution_id=identity,
                            revision=row.revision,
                            kind="UNKNOWN",
                            observation=observation,
                        )
                    )
        finally:
            if workspace_lock is not None:
                os.close(workspace_lock)
            os.close(lock)

    def doctor(self, actor: AuthenticatedContext, identity: str) -> dict[str, object]:
        with work_transaction(self.engine, actor) as db:
            row = authorized_execution(db, actor, identity)
            self.check_configuration(db, actor, row)
            command = ExecutionStart.model_validate(row.inputs["command"])
            self.inputs(db, actor, command)
            view = execution_view(db, row)
            installed = row.inputs.get("installation")
        observed = installation_observation()
        with work_transaction(self.engine, actor) as db:
            row = authorized_execution(db, actor, identity)
            self.check_configuration(db, actor, row)
            self.inputs(db, actor, command)
            current = execution_view(db, row)
            qualified = (
                current.revision == view.revision
                and installed == observed
                and current.state == "COMPLETED"
                and current.verification_passed
                and current.drained
                and bool(current.invocation_id)
                and bool(current.containment)
                and bool(current.evidence_digest)
            )
        return {
            "execution_id": identity,
            "qualified": qualified,
            "installation": observed,
            "evidence_digest": current.evidence_digest,
            "scope": "CURRENT_DIRECT_VERIFICATION_ROUTE",
        }

    def stop(self, actor: AuthenticatedContext, command: ExecutionStop) -> ExecutionReceipt:
        with work_transaction(self.engine, actor) as db:
            prior = db.scalar(
                select(Receipt)
                .options(defer(Receipt.result))
                .where(
                    Receipt.principal_id == actor.principal_id,
                    Receipt.command == "execution.stop.v1",
                    Receipt.idempotency_key == command.idempotency_key,
                )
            )
            if prior is not None:
                row = authorized_execution(db, actor, prior.target_id, "stop")
                require_grant(db, actor, "execution.drain", project_id=row.project_id)
                self.check_configuration(db, actor, row)
                result = execution_receipt(db, actor, prior)
                if prior.payload_hash != digest(
                    command.model_dump(mode="json", exclude={"idempotency_key"})
                ):
                    raise DomainError(
                        "IDEMPOTENCY_CONFLICT", "Execution stop identity has different input"
                    )
                return result
            row = authorized_execution(db, actor, command.execution_id, "stop")
            for action in ("read", "drain", "receipt.read"):
                require_grant(db, actor, "execution." + action, project_id=row.project_id)
            self.check_configuration(db, actor, row)
            view = execution_view(db, row)
            if view.revision != command.expected_revision:
                raise DomainError("REVISION_CONFLICT", "Execution changed before stop")
            if view.state not in ("STARTING", "RUNNING"):
                raise DomainError("REVISION_CONFLICT", "Execution is already settled")
            view = view.model_copy(update={"revision": view.revision + 1, "stop_requested": True})
            store_view(row, view)
            return self.receipt(db, actor, command, "execution.stop.v1", view)

    def reconcile(self) -> None:
        if self.configuration is None or self.configuration.executions is None:
            return
        config = self.configuration.executions
        with transaction(self.engine) as db:
            identities = list(db.scalars(select(Execution.id).where(Execution.drained.is_(False))))
        directory = open_directory(Path(config.storage_path))
        try:
            for identity in identities:
                lock = os.open(
                    "execution-" + identity + ".lock", os.O_RDWR | os.O_NOFOLLOW, dir_fd=directory
                )
                try:
                    try:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        continue
                    with transaction(self.engine) as db:
                        row = db.get(Execution, identity)
                        assert row is not None
                        view = execution_view(db, row)
                        route = LocalRoute.model_validate(row.inputs["route"])
                    observation = reconcile_unit(view.unit, view.invocation_id, route)
                    with transaction(self.engine) as db:
                        row = db.get(Execution, identity)
                        assert row is not None
                        view = execution_view(db, row)
                        store_view(
                            row,
                            view.model_copy(
                                update={
                                    "revision": view.revision + 1,
                                    "state": "UNKNOWN",
                                    "drained": observation["drained"],
                                    "verification_passed": False,
                                }
                            ),
                        )
                        db.add(
                            ExecutionEffect(
                                id=str(uuid4()),
                                execution_id=identity,
                                revision=row.revision,
                                kind="RECONCILED",
                                observation=observation,
                            )
                        )
                finally:
                    os.close(lock)
        finally:
            os.close(directory)

    def shutdown(self) -> None:
        with self.pool_lock:
            self.stopping.set()
            pool = self.pool
        if pool is not None:
            pool.shutdown(wait=True)
