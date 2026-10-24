# SPDX-License-Identifier: AGPL-3.0-only
"""Closed deterministic local route backed by namespaces and measured cgroup limits."""

import hashlib
import json
import os
import selectors
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Protocol, Self

from pydantic import Field, model_validator

from journeon import execution_helper
from journeon.contracts import Contract, Identifier, PositiveRevision


class LocalRoute(Contract):
    key: Identifier
    revision: PositiveRevision
    project_id: Identifier
    check_id: Identifier
    argv: list[str] = Field(min_length=1)
    executable_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    cwd: str
    environment: dict[str, str]
    artifacts: list[str]
    memory_bytes: int = Field(gt=0)
    processes: int = Field(gt=0)
    cpu_percent: int = Field(gt=0)
    workspace_bytes: int = Field(gt=0)
    temporary_bytes: int = Field(gt=0)
    output_bytes: int = Field(gt=0)
    artifact_bytes: int = Field(gt=0)
    artifact_files: int = Field(gt=0)
    core_memory_reserve_bytes: int = Field(gt=0)
    disk_reserve_bytes: int = Field(gt=0)
    authority_lease_seconds: int = Field(gt=0)
    authority_poll_seconds: float = Field(gt=0)
    drain_seconds: int = Field(gt=0)
    control_seconds: int = Field(gt=0)

    @model_validator(mode="after")
    def closed_paths(self) -> Self:
        executable = Path(self.argv[0])
        if not executable.is_absolute() or not executable.is_relative_to("/usr"):
            raise ValueError("Local route executables require an explicit installed tool path")
        for path in [self.cwd, *self.artifacts]:
            if Path(path).is_absolute() or ".." in Path(path).parts or str(Path(path)) != path:
                raise ValueError("Local route paths must remain within the writable workspace")
        if any("\0" in value for value in self.argv):
            raise ValueError("Local route arguments cannot contain null characters")
        if any(
            not key or "=" in key or "\0" in key + value for key, value in self.environment.items()
        ):
            raise ValueError("Local route environment entries are invalid")
        if self.authority_poll_seconds >= self.authority_lease_seconds:
            raise ValueError("Authority renewal must precede its lease deadline")
        if len(set(self.artifacts)) != len(self.artifacts):
            raise ValueError("Declared artifact paths must be distinct")
        return self


class ExecutionAuthority(Protocol):
    def current(self) -> bool: ...

    def preparing(self, unit: str, invocation_id: str, containment: dict[str, str]) -> None: ...

    def starting(self, unit: str, invocation_id: str, containment: dict[str, str]) -> None: ...

    def started(
        self, unit: str, invocation_id: str, containment: dict[str, str], process_id: int
    ) -> None: ...


class ExecutionConfiguration(Contract):
    revision: PositiveRevision
    storage_path: str
    snapshot_bytes: int = Field(gt=0)
    snapshot_files: int = Field(gt=0)
    concurrent_executions: int = Field(gt=0)
    memory_bytes: int = Field(gt=0)
    storage_bytes: int = Field(gt=0)
    cpu_percent: int = Field(gt=0)
    core_cpu_reserve_percent: int = Field(gt=0)
    routes: list[LocalRoute] = Field(min_length=1)

    @model_validator(mode="after")
    def distinct_routes(self) -> Self:
        if (
            not Path(self.storage_path).is_absolute()
            or str(Path(self.storage_path)) != self.storage_path
            or ".." in Path(self.storage_path).parts
        ):
            raise ValueError("Execution storage requires a normalized absolute path")
        if len({route.key for route in self.routes}) != len(self.routes):
            raise ValueError("Execution route keys must be distinct")
        return self


def control_environment() -> dict[str, str]:
    runtime = f"/run/user/{os.getuid()}"
    return {
        "PATH": "/usr/bin:/bin",
        "XDG_RUNTIME_DIR": runtime,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus",
    }


def unit_observation(unit: str, timeout: int) -> tuple[str, Path]:
    observed = subprocess.run(
        [
            "/usr/bin/systemctl",
            "--user",
            "show",
            unit,
            "--property=InvocationID",
            "--property=ControlGroup",
        ],
        env=control_environment(),
        capture_output=True,
        check=True,
        timeout=timeout,
    )
    values = dict(line.split("=", 1) for line in observed.stdout.decode().splitlines())
    group = values["ControlGroup"]
    if not group.startswith("/") or ".." in Path(group).parts or not values["InvocationID"]:
        raise ValueError("Execution unit identity is unavailable")
    return values["InvocationID"], Path("/sys/fs/cgroup") / group.removeprefix("/")


def reconcile_unit(unit: str, invocation_id: str | None, route: LocalRoute) -> dict[str, Any]:
    deadline = time.monotonic() + route.authority_lease_seconds + route.drain_seconds
    stopped = False
    while True:
        observed = subprocess.run(
            [
                "/usr/bin/systemctl",
                "--user",
                "show",
                unit,
                "--property=InvocationID",
                "--property=ControlGroup",
                "--property=LoadState",
                "--property=ActiveState",
            ],
            env=control_environment(),
            capture_output=True,
            check=False,
            timeout=route.control_seconds,
        )
        values = dict(line.split("=", 1) for line in observed.stdout.decode().splitlines())
        if (
            observed.returncode in (0, 4)
            and values.get("LoadState") == "not-found"
            and values.get("ActiveState") == "inactive"
            and not values.get("ControlGroup")
        ):
            return {"drained": True, "unit_state": "NOT_FOUND", "stop_requested": stopped}
        if observed.returncode != 0:
            return {"drained": False, "unit_state": "UNAVAILABLE", "stop_requested": stopped}
        if invocation_id is not None and values.get("InvocationID") == invocation_id:
            if not stopped:
                subprocess.run(
                    ["/usr/bin/systemctl", "--user", "stop", "--no-block", unit],
                    env=control_environment(),
                    capture_output=True,
                    check=True,
                    timeout=route.control_seconds,
                )
                stopped = True
        elif invocation_id is not None and values.get("InvocationID"):
            return {"drained": False, "unit_state": "IDENTITY_CHANGED", "stop_requested": stopped}
        if time.monotonic() >= deadline:
            return {"drained": False, "unit_state": "UNSETTLED", "stop_requested": stopped}
        time.sleep(min(route.authority_poll_seconds, max(0, deadline - time.monotonic())))


def installation_observation() -> dict[str, Any]:
    files = {}
    for path in (
        "/usr/bin/bwrap",
        "/usr/bin/systemd-run",
        "/usr/bin/systemctl",
        "/usr/bin/python3",
        str(Path(execution_helper.__file__).resolve()),
    ):
        with Path(path).open("rb") as stream:
            before = os.fstat(stream.fileno())
            fingerprint = hashlib.file_digest(stream, "sha256").hexdigest()
            after = os.fstat(stream.fileno())
        current = Path(path).stat()
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(
            getattr(before, field) != getattr(item, field)
            for item in (after, current)
            for field in fields
        ):
            raise OSError("Execution installation changed during observation")
        files[path] = fingerprint
    kernel = os.uname()
    return {
        "backend": "LINUX_SYSTEMD_BWRAP_V1",
        "files": files,
        "kernel": kernel.release,
        "machine": kernel.machine,
    }


def resource_observation(source: Path) -> dict[str, int]:
    memory = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    available = int(memory["MemAvailable"].split()[0]) * 1024
    cpu = len(os.sched_getaffinity(0)) * 100
    memberships = Path("/proc/self/cgroup").read_text().splitlines()
    relative = next((line[3:] for line in memberships if line.startswith("0::")), None)
    if relative is None or not relative.startswith("/") or ".." in Path(relative).parts:
        raise OSError("Unified resource hierarchy is unavailable")
    hierarchy = Path("/sys/fs/cgroup")
    group = hierarchy / relative.removeprefix("/")
    while True:
        try:
            maximum = (group / "memory.max").read_text().strip()
            if maximum != "max":
                consumed = int((group / "memory.current").read_text())
                available = min(available, max(0, int(maximum) - consumed))
            quota, period = (group / "cpu.max").read_text().split()
            if quota != "max":
                cpu = min(cpu, int(quota) * 100 // int(period))
        except FileNotFoundError:
            if group != hierarchy:
                raise OSError("Required resource controllers are unavailable") from None
        if group == hierarchy:
            break
        group = group.parent
    disk = os.statvfs(source)
    return {
        "memory_available": available,
        "storage_available": disk.f_bavail * disk.f_frsize,
        "cpu_percent": cpu,
    }


def resource_admission(route: LocalRoute, source: Path) -> None:
    observed = resource_observation(source)
    if observed["memory_available"] < route.memory_bytes + route.core_memory_reserve_bytes:
        raise OSError("Execution memory admission would consume the core reserve")
    if observed["storage_available"] < route.artifact_bytes + route.disk_reserve_bytes:
        raise OSError("Execution storage admission would consume the recovery reserve")


class ExecutionInterrupted(OSError):
    def __init__(self, observation: dict[str, Any]) -> None:
        super().__init__("Execution ended without authenticated completion")
        self.observation = observation


def run_local(
    route: LocalRoute,
    source: Path,
    authority: ExecutionAuthority,
    *,
    unit: str | None = None,
    object_mounts: list[Path] | None = None,
) -> dict[str, Any]:
    if not authority.current():
        raise PermissionError("Current execution authority is required")
    if hashlib.sha256(Path(route.argv[0]).read_bytes()).hexdigest() != route.executable_sha256:
        raise ValueError("Installed executable differs from the authorized route")
    resource_admission(route, source)
    unit = unit or f"journeon-execution-{uuid.uuid4().hex}.service"
    helper = Path(execution_helper.__file__).resolve()
    from journeon.instruction_config import open_directory

    mount_identities = {}
    for host_path, namespace_path in [
        (source, "/input"),
        *[(path, f"/git-objects/{index}") for index, path in enumerate(object_mounts or [])],
    ]:
        descriptor = open_directory(host_path)
        try:
            metadata = os.fstat(descriptor)
            mount_identities[namespace_path] = [metadata.st_dev, metadata.st_ino]
        finally:
            os.close(descriptor)
    git_mounts = [
        argument
        for index, path in enumerate(object_mounts or [])
        for argument in ("--ro-bind", str(path), f"/git-objects/{index}")
    ]
    command = [
        "/usr/bin/systemd-run",
        "--user",
        f"--unit={unit}",
        "--collect",
        "--wait",
        "--pipe",
        "--quiet",
        "-p",
        f"MemoryMax={route.memory_bytes}",
        "-p",
        "MemorySwapMax=0",
        "-p",
        f"TasksMax={route.processes}",
        "-p",
        f"CPUQuota={route.cpu_percent}%",
        "-p",
        "KillMode=control-group",
        "-p",
        "OOMPolicy=kill",
        "-p",
        f"TimeoutStopSec={route.drain_seconds}s",
        "/usr/bin/bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--as-pid-1",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/lib",
        "/lib",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--ro-bind",
        str(source),
        "/input",
        "--ro-bind",
        str(helper),
        "/helper.py",
        *git_mounts,
        "--size",
        str(route.workspace_bytes),
        "--tmpfs",
        "/workspace",
        "--size",
        str(route.temporary_bytes),
        "--tmpfs",
        "/tmp",
        "--chdir",
        "/workspace",
        "/usr/bin/python3",
        "-I",
        "-S",
        "/helper.py",
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=control_environment(),
        start_new_session=True,
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    configuration = {
        "argv": route.argv,
        "cwd": str(Path("/workspace") / route.cwd),
        "environment": route.environment,
        "artifacts": route.artifacts,
        "output_bytes": route.output_bytes,
        "artifact_bytes": route.artifact_bytes,
        "artifact_files": route.artifact_files,
        "authority_lease_seconds": route.authority_lease_seconds,
        "drain_seconds": route.drain_seconds,
        "mount_identities": mount_identities,
    }
    process.stdin.write((json.dumps(configuration) + "\n").encode())
    process.stdin.flush()
    selector = selectors.DefaultSelector()
    for stream, name in ((process.stdout, "protocol"), (process.stderr, "diagnostic")):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    pending = b""
    frames: list[dict[str, Any]] = []
    invocation_id = ""
    containment: dict[str, str] = {}
    last_authority = time.monotonic()
    startup_deadline = last_authority + route.control_seconds
    completion = None
    command_started = False
    start_requested = False
    cancelled = False
    # Each nonempty OUTPUT may contain one raw byte and four base64 bytes.
    output_frame_bytes = len(b'{"kind":"OUTPUT","stream":"stdout","data":""}\n')
    artifact_metadata_bytes = sum(
        len(
            json.dumps(
                {"path": name, "byte_count": route.artifact_bytes, "sha256": "0" * 64, "data": ""},
                separators=(",", ":"),
            ).encode()
        )
        + 1
        for name in route.artifacts
    )
    protocol_bound = (
        (output_frame_bytes + 4) * route.output_bytes
        + 4 * route.artifact_bytes
        + artifact_metadata_bytes
        + 2 * len(json.dumps(mount_identities).encode())
        + 65536
    )
    received = 0
    diagnostic_bytes = 0
    try:
        while selector.get_map():
            now = time.monotonic()
            if not command_started and now >= startup_deadline:
                raise TimeoutError("Execution installation handshake did not complete")
            if completion is None and now - last_authority >= route.authority_poll_seconds:
                permitted = authority.current()
                action = "RENEW" if permitted and not cancelled else "STOP"
                cancelled = cancelled or not permitted
                try:
                    process.stdin.write((json.dumps({"action": action}) + "\n").encode())
                    process.stdin.flush()
                except BrokenPipeError:
                    pass
                last_authority = now
            for key, _ in selector.select(route.authority_poll_seconds):
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "diagnostic":
                    diagnostic_bytes += len(data)
                    if diagnostic_bytes > 65536:
                        raise ValueError("Execution diagnostics exceeded their control bound")
                    continue
                received += len(data)
                if received > protocol_bound:
                    raise ValueError("Execution protocol exceeded its declared output bound")
                pending += data
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    frame = json.loads(line)
                    if frame == {"kind": "REJECTED", "reason": "MOUNT_IDENTITY"}:
                        raise ValueError("Execution mount identity changed before preparation")
                    if frame["kind"] == "PREPARING":
                        if frame.get("mount_identities") != mount_identities:
                            raise ValueError("Execution mount identity observation is incomplete")
                        if invocation_id:
                            raise ValueError("Execution helper repeated its start handshake")
                        invocation_id, group = unit_observation(unit, route.control_seconds)
                        containment = {
                            name: (group / name).read_text().strip()
                            for name in ("memory.max", "memory.swap.max", "pids.max", "cpu.max")
                        }
                        quota, period = containment["cpu.max"].split()
                        if (
                            containment["memory.max"] != str(route.memory_bytes)
                            or containment["memory.swap.max"] != "0"
                            or containment["pids.max"] != str(route.processes)
                            or quota == "max"
                            or int(quota) * 100 != route.cpu_percent * int(period)
                        ):
                            raise ValueError("Kernel limits differ from the authorized route")
                        if not authority.current() or cancelled:
                            raise PermissionError("Execution start authority was revoked")
                        authority.preparing(unit, invocation_id, containment)
                    elif frame["kind"] == "READY":
                        if (
                            not invocation_id
                            or start_requested
                            or frame.get("mount_identities") != mount_identities
                        ):
                            raise ValueError("Execution preparation handshake is incomplete")
                        if not authority.current() or cancelled:
                            raise PermissionError("Execution start authority was revoked")
                        authority.starting(unit, invocation_id, containment)
                        process.stdin.write(b'{"action":"START"}\n')
                        process.stdin.flush()
                        start_requested = True
                    elif frame["kind"] == "STARTED":
                        if (
                            not start_requested
                            or command_started
                            or type(frame.get("pid")) is not int
                            or frame["pid"] <= 1
                        ):
                            raise ValueError("Execution launch observation is invalid")
                        authority.started(unit, invocation_id, containment, frame["pid"])
                        command_started = True
                    elif frame["kind"] == "OUTPUT" and command_started:
                        frames.append(frame)
                    elif frame["kind"] == "RESULT" and command_started and completion is None:
                        completion = frame
                    else:
                        raise ValueError("Execution helper returned an invalid protocol state")
        launcher_exit = process.wait()
        observation = {
            "unit": unit,
            "invocation_id": invocation_id,
            "containment": containment,
            "launcher_exit_code": launcher_exit,
            "completion": completion,
            "output": frames,
        }
        if launcher_exit != 0 or completion is None or pending:
            raise ExecutionInterrupted(observation)
        return observation
    finally:
        try:
            process.stdin.close()
        except BrokenPipeError:
            # A terminated helper cannot consume a queued renewal; keep its observed result.
            pass
        if process.poll() is None:
            # Closing the private controller pipe expires authority and drains the namespace.
            process.wait(
                timeout=route.authority_lease_seconds + route.drain_seconds + route.control_seconds
            )
        selector.close()
        process.stdout.close()
        process.stderr.close()
