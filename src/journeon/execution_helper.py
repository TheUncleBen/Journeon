# SPDX-License-Identifier: AGPL-3.0-only
"""Private PID-namespace supervisor; invoked only by the closed execution route."""

import base64
import ctypes
import hashlib
import json
import os
import select
import selectors
import shutil
import signal
import stat
import subprocess
import time
from pathlib import Path
from typing import Any, BinaryIO, cast


class Channel:
    def __init__(self, lease_seconds: float) -> None:
        self.lease_seconds = lease_seconds
        self.deadline = time.monotonic() + lease_seconds
        self.pending = b""
        self.reporting_deadline: float | None = None
        os.set_blocking(0, False)
        os.set_blocking(1, False)

    def send(self, value: dict[str, Any]) -> None:
        data = memoryview(json.dumps(value, separators=(",", ":")).encode() + b"\n")
        while data:
            remaining = (self.reporting_deadline or self.deadline) - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Authority lease expired")
            if not select.select([], [1], [], remaining)[1]:
                raise TimeoutError("Controller did not drain output")
            try:
                data = data[os.write(1, data) :]
            except BlockingIOError:
                continue

    def receive(self) -> list[str]:
        try:
            data = os.read(0, 4096)
        except BlockingIOError:
            return []
        if not data:
            raise EOFError("Controller disconnected")
        self.pending += data
        if len(self.pending) > 65536:
            raise ValueError("Control message exceeds bound")
        messages = []
        while b"\n" in self.pending:
            line, self.pending = self.pending.split(b"\n", 1)
            value = json.loads(line)
            if value not in ({"action": "START"}, {"action": "RENEW"}, {"action": "STOP"}):
                raise ValueError("Unknown control message")
            messages.append(value["action"])
        return messages


def kill_children() -> None:
    if os.getpid() != 1:
        raise RuntimeError("A private PID namespace is required")
    try:
        os.kill(-1, signal.SIGKILL)
    except ProcessLookupError:
        pass


def collect_artifacts(configuration: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    total = 0
    root = os.open("/workspace", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in configuration["artifacts"]:
            parts = Path(name).parts
            if not parts or Path(name).is_absolute() or any(p in (".", "..") for p in parts):
                raise ValueError("Artifact path is outside the workspace")
            directory = os.dup(root)
            try:
                for part in parts[:-1]:
                    following = os.open(
                        part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
                    )
                    os.close(directory)
                    directory = following
                try:
                    descriptor = os.open(
                        parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
                    )
                except FileNotFoundError:
                    continue
                try:
                    metadata = os.fstat(descriptor)
                    if not stat.S_ISREG(metadata.st_mode):
                        raise ValueError("Artifact must be a regular file")
                    remaining = configuration["artifact_bytes"] - total
                    if metadata.st_size > remaining:
                        raise OverflowError("Artifact bytes exceed bound")
                    data = b""
                    while chunk := os.read(descriptor, min(65536, remaining - len(data) + 1)):
                        data += chunk
                        if len(data) > remaining:
                            raise OverflowError("Artifact bytes exceed bound")
                finally:
                    os.close(descriptor)
            finally:
                os.close(directory)
            total += len(data)
            if len(artifacts) >= configuration["artifact_files"]:
                raise OverflowError("Artifact count exceeds bound")
            artifacts.append(
                {
                    "path": name,
                    "byte_count": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "data": base64.b64encode(data).decode("ascii"),
                }
            )
    finally:
        os.close(root)
    return artifacts


def copy_workspace() -> None:
    shutil.copytree("/input", "/workspace", symlinks=True, dirs_exist_ok=True)


def prepare_workspace(channel: Channel) -> bool:
    child = os.fork()
    if child == 0:
        os.close(0)
        os.close(1)
        try:
            copy_workspace()
        except BaseException:
            os._exit(1)
        os._exit(0)
    reaped = False
    try:
        while True:
            if time.monotonic() >= channel.deadline:
                raise TimeoutError("Workspace preparation authority expired")
            actions = channel.receive()
            if "STOP" in actions:
                return False
            if "START" in actions:
                raise ValueError("Workspace preparation is incomplete")
            if "RENEW" in actions:
                channel.deadline = time.monotonic() + channel.lease_seconds
            observed, status = os.waitpid(child, os.WNOHANG)
            if observed:
                reaped = True
                if status != 0:
                    raise OSError("Workspace preparation failed")
                return True
            select.select([0], [], [], min(0.05, max(0, channel.deadline - time.monotonic())))
    finally:
        if not reaped:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)


def supervise(configuration: dict[str, Any], channel: Channel) -> None:
    observed_mounts = {}
    for path, identity in configuration.get("mount_identities", {}).items():
        observed = os.stat(path)
        observed_mounts[path] = [observed.st_dev, observed.st_ino]
        if observed_mounts[path] != identity:
            channel.send({"kind": "REJECTED", "reason": "MOUNT_IDENTITY"})
            return
    channel.send({"kind": "PREPARING", "mount_identities": observed_mounts})
    if not prepare_workspace(channel):
        return
    channel.send({"kind": "READY", "pid": os.getpid(), "mount_identities": observed_mounts})
    while True:
        if time.monotonic() >= channel.deadline:
            raise TimeoutError("Start authority expired")
        select.select([0], [], [], max(0, channel.deadline - time.monotonic()))
        actions = channel.receive()
        if "STOP" in actions:
            return
        if "RENEW" in actions:
            channel.deadline = time.monotonic() + channel.lease_seconds
        if "START" in actions:
            break
    process = subprocess.Popen(
        configuration["argv"],
        cwd=configuration["cwd"],
        env=configuration["environment"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    channel.send({"kind": "STARTED", "pid": process.pid})
    selector = selectors.DefaultSelector()
    assert process.stdout is not None and process.stderr is not None
    for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    selector.register(0, selectors.EVENT_READ, "control")
    byte_count = 0
    reason = "EXITED"
    stopping = False
    drain_deadline = None
    while True:
        now = time.monotonic()
        if not stopping and (process.poll() is not None or now >= channel.deadline):
            if now >= channel.deadline:
                reason = "AUTHORITY_EXPIRED"
            stopping = True
        if stopping and drain_deadline is None:
            kill_children()
            drain_deadline = now + configuration["drain_seconds"]
            channel.reporting_deadline = drain_deadline
        if drain_deadline is not None and now >= drain_deadline:
            reason = "DRAIN_INCOMPLETE"
            break
        if stopping and not any(
            key.data in ("stdout", "stderr") for key in selector.get_map().values()
        ):
            break
        for key, _ in selector.select(0.05):
            if key.data == "control":
                try:
                    actions = channel.receive()
                    if "RENEW" in actions:
                        channel.deadline = time.monotonic() + channel.lease_seconds
                    if "STOP" in actions or "START" in actions:
                        reason, stopping = "CANCELLED", True
                except (EOFError, ValueError):
                    reason, stopping = "CONTROLLER_LOST", True
                    selector.unregister(0)
            else:
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    cast(BinaryIO, key.fileobj).close()
                    continue
                remaining = configuration["output_bytes"] - byte_count
                if len(data) > remaining:
                    data = data[:remaining]
                    reason, stopping = "OUTPUT_LIMIT", True
                byte_count += len(data)
                if data:
                    channel.send(
                        {
                            "kind": "OUTPUT",
                            "stream": key.data,
                            "data": base64.b64encode(data).decode("ascii"),
                        }
                    )
    process.wait()
    drained = reason != "DRAIN_INCOMPLETE"
    while True:
        try:
            child, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if child == 0:
            if drain_deadline is not None and time.monotonic() < drain_deadline:
                time.sleep(0.01)
            else:
                drained = False
                break
    artifacts: list[dict[str, Any]] = []
    if drained:
        try:
            artifacts = collect_artifacts(configuration)
        except OverflowError:
            reason = "ARTIFACT_LIMIT"
        except (OSError, ValueError):
            reason = "ARTIFACT_UNAVAILABLE"
    channel.send(
        {
            "kind": "RESULT",
            "exit_code": process.returncode,
            "reason": reason,
            "drained": drained,
            "output_bytes": byte_count,
            "artifacts": artifacts,
        }
    )


def main() -> None:
    if os.getpid() != 1:
        raise RuntimeError("Execution helper requires a private PID namespace")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) or libc.prctl(38, 1, 0, 0, 0):
        raise OSError(ctypes.get_errno(), "Process protection unavailable")
    line = bytearray()
    while not line.endswith(b"\n"):
        chunk = os.read(0, 1)
        if not chunk or len(line) >= 65536:
            raise ValueError("Execution configuration unavailable")
        line.extend(chunk)
    configuration = json.loads(line)
    channel = Channel(configuration["authority_lease_seconds"])
    try:
        supervise(configuration, channel)
    finally:
        kill_children()


if __name__ == "__main__":
    main()
