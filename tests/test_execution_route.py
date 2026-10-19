# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import threading
from pathlib import Path

import pytest


class CurrentAuthority:
    def __init__(self):
        self.cancelled = threading.Event()

    def current(self):
        return not self.cancelled.is_set()

    def preparing(self, unit, invocation_id, containment):
        self.preparation = (unit, invocation_id, containment)

    def starting(self, unit, invocation_id, containment):
        self.start_request = (unit, invocation_id, containment)

    def started(self, unit, invocation_id, containment, process_id):
        self.observation = (unit, invocation_id, containment)
        self.process_id = process_id


def route():
    from journeon.execution_process import LocalRoute

    return LocalRoute(
        key="fixture-route",
        revision=1,
        project_id="fixture-project",
        check_id="fixture-check",
        argv=[
            "/usr/bin/python3",
            "-I",
            "-S",
            "-c",
            "from pathlib import Path; Path('result.txt').write_text('verified'); print('ok')",
        ],
        executable_sha256=hashlib.sha256(Path("/usr/bin/python3").read_bytes()).hexdigest(),
        cwd=".",
        environment={},
        artifacts=["result.txt"],
        memory_bytes=134217728,
        processes=16,
        cpu_percent=25,
        workspace_bytes=1048576,
        temporary_bytes=1048576,
        output_bytes=4096,
        artifact_bytes=4096,
        artifact_files=10,
        core_memory_reserve_bytes=1048576,
        disk_reserve_bytes=1048576,
        authority_lease_seconds=5,
        authority_poll_seconds=0.1,
        drain_seconds=2,
        control_seconds=10,
    )


def test_real_local_route_binds_kernel_limits_and_command_result(tmp_path):
    from journeon.execution_process import run_local

    source = tmp_path / "source"
    source.mkdir()
    result = run_local(route(), source, CurrentAuthority())
    assert result["completion"]["exit_code"] == 0
    assert result["completion"]["drained"] is True
    assert result["completion"]["artifacts"][0]["path"] == "result.txt"
    assert result["containment"]["memory.max"] == "134217728"
    assert result["containment"]["pids.max"] == "16"
    assert result["containment"]["memory.swap.max"] == "0"
    assert result["invocation_id"]
    assert result["launcher_exit_code"] == 0


def test_real_local_route_rejects_revoked_start_before_spawn(tmp_path):
    import pytest

    from journeon.execution_process import run_local

    authority = CurrentAuthority()
    authority.cancelled.set()
    with pytest.raises(PermissionError):
        run_local(route(), tmp_path, authority)


def test_real_local_route_revocation_cancels_and_drains(tmp_path):
    from journeon.execution_process import run_local

    class CancelAfterLaunch(CurrentAuthority):
        def started(self, unit, invocation_id, containment, process_id):
            super().started(unit, invocation_id, containment, process_id)
            self.cancelled.set()

    authority = CancelAfterLaunch()
    configuration = route().model_copy(
        update={"argv": ["/usr/bin/python3", "-I", "-S", "-c", "import time; time.sleep(60)"]}
    )
    result = run_local(configuration, tmp_path, authority)
    assert result["completion"]["reason"] == "CANCELLED"
    assert result["completion"]["drained"] is True
    assert result["completion"]["exit_code"] < 0


def test_real_local_route_memory_reserve_is_actual_admission(tmp_path):
    import pytest

    from journeon.execution_process import run_local

    configuration = route().model_copy(update={"core_memory_reserve_bytes": 2**62})
    with pytest.raises(OSError, match="core reserve"):
        run_local(configuration, tmp_path, CurrentAuthority())


@pytest.mark.parametrize("source_mutation", [False, True])
def test_real_local_route_preserves_git_head_index_and_writable_worktree(tmp_path, source_mutation):
    import base64

    from test_attempt_snapshots import git

    from journeon.attempt_snapshots import capture_snapshot, materialize_projection
    from journeon.execution_git import project_git_view
    from journeon.execution_process import run_local

    source = tmp_path / "project"
    source.mkdir()
    git(source, "init", "-q")
    git(source, "config", "user.name", "Fixture")
    git(source, "config", "user.email", "fixture@example.invalid")
    (source / "input.txt").write_text("base")
    git(source, "add", ".")
    git(source, "commit", "-qm", "fixture")
    (source / "input.txt").write_text("index")
    git(source, "add", ".")
    (source / "input.txt").write_text("working")
    captured = capture_snapshot(source, max_bytes=1048576, max_files=100)
    projection = tmp_path / "input"
    materialize_projection(projection, captured)
    mounts = project_git_view(
        source, projection, captured, admitted_roots=[source], max_bytes=1048576, max_files=100
    )
    if source_mutation:
        identity = captured.snapshot.index[0].object_id
        changed = source / ".git" / "objects" / identity[:2] / identity[2:]
        changed.unlink()
        changed.write_bytes(b"changed after capture")
    configuration = route().model_copy(
        update={
            "argv": [
                "/usr/bin/python3",
                "-I",
                "-S",
                "-c",
                "import subprocess; from pathlib import Path; "
                "assert subprocess.check_output(['/usr/bin/git','show',':input.txt']) == b'index'; "
                "assert Path('input.txt').read_text() == 'working'; "
                "Path('result.txt').write_text(subprocess.check_output(["
                "'/usr/bin/git','rev-parse','HEAD']).decode())",
            ]
        }
    )
    actual = run_local(configuration, projection, CurrentAuthority(), object_mounts=mounts.mounts)
    assert actual["completion"]["exit_code"] == 0
    assert (
        base64.b64decode(actual["completion"]["artifacts"][0]["data"]).decode().strip()
        == captured.snapshot.head
    )
    assert (source / "input.txt").read_text() == "working"


@pytest.mark.parametrize("replacement", ["leaf_symlink", "parent_symlink", "directory"])
def test_real_local_route_rejects_rebound_object_mount_before_start(
    tmp_path, monkeypatch, replacement
):
    import pytest

    from journeon import execution_process

    source = tmp_path / "input"
    source.mkdir()
    admitted = tmp_path / "admitted"
    admitted.mkdir()
    objects = admitted / "objects"
    objects.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    foreign = outside / "objects"
    foreign.mkdir()
    (foreign / "canary.txt").write_text("outside admitted projection")
    original = execution_process.subprocess.Popen

    def replaced_mount(*args, **kwargs):
        if args[0][0] == "/usr/bin/systemd-run":
            if replacement == "parent_symlink":
                admitted.rename(tmp_path / "original-parent")
                admitted.symlink_to(outside, target_is_directory=True)
            else:
                objects.rename(tmp_path / "original-objects")
                if replacement == "leaf_symlink":
                    objects.symlink_to(foreign, target_is_directory=True)
                else:
                    foreign.rename(objects)
        return original(*args, **kwargs)

    monkeypatch.setattr(execution_process.subprocess, "Popen", replaced_mount)
    configuration = route().model_copy(
        update={
            "argv": [
                "/usr/bin/python3",
                "-I",
                "-S",
                "-c",
                "from pathlib import Path; Path('result.txt').write_text"
                "(Path('/git-objects/0/canary.txt').read_text())",
            ]
        }
    )
    with pytest.raises(ValueError, match="mount identity"):
        execution_process.run_local(
            configuration, source, CurrentAuthority(), object_mounts=[objects]
        )


def test_closed_route_has_no_host_credentials_files_or_loopback_egress(tmp_path, monkeypatch):
    import socket

    from journeon.execution_process import run_local

    source = tmp_path / "input"
    source.mkdir()
    hidden = tmp_path / "host-only-canary"
    hidden.write_text("disposable qualification canary")
    monkeypatch.setenv("JOURNEON_DISPOSABLE_CANARY", "not-a-secret")
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        code = (
            "import os,socket; from pathlib import Path; "
            "assert 'JOURNEON_DISPOSABLE_CANARY' not in os.environ; "
            f"assert not Path({str(hidden)!r}).exists(); "
            "assert not Path('/home').exists(); assert not Path('/run/user').exists(); "
            "s=socket.socket(); s.settimeout(.2); "
            f"assert s.connect_ex(('127.0.0.1',{port})) != 0"
        )
        configured = route().model_copy(
            update={
                "argv": ["/usr/bin/python3", "-I", "-S", "-c", code],
                "artifacts": [],
            }
        )
        result = run_local(configured, source, CurrentAuthority())
    assert result["completion"]["exit_code"] == 0
    assert result["completion"]["drained"]


def test_closed_route_rejects_changed_executable_and_storage_reserve(tmp_path):
    from journeon.execution_process import run_local

    with pytest.raises(ValueError, match="executable differs"):
        run_local(
            route().model_copy(update={"executable_sha256": "0" * 64}), tmp_path, CurrentAuthority()
        )
    with pytest.raises(OSError, match="recovery reserve"):
        run_local(
            route().model_copy(update={"disk_reserve_bytes": 2**62}), tmp_path, CurrentAuthority()
        )


def test_kernel_process_limit_prevents_unbounded_children_and_drains(tmp_path):
    from journeon.execution_process import run_local

    code = """import os,time
children=[]
try:
 for index in range(100):
  pid=os.fork()
  if pid == 0:
   time.sleep(60)
   os._exit(0)
  children.append(pid)
except BlockingIOError:
 assert 0 < len(children) < 16
else:
 raise AssertionError('process limit was not enforced')
"""
    configured = route().model_copy(
        update={
            "argv": ["/usr/bin/python3", "-I", "-S", "-c", code],
            "artifacts": [],
        }
    )
    result = run_local(configured, tmp_path, CurrentAuthority())
    assert result["completion"]["exit_code"] == 0
    assert result["completion"]["drained"]


def test_memory_limit_failure_retains_observed_launcher_and_partial_output(tmp_path):
    from journeon.execution_process import run_local

    configured = route().model_copy(
        update={
            "argv": [
                "/usr/bin/python3",
                "-I",
                "-S",
                "-c",
                "import time; print('before-allocation',flush=True); "
                "time.sleep(.1); x=bytearray(400*1024*1024)",
            ],
            "artifacts": [],
        }
    )
    with pytest.raises(OSError) as error:
        run_local(configured, tmp_path, CurrentAuthority())
    assert error.value.observation["launcher_exit_code"] != 0
    assert error.value.observation["output"]
    assert error.value.observation["completion"] is None


def test_resource_admission_observes_ancestor_cgroup_capacity(tmp_path, monkeypatch):
    import os

    from journeon.execution_process import resource_observation

    original = Path.read_text
    observed = {
        "/proc/meminfo": "MemAvailable: 1000 kB\n",
        "/proc/self/cgroup": "0::/qualification\n",
        "/sys/fs/cgroup/qualification/memory.max": "4096",
        "/sys/fs/cgroup/qualification/memory.current": "1024",
        "/sys/fs/cgroup/qualification/cpu.max": "200000 100000",
        "/sys/fs/cgroup/memory.max": "2048",
        "/sys/fs/cgroup/memory.current": "1024",
        "/sys/fs/cgroup/cpu.max": "50000 100000",
    }

    def read(path, *args, **kwargs):
        return observed[str(path)] if str(path) in observed else original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(os, "sched_getaffinity", lambda pid: set(range(8)))
    result = resource_observation(tmp_path)
    assert result["memory_available"] == 1024
    assert result["cpu_percent"] == 50
