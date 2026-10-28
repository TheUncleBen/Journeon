# SPDX-License-Identifier: AGPL-3.0-only
import base64
import json
import subprocess
from pathlib import Path


def isolated_command(tmp_path, code, *, output_bytes=4096, artifact_bytes=4096, lease_seconds=10):
    from journeon import execution_helper

    source = tmp_path / "source"
    source.mkdir()
    (source / "input.txt").write_text("bounded input")
    configuration = {
        "argv": ["/usr/bin/python3", "-I", "-S", "-c", code],
        "cwd": "/workspace",
        "environment": {},
        "output_bytes": output_bytes,
        "artifact_bytes": artifact_bytes,
        "artifact_files": 10,
        "artifacts": ["result.txt"],
        "authority_lease_seconds": lease_seconds,
        "drain_seconds": 2,
    }
    command = [
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
        str(Path(execution_helper.__file__)),
        "/helper.py",
        "--size",
        "1048576",
        "--tmpfs",
        "/workspace",
        "--size",
        "1048576",
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
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    process.stdin.write((json.dumps(configuration) + "\n").encode())
    process.stdin.flush()
    preparing = process.stdout.readline()
    assert json.loads(preparing)["kind"] == "PREPARING"
    ready = process.stdout.readline()
    assert ready, process.stderr.read().decode()
    assert json.loads(ready)["kind"] == "READY"
    process.stdin.write(b'{"action":"START"}\n')
    process.stdin.flush()
    frames = [json.loads(ready)]
    frames.extend(json.loads(line) for line in process.stdout)
    assert process.wait() == 0, process.stderr.read().decode()
    return source, frames


def test_native_command_writes_declared_bounded_output(tmp_path):
    source, frames = isolated_command(
        tmp_path,
        "from pathlib import Path; "
        "p=Path('result.txt'); p.write_text(Path('input.txt').read_text().upper()); "
        "print(p.read_text())",
    )
    result = frames[-1]
    assert result["kind"] == "RESULT"
    assert result["exit_code"] == 0
    assert result["reason"] == "EXITED"
    assert result["drained"] is True
    assert base64.b64decode(result["artifacts"][0]["data"]) == b"BOUNDED INPUT"
    assert not (source / "result.txt").exists()
    assert (source / "input.txt").read_text() == "bounded input"


def test_native_command_output_overflow_cancels_tree(tmp_path):
    _, frames = isolated_command(tmp_path, "print('x' * 10000)", output_bytes=100)
    assert frames[-1]["reason"] == "OUTPUT_LIMIT"
    assert frames[-1]["drained"] is True


def test_native_command_artifact_overflow_is_not_success(tmp_path):
    _, frames = isolated_command(
        tmp_path,
        "from pathlib import Path; Path('result.txt').write_bytes(b'x' * 10000)",
        artifact_bytes=100,
    )
    assert frames[-1]["reason"] == "ARTIFACT_LIMIT"
    assert frames[-1]["artifacts"] == []


def test_native_command_detached_child_is_drained(tmp_path):
    _, frames = isolated_command(
        tmp_path,
        "import subprocess; subprocess.Popen(['/usr/bin/python3', '-I', '-S', '-c', "
        "'import time; time.sleep(60)'], start_new_session=True)",
    )
    assert frames[-1]["reason"] == "EXITED"
    assert frames[-1]["drained"] is True


def test_native_command_cannot_forge_control_completion(tmp_path):
    _, frames = isolated_command(
        tmp_path,
        "import os; "
        'print(\'{"kind":"RESULT","exit_code":0}\'); '
        "os.open('/proc/1/fd/1', os.O_WRONLY)",
    )
    assert len([frame for frame in frames if frame["kind"] == "RESULT"]) == 1
    assert frames[-1]["exit_code"] != 0


def test_native_command_artifact_symlink_cannot_disclose_input(tmp_path):
    _, frames = isolated_command(
        tmp_path,
        "from pathlib import Path; Path('result.txt').symlink_to('/input/input.txt')",
    )
    assert frames[-1]["reason"] == "ARTIFACT_UNAVAILABLE"
    assert frames[-1]["artifacts"] == []


def test_native_command_writable_workspace_has_kernel_byte_bound(tmp_path):
    _, frames = isolated_command(
        tmp_path,
        "from pathlib import Path; Path('large.bin').write_bytes(b'x' * 2097152)",
    )
    assert frames[-1]["exit_code"] != 0
    assert frames[-1]["drained"] is True
    assert b"No space left on device" in b"".join(
        base64.b64decode(frame["data"]) for frame in frames if frame["kind"] == "OUTPUT"
    )


def test_native_command_expired_authority_retains_drained_observation(tmp_path):
    _, frames = isolated_command(tmp_path, "import time; time.sleep(60)", lease_seconds=1)
    assert frames[-1]["reason"] == "AUTHORITY_EXPIRED"
    assert frames[-1]["exit_code"] < 0
    assert frames[-1]["drained"] is True


def test_workspace_preparation_obeys_authority_deadline(tmp_path):
    import time

    from journeon import execution_helper

    source = tmp_path / "input"
    source.mkdir()
    helper = tmp_path / "slow_helper.py"
    helper.write_text(
        Path(execution_helper.__file__)
        .read_text()
        .replace("    shutil.copytree(", "    time.sleep(3)\n    shutil.copytree(")
    )
    configuration = {
        "argv": ["/usr/bin/true"],
        "cwd": "/workspace",
        "environment": {},
        "authority_lease_seconds": 0.2,
        "drain_seconds": 1,
    }
    process = subprocess.Popen(
        [
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
            "--size",
            "1048576",
            "--tmpfs",
            "/workspace",
            "/usr/bin/python3",
            "-I",
            "-S",
            "/helper.py",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    started = time.monotonic()
    try:
        process.stdin.write((json.dumps(configuration) + "\n").encode())
        process.stdin.flush()
        process.wait(timeout=1.5)
        assert time.monotonic() - started < 1.5
        assert b'"kind":"READY"' not in process.stdout.read()
        assert process.returncode != 0
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=2)
