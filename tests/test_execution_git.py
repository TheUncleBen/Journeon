# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from test_attempt_snapshots import git
from test_execution_route import CurrentAuthority, route

from journeon.attempt_snapshots import capture_snapshot, materialize_projection
from journeon.contracts import DomainError
from journeon.execution_git import project_git_view
from journeon.execution_process import run_local


def repository(path):
    path.mkdir()
    git(path, "init", "-q")
    git(path, "config", "user.name", "Fixture")
    git(path, "config", "user.email", "fixture@example.invalid")
    (path / "file.txt").write_text("base")
    git(path, "add", ".")
    git(path, "commit", "-qm", "fixture")


def test_git_projection_keeps_dirty_submodule_index_and_working_bytes(tmp_path):
    dependency = tmp_path / "dependency"
    repository(dependency)
    source = tmp_path / "source"
    repository(source)
    git(source, "-c", "protocol.file.allow=always", "submodule", "add", str(dependency), "module")
    git(source, "commit", "-qam", "module")
    (source / "module" / "file.txt").write_text("staged")
    git(source / "module", "add", ".")
    (source / "module" / "file.txt").write_text("working")
    captured = capture_snapshot(source, max_bytes=1048576, max_files=100)
    target = tmp_path / "input"
    materialize_projection(target, captured)
    projection = project_git_view(
        source, target, captured, admitted_roots=[source], max_bytes=1048576, max_files=100
    )
    configured = route().model_copy(
        update={
            "argv": [
                "/usr/bin/python3",
                "-I",
                "-S",
                "-c",
                "import subprocess; from pathlib import Path; "
                "assert subprocess.check_output(['/usr/bin/git','-C','mo"
                "dule','show',':file.txt']) == b'staged'; "
                "assert Path('module/file.txt').read_text() == 'working'",
            ],
            "artifacts": [],
        }
    )
    result = run_local(configured, target, CurrentAuthority(), object_mounts=projection.mounts)
    assert result["completion"]["exit_code"] == 0


def test_git_alternate_objects_require_admission_and_are_copied(tmp_path):
    dependency = tmp_path / "dependency"
    repository(dependency)
    source = tmp_path / "source"
    git(tmp_path, "clone", "--shared", str(dependency), str(source))
    captured = capture_snapshot(source, max_bytes=1048576, max_files=100)
    denied = tmp_path / "denied" / "input"
    denied.parent.mkdir()
    materialize_projection(denied, captured)
    with pytest.raises(DomainError) as error:
        project_git_view(
            source, denied, captured, admitted_roots=[source], max_bytes=1048576, max_files=100
        )
    assert error.value.code == "PERMISSION_DENIED"
    target = tmp_path / "accepted" / "input"
    target.parent.mkdir()
    materialize_projection(target, captured)
    projection = project_git_view(
        source,
        target,
        captured,
        admitted_roots=[source, dependency],
        max_bytes=1048576,
        max_files=100,
    )
    assert len(projection.mounts) == 2
    assert all(path.is_relative_to(target.parent) for path in projection.mounts)
    configured = route().model_copy(
        update={
            "argv": [
                "/usr/bin/python3",
                "-I",
                "-S",
                "-c",
                "import subprocess; assert subprocess.check_output(['/us"
                "r/bin/git','show','HEAD:file.txt']) == b'base'",
            ],
            "artifacts": [],
        }
    )
    result = run_local(configured, target, CurrentAuthority(), object_mounts=projection.mounts)
    assert result["completion"]["exit_code"] == 0


def test_unstable_git_object_capture_is_rejected(tmp_path, monkeypatch):
    from journeon import execution_git

    source = tmp_path / "source"
    repository(source)
    captured = capture_snapshot(source, max_bytes=1048576, max_files=100)
    target = tmp_path / "input"
    materialize_projection(target, captured)
    original = execution_git.materialize_projection

    def changed_after_copy(destination, captured_objects):
        original(destination, captured_objects)
        (source / ".git" / "objects" / "changed.txt").write_text("concurrent source mutation")

    monkeypatch.setattr(execution_git, "materialize_projection", changed_after_copy)
    with pytest.raises(DomainError) as error:
        project_git_view(
            source, target, captured, admitted_roots=[source], max_bytes=1048576, max_files=100
        )
    assert error.value.code == "REVISION_CONFLICT"
