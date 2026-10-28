# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from test_attempt_snapshots import git
from test_execution_route import CurrentAuthority, route

from journeon.attempt_snapshots import (
    capture_snapshot,
    materialize_projection,
    materialize_worktree,
)
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


@pytest.mark.parametrize("snapshot_bound", [False, True])
def test_git_projection_keeps_dirty_submodule_index_and_working_bytes(tmp_path, snapshot_bound):
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
        source,
        target,
        captured,
        admitted_roots=[source],
        max_bytes=1048576,
        max_files=100,
        snapshot_bound=snapshot_bound,
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


@pytest.mark.parametrize("snapshot_bound", [False, True])
def test_git_alternate_objects_require_admission_and_are_copied(tmp_path, snapshot_bound):
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
        snapshot_bound=snapshot_bound,
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


@pytest.mark.parametrize("alter_original_boundary", [False, True])
@pytest.mark.parametrize("empty_boundary", [False, True])
def test_shallow_attempt_retains_admitted_history_boundary(
    tmp_path, alter_original_boundary, empty_boundary
):
    seed = tmp_path / "seed"
    repository(seed)
    (seed / "file.txt").write_text("second")
    git(seed, "commit", "-qam", "Second fixture revision")
    source = tmp_path / "source"
    git(
        tmp_path,
        "clone",
        "--no-hardlinks",
        *([] if empty_boundary else ["--depth=1"]),
        seed.as_uri(),
        str(source),
    )
    if empty_boundary:
        (source / ".git" / "shallow").write_bytes(b"")
    expected_count = "2" if empty_boundary else "1"
    (source / "verify.py").write_text(
        "import subprocess as s\n"
        "assert s.check_output(['git','rev-parse','--is-shallow-repository']).strip()==b'true'\n"
        f"assert s.check_output(['git','rev-list','--count','HEAD']).strip()==b'{expected_count}'\n"
        "assert s.check_output(['git','show','HEAD:file.txt'])==b'second'\n"
    )
    admitted = capture_snapshot(source, max_bytes=1048576, max_files=100)
    workspace = tmp_path / "attempt"
    materialize_worktree(source, workspace, "attempt/shallow", admitted)
    assert (
        capture_snapshot(workspace, max_bytes=1048576, max_files=100).snapshot == admitted.snapshot
    )
    destination = tmp_path / "input"
    materialize_projection(destination, admitted)
    if alter_original_boundary:
        (source / ".git" / "shallow").unlink()
    projected = project_git_view(
        workspace,
        destination,
        admitted,
        admitted_roots=[source],
        max_bytes=1048576,
        max_files=100,
        snapshot_bound=True,
    )
    configured = route().model_copy(
        update={
            "argv": ["/usr/bin/python3", "-I", "-S", "verify.py"],
            "artifacts": [],
        }
    )
    observed = run_local(
        configured, destination, CurrentAuthority(), object_mounts=projected.mounts
    )
    assert observed["completion"]["exit_code"] == 0


def test_missing_parent_is_not_treated_as_a_shallow_boundary(tmp_path):
    source = tmp_path / "source"
    repository(source)
    parent = git(source, "rev-parse", "HEAD").strip()
    (source / "file.txt").write_text("later")
    git(source, "commit", "-qam", "Later fixture revision")
    captured = capture_snapshot(source, max_bytes=1048576, max_files=100)
    assert captured.snapshot.git_history is not None
    assert not captured.snapshot.git_history.shallow
    assert captured.snapshot.git_history.boundaries == []
    (source / ".git" / "objects" / parent[:2] / parent[2:]).unlink()
    destination = tmp_path / "input"
    materialize_projection(destination, captured)
    with pytest.raises(DomainError):
        project_git_view(
            source,
            destination,
            captured,
            admitted_roots=[source],
            max_bytes=1048576,
            max_files=100,
            snapshot_bound=True,
        )


def test_malformed_shallow_metadata_is_rejected(tmp_path):
    source = tmp_path / "source"
    repository(source)
    (source / ".git" / "shallow").write_text("invalid boundary\n")
    with pytest.raises(DomainError):
        capture_snapshot(source, max_bytes=1048576, max_files=100)
