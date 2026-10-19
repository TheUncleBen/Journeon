# SPDX-License-Identifier: AGPL-3.0-only
import subprocess

from journeon.attempt_snapshots import capture_snapshot, materialize_worktree


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def test_real_git_snapshot_retains_index_worktree_and_nontext_state(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.name", "Fixture")
    git(root, "config", "user.email", "fixture@example.invalid")
    (root / "tracked.txt").write_text("base")
    (root / "deleted.txt").write_text("remove")
    git(root, "add", ".")
    git(root, "commit", "-qm", "fixture")
    (root / "tracked.txt").write_text("index")
    git(root, "add", "tracked.txt")
    (root / "tracked.txt").write_text("working")
    (root / "deleted.txt").unlink()
    (root / "binary.bin").write_bytes(b"\x00\xff\x80")
    (root / "link").symlink_to("tracked.txt")
    captured = capture_snapshot(root, max_bytes=1048576, max_files=100)
    assert captured.snapshot.head == git(root, "rev-parse", "HEAD")
    assert captured.snapshot.deleted == ["deleted.txt"]
    assert {"binary.bin", "link"} <= set(captured.snapshot.untracked)
    assert captured.snapshot.index_hash != captured.snapshot.working_hash
    target = tmp_path / "attempt"
    materialize_worktree(root, target, "attempt-fixture", captured)
    assert git(target, "branch", "--show-current") == "attempt-fixture"
    assert git(target, "show", ":tracked.txt") == "index"
    assert (target / "tracked.txt").read_text() == "working"
    assert not (target / "deleted.txt").exists()
    assert (target / "binary.bin").read_bytes() == b"\x00\xff\x80"
    assert (target / "link").is_symlink()
    restored = capture_snapshot(target, max_bytes=1048576, max_files=100)
    assert restored.snapshot.snapshot_hash == captured.snapshot.snapshot_hash


def test_submodule_snapshot_retains_actual_dirty_child_worktree(tmp_path):
    source = tmp_path / "dependency"
    source.mkdir()
    git(source, "init", "-q")
    git(source, "config", "user.name", "Fixture")
    git(source, "config", "user.email", "fixture@example.invalid")
    (source / "module.txt").write_text("base")
    git(source, "add", ".")
    git(source, "commit", "-qm", "fixture")
    root = tmp_path / "project"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.name", "Fixture")
    git(root, "config", "user.email", "fixture@example.invalid")
    git(root, "-c", "protocol.file.allow=always", "submodule", "add", str(source), "module")
    git(root, "commit", "-qam", "module")
    (root / "module" / "module.txt").write_text("index")
    git(root / "module", "add", "module.txt")
    (root / "module" / "module.txt").write_text("working")
    captured = capture_snapshot(root, max_bytes=1048576, max_files=100)
    assert "module" in captured.snapshot.submodules
    target = tmp_path / "attempt"
    materialize_worktree(root, target, "attempt-submodule", captured)
    assert git(target / "module", "show", ":module.txt") == "index"
    assert (
        capture_snapshot(target, max_bytes=1048576, max_files=100).snapshot.snapshot_hash
        == captured.snapshot.snapshot_hash
    )


def test_snapshot_preserves_directory_permissions(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.name", "Fixture")
    git(root, "config", "user.email", "fixture@example.invalid")
    (root / "folder").mkdir(mode=0o700)
    (root / "folder" / "file").write_text("fixture")
    git(root, "add", ".")
    git(root, "commit", "-qm", "fixture")
    captured = capture_snapshot(root, max_bytes=1048576, max_files=100)
    target = tmp_path / "attempt"
    materialize_worktree(root, target, "attempt-mode", captured)
    assert (
        capture_snapshot(target, max_bytes=1048576, max_files=100).snapshot.snapshot_hash
        == captured.snapshot.snapshot_hash
    )


def test_git_observation_enforces_output_bound(tmp_path):
    import pytest

    from journeon.attempt_snapshots import git as observed_git
    from journeon.contracts import DomainError

    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "fixture.large", "x" * 16384)
    with pytest.raises(DomainError, match="output limit"):
        observed_git(tmp_path, "config", "--get", "fixture.large", max_output_bytes=1024)
