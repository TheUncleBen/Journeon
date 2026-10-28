# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded source observations and attempt-specific Git worktrees; no execution sandbox."""

import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any, Literal

from journeon.contracts import ChangeSetSnapshot, DomainError, GitHistory, IndexEntry, SourceEntry


def content_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def snapshot_digest(value: Any) -> str:
    return content_hash(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


@dataclass
class CapturedSnapshot:
    snapshot: ChangeSetSnapshot
    blobs: dict[str, bytes]
    submodules: dict[str, "CapturedSnapshot"] = field(default_factory=dict)


def git(root: Path, *args: str, max_output_bytes: int, data: bytes | None = None) -> bytes:
    if max_output_bytes <= 0:
        raise ValueError("An explicit positive Git output limit is required")
    command = [
        "/usr/bin/git",
        "--no-optional-locks",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "protocol.allow=never",
        "-c",
        "submodule.recurse=false",
        "-C",
        str(root),
        *args,
    ]
    output = bytearray()
    total = 0
    with tempfile.TemporaryFile() as input_file:
        input_file.write(data or b"")
        input_file.seek(0)
        process = subprocess.Popen(
            command,
            stdin=input_file,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            env={
                "PATH": "/usr/bin:/bin",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_SYSTEM": "/dev/null",
                "GIT_TERMINAL_PROMPT": "0",
            },
        )
        assert process.stdout is not None and process.stderr is not None
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                selector.register(process.stderr, selectors.EVENT_READ)
                while selector.get_map():
                    for key, _ in selector.select():
                        chunk = os.read(key.fd, min(65536, max_output_bytes - total + 1))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > max_output_bytes:
                            raise DomainError(
                                "DEPENDENCY_UNAVAILABLE", "Git observation output limit reached"
                            )
                        if key.fileobj is process.stdout:
                            output.extend(chunk)
            if process.wait():
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE", "Git workspace observation is unavailable"
                )
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            process.stdout.close()
            process.stderr.close()
    return bytes(output)


def _same(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, key) == getattr(right, key)
        for key in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    )


def shallow_boundary(root: Path, *, max_bytes: int, max_files: int) -> tuple[GitHistory, int]:
    from journeon.instruction_config import open_directory

    location = Path(
        git(
            root,
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "shallow",
            max_output_bytes=max_bytes,
        )
        .decode()
        .strip()
    )
    directory = open_directory(location.parent)
    try:
        try:
            descriptor = os.open(
                location.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
            )
        except FileNotFoundError:
            return GitHistory(shallow=False, boundaries=[]), 0
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE", "Git shallow metadata exceeds snapshot limits"
                )
            raw = stream.read(max_bytes + 1)
            if (
                len(raw) > max_bytes
                or not _same(before, os.fstat(stream.fileno()))
                or not _same(
                    before, os.stat(location.name, dir_fd=directory, follow_symlinks=False)
                )
            ):
                raise DomainError(
                    "REVISION_CONFLICT", "Git shallow metadata changed during capture"
                )
    finally:
        os.close(directory)
    lines = raw.decode("ascii").splitlines()
    if len(lines) > max_files or any(
        not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", line) for line in lines
    ):
        raise DomainError(
            "DEPENDENCY_UNAVAILABLE", "Git shallow boundary is malformed or exceeds snapshot limits"
        )
    return GitHistory(shallow=True, boundaries=sorted(set(lines))), len(raw)


def capture_snapshot(root: Path, *, max_bytes: int, max_files: int) -> CapturedSnapshot:
    if max_bytes <= 0 or max_files <= 0:
        raise ValueError("Explicit positive snapshot limits are required")
    bounded_git = partial(git, max_output_bytes=max_bytes)
    entries: list[SourceEntry] = []
    blobs: dict[str, bytes] = {}
    total = 0
    kind: Literal["FILE", "DIRECTORY", "SYMLINK"]
    from journeon.instruction_config import open_directory

    root_descriptor = open_directory(root)
    root_identity = os.fstat(root_descriptor)
    pending: list[tuple[int, str]] = [(os.dup(root_descriptor), "")]
    try:
        while pending:
            directory, prefix = pending.pop()
            try:
                for name in sorted(os.listdir(directory)):
                    if name == ".git":
                        continue
                    path = prefix + name
                    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    mode = stat.S_IMODE(before.st_mode)
                    if len(entries) >= max_files:
                        raise DomainError("DEPENDENCY_UNAVAILABLE", "Snapshot file limit reached")
                    if stat.S_ISDIR(before.st_mode):
                        child = os.open(
                            name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
                        )
                        if not _same(before, os.fstat(child)):
                            os.close(child)
                            raise DomainError(
                                "REVISION_CONFLICT", "Workspace changed during snapshot"
                            )
                        pending.append((child, path + "/"))
                        kind, data, link = "DIRECTORY", b"", None
                    elif stat.S_ISLNK(before.st_mode):
                        link = os.readlink(name, dir_fd=directory)
                        kind, data = "SYMLINK", os.fsencode(link)
                    elif stat.S_ISREG(before.st_mode):
                        descriptor = os.open(
                            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
                        )
                        with os.fdopen(descriptor, "rb") as stream:
                            if (
                                not _same(before, os.fstat(stream.fileno()))
                                or before.st_size > max_bytes - total
                            ):
                                raise DomainError(
                                    "DEPENDENCY_UNAVAILABLE",
                                    "Snapshot byte limit or file stability failed",
                                )
                            data = stream.read(max_bytes - total + 1)
                            if not _same(before, os.fstat(stream.fileno())):
                                raise DomainError(
                                    "REVISION_CONFLICT", "Workspace changed during snapshot"
                                )
                        kind, link = "FILE", None
                    else:
                        raise DomainError(
                            "DEPENDENCY_UNAVAILABLE",
                            "Workspace contains an unsupported special file",
                        )
                    if not _same(before, os.stat(name, dir_fd=directory, follow_symlinks=False)):
                        raise DomainError("REVISION_CONFLICT", "Workspace changed during snapshot")
                    total += len(data)
                    if total > max_bytes:
                        raise DomainError("DEPENDENCY_UNAVAILABLE", "Snapshot byte limit reached")
                    hashed = content_hash(data)
                    if kind == "FILE":
                        blobs[hashed] = data
                    entries.append(
                        SourceEntry(
                            path=path,
                            kind=kind,
                            mode=mode,
                            content_hash=hashed,
                            byte_count=len(data),
                            link_target=link,
                        )
                    )
            finally:
                os.close(directory)
        if not _same(root_identity, root.stat()):
            raise DomainError("REVISION_CONFLICT", "Workspace changed during snapshot")
    finally:
        os.close(root_descriptor)
        for descriptor, _ in pending:
            os.close(descriptor)
    entries.sort(key=lambda entry: entry.path)
    index: list[IndexEntry] = []
    submodules: dict[str, CapturedSnapshot] = {}
    head = None
    binary = None
    shallow = None
    shallow_bytes = 0
    if (root / ".git").exists():
        shallow, shallow_bytes = shallow_boundary(root, max_bytes=max_bytes, max_files=max_files)
        total += shallow_bytes
        if total > max_bytes:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Snapshot byte limit reached")
        if shallow.shallow and len(entries) >= max_files:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Snapshot file limit reached")
        head = bounded_git(root, "rev-parse", "--verify", "HEAD").decode().strip()
        encoded_index = bounded_git(root, "ls-files", "--stage", "-z")
        for line in encoded_index.split(b"\0"):
            if not line:
                continue
            metadata, path_bytes = line.split(b"\t", 1)
            index_mode, object_id, stage = metadata.decode().split()
            path = os.fsdecode(path_bytes)
            index_content_hash: str | None = None
            if index_mode != "160000":
                size = int(bounded_git(root, "cat-file", "-s", object_id))
                if size > max_bytes - total:
                    raise DomainError("DEPENDENCY_UNAVAILABLE", "Snapshot index byte limit reached")
                data = bounded_git(root, "cat-file", "blob", object_id)
                total += len(data)
                index_content_hash = content_hash(data)
                blobs[index_content_hash] = data
            elif (root / path / ".git").exists():
                submodules[path] = capture_snapshot(
                    root / path, max_bytes=max_bytes - total, max_files=max_files
                )
                total += submodules[path].snapshot.byte_count
            index.append(
                IndexEntry(
                    path=path,
                    mode=index_mode,
                    object_id=object_id,
                    stage=int(stage),
                    content_hash=index_content_hash,
                )
            )
        binary = content_hash(
            bounded_git(root, "diff", "--binary", "--no-ext-diff", "--no-textconv", "HEAD", "--")
            + bounded_git(
                root, "diff", "--cached", "--binary", "--no-ext-diff", "--no-textconv", "HEAD", "--"
            )
        )
        if (
            shallow_boundary(root, max_bytes=max_bytes, max_files=max_files)
            != (shallow, shallow_bytes)
            or bounded_git(root, "ls-files", "--stage", "-z") != encoded_index
            or bounded_git(root, "rev-parse", "--verify", "HEAD").decode().strip() != head
        ):
            raise DomainError("REVISION_CONFLICT", "Git state changed during snapshot")
    tracked = {entry.path for entry in index}
    working_paths = {entry.path for entry in entries}
    value = dict(
        kind="GIT" if head else "DIRECTORY",
        base_commit=head,
        git_history=shallow,
        head=head,
        index=index,
        working=entries,
        deleted=sorted(tracked - working_paths),
        untracked=sorted(
            entry.path
            for entry in entries
            if entry.path not in tracked and entry.kind != "DIRECTORY"
        ),
        index_hash=snapshot_digest([entry.model_dump() for entry in index]),
        working_hash=snapshot_digest([entry.model_dump() for entry in entries]),
        binary_diff_hash=binary,
        submodules={path: item.snapshot.snapshot_hash for path, item in submodules.items()},
        byte_count=total,
    )
    snapshot = ChangeSetSnapshot.model_validate(value | {"snapshot_hash": "pending"})
    snapshot = snapshot.model_copy(
        update={"snapshot_hash": snapshot_digest(snapshot.model_dump(exclude={"snapshot_hash"}))}
    )
    return CapturedSnapshot(snapshot, blobs, submodules)


def materialize_worktree(
    source: Path, target: Path, branch: str, captured: CapturedSnapshot
) -> None:
    if target.exists() or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}", branch):
        raise DomainError("REVISION_CONFLICT", "Attempt workspace identity is unavailable")
    from journeon.instruction_config import open_directory

    parent = open_directory(target.parent)
    os.close(parent)
    if captured.snapshot.kind != "GIT" or captured.snapshot.head is None:
        raise DomainError("VALIDATION_FAILED", "A Git snapshot is required for a worktree")
    bounded_git = partial(
        git,
        max_output_bytes=len(captured.snapshot.model_dump_json().encode())
        + captured.snapshot.byte_count,
    )
    bounded_git(
        source,
        "worktree",
        "add",
        "--no-checkout",
        "-b",
        branch,
        str(target),
        captured.snapshot.head,
    )
    bounded_git(target, "read-tree", "--empty")
    encoded = b"".join(
        f"{entry.mode} {entry.object_id} {entry.stage}\t".encode() + os.fsencode(entry.path) + b"\0"
        for entry in captured.snapshot.index
    )
    bounded_git(target, "update-index", "-z", "--index-info", data=encoded)
    _materialize_files(target, captured)
    for name, module in captured.submodules.items():
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        module_branch = (
            branch.split("/")[0] + "/module-" + content_hash(os.fsencode(destination))[:16]
        )
        materialize_worktree(source / name, destination, module_branch, module)

    _directory_modes(target, captured)


def _materialize_files(target: Path, captured: CapturedSnapshot) -> None:
    for entry in sorted(
        captured.snapshot.working, key=lambda item: (item.path.count("/"), item.path)
    ):
        path = target / entry.path
        if any(
            entry.path == module or entry.path.startswith(module + "/")
            for module in captured.submodules
        ):
            continue
        if entry.kind == "DIRECTORY":
            path.mkdir(exist_ok=True)
        elif entry.kind == "SYMLINK":
            assert entry.link_target is not None
            path.symlink_to(entry.link_target)
        else:
            data = captured.blobs[entry.content_hash]
            if content_hash(data) != entry.content_hash:
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Snapshot content requires repair")
            with path.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            path.chmod(entry.mode)


def _directory_modes(target: Path, captured: CapturedSnapshot) -> None:
    for entry in sorted(
        captured.snapshot.working, key=lambda item: item.path.count("/"), reverse=True
    ):
        if entry.kind == "DIRECTORY":
            (target / entry.path).chmod(entry.mode)


def materialize_directory(target: Path, captured: CapturedSnapshot) -> None:
    if captured.snapshot.kind != "DIRECTORY":
        raise DomainError("VALIDATION_FAILED", "A directory snapshot is required")
    materialize_projection(target, captured)


def materialize_projection(target: Path, captured: CapturedSnapshot) -> None:
    """Write captured working bytes; Git metadata is owned by the selected projection producer."""
    target.mkdir(mode=0o700)
    _materialize_files(target, captured)
    for name, child in captured.submodules.items():
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        materialize_projection(destination, child)
    _directory_modes(target, captured)
