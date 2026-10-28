# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded descriptor-relative instruction publication primitives."""

import hashlib
import os
import stat
from pathlib import Path, PurePosixPath
from uuid import uuid4

from journeon.contracts import DomainError
from journeon.instruction_config import open_directory
from journeon.instruction_contracts import Document
from journeon.instructions import digest

MAX_TREE_BYTES = 4 * 1024 * 1024
MAX_DOCUMENTS = 256


def snapshot(documents: list[Document]) -> dict[str, str]:
    result = {document.path: document.content for document in documents}
    if (
        len(result) != len(documents)
        or len(result) > MAX_DOCUMENTS
        or sum(len(value.encode()) for value in result.values()) > MAX_TREE_BYTES
    ):
        raise DomainError("VALIDATION_FAILED", "Instruction tree exceeds its bounded shape")
    for path in result:
        if any(
            str(parent) in result for parent in PurePosixPath(path).parents if str(parent) != "."
        ):
            raise DomainError("VALIDATION_FAILED", "Instruction file and directory paths overlap")
    return result


def tree_hash(documents: dict[str, str]) -> str:
    return digest(
        {
            name: hashlib.sha256(content.encode()).hexdigest()
            for name, content in sorted(documents.items())
        }
    )


def read_tree(path: Path) -> dict[str, str]:
    if not path.exists() and not path.is_symlink():
        # Existing ancestors are still checked; absent canonical leaf is an empty initial tree.
        ancestor = path.parent
        while not ancestor.exists():
            ancestor = ancestor.parent
        descriptor = open_directory(ancestor)
        os.close(descriptor)
        return {}
    result: dict[str, str] = {}
    total = 0

    def walk(descriptor: int, prefix: str) -> None:
        nonlocal total
        for name in sorted(os.listdir(descriptor)):
            identity = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            relative = prefix + name
            if stat.S_ISDIR(identity.st_mode):
                child = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
                )
                try:
                    walk(child, relative + "/")
                finally:
                    os.close(child)
            elif stat.S_ISREG(identity.st_mode):
                if identity.st_size > 65536 or len(result) >= MAX_DOCUMENTS:
                    raise ValueError("Instruction tree is too large")
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    data = os.read(child, 65537)
                    if len(data) > 65536 or os.read(child, 1):
                        raise ValueError("Instruction document is too large")
                    if os.fstat(child).st_ino != identity.st_ino:
                        raise ValueError("Instruction document changed")
                finally:
                    os.close(child)
                total += len(data)
                if total > MAX_TREE_BYTES:
                    raise ValueError("Instruction tree is too large")
                result[relative] = data.decode("utf-8")
            else:
                raise ValueError("Instruction tree contains a nonregular entry")

    descriptor = open_directory(path)
    try:
        walk(descriptor, "")
    finally:
        os.close(descriptor)
    return result


def ensure_directory(path: Path, anchor: tuple[Path, int, int] | None = None) -> int:
    if anchor is None:
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        parts = path.parts[1:]
    else:
        base, device, inode = anchor
        parts = path.relative_to(base).parts
        descriptor = open_directory(base)
        identity = os.fstat(descriptor)
        if (identity.st_dev, identity.st_ino) != (device, inode):
            os.close(descriptor)
            raise ValueError("Admitted publication root changed")
    try:
        for name in parts:
            try:
                os.mkdir(name, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def replace_document(
    root: Path,
    name: str,
    expected: str | None,
    target: str | None,
    *,
    anchor: tuple[Path, int, int] | None = None,
) -> None:
    Document(path=name, content=target or "")
    parent = root.joinpath(*PurePosixPath(name).parts[:-1])
    descriptor = ensure_directory(parent, anchor)
    leaf = PurePosixPath(name).name
    temporary = ".instruction-" + str(uuid4())
    try:
        try:
            current = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        except FileNotFoundError:
            observed = None
        else:
            try:
                if not stat.S_ISREG(os.fstat(current).st_mode):
                    raise ValueError("Instruction path is not a file")
                data = os.read(current, 65537)
                observed = data.decode("utf-8")
            finally:
                os.close(current)
        if observed != expected:
            raise ValueError("Instruction preimage changed")
        if target is None:
            if observed is not None:
                os.unlink(leaf, dir_fd=descriptor)
        else:
            staged = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=descriptor,
            )
            try:
                data = target.encode()
                position = 0
                while position < len(data):
                    position += os.write(staged, data[position:])
                os.fsync(staged)
            finally:
                os.close(staged)
            os.replace(temporary, leaf, src_dir_fd=descriptor, dst_dir_fd=descriptor)
        os.fsync(descriptor)
    finally:
        try:
            os.unlink(temporary, dir_fd=descriptor)
        except FileNotFoundError:
            pass
        os.close(descriptor)


def git_checkpoint(root: Path, documents: dict[str, str], staging: Path) -> dict[str, str] | None:
    """Preserve only the exact instruction subset without changing the user's index."""
    import subprocess
    import tempfile

    if not (root / ".git").exists():
        return None
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_TERMINAL_PROMPT="0"
    )
    directory = ensure_directory(staging)
    os.close(directory)
    with tempfile.TemporaryDirectory(prefix="checkpoint-", dir=staging) as temporary:
        environment["GIT_INDEX_FILE"] = str(Path(temporary) / "index")

        def git(*args: str, data: bytes | None = None) -> str:
            result = subprocess.run(
                [
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "core.attributesFile=/dev/null",
                    "-C",
                    str(root),
                    *args,
                ],
                input=data,
                env=environment,
                capture_output=True,
                check=True,
                timeout=30,
            )
            return result.stdout.decode().strip()

        worktree = git("rev-parse", "--show-toplevel")
        if Path(worktree) != root:
            raise ValueError("Checkpoint requires the exact admitted worktree root")
        gitdir = git("rev-parse", "--absolute-git-dir")
        git("read-tree", "--empty")
        records = []
        for name, content in sorted(documents.items()):
            Document(path=name, content=content)
            blob = git("hash-object", "-w", "--stdin", data=content.encode())
            records.append(f"100644 {blob}\t{name}\x00".encode())
        git("update-index", "-z", "--index-info", data=b"".join(records))
        return {
            "worktree": worktree,
            "git_directory": gitdir,
            "tree": git("write-tree"),
            "subset_hash": tree_hash(documents),
        }


def observe_tree(path: Path) -> dict[str, str]:
    try:
        return read_tree(path)
    except (OSError, ValueError):
        raise DomainError(
            "DEPENDENCY_UNAVAILABLE", "Canonical instruction tree is unavailable"
        ) from None
