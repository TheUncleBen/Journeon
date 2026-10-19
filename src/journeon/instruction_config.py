# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit host-owned instruction boundaries; requests cannot supply host paths."""

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator

from journeon.contracts import Contract, Identifier


class RootConfiguration(Contract):
    key: Identifier
    path: str
    role: Literal["ENVIRONMENT", "PROJECT"]
    project_id: Identifier | None
    revision: int = Field(gt=0)

    @model_validator(mode="after")
    def check_identity(self) -> Self:
        if not Path(self.path).is_absolute() or str(Path(self.path)) != self.path:
            raise ValueError("A normalized absolute root path is required")
        if (self.role == "PROJECT") != (self.project_id is not None):
            raise ValueError("Project roots require an exact Project identity")
        return self


class ReleaseTrustConfiguration(Contract):
    public_key_hex: str
    manifest_path: str
    signature_path: str
    artifact_path: str
    backup_path: str
    channel: str
    platform: str
    authority: str
    revision: int = Field(gt=0)


class InstructionConfiguration(Contract):
    release_trust: ReleaseTrustConfiguration | None = None
    roots: list[RootConfiguration]
    protected_request_seconds: int = Field(gt=0, lt=2**31)
    protected_preview_seconds: int = Field(gt=0, lt=2**31)

    @model_validator(mode="after")
    def check_roots(self) -> Self:
        if len({root.key for root in self.roots}) != len(self.roots):
            raise ValueError("Root keys must be distinct")
        paths = [Path(root.path) for root in self.roots]
        for index, path in enumerate(paths):
            if any(
                path.is_relative_to(other) or other.is_relative_to(path) for other in paths[:index]
            ):
                raise ValueError("Instruction root boundaries cannot overlap")
        return self


class RootObservation(Contract):
    key: Identifier
    revision: int
    device: int
    inode: int
    tree_hash: str
    git_identity: str
    digest: str


def open_directory(path: Path) -> int:
    """Walk from the host root using descriptors and never follow a symbolic link."""
    if not path.is_absolute():
        raise ValueError("An absolute directory is required")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            if component in {".", ".."}:
                raise ValueError("Directory traversal is unavailable")
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def observe_root(configuration: RootConfiguration) -> RootObservation:
    try:
        descriptor = open_directory(Path(configuration.path))
        try:
            identity = os.fstat(descriptor)
            rows = []
            for name in sorted(os.listdir(descriptor)):
                item = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                rows.append(
                    (name, item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns)
                )
            tree_hash = hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()
            worktree = git_identity(Path(configuration.path))
            operands = [
                configuration.model_dump(),
                identity.st_dev,
                identity.st_ino,
                tree_hash,
                worktree,
            ]
            digest = hashlib.sha256(
                json.dumps(operands, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if not stat.S_ISDIR(identity.st_mode):
                raise ValueError("A local directory is required")
            return RootObservation(
                key=configuration.key,
                revision=configuration.revision,
                device=identity.st_dev,
                inode=identity.st_ino,
                tree_hash=tree_hash,
                git_identity=worktree,
                digest=digest,
            )
        finally:
            os.close(descriptor)
    except OSError:
        raise ValueError("Configured instruction root is unavailable") from None


def git_identity(root: Path) -> str:
    descriptor = open_directory(root)
    try:
        try:
            item = os.stat(".git", dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return hashlib.sha256(b"NON_GIT").hexdigest()
        if stat.S_ISDIR(item.st_mode):
            values = [item.st_dev, item.st_ino, "directory"]
        elif stat.S_ISREG(item.st_mode):
            file = os.open(".git", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                raw = os.read(file, 4097)
                if len(raw) > 4096 or not raw.startswith(b"gitdir: "):
                    raise ValueError("Invalid worktree identity file")
            finally:
                os.close(file)
            selected = Path(raw.decode().strip()[8:])
            if not selected.is_absolute():
                selected = root / selected
            selected = Path(os.path.abspath(selected))
            gitdir = open_directory(selected)
            try:
                target = os.fstat(gitdir)
                values = [item.st_dev, item.st_ino, raw.hex(), target.st_dev, target.st_ino]
            finally:
                os.close(gitdir)
        else:
            raise ValueError("Git worktree identity must be a regular entry")
        return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()
    finally:
        os.close(descriptor)
