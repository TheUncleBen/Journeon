# SPDX-License-Identifier: AGPL-3.0-only
"""Clean Git metadata for bounded verification projections and admitted object stores."""

import codecs
import hashlib
import os
import re
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from journeon.attempt_snapshots import (
    CapturedSnapshot,
    capture_snapshot,
    git,
    materialize_projection,
)
from journeon.contracts import DomainError


@dataclass
class GitProjection:
    mounts: list[Path]
    observations: list[dict[str, Any]]


def project_git_view(
    source: Path,
    target: Path,
    captured: CapturedSnapshot,
    *,
    admitted_roots: list[Path],
    max_bytes: int,
    max_files: int,
    snapshot_bound: bool = False,
) -> GitProjection:
    from journeon.instruction_config import open_directory

    mounts: list[Path] = []
    observations: list[dict[str, Any]] = []
    identities: dict[Path, int] = {}
    remaining_bytes, remaining_files = max_bytes, max_files
    storage = target.parent / "git-objects"
    repositories: list[tuple[Path, CapturedSnapshot, int, str]] = []

    def capture_objects(objects: Path) -> int:
        nonlocal remaining_bytes, remaining_files
        objects = Path(os.path.abspath(objects))
        if objects in identities:
            return identities[objects]
        if not any(objects.is_relative_to(root) for root in admitted_roots):
            raise DomainError(
                "PERMISSION_DENIED", "Git object storage requires an admitted Project root"
            )
        descriptor = open_directory(objects)
        os.close(descriptor)
        captured_objects = capture_snapshot(
            objects, max_bytes=remaining_bytes, max_files=remaining_files
        )
        if any(entry.kind == "SYMLINK" for entry in captured_objects.snapshot.working):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Git object links require explicit immutable projection"
            )
        remaining_bytes -= captured_objects.snapshot.byte_count
        remaining_files -= len(captured_objects.snapshot.working)
        index = len(mounts)
        identities[objects] = index
        copied = storage / str(index)
        mounts.append(copied)
        observation: dict[str, Any] = {
            "source": str(objects),
            "snapshot": captured_objects.snapshot.model_dump(mode="json"),
        }
        observations.append(observation)
        materialize_projection(copied, captured_objects)
        alternate = next(
            (
                entry
                for entry in captured_objects.snapshot.working
                if entry.path == "info/alternates"
            ),
            None,
        )
        if alternate is not None:
            references = []
            for raw in captured_objects.blobs[alternate.content_hash].splitlines():
                if not raw:
                    continue
                if raw.startswith(b'"'):
                    if not raw.endswith(b'"'):
                        raise DomainError(
                            "DEPENDENCY_UNAVAILABLE", "Git alternate path is malformed"
                        )
                    raw = cast(bytes, codecs.escape_decode(raw[1:-1])[0])
                path = Path(os.fsdecode(raw))
                if not path.is_absolute():
                    path = objects / path
                alternate_index = capture_objects(path)
                references.append(
                    str(mounts[alternate_index])
                    if snapshot_bound
                    else "/git-objects/" + str(alternate_index)
                )
            (copied / "info" / "alternates").write_text(
                "".join(reference + "\n" for reference in references)
            )
        if (
            capture_snapshot(objects, max_bytes=max_bytes, max_files=max_files).snapshot
            != captured_objects.snapshot
        ):
            raise DomainError("REVISION_CONFLICT", "Git objects changed during immutable capture")
        observation["projection"] = capture_snapshot(
            copied, max_bytes=max_bytes, max_files=max_files
        ).snapshot.model_dump(mode="json")
        return index

    def project(original: Path, destination: Path, snapshot: CapturedSnapshot) -> None:
        if snapshot.snapshot.kind != "GIT":
            return
        objects = Path(
            git(
                original,
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                "objects",
                max_output_bytes=max_bytes,
            )
            .decode()
            .strip()
        )
        index = capture_objects(objects)
        object_format = (
            git(original, "rev-parse", "--show-object-format", max_output_bytes=max_bytes)
            .decode()
            .strip()
        )
        if object_format not in ("sha1", "sha256"):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Git object format is unsupported")
        git(
            destination,
            "init",
            "--quiet",
            "--template=",
            "--object-format=" + object_format,
            max_output_bytes=max_bytes,
        )
        metadata = destination / ".git"
        (metadata / "objects" / "info" / "alternates").write_text(
            (str(mounts[index]) if snapshot_bound else f"/git-objects/{index}") + "\n"
        )
        repositories.append((destination, snapshot, index, object_format))
        branch = (
            git(original, "rev-parse", "--abbrev-ref", "HEAD", max_output_bytes=max_bytes)
            .decode()
            .strip()
        )
        if branch == "HEAD":
            (metadata / "HEAD").write_text(str(snapshot.snapshot.head) + "\n")
        else:
            git(original, "check-ref-format", "refs/heads/" + branch, max_output_bytes=max_bytes)
            reference = metadata / "refs" / "heads" / branch
            reference.parent.mkdir(parents=True, exist_ok=True)
            reference.write_text(str(snapshot.snapshot.head) + "\n")
            (metadata / "HEAD").write_text("ref: refs/heads/" + branch + "\n")
        git(destination, "read-tree", "--empty", max_output_bytes=max_bytes)
        records = b"".join(
            f"{entry.mode} {entry.object_id} {entry.stage}\t".encode()
            + os.fsencode(entry.path)
            + b"\0"
            for entry in snapshot.snapshot.index
        )
        git(
            destination,
            "update-index",
            "-z",
            "--index-info",
            data=records,
            max_output_bytes=max_bytes,
        )
        for name, child in sorted(snapshot.submodules.items()):
            project(original / name, destination / name, child)

    if captured.snapshot.kind == "GIT":
        storage.mkdir(mode=0o700)
        project(source, target, captured)
    if snapshot_bound and mounts:
        sealed = [target.parent / "git-snapshot-objects" / str(i) for i in range(len(mounts))]
        for directory in sealed:
            directory.mkdir(parents=True, mode=0o700)
        retained: set[tuple[int, str]] = set()
        for destination, snapshot, index, object_format in repositories:
            roots = {entry.object_id for entry in snapshot.snapshot.index if entry.mode != "160000"}
            if snapshot.snapshot.head is not None:
                roots.add(snapshot.snapshot.head)
            reachable = (
                git(
                    destination,
                    "rev-list",
                    "--objects",
                    "--no-object-names",
                    "--stdin",
                    data="".join(root + "\n" for root in sorted(roots)).encode(),
                    max_output_bytes=max_bytes,
                )
                .decode()
                .splitlines()
            )
            for object_id in reachable:
                if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", object_id):
                    raise DomainError("DEPENDENCY_UNAVAILABLE", "Git object identity is malformed")
                if (index, object_id) in retained:
                    continue
                kind = git(destination, "cat-file", "-t", object_id, max_output_bytes=32).strip()
                if kind not in (b"blob", b"tree", b"commit", b"tag"):
                    raise DomainError("DEPENDENCY_UNAVAILABLE", "Git object type is unsupported")
                content = git(
                    destination,
                    "cat-file",
                    kind.decode(),
                    object_id,
                    max_output_bytes=max(1, remaining_bytes),
                )
                raw = kind + b" " + str(len(content)).encode() + b"\0" + content
                if hashlib.new(object_format, raw).hexdigest() != object_id:
                    raise DomainError(
                        "DEPENDENCY_UNAVAILABLE", "Git object content differs from its identity"
                    )
                compressed = zlib.compress(raw)
                remaining_bytes -= max(len(raw), len(compressed))
                remaining_files -= 1
                if remaining_bytes < 0 or remaining_files < 0:
                    raise DomainError(
                        "DEPENDENCY_UNAVAILABLE",
                        "Git snapshot object closure exceeds configured limits",
                    )
                output = sealed[index] / object_id[:2] / object_id[2:]
                output.parent.mkdir(exist_ok=True)
                with output.open("xb") as stream:
                    stream.write(compressed)
                retained.add((index, object_id))
        for destination, _, index, _ in repositories:
            (destination / ".git" / "objects" / "info" / "alternates").write_text(
                f"/git-objects/{index}\n"
            )
        mounts = sealed
        for index, directory in enumerate(mounts):
            observations[index]["projection"] = capture_snapshot(
                directory, max_bytes=max_bytes, max_files=max_files
            ).snapshot.model_dump(mode="json")
    return GitProjection(mounts, observations)
