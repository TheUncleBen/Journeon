# SPDX-License-Identifier: AGPL-3.0-only
"""Clean Git metadata for bounded verification projections and admitted object stores."""

import codecs
import os
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
) -> GitProjection:
    from journeon.instruction_config import open_directory

    mounts: list[Path] = []
    observations: list[dict[str, Any]] = []
    identities: dict[Path, int] = {}
    remaining_bytes, remaining_files = max_bytes, max_files
    storage = target.parent / "git-objects"

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
                references.append("/git-objects/" + str(capture_objects(path)))
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
        (metadata / "objects" / "info" / "alternates").write_text(f"/git-objects/{index}\n")
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
    return GitProjection(mounts, observations)
