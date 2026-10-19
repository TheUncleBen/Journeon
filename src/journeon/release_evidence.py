# SPDX-License-Identifier: AGPL-3.0-only
"""Verify configured installed-release evidence; no download or private signing key."""

import hashlib
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import Engine

from journeon.contracts import Contract, DomainError
from journeon.database import SCHEMA_REVISION, transaction
from journeon.installed_instructions import candidate_manifest
from journeon.instruction_config import InstructionConfiguration, open_directory
from journeon.models import InstalledReleaseEvidence
from journeon.permissions import AuthenticatedContext, current_owner


class SignedReleaseManifest(Contract):
    format: int
    instruction_manifest_digest: str
    artifact_sha256: str
    source_digest: str
    source_commit: str
    version: str
    channel: str
    platform: str
    schema_revision: str
    eval_suite: str


def regular_bytes(path: str, limit: int) -> bytes:
    import os
    import stat

    location = Path(path)
    parent = open_directory(location.parent)
    try:
        descriptor = os.open(location.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            identity = os.fstat(descriptor)
            if not stat.S_ISREG(identity.st_mode) or identity.st_size > limit:
                raise ValueError("Invalid evidence file")
            chunks = []
            total = 0
            while chunk := os.read(descriptor, 65536):
                total += len(chunk)
                if total > limit:
                    raise ValueError("Evidence file exceeds bound")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def verified_snapshot(config: InstructionConfiguration) -> dict[str, Any]:
    trust = config.release_trust
    if trust is None:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Installed release trust is not configured")
    try:
        raw = regular_bytes(trust.manifest_path, 65536)
        signature = regular_bytes(trust.signature_path, 64)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(trust.public_key_hex)).verify(
            signature, raw
        )
        manifest = SignedReleaseManifest.model_validate_json(raw)
        import tomllib

        package_version = tomllib.loads(
            Path(__file__).resolve().parents[2].joinpath("pyproject.toml").read_text()
        )["project"]["version"]
        if (
            manifest.format,
            manifest.channel,
            manifest.platform,
            manifest.schema_revision,
            manifest.eval_suite,
            manifest.version,
            manifest.instruction_manifest_digest,
        ) != (
            1,
            trust.channel,
            trust.platform,
            SCHEMA_REVISION,
            "instruction-boundaries-v1",
            package_version,
            candidate_manifest().digest,
        ):
            raise ValueError("Release binding mismatch")
        if manifest.source_digest != candidate_manifest().source_digest:
            raise ValueError("Installed source identity differs from signed release")
        import platform
        import sys

        if manifest.platform != sys.platform + "-" + platform.machine():
            raise ValueError("Installed platform differs from signed release")
        artifact = regular_bytes(trust.artifact_path, 512 * 1024 * 1024)
        if hashlib.sha256(artifact).hexdigest() != manifest.artifact_sha256:
            raise ValueError("Artifact hash mismatch")
        backup = regular_bytes(trust.backup_path, 512 * 1024 * 1024)
        # Inspect the supplied coherent backup through a private in-memory SQLite copy.
        with closing(sqlite3.connect(":memory:")) as db:
            db.deserialize(backup)
            if (
                db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]
                or db.execute("PRAGMA foreign_key_check").fetchall()
            ):
                raise ValueError("Backup validation failed")
            from journeon.models import Base

            tables = {
                row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if not set(Base.metadata.tables) <= tables:
                raise ValueError("Backup does not contain the complete canonical store")
            if db.execute("SELECT version_num FROM alembic_version").fetchall() != [
                (SCHEMA_REVISION,)
            ]:
                raise ValueError("Backup schema mismatch")
        return {
            "manifest": manifest.model_dump(mode="json"),
            "manifest_hash": hashlib.sha256(raw).hexdigest(),
            "signature_hash": hashlib.sha256(signature).hexdigest(),
            "backup_hash": hashlib.sha256(backup).hexdigest(),
            "trust_revision": trust.revision,
            "authority": trust.authority,
            "public_key_hash": hashlib.sha256(bytes.fromhex(trust.public_key_hex)).hexdigest(),
        }
    except (ValueError, OSError, InvalidSignature, sqlite3.Error):
        raise DomainError("PERMISSION_DENIED", "Installed release verification failed") from None


def verify_current_evidence(config: InstructionConfiguration, stored: dict[str, Any]) -> None:
    if verified_snapshot(config) != stored:
        raise DomainError("PERMISSION_DENIED", "Installed release evidence changed")


def verify_release(
    engine: Engine, config: InstructionConfiguration, actor: AuthenticatedContext
) -> str:
    from uuid import uuid4

    with transaction(engine) as db:
        current_owner(db, actor)
    snapshot = verified_snapshot(config)
    with transaction(engine) as db:
        current_owner(db, actor)
        identity = str(uuid4())
        db.add(
            InstalledReleaseEvidence(
                id=identity,
                principal_id=actor.principal_id,
                manifest_digest=snapshot["manifest"]["instruction_manifest_digest"],
                snapshot=snapshot,
            )
        )
        return identity
