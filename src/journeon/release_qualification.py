# SPDX-License-Identifier: AGPL-3.0-only
"""Owned current instruction health and paired database/tree backup evidence."""

import hashlib
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from journeon.contracts import DomainError
from journeon.database import SCHEMA_REVISION, transaction
from journeon.installed_instructions import candidate_manifest
from journeon.instruction_config import InstructionConfiguration, open_directory
from journeon.instructions import digest
from journeon.operations import snapshot_database, validate_snapshot
from journeon.permissions import AuthenticatedContext, current_owner

TABLES = (
    "instruction_roots",
    "project_instruction_bindings",
    "project_instruction_revisions",
    "project_instruction_policies",
    "instruction_publications",
    "instruction_projections",
    "instruction_installations",
    "instruction_assets",
    "instruction_revisions",
)


def state(db: Session) -> str:
    from sqlalchemy import text

    return digest(
        {
            table: [
                dict(row)
                for row in db.execute(text(f"SELECT * FROM {table} ORDER BY 1,2")).mappings()
            ]
            for table in TABLES
        }
    )


def health(
    engine: Engine, config: InstructionConfiguration, actor: AuthenticatedContext
) -> dict[str, Any]:
    from sqlalchemy import select, text

    from journeon.health import schema_and_database
    from journeon.instruction_config import observe_root
    from journeon.instruction_files import read_tree, tree_hash
    from journeon.models import (
        InstructionPublication,
        InstructionRoot,
        ProjectInstructionBinding,
        ProjectInstructionRevision,
    )

    foundation = schema_and_database(engine)
    if foundation.database != "AVAILABLE" or foundation.schema_state != "CURRENT":
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Current runtime store health is unavailable")
    package = candidate_manifest()
    trees = {}
    with transaction(engine) as db:
        current_owner(db, actor)
        if (
            db.execute(text("PRAGMA integrity_check")).all() != [("ok",)]
            or db.execute(text("PRAGMA foreign_key_check")).first()
        ):
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Current instruction store is unhealthy")
        if (
            db.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
            != SCHEMA_REVISION
        ):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Installed instruction schema is incompatible"
            )
        if db.scalar(
            select(InstructionPublication.id).where(
                InstructionPublication.status.not_in(("CANONICAL_COMMITTED", "ABANDONED"))
            )
        ):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE",
                "Publication must be reconciled before release qualification",
            )
        initial = state(db)
        roots = {root.id: root for root in db.scalars(select(InstructionRoot))}
        bindings = list(db.scalars(select(ProjectInstructionBinding)))
        revisions = {
            (row.project_id, row.revision): row
            for row in db.scalars(select(ProjectInstructionRevision))
        }
    configured = {root.key: root for root in config.roots}
    locations = {}
    for root in roots.values():
        if not root.enabled:
            continue
        supplied = configured.get(root.root_key)
        if supplied is None or (supplied.revision, supplied.role, supplied.project_id) != (
            root.config_revision,
            root.role,
            root.project_id,
        ):
            raise DomainError("PERMISSION_DENIED", "Current backup root configuration differs")
        try:
            observed = observe_root(supplied)
        except (ValueError, OSError):
            raise DomainError("PERMISSION_DENIED", "Current backup root is unavailable") from None
        if (observed.device, observed.inode, observed.git_identity) != (
            root.device,
            root.inode,
            root.git_identity,
        ):
            raise DomainError("PERMISSION_DENIED", "Current backup root identity differs")
        locations[root.id] = Path(supplied.path)
    for binding in bindings:
        if binding.active_operation:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE",
                "Publication must be reconciled before release qualification",
            )
        if binding.revision == 0:
            continue
        root = roots[binding.root_id]
        if binding.root_id not in locations or root.revision != binding.root_revision:
            raise DomainError("PERMISSION_DENIED", "Current backup binding is unavailable")
        location = locations[binding.root_id] / (
            ".journeon/instructions"
            if binding.owner == "PROJECT"
            else "instructions/projects/" + binding.project_id
        )
        documents = read_tree(location)
        revision = revisions.get((binding.project_id, binding.revision))
        if (
            revision is None
            or tree_hash(documents) != revision.tree_hash
            or documents != revision.snapshot["documents"]
        ):
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE",
                "Canonical instruction tree does not match its accepted revision",
            )
        trees[binding.project_id] = {
            "root_id": binding.root_id,
            "owner": binding.owner,
            "revision": binding.revision,
            "documents": documents,
        }
    with transaction(engine) as db:
        current_owner(db, actor)
        if initial != state(db):
            raise DomainError("REVISION_CONFLICT", "Instruction state changed during qualification")
    return {
        "result": "PASS",
        "foundation": foundation.model_dump(mode="json"),
        "schema": SCHEMA_REVISION,
        "package": package.digest,
        "source": package.source_digest,
        "state": initial,
        "trees": trees,
        "configuration": digest(config.model_dump(mode="json")),
        "scope": "CURRENT_CANONICAL_STORE_ROOTS_TREES_AND_INSTALLED_RENDERER",
    }


def produce(
    engine: Engine, config: InstructionConfiguration, actor: AuthenticatedContext
) -> dict[str, Any]:
    trust = config.release_trust
    assert trust is not None
    before = health(engine, config, actor)
    destination = Path(trust.backup_path + ".qualification-" + str(uuid4()))
    descriptor = open_directory(destination.parent)
    os.close(descriptor)
    backup = snapshot_database(Path(str(engine.url.database)), destination)
    tree_bytes = json.dumps(before["trees"], sort_keys=True, separators=(",", ":")).encode()
    fd = os.open(
        destination / "trees.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(fd, "wb") as writer:
        writer.write(tree_bytes)
        writer.flush()
        os.fsync(writer.fileno())
    with closing(
        sqlite3.connect((destination / "database.sqlite").as_uri() + "?mode=ro", uri=True)
    ) as saved:
        saved.row_factory = sqlite3.Row
        saved_state = digest(
            {
                table: [dict(row) for row in saved.execute(f"SELECT * FROM {table} ORDER BY 1,2")]
                for table in TABLES
            }
        )
    if saved_state != before["state"] or health(engine, config, actor) != before:
        raise DomainError(
            "REVISION_CONFLICT",
            "Release backup observations changed; retained output is not approved",
        )
    return {
        "health": {key: value for key, value in before.items() if key != "trees"},
        "backup": {
            "directory": str(destination),
            "database": backup,
            "trees_hash": hashlib.sha256(tree_bytes).hexdigest(),
        },
    }


def verify(
    engine: Engine,
    config: InstructionConfiguration,
    evidence: dict[str, Any],
    actor: AuthenticatedContext,
) -> None:
    from journeon.release_evidence import regular_bytes

    try:
        current = health(engine, config, actor)
        trees = current.pop("trees")
        if current != evidence["health"]:
            raise ValueError("Health evidence is stale")
        directory = Path(evidence["backup"]["directory"])
        trust = config.release_trust
        if (
            trust is None
            or directory.parent != Path(trust.backup_path).parent
            or not directory.name.startswith(Path(trust.backup_path).name + ".qualification-")
        ):
            raise ValueError("Backup identity differs")
        descriptor = open_directory(directory)
        os.close(descriptor)
        if validate_snapshot(directory) != evidence["backup"]["database"]:
            raise ValueError("Database backup changed")
        raw = regular_bytes(str(directory / "trees.json"), 512 * 1024 * 1024)
        if (
            hashlib.sha256(raw).hexdigest() != evidence["backup"]["trees_hash"]
            or json.loads(raw) != trees
        ):
            raise ValueError("External tree backup changed")
    except (KeyError, TypeError, ValueError, OSError):
        raise DomainError(
            "PERMISSION_DENIED", "Current coherent release qualification is required"
        ) from None
