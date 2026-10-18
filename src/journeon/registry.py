# SPDX-License-Identifier: AGPL-3.0-only
"""Bound command and module metadata; not a second permission authority."""

from dataclasses import dataclass

from journeon.contracts import OperationReceipt, ProjectCreate


@dataclass(frozen=True)
class CommandDefinition:
    name: str
    owner: str
    input_model: type[ProjectCreate]
    result_model: type[OperationReceipt]
    permissions: tuple[str, ...]
    risk: str
    external_effects: tuple[str, ...]
    reversibility: str
    dry_run: bool
    idempotent: bool
    verification: str
    stability: str = "INTERNAL"


PROJECT_CREATE = CommandDefinition(
    name="project.create.v1",
    owner="projects",
    input_model=ProjectCreate,
    result_model=OperationReceipt,
    permissions=("project.create", "project.receipt.read"),
    risk="LOCAL_CANONICAL_MUTATION",
    external_effects=(),
    reversibility="No automatic undo; separate authorized lifecycle operation required",
    dry_run=False,
    idempotent=True,
    verification="Atomic Project, receipt and outbox persistence",
)

COMMANDS = {PROJECT_CREATE.name: PROJECT_CREATE}

MODULES = {
    "identity": {
        "tables": ("principals", "browser_sessions"),
        "backup_class": "R0",
        "health": "schema_and_database",
        "permissions": (),
        "migration": "0002_browser_sessions",
        "settings": (),
    },
    "permissions": {
        "tables": ("access_grants",),
        "backup_class": "R0",
        "health": "schema_and_database",
        "permissions": ("project.create", "project.receipt.read"),
        "migration": "0001_foundation",
        "settings": (),
    },
    "egress": {
        "tables": ("deployment_policy",),
        "backup_class": "R0",
        "health": "schema_and_database",
        "permissions": (),
        "migration": "0001_foundation",
        "settings": (),
    },
    "projects": {
        "tables": ("projects",),
        "backup_class": "R0",
        "health": "schema_and_database",
        "permissions": ("project.create", "project.receipt.read"),
        "migration": "0001_foundation",
        "settings": (),
    },
    "operations": {
        "tables": ("operation_receipts", "outbox_events"),
        "backup_class": "R1",
        "health": "schema_and_database",
        "permissions": ("project.receipt.read",),
        "migration": "0001_foundation",
        "settings": (),
    },
}
