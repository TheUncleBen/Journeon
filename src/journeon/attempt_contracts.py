# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit host configuration for deterministic Attempt preparation."""

from pathlib import Path
from typing import Self

from pydantic import Field, model_validator

from journeon.contracts import AttemptPrepare as AttemptPrepare
from journeon.contracts import AttemptReceipt as AttemptReceipt
from journeon.contracts import AttemptView as AttemptView
from journeon.contracts import Contract, Identifier, PositiveRevision
from journeon.contracts import DeterministicInstructionBundle as DeterministicInstructionBundle
from journeon.contracts import RunManifest as RunManifest


class AttemptWorkspaceConfiguration(Contract):
    key: Identifier
    revision: PositiveRevision
    project_id: Identifier
    root_key: Identifier
    root_revision: PositiveRevision


class AttemptConfiguration(Contract):
    storage_path: str
    revision: PositiveRevision
    snapshot_bytes: int = Field(gt=0)
    snapshot_files: int = Field(gt=0)
    pending_bytes: int = Field(gt=0)
    pending_count: int = Field(gt=0)
    lease_seconds: int = Field(gt=0)
    workspaces: list[AttemptWorkspaceConfiguration] = Field(min_length=1)

    @model_validator(mode="after")
    def unambiguous_boundaries(self) -> Self:
        path = Path(self.storage_path)
        if not path.is_absolute() or str(path) != self.storage_path or ".." in path.parts:
            raise ValueError("Attempt storage requires a normalized absolute path")
        if len({item.key for item in self.workspaces}) != len(self.workspaces):
            raise ValueError("Attempt workspace keys must be distinct")
        return self
