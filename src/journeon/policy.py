# SPDX-License-Identifier: AGPL-3.0-only
"""Strict validation of persisted policy before it can become authorization input."""

from pydantic import model_validator

from journeon.contracts import Contract, Identifier, PositiveRevision


class PolicyState(Contract):
    revision: PositiveRevision
    approval_id: Identifier | None
    approved_by: Identifier | None
    approved_providers: list[Identifier]
    verification_policy_ref: Identifier | None

    @model_validator(mode="after")
    def validate_approval(self) -> "PolicyState":
        if (self.approval_id is None) != (self.approved_by is None):
            raise ValueError("Approval attribution must be complete")
        if len(set(self.approved_providers)) != len(self.approved_providers):
            raise ValueError("Approved providers must be distinct")
        return self
