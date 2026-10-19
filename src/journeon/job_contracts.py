# SPDX-License-Identifier: AGPL-3.0-only
from typing import Literal

from pydantic import Field, RootModel

from journeon.contracts import Contract, Identifier
from journeon.contracts import JobReceipt as JobReceipt


class JobConfiguration(Contract):
    pending_count: int = Field(gt=0)
    pending_bytes: int = Field(gt=0)
    concurrency: Literal[1]
    lease_seconds: int = Field(gt=0, lt=2**31)
    poll_seconds: int = Field(gt=0, lt=2**31)
    retry_seconds: int = Field(gt=0, lt=2**31)
    max_attempts: int = Field(gt=0)


class JobView(Contract):
    job_id: Identifier
    project_id: Identifier
    candidate_id: Identifier
    revision: int
    state: Literal["QUEUED", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED", "RETRY_WAIT"]
    effect: Literal["NONE", "UNKNOWN", "COMMITTED", "ABANDONED"]
    reason: str | None
    operation_id: Identifier | None
    admission_id: Identifier


class JobCancel(Contract):
    expected_revision: int = Field(gt=0)


class AttentionView(Contract):
    attention_id: Identifier
    job_id: Identifier
    reason: str
    occurrences: int
    disposition: Literal["OPEN", "DISMISSED", "RESOLVED"]


class ReplayCursor(Contract):
    incarnation: Identifier
    sequence: int = Field(ge=0)


class ReplayQuery(Contract):
    cursor: ReplayCursor | None = None
    limit: int = Field(gt=0, le=100)


class ReplayEvent(Contract):
    event_id: Identifier
    event_type: str
    target_id: Identifier
    target_revision: int
    operation_id: Identifier


class ReplayPage(Contract):
    status: Literal["AVAILABLE", "CANONICAL_REFETCH_REQUIRED"]
    cursor: ReplayCursor
    events: list[ReplayEvent]
    truncated: bool


class AttentionList(RootModel[list[AttentionView]]):
    pass
