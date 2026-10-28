# SPDX-License-Identifier: AGPL-3.0-only
from typing import Literal

from pydantic import Field, RootModel, model_validator

from journeon.contracts import (
    AttemptPrepare,
    Contract,
    ExecutionView,
    Identifier,
    PositiveRevision,
    RunManifest,
    TaskAttemptOrigin,
    TaskCriterion,
)
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
    kind: Literal["INSTRUCTION_NAVIGATION", "TASK_VERIFICATION"]
    candidate_id: Identifier | None
    task_id: Identifier | None
    revision: int
    state: Literal["QUEUED", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED", "RETRY_WAIT"]
    effect: Literal["NONE", "UNKNOWN", "COMMITTED", "ABANDONED"]
    reason: str | None
    operation_id: Identifier | None
    admission_id: Identifier

    @model_validator(mode="after")
    def exact_origin(self) -> "JobView":
        if (
            self.kind == "TASK_VERIFICATION"
            and (self.task_id is None or self.candidate_id is not None)
        ) or (
            self.kind == "INSTRUCTION_NAVIGATION"
            and (self.candidate_id is None or self.task_id is not None)
        ):
            raise ValueError("Job requires its exact typed origin")
        return self


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


class TaskDispatch(AttemptPrepare):
    origin: TaskAttemptOrigin
    attempt_id: Identifier | None = None
    step_id: Identifier
    route_key: Identifier
    route_revision: PositiveRevision


class TaskEvidence(Contract):
    evidence_id: Identifier
    job_id: Identifier
    attempt_id: Identifier
    manifest: RunManifest
    step_id: Identifier
    criterion: TaskCriterion
    claim_fence: PositiveRevision
    claim_owner: Identifier
    claim_incarnation: Identifier
    execution: ExecutionView
    execution_operation_id: Identifier
    process_id: int = Field(gt=1)
    passed: bool
    published_at: str
    content_digest: str
