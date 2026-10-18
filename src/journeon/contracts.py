# SPDX-License-Identifier: AGPL-3.0-only
"""Concrete INTERNAL v1 bindings; identifiers here are implementation-owned."""

from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)


def integer_schema_version(value: object) -> object:
    # Literal[1] alone accepts True and 1.0 even in strict Pydantic models.
    if type(value) is not int:
        raise ValueError("Schema version must be an integer")
    return value


SchemaVersion = Annotated[Literal[1], BeforeValidator(integer_schema_version)]

Identifier = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$")]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
Description = Annotated[str, StringConstraints(max_length=2000)]
PositiveRevision = Annotated[int, Field(ge=1)]
ErrorCode = Literal[
    "AUTHENTICATION_REQUIRED",
    "PERMISSION_DENIED",
    "VALIDATION_FAILED",
    "REVISION_CONFLICT",
    "IDEMPOTENCY_CONFLICT",
    "DEPENDENCY_UNAVAILABLE",
    "SCHEMA_UNSUPPORTED",
    "NOT_FOUND",
]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ProjectCreate(Contract):
    schema_version: SchemaVersion
    idempotency_key: Identifier
    name: Name
    description: Description = ""
    expected_policy_revision: PositiveRevision
    provider_mode: Literal["INHERIT", "NARROW", "LOCAL_ONLY"] = "INHERIT"
    selected_providers: Annotated[list[Identifier], Field(max_length=128)] | None = None

    @model_validator(mode="after")
    def validate_selection(self) -> "ProjectCreate":
        if self.provider_mode == "NARROW":
            if self.selected_providers is None:
                raise ValueError("NARROW requires an explicit provider selection")
            if len(set(self.selected_providers)) != len(self.selected_providers):
                raise ValueError("Provider selection contains duplicates")
        elif self.selected_providers is not None:
            raise ValueError("Only NARROW accepts a provider selection")
        return self


class ProviderSnapshot(Contract):
    """Historical consent only; never proof of current egress/route eligibility."""

    interpretation: Literal["HISTORICAL_CREATION_SNAPSHOT"] = "HISTORICAL_CREATION_SNAPSHOT"
    mode: Literal["INHERIT", "NARROW", "LOCAL_ONLY"]
    policy_revision: PositiveRevision
    approval_id: Identifier | None
    providers: list[Identifier]


class ProjectCreated(Contract):
    project_id: Identifier
    revision: PositiveRevision
    name: Name
    description: Description
    instruction_owner: Literal["ENVIRONMENT"] = "ENVIRONMENT"
    instruction_authority_ref: Identifier
    provider_allowance_at_creation: ProviderSnapshot
    verification_policy_ref: Identifier | None
    resource_refs: list[Identifier]


class OperationReceipt(Contract):
    schema_version: SchemaVersion = 1
    operation_id: Identifier
    command: Literal["project.create.v1"] = "project.create.v1"
    outcome: Literal["CANONICAL_COMMITTED"] = "CANONICAL_COMMITTED"
    committed_at: str
    project: ProjectCreated


class PasskeyLabelCommand(Contract):
    schema_version: SchemaVersion
    idempotency_key: Identifier
    passkey_id: Identifier
    expected_revision: PositiveRevision
    label: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]


class PasskeySummary(Contract):
    passkey_id: Identifier
    principal_id: Identifier
    revision: PositiveRevision
    label: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    revoked: bool


class PasskeyMutationReceipt(Contract):
    schema_version: SchemaVersion = 1
    operation_id: Identifier
    command: Literal["passkey.label.v1"] = "passkey.label.v1"
    outcome: Literal["CANONICAL_COMMITTED"] = "CANONICAL_COMMITTED"
    committed_at: str
    passkey: PasskeySummary


TaskState = Literal[
    "BACKLOG", "READY", "RUNNING", "WAITING", "REVIEW", "BLOCKED", "DONE", "CANCELLED", "ARCHIVED"
]
TaskAction = Literal["pause", "resume", "cancel"]


class TaskCreate(Contract):
    schema_version: SchemaVersion
    idempotency_key: Identifier
    project_id: Identifier
    expected_project_revision: PositiveRevision
    objective: Name
    success_conditions: list[Name] = Field(default_factory=list)
    responsibility: Literal["HUMAN", "UNASSIGNED"]
    dependencies: list[Identifier] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_dependencies(self) -> "TaskCreate":
        if len(set(self.dependencies)) != len(self.dependencies):
            raise ValueError("Task dependencies must be distinct")
        return self


class TaskControl(Contract):
    schema_version: SchemaVersion
    idempotency_key: Identifier
    task_id: Identifier
    expected_revision: PositiveRevision
    reason: Name


class TaskCriterion(Contract):
    text: Name
    provenance: Literal["USER"] = "USER"
    principal_id: Identifier
    objective_revision: PositiveRevision


class TaskPolicyBinding(Contract):
    source: Literal["PROJECT"] = "PROJECT"
    project_id: Identifier
    project_revision: PositiveRevision
    policy_ref: Identifier | None


class TaskAssignment(Contract):
    responsibility: Literal["HUMAN", "UNASSIGNED"]
    principal_id: Identifier | None
    assigned_by: Identifier
    assigned_at: str
    reason: Literal["Task created"] = "Task created"

    @model_validator(mode="after")
    def responsible_human(self) -> "TaskAssignment":
        if (self.responsibility == "HUMAN") != (self.principal_id is not None):
            raise ValueError("Human responsibility requires an attributed Principal")
        return self


class TaskView(Contract):
    task_id: Identifier
    project_id: Identifier
    initiating_principal_id: Identifier
    revision: PositiveRevision
    objective: Name
    objective_revision: PositiveRevision
    criteria_revision: PositiveRevision
    success_conditions: list[TaskCriterion]
    verification_policy: TaskPolicyBinding
    assignment: TaskAssignment
    assignment_history: list[TaskAssignment]
    dependencies: list[Identifier]
    state: TaskState
    paused: bool
    pause_reason: Name | None
    stop_reason: Name | None
    blocker: Name | None
    created_at: str
    updated_at: str


class TaskReceipt(Contract):
    schema_version: SchemaVersion = 1
    operation_id: Identifier
    command: Literal["task.create.v1", "task.pause.v1", "task.resume.v1", "task.cancel.v1"]
    outcome: Literal["CANONICAL_COMMITTED"] = "CANONICAL_COMMITTED"
    committed_at: str
    task: TaskView


CanonicalReceipt = OperationReceipt | PasskeyMutationReceipt | TaskReceipt


class ErrorEnvelope(Contract):
    schema_version: SchemaVersion = 1
    code: ErrorCode
    reason: str


class DomainError(Exception):
    def __init__(self, code: ErrorCode, reason: str) -> None:
        self.code = code
        self.reason = reason
        super().__init__(reason)


ERROR_HTTP_STATUS: dict[ErrorCode, int] = {
    "AUTHENTICATION_REQUIRED": 401,
    "PERMISSION_DENIED": 403,
    "VALIDATION_FAILED": 422,
    "REVISION_CONFLICT": 409,
    "IDEMPOTENCY_CONFLICT": 409,
    "DEPENDENCY_UNAVAILABLE": 503,
    "SCHEMA_UNSUPPORTED": 422,
    "NOT_FOUND": 404,
}
