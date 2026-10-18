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


PreferenceKey = Literal["harness", "model", "provider", "host"]
ConfigurationKind = Literal["profile", "bot", "team", "instruction_bundle"]


class Preferences(Contract):
    harness: Identifier | None = None
    model: Identifier | None = None
    provider: Identifier | None = None
    host: Identifier | None = None


class InstructionTemplate(Contract):
    template_id: Identifier
    template: Annotated[str, StringConstraints(max_length=65536)]
    required_variables: list[Identifier]
    eval_ids: list[Identifier]


class ProfileCreate(Contract):
    idempotency_key: Identifier
    name: Name
    baseline: InstructionTemplate
    preferences: Preferences
    eligibility: list[Identifier]
    visual_ref: Identifier | None = None


class ProfileRevisionPreview(ProfileCreate):
    profile_id: Identifier
    expected_revision: PositiveRevision
    expected_hash: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
    reason: Name


class BotImpact(Contract):
    bot_id: Identifier
    revision: PositiveRevision
    changed_inherited_fields: list[PreferenceKey]
    baseline_changed: bool


class ProfileImpact(Contract):
    digest: str
    profile_revision: PositiveRevision
    affected_bots: list[BotImpact]
    disclosure_scope: Literal["AUTHORIZED_BOTS_ONLY"] = "AUTHORIZED_BOTS_ONLY"


class ProfileRevise(ProfileRevisionPreview):
    preview_digest: str
    expected_affected_bots: list[BotImpact]


class BotCreate(Contract):
    idempotency_key: Identifier
    name: Name
    profile_id: Identifier
    expected_profile_revision: PositiveRevision
    additive: InstructionTemplate
    memory_enabled: bool
    overrides: Preferences


class BotRevise(Contract):
    idempotency_key: Identifier
    bot_id: Identifier
    expected_revision: PositiveRevision
    expected_hash: str
    name: Name
    additive: InstructionTemplate
    overrides: Preferences
    reset_to_inherit: list[PreferenceKey]
    visual_ref: Identifier | None
    reason: Name


class TeamMember(Contract):
    key: Identifier
    bot: BotCreate


class TeamCreate(Contract):
    idempotency_key: Identifier
    name: Name
    members: Annotated[list[TeamMember], Field(min_length=1, max_length=128)]
    lead_key: Identifier

    @model_validator(mode="after")
    def valid_members(self) -> "TeamCreate":
        keys = [member.key for member in self.members]
        if len(keys) != len(set(keys)) or self.lead_key not in keys:
            raise ValueError("Team requires unique members and a member lead")
        return self


class ProfileView(Contract):
    profile_id: Identifier
    revision: PositiveRevision
    name: Name
    baseline_asset_id: Identifier
    baseline_revision: PositiveRevision
    baseline_hash: str
    baseline: InstructionTemplate
    preferences: Preferences
    eligibility: list[Identifier]
    visual_ref: Identifier | None


class BotView(Contract):
    bot_id: Identifier
    revision: PositiveRevision
    name: Name
    profile_id: Identifier
    team_id: Identifier | None
    additive_asset_id: Identifier
    additive_revision: PositiveRevision
    additive_hash: str
    additive: InstructionTemplate
    memory_enabled: bool
    namespace_ref: Identifier
    overrides: Preferences
    visual_ref: Identifier | None
    builtin_role: Literal["RESEARCHER", "LIBRARIAN"] | None


class TeamView(Contract):
    team_id: Identifier
    revision: PositiveRevision
    name: Name
    authorized_members: list[BotView]
    authorized_lead_id: Identifier | None


class EffectiveField(Contract):
    field: PreferenceKey
    value: Identifier | None
    source: Literal["PROFILE", "BOT_OVERRIDE"]
    source_revision: PositiveRevision
    schema_type: Literal["optional-reference"] = "optional-reference"
    applicability: Literal["NEXT_QUALIFIED_TRANSITION"] = "NEXT_QUALIFIED_TRANSITION"
    portability: Literal["REFERENCE_ONLY"] = "REFERENCE_ONLY"
    secret_classification: Literal["NON_SECRET_REFERENCE"] = "NON_SECRET_REFERENCE"
    execution_qualified: Literal[False] = False


class EffectiveSettings(Contract):
    bot_id: Identifier
    fields: list[EffectiveField]
    visual_ref: Identifier | None
    eligibility: list[Identifier]
    eligibility_grants_authority: Literal[False] = False


class ConfigurationReceipt(Contract):
    schema_version: SchemaVersion = 1
    operation_id: Identifier
    command: Literal[
        "profile.create.v1",
        "profile.revise.v1",
        "bot.create.v1",
        "bot.revise.v1",
        "team.create.v1",
        "instruction.bundle.resolve.v1",
    ]
    outcome: Literal["CANONICAL_COMMITTED"] = "CANONICAL_COMMITTED"
    committed_at: str
    target_kind: ConfigurationKind
    target_id: Identifier
    revision: PositiveRevision
    member_ids: list[Identifier] = Field(default_factory=list)


class EffectivePermission(Contract):
    allowed: bool
    resource_kind: ConfigurationKind
    resource_id: Identifier
    action: Literal["read", "revise", "use", "receipt.read"]
    checked_revision: PositiveRevision | None
    reason: Literal["CURRENT_AUTHORITY", "UNAVAILABLE"]


def explicit_consent(value: object) -> object:
    if value is not True:
        raise ValueError("Explicit destination consent is required")
    return value


class LegacyMapping(Contract):
    collection_id: Identifier
    version: PositiveRevision
    content_hash: str
    provenance_ref: Identifier
    bot_id: Identifier
    expected_bot_revision: PositiveRevision
    memory_enabled: bool
    destination_consent: Annotated[Literal[True], BeforeValidator(explicit_consent)]


class LegacyPreview(Contract):
    mappings: list[LegacyMapping]
    unmapped: list[Identifier]


class LegacyPlan(Contract):
    mappings: list[LegacyMapping]
    unmapped: list[Identifier]
    execution: Literal["PREVIEW_ONLY_NO_BYTES_COPIED"] = "PREVIEW_ONLY_NO_BYTES_COPIED"


class ComponentRef(Contract):
    asset_id: Identifier
    revision: PositiveRevision
    content_hash: str


class VariableBinding(Contract):
    asset_id: Identifier
    name: Identifier
    value: Annotated[str, StringConstraints(max_length=65536)]


class BundleOrigin(Contract):
    kind: Literal["NAMED_BOT", "ONE_OFF_PROFILE"]
    source_kind: Literal["CHAT", "TASK_ATTEMPT", "OTHER"]
    source_id: Identifier
    task_id: Identifier | None = None
    bot_id: Identifier | None = None
    bot_revision: PositiveRevision | None = None

    @model_validator(mode="after")
    def legal_origin(self) -> "BundleOrigin":
        if (self.kind == "NAMED_BOT") != (
            self.bot_id is not None and self.bot_revision is not None
        ):
            raise ValueError("Origin requires its exact Bot variant")
        if self.kind == "ONE_OFF_PROFILE" and (
            self.bot_id is not None or self.bot_revision is not None
        ):
            raise ValueError("One-off origin cannot contain Bot identity")
        if (self.source_kind == "TASK_ATTEMPT") != (self.task_id is not None):
            raise ValueError("Task Attempt requires Task identity")
        return self


class BundleResolve(Contract):
    idempotency_key: Identifier
    profile_id: Identifier
    profile_revision: PositiveRevision
    project_id: Identifier
    project_revision: PositiveRevision
    origin: BundleOrigin
    components: list[ComponentRef]
    variables: list[VariableBinding]


class BundleView(Contract):
    bundle_id: Identifier
    initiating_principal_id: Identifier
    profile_id: Identifier
    profile_revision: PositiveRevision
    project_id: Identifier
    project_revision: PositiveRevision
    origin: BundleOrigin
    components: list[ComponentRef]
    content_digest: str
    byte_count: int


class BundleResult(Contract):
    receipt: ConfigurationReceipt
    bundle: BundleView
    rendering: str


CanonicalReceipt = OperationReceipt | PasskeyMutationReceipt | TaskReceipt | ConfigurationReceipt
