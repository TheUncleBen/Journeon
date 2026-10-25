# SPDX-License-Identifier: AGPL-3.0-only
"""Typed Project instruction effects and exact protected operands."""

from typing import Annotated, Any, Literal, cast

from pydantic import Field, RootModel, StringConstraints, TypeAdapter, model_validator

from journeon.contracts import (
    Contract,
    DeploymentPolicyReceipt,
    GrantReceipt,
    GrantRevoke,
    GrantSet,
    Identifier,
    Name,
    PolicyInitialize,
    SessionMutationReceipt,
    SessionRevoke,
)
from journeon.contracts import InstructionReceipt as InstructionReceipt
from journeon.restore_contracts import RestoreAuthorization, RestorePlan

Hash = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
Revision = Annotated[int, Field(ge=0)]


InstructionCategory = Literal[
    "NAVIGATION_REPAIR",
    "ORDINARY",
    "SECURITY",
    "DEPLOYMENT",
    "PERMISSIONS",
    "DESTRUCTIVE",
    "ARCHITECTURE",
    "GLOSSARY",
]


class RootInspect(Contract):
    root_key: Identifier
    config_revision: Revision


class RootAdmit(RootInspect):
    kind: Literal["project.root.admit.v1"] = "project.root.admit.v1"
    idempotency_key: Identifier
    inspection_digest: Hash
    expected_revision: Revision


class RootRevoke(Contract):
    kind: Literal["project.root.revoke.v1"] = "project.root.revoke.v1"
    idempotency_key: Identifier
    root_id: Identifier
    expected_revision: Revision


class InstructionPolicy(Contract):
    authorized_categories: Annotated[list[InstructionCategory], Field(min_length=1)]
    navigation_repairs: bool
    independent_review: bool
    require_confirmation: bool
    required_evals: Annotated[
        list[Literal["instruction-boundaries-v1"]], Field(min_length=1, max_length=1)
    ]


class PolicyConfigure(Contract):
    kind: Literal["project.instructions.policy.configure.v1"] = (
        "project.instructions.policy.configure.v1"
    )
    idempotency_key: Identifier
    project_id: Identifier
    expected_project_revision: Revision
    expected_binding_revision: Revision
    expected_root_revision: Revision
    expected_policy_revision: Revision
    policy: InstructionPolicy


class CandidateRegister(Contract):
    kind: Literal["instruction.candidate.register.v1"] = "instruction.candidate.register.v1"
    idempotency_key: Identifier
    manifest_digest: Hash
    expected_revision: Revision


class ReleaseInstall(Contract):
    kind: Literal["instruction.release.install.v1"] = "instruction.release.install.v1"
    idempotency_key: Identifier
    evidence_id: Identifier
    manifest_digest: Hash
    expected_revision: Revision


class InstructionChangeConsent(Contract):
    kind: Literal["project.instructions.accept.v1"] = "project.instructions.accept.v1"
    idempotency_key: Identifier
    project_id: Identifier
    candidate_id: Identifier
    candidate_hash: Hash
    expected_binding_revision: Revision
    expected_policy_revision: Revision
    review_ids: list[Identifier]
    eval_ids: list[Identifier]


class RecoveryRootRevision(Contract):
    root_id: Identifier
    revision: Revision


class RecoveryTarget(Contract):
    root_revisions: Annotated[list[RecoveryRootRevision], Field(min_length=1, max_length=2)]
    project_id: Identifier
    operation_id: Identifier
    expected_generation: Revision
    expected_binding_revision: Revision
    expected_policy_revision: Revision
    publication_hash: Hash
    target_hash: Hash


class RecoveryInspect(Contract):
    project_id: Identifier


class PublicationRecovery(RecoveryTarget):
    disposition: Literal["FINISH_TARGET", "RESTORE_BASE"]
    kind: Literal["project.instructions.recover.v1"] = "project.instructions.recover.v1"
    idempotency_key: Identifier


ProtectedEffect = Annotated[
    RootAdmit
    | RootRevoke
    | PolicyConfigure
    | CandidateRegister
    | ReleaseInstall
    | InstructionChangeConsent
    | PublicationRecovery
    | RestorePlan
    | GrantSet
    | SessionRevoke
    | GrantRevoke
    | PolicyInitialize,
    Field(discriminator="kind"),
]
EFFECT_ADAPTER: TypeAdapter[ProtectedEffect] = TypeAdapter(cast(Any, ProtectedEffect))


class ProtectedPrepare(Contract):
    effect: ProtectedEffect


class ProtectedIdentity(Contract):
    request_id: Identifier


class ExactConfirmation(ProtectedIdentity):
    nonce: Annotated[str, StringConstraints(min_length=43, max_length=43)]
    request_hash: Hash


class OfficialPreview(ProtectedIdentity):
    request_hash: Hash
    effect: ProtectedEffect
    deadline: int
    nonce: str
    provenance: Literal["OFFICIAL_EXACT_EFFECT"] = "OFFICIAL_EXACT_EFFECT"


class Document(Contract):
    path: Annotated[str, StringConstraints(min_length=1, max_length=240)]
    content: Annotated[str, StringConstraints(max_length=65536)]

    @model_validator(mode="after")
    def safe_path(self) -> "Document":
        from pathlib import PurePosixPath

        path = PurePosixPath(self.path)
        if (
            path.is_absolute()
            or str(path) != self.path
            or any(part in {".", "..", ".git"} for part in path.parts)
            or "\\" in self.path
            or any(ord(character) < 32 or ord(character) == 127 for character in self.path)
        ):
            raise ValueError("An instruction-relative regular document path is required")
        return self


class InstructionBind(Contract):
    idempotency_key: Identifier
    project_id: Identifier
    expected_project_revision: Revision
    expected_binding_revision: Revision
    root_id: Identifier
    expected_root_revision: Revision
    expected_tree_hash: Hash
    owner: Literal["ENVIRONMENT", "PROJECT"]
    documents: Annotated[list[Document], Field(max_length=256)]
    required_fragments: list[str]
    reason: Name


class InstructionPropose(Contract):
    idempotency_key: Identifier
    project_id: Identifier
    expected_revision: Revision
    expected_tree_hash: Hash
    documents: Annotated[list[Document], Field(max_length=256)]
    required_fragments: list[str]
    reason: Name
    source_refs: list[Identifier]
    category: InstructionCategory


class CandidateReference(Contract):
    project_id: Identifier
    candidate_id: Identifier
    candidate_hash: Hash
    expected_binding_revision: Revision
    expected_policy_revision: Revision


class InstructionAccept(CandidateReference):
    consent_request_id: Identifier | None = None
    idempotency_key: Identifier
    review_ids: list[Identifier]
    eval_ids: list[Identifier]


class InstructionReview(CandidateReference):
    idempotency_key: Identifier
    verdict: Literal["PASS", "FAIL"]
    coverage: Name
    limitations: Name
    findings: list[Name]


class InstructionRestore(Contract):
    idempotency_key: Identifier
    project_id: Identifier
    revision: Revision
    expected_revision: Revision
    expected_tree_hash: Hash
    reason: Name


class DocumentReference(Contract):
    project_id: Identifier
    revision: Revision
    path: str
    content_hash: Hash


class InstructionView(Contract):
    selected_refs: list[DocumentReference]
    project_id: Identifier
    revision: Revision
    tree_hash: Hash
    policy_revision: Revision
    owner: Literal["ENVIRONMENT", "PROJECT"]
    root_id: Identifier
    status: Literal["AVAILABLE", "DRIFT", "PENDING", "REVOKED"]
    selected_documents: list[Document]


class CandidateView(CandidateReference):
    job_id: Identifier | None = None
    author: Identifier
    category: str
    diff: str
    tree_hash: Hash
    automatic: bool
    required_evals: list[str]
    byte_count: int
    growth_bytes: int
    duplicate_segments: int


class ProjectionCommand(Contract):
    idempotency_key: Identifier
    project_id: Identifier
    expected_revision: Revision
    root_id: Identifier
    expected_root_revision: Revision
    filename: Literal["AGENTS.md", "CLAUDE.md", "GEMINI.md"]
    format_version: Literal[1] = 1
    expected_observed_hash: Hash | None


class ProjectionView(Contract):
    desired_hash: Hash
    observed_hash: Hash | None
    owned: bool
    content: str
    status: Literal["MATCH", "DRIFT", "UNMANAGED", "ABSENT"]


class EvidenceIdentity(Contract):
    evidence_id: Identifier


class ProtectedState(Contract):
    state: Literal["PENDING", "APPROVED", "COMMITTED", "CANCELLED", "EXPIRED", "INVALIDATED"]


class ReleaseVerify(Contract):
    expected_manifest_digest: Hash


class BindingPreview(InstructionBind):
    pass


class BindingImpact(Contract):
    project_id: Identifier
    root_id: Identifier
    previous_owner: Literal["ENVIRONMENT", "PROJECT"] | None
    proposed_owner: Literal["ENVIRONMENT", "PROJECT"]
    existing_tree_hash: Hash
    proposed_tree_hash: Hash
    diff: str
    binding_digest: Hash


class HistoryRead(Contract):
    project_id: Identifier
    revision: Revision


class DocumentRead(HistoryRead):
    path: Annotated[str, StringConstraints(min_length=1, max_length=240)]


class HistoryView(Contract):
    project_id: Identifier
    revision: Revision
    tree_hash: Hash
    author: Identifier
    reason: str
    required_fragments: list[str]


class ProtectedEffectResult(
    RootModel[
        InstructionReceipt
        | RestoreAuthorization
        | GrantReceipt
        | DeploymentPolicyReceipt
        | SessionMutationReceipt
    ]
):
    pass
