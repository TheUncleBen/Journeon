# SPDX-License-Identifier: AGPL-3.0-only
"Canonical Project instruction history and recoverable local publication."

import difflib
import hashlib
from pathlib import Path
from typing import Any, Literal, cast
from uuid import uuid4

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, defer

from journeon.contracts import DomainError, InstructionTemplate
from journeon.database import require_compatible_schema, transaction
from journeon.instruction_admin import InstructionAdministration
from journeon.instruction_config import InstructionConfiguration, open_directory
from journeon.instruction_contracts import (
    BindingImpact,
    CandidateReference,
    CandidateView,
    Document,
    DocumentRead,
    DocumentReference,
    HistoryRead,
    HistoryView,
    InstructionAccept,
    InstructionBind,
    InstructionPolicy,
    InstructionPropose,
    InstructionReceipt,
    InstructionRestore,
    InstructionReview,
    InstructionView,
    ProjectionCommand,
    ProjectionView,
    PublicationRecovery,
    RecoveryRootRevision,
    RecoveryTarget,
)
from journeon.instruction_files import observe_tree as read_tree
from journeon.instruction_files import replace_document, snapshot, tree_hash
from journeon.instruction_operations import record, retry
from journeon.instructions import digest
from journeon.models import (
    Base,
    InstructionAsset,
    InstructionCandidate,
    InstructionEvidence,
    InstructionPublication,
    InstructionRevision,
    InstructionRoot,
    Project,
    ProjectInstructionBinding,
    ProjectInstructionPolicy,
    ProjectInstructionRevision,
)
from journeon.permissions import AuthenticatedContext, require_grant


def stored[Stored: Base](db: Session, model: type[Stored], identity: Any) -> Stored:
    row = db.get(model, identity)
    if row is None:
        raise DomainError("DEPENDENCY_UNAVAILABLE", "Canonical instruction state requires repair")
    return row


DEFAULT_NAVIGATION_POLICY = InstructionPolicy(
    authorized_categories=["NAVIGATION_REPAIR"],
    navigation_repairs=True,
    independent_review=True,
    require_confirmation=False,
    required_evals=["instruction-boundaries-v1"],
)


def initialize_project_policy(db: Session, actor: AuthenticatedContext, project_id: str) -> None:
    db.add(
        ProjectInstructionPolicy(
            project_id=project_id,
            revision=1,
            snapshot=DEFAULT_NAVIGATION_POLICY.model_dump(mode="json"),
            author=actor.principal_id,
        )
    )


def require_project(
    db: Session, actor: AuthenticatedContext, project_id: str, action: str
) -> Project:
    require_compatible_schema(db)
    require_grant(
        db, actor, "project.instruction." + action, resource_kind="project", resource_id=project_id
    )
    project = db.get(Project, project_id)
    if project is None:
        raise DomainError("NOT_FOUND", "Project is unavailable")
    return project


def navigation(documents: dict[str, str], required: list[str]) -> str:
    return (
        "# Instruction navigation\n\n"
        + "".join(f"- [{name}]({name})\n" for name in sorted(documents) if name != "INDEX.md")
        + "\nRequired fragments:\n"
        + "".join(f"- {name}\n" for name in sorted(required))
    )


def validate_tree(documents: dict[str, str], required: list[str]) -> None:
    if (
        "INDEX.md" not in documents
        or len(set(required)) != len(required)
        or any(name not in documents or name == "INDEX.md" for name in required)
    ):
        raise DomainError("VALIDATION_FAILED", "INDEX and exact required fragments are required")
    for name, content in documents.items():
        Document(path=name, content=content)
        if len(content.encode()) > 65536:
            raise DomainError("VALIDATION_FAILED", "Instruction document exceeds its byte bound")
    from journeon.instructions import validate_template

    selected = "\n\n".join(documents[name] for name in ["INDEX.md", *required])
    if len(selected.encode()) > 65536:
        raise DomainError(
            "VALIDATION_FAILED", "Selected instruction fragments exceed the rendering byte bound"
        )
    validate_template(
        InstructionTemplate(
            template_id="project-tree",
            template=selected,
            required_variables=[],
            eval_ids=["instruction-boundaries-v1"],
        )
    )
    # Local markdown links are navigation only and cannot widen the tree boundary.
    import re

    for target in re.findall(r"\]\(([^)]+)\)", documents["INDEX.md"]):
        if target not in documents:
            raise DomainError(
                "VALIDATION_FAILED", "Instruction navigation target is outside the tree"
            )


class ProjectInstructionService:
    def __init__(self, engine: Engine, configuration: InstructionConfiguration):
        self.engine = engine
        self.configuration = configuration

    def root_path(
        self, db: Session, actor: AuthenticatedContext, root_id: str, revision: int, project_id: str
    ) -> Path:
        root = db.get(InstructionRoot, root_id)
        if (
            root is None
            or not root.enabled
            or root.revision != revision
            or (root.project_id is not None and root.project_id != project_id)
        ):
            raise DomainError("PERMISSION_DENIED", "Current admitted root is unavailable")
        config = InstructionAdministration(self.engine, self.configuration).root_configuration(
            root.root_key
        )
        if (
            config.revision != root.config_revision
            or config.role != root.role
            or config.project_id != root.project_id
        ):
            raise DomainError("REVISION_CONFLICT", "Root configuration changed")
        import os

        try:
            descriptor = open_directory(Path(config.path))
            try:
                observed = os.fstat(descriptor)
            finally:
                os.close(descriptor)
        except OSError:
            raise DomainError("PERMISSION_DENIED", "Admitted root is unavailable") from None
        if (observed.st_dev, observed.st_ino) != (root.device, root.inode):
            raise DomainError("PERMISSION_DENIED", "Admitted root identity changed")
        from journeon.instruction_config import git_identity

        try:
            if git_identity(Path(config.path)) != root.git_identity:
                raise ValueError("Git worktree identity changed")
        except (OSError, ValueError):
            raise DomainError(
                "PERMISSION_DENIED", "Admitted Git worktree identity changed"
            ) from None
        return Path(config.path)

    def location(
        self, db: Session, actor: AuthenticatedContext, binding: ProjectInstructionBinding
    ) -> Path:
        root = self.root_path(db, actor, binding.root_id, binding.root_revision, binding.project_id)
        if binding.owner == "PROJECT":
            return root / ".journeon" / "instructions"
        return root / "instructions" / "projects" / binding.project_id

    def binding(
        self, db: Session, actor: AuthenticatedContext, project_id: str, action: str = "read"
    ) -> ProjectInstructionBinding:
        require_project(db, actor, project_id, action)
        if action != "read":
            require_project(db, actor, project_id, "read")
        row = db.get(ProjectInstructionBinding, project_id)
        if row is None:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Project instructions are not bound")
        self.location(db, actor, row)
        return row

    def read(self, actor: AuthenticatedContext, project_id: str) -> InstructionView:
        with transaction(self.engine) as db:
            binding = self.binding(db, actor, project_id)
            if binding.active_operation:
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Instruction publication is unresolved")
            history = db.get(ProjectInstructionRevision, (project_id, binding.revision))
            if history is None:
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Project instructions are not accepted")
            stored = history.snapshot
            path = self.location(db, actor, binding)
            revision, policy, owner, root, expected = (
                binding.revision,
                binding.policy_revision,
                binding.owner,
                binding.root_id,
                binding.tree_hash,
            )
        observed = read_tree(path)
        with transaction(self.engine) as db:
            current = self.binding(db, actor, project_id)
            if current.revision != revision or current.active_operation:
                raise DomainError("REVISION_CONFLICT", "Project instructions changed")
        if tree_hash(observed) != expected:
            raise DomainError("REVISION_CONFLICT", "Canonical instructions have unaccepted changes")
        selected = ["INDEX.md", *stored["required_fragments"]]
        return InstructionView(
            project_id=project_id,
            revision=revision,
            tree_hash=expected,
            policy_revision=policy,
            owner=cast(Literal["ENVIRONMENT", "PROJECT"], owner),
            root_id=root,
            status="AVAILABLE",
            selected_documents=[Document(path=name, content=observed[name]) for name in selected],
            selected_refs=[
                DocumentReference(
                    project_id=project_id,
                    revision=revision,
                    path=name,
                    content_hash=hashlib.sha256(observed[name].encode()).hexdigest(),
                )
                for name in selected
            ],
        )

    def preview_binding(
        self, actor: AuthenticatedContext, command: InstructionBind
    ) -> BindingImpact:
        from journeon.instruction_contracts import BindingImpact

        target = snapshot(command.documents)
        validate_tree(target, command.required_fragments)
        with transaction(self.engine) as db:
            project = require_project(db, actor, command.project_id, "bind")
            require_project(db, actor, command.project_id, "read")
            binding = db.get(ProjectInstructionBinding, project.id)
            if (
                project.revision != command.expected_project_revision
                or (binding.revision if binding else 0) != command.expected_binding_revision
                or (binding and binding.active_operation)
            ):
                raise DomainError("REVISION_CONFLICT", "Binding preview base changed")
            base = self.root_path(
                db, actor, command.root_id, command.expected_root_revision, project.id
            )
            root = stored(db, InstructionRoot, command.root_id)
            if root.role != command.owner:
                raise DomainError("PERMISSION_DENIED", "Root ownership does not match")
            previous_owner = binding.owner if binding else None
            if binding:
                self.location(db, actor, binding)
            path = (
                base / ".journeon" / "instructions"
                if command.owner == "PROJECT"
                else base / "instructions" / "projects" / project.id
            )
        observed = read_tree(path)
        if tree_hash(observed) != command.expected_tree_hash:
            raise DomainError("REVISION_CONFLICT", "Binding preview tree changed")
        with transaction(self.engine) as db:
            require_project(db, actor, command.project_id, "bind")
            require_project(db, actor, command.project_id, "read")
            self.root_path(
                db, actor, command.root_id, command.expected_root_revision, command.project_id
            )
        changes = "".join(
            "".join(
                difflib.unified_diff(
                    observed.get(name, "").splitlines(keepends=True),
                    target.get(name, "").splitlines(keepends=True),
                    fromfile=name,
                    tofile=name,
                )
            )
            for name in sorted(set(observed) | set(target))
        )
        return BindingImpact(
            project_id=command.project_id,
            root_id=command.root_id,
            previous_owner=cast(Literal["ENVIRONMENT", "PROJECT"] | None, previous_owner),
            proposed_owner=command.owner,
            existing_tree_hash=tree_hash(observed),
            proposed_tree_hash=tree_hash(target),
            diff=changes,
            binding_digest=digest(command.model_dump(mode="json")),
        )

    def history(self, actor: AuthenticatedContext, command: HistoryRead) -> HistoryView:
        from journeon.instruction_contracts import HistoryView

        with transaction(self.engine) as db:
            binding = self.binding(db, actor, command.project_id)
            if binding.active_operation:
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Instruction publication is unresolved")
            history = db.get(ProjectInstructionRevision, (command.project_id, command.revision))
            if history is None:
                raise DomainError("NOT_FOUND", "Instruction history is unavailable")
            return HistoryView(
                project_id=command.project_id,
                revision=history.revision,
                tree_hash=history.tree_hash,
                author=history.author,
                reason=history.reason,
                required_fragments=history.snapshot["required_fragments"],
            )

    def document(self, actor: AuthenticatedContext, command: DocumentRead) -> Document:
        Document(path=command.path, content="")
        with transaction(self.engine) as db:
            binding = self.binding(db, actor, command.project_id)
            if binding.active_operation:
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Instruction publication is unresolved")
            history = db.get(ProjectInstructionRevision, (command.project_id, command.revision))
            if history is None or command.path not in history.snapshot["documents"]:
                raise DomainError("NOT_FOUND", "Instruction document is unavailable")
            return Document(path=command.path, content=history.snapshot["documents"][command.path])

    def bind(self, actor: AuthenticatedContext, command: InstructionBind) -> InstructionReceipt:
        target = snapshot(command.documents)
        validate_tree(target, command.required_fragments)
        payload = command.model_dump(mode="json")
        with transaction(self.engine) as db:
            project = require_project(db, actor, command.project_id, "bind")
            previous = retry(
                db, actor, "project.instructions.bind.v1", command.idempotency_key, payload
            )
            if previous:
                return previous
            pending = db.scalar(
                select(InstructionPublication).where(
                    InstructionPublication.project_id == project.id,
                    InstructionPublication.principal_id == actor.principal_id,
                    InstructionPublication.idempotency_key == command.idempotency_key,
                )
            )
            if pending:
                if pending.payload_hash != digest(payload):
                    raise DomainError(
                        "IDEMPOTENCY_CONFLICT", "Binding operation has different input"
                    )
                operation = pending.id
            else:
                operation = None
            binding = db.get(ProjectInstructionBinding, project.id)
            if operation is None and (
                project.revision != command.expected_project_revision
                or (binding.revision if binding else 0) != command.expected_binding_revision
            ):
                raise DomainError("REVISION_CONFLICT", "Project binding changed")
            root = db.get(InstructionRoot, command.root_id)
            base = self.root_path(
                db, actor, command.root_id, command.expected_root_revision, project.id
            )
            if root is None or root.role != command.owner:
                raise DomainError("PERMISSION_DENIED", "Root ownership does not match")
            if binding:
                self.location(db, actor, binding)
                if (
                    binding.root_id == command.root_id
                    and binding.revision > 0
                    and operation is None
                ):
                    raise DomainError(
                        "REVISION_CONFLICT", "Project already has this canonical owner"
                    )
            path = (
                base / ".journeon" / "instructions"
                if command.owner == "PROJECT"
                else base / "instructions" / "projects" / project.id
            )
        if operation is not None:
            return self.publish(actor, operation)
        observed = read_tree(path)
        if tree_hash(observed) != command.expected_tree_hash:
            raise DomainError("REVISION_CONFLICT", "Existing instruction tree changed")
        with transaction(self.engine) as db:
            project = require_project(db, actor, command.project_id, "bind")
            binding = db.get(ProjectInstructionBinding, project.id)
            if (
                project.revision != command.expected_project_revision
                or (binding.revision if binding else 0) != command.expected_binding_revision
            ):
                raise DomainError("REVISION_CONFLICT", "Project binding changed")
            self.root_path(db, actor, command.root_id, command.expected_root_revision, project.id)
            if binding is None:
                binding = ProjectInstructionBinding(
                    project_id=project.id,
                    root_id=command.root_id,
                    root_revision=command.expected_root_revision,
                    owner=command.owner,
                    revision=0,
                    tree_hash=tree_hash(observed),
                    policy_revision=1,
                    generation=1,
                    active_operation=None,
                )
                db.add(binding)
                if db.get(ProjectInstructionPolicy, (project.id, 1)) is None:
                    binding.policy_revision = 0
            elif binding.revision > 0:
                history = db.get(ProjectInstructionRevision, (project.id, binding.revision))
                if (
                    history is None
                    or history.snapshot["documents"] != target
                    or history.snapshot["required_fragments"] != command.required_fragments
                ):
                    raise DomainError(
                        "REVISION_CONFLICT",
                        "Ownership transfer must preserve accepted instructions",
                    )
            operation = self.admit(
                db,
                actor,
                binding,
                "project.instructions.bind.v1",
                command.idempotency_key,
                payload,
                observed,
                target,
                command.required_fragments,
                command.reason,
            )
            db.flush()
            journal = self.journal(db, operation)
            journal.snapshot = {
                **journal.snapshot,
                "destination": {
                    "root_id": command.root_id,
                    "root_revision": command.expected_root_revision,
                    "owner": command.owner,
                },
            }
        return self.publish(actor, operation)

    def propose(self, actor: AuthenticatedContext, command: InstructionPropose) -> CandidateView:
        target = snapshot(command.documents)
        validate_tree(target, command.required_fragments)
        payload = command.model_dump(mode="json")
        with transaction(self.engine) as db:
            binding = self.binding(db, actor, command.project_id, "propose")
            previous = db.scalar(
                select(InstructionCandidate)
                .options(defer(InstructionCandidate.snapshot))
                .where(
                    InstructionCandidate.project_id == command.project_id,
                    InstructionCandidate.principal_id == actor.principal_id,
                    InstructionCandidate.idempotency_key == command.idempotency_key,
                )
            )
            if previous:
                require_project(db, actor, command.project_id, "read")
                if previous.payload_hash != digest(payload):
                    raise DomainError(
                        "IDEMPOTENCY_CONFLICT", "Candidate identity has different input"
                    )
                return CandidateView.model_validate(previous.snapshot["view"])
            if binding.active_operation or (binding.revision, binding.tree_hash) != (
                command.expected_revision,
                command.expected_tree_hash,
            ):
                raise DomainError("REVISION_CONFLICT", "Instruction base changed")
            history = db.get(ProjectInstructionRevision, (command.project_id, binding.revision))
            if history is None:
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE", "Accepted instruction history is unavailable"
                )
            base = history.snapshot["documents"]
            required = history.snapshot["required_fragments"]
            automatic = (
                command.category == "NAVIGATION_REPAIR"
                and required == command.required_fragments
                and {k: v for k, v in target.items() if k != "INDEX.md"}
                == {k: v for k, v in base.items() if k != "INDEX.md"}
                and target["INDEX.md"] == navigation(base, required)
                and sorted(line.strip() for line in base["INDEX.md"].splitlines() if line.strip())
                == sorted(
                    line.strip() for line in navigation(base, required).splitlines() if line.strip()
                )
            )
            policy_row = db.get(
                ProjectInstructionPolicy, (command.project_id, binding.policy_revision)
            )
            policy = InstructionPolicy.model_validate(policy_row.snapshot) if policy_row else None
            automatic = (
                automatic
                and policy is not None
                and policy.navigation_repairs
                and command.category in policy.authorized_categories
            )
            changes = "".join(
                "".join(
                    difflib.unified_diff(
                        base.get(name, "").splitlines(keepends=True),
                        target.get(name, "").splitlines(keepends=True),
                        fromfile=name,
                        tofile=name,
                    )
                )
                for name in sorted(set(base) | set(target))
            )
            candidate_id = str(uuid4())
            content_hash = digest(payload)
            lines = [
                line for value in target.values() for line in value.splitlines() if line.strip()
            ]
            view = CandidateView(
                project_id=command.project_id,
                candidate_id=candidate_id,
                candidate_hash=content_hash,
                expected_binding_revision=binding.revision,
                expected_policy_revision=binding.policy_revision,
                author=actor.principal_id,
                category=command.category,
                diff=changes,
                tree_hash=tree_hash(target),
                automatic=automatic,
                required_evals=list(policy.required_evals) if policy else [],
                byte_count=sum(len(value.encode()) for value in target.values()),
                growth_bytes=sum(len(value.encode()) for value in target.values())
                - sum(len(value.encode()) for value in base.values()),
                duplicate_segments=len(lines) - len(set(lines)),
            )
            db.add(
                InstructionCandidate(
                    id=candidate_id,
                    project_id=command.project_id,
                    principal_id=actor.principal_id,
                    idempotency_key=command.idempotency_key,
                    payload_hash=content_hash,
                    snapshot={
                        "view": view.model_dump(mode="json"),
                        "documents": target,
                        "required_fragments": command.required_fragments,
                        "source_refs": command.source_refs,
                        "reason": command.reason,
                    },
                )
            )
        if automatic:
            evidence = self.evaluate(actor, view)
            self.accept(
                actor,
                InstructionAccept(
                    **view.model_dump(include=set(CandidateReference.model_fields)),
                    idempotency_key="automatic:" + candidate_id,
                    review_ids=[],
                    eval_ids=[evidence],
                ),
            )
        return view

    def candidate(
        self, db: Session, actor: AuthenticatedContext, command: CandidateReference, action: str
    ) -> tuple[ProjectInstructionBinding, InstructionCandidate, CandidateView]:
        binding = self.binding(db, actor, command.project_id, action)
        if (binding.revision, binding.policy_revision) != (
            command.expected_binding_revision,
            command.expected_policy_revision,
        ) or binding.active_operation:
            raise DomainError("REVISION_CONFLICT", "Candidate base or policy changed")
        row = db.get(
            InstructionCandidate,
            command.candidate_id,
            options=[defer(InstructionCandidate.snapshot)],
        )
        if row is None or row.project_id != command.project_id:
            raise DomainError("NOT_FOUND", "Instruction candidate is unavailable")
        if row.payload_hash != command.candidate_hash:
            raise DomainError("REVISION_CONFLICT", "Candidate changed")
        view = CandidateView.model_validate(row.snapshot["view"])
        if (view.expected_binding_revision, view.expected_policy_revision) != (
            binding.revision,
            binding.policy_revision,
        ):
            raise DomainError("REVISION_CONFLICT", "Candidate evidence is stale")
        return binding, row, view

    def preview(self, actor: AuthenticatedContext, command: CandidateReference) -> CandidateView:
        with transaction(self.engine) as db:
            _, _, view = self.candidate(db, actor, command, "read")
            return view

    def evaluate(self, actor: AuthenticatedContext, command: CandidateReference) -> str:
        with transaction(self.engine) as db:
            _, row, view = self.candidate(db, actor, command, "evaluate")
            validate_tree(row.snapshot["documents"], row.snapshot["required_fragments"])
            from journeon.instruction_evals import execute

            if tree_hash(row.snapshot["documents"]) != view.tree_hash:
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE", "Candidate manifest differs from retained documents"
                )
            selected = ["INDEX.md", *row.snapshot["required_fragments"]]
            executed = execute(
                InstructionTemplate(
                    template_id="project-candidate",
                    template="\n\n".join(row.snapshot["documents"][name] for name in selected),
                    required_variables=[],
                    eval_ids=["instruction-boundaries-v1"],
                )
            )
            identity = str(uuid4())
            db.add(
                InstructionEvidence(
                    id=identity,
                    candidate_id=row.id,
                    project_id=row.project_id,
                    principal_id=actor.principal_id,
                    session_id=actor.authentication_ref,
                    kind="EVAL",
                    snapshot={
                        "candidate_hash": view.candidate_hash,
                        "policy_revision": view.expected_policy_revision,
                        **executed,
                    },
                )
            )
            return identity

    def review(self, actor: AuthenticatedContext, command: InstructionReview) -> str:
        with transaction(self.engine) as db:
            _, row, view = self.candidate(db, actor, command, "review")
            if row.principal_id == actor.principal_id:
                raise DomainError(
                    "PERMISSION_DENIED",
                    "Independent review cannot be authored by the candidate author",
                )
            payload = command.model_dump(mode="json")
            for previous in db.scalars(
                select(InstructionEvidence).where(
                    InstructionEvidence.project_id == command.project_id,
                    InstructionEvidence.principal_id == actor.principal_id,
                    InstructionEvidence.kind == "REVIEW",
                )
            ):
                if previous.snapshot.get("idempotency_key") == command.idempotency_key:
                    if previous.snapshot != payload:
                        raise DomainError(
                            "IDEMPOTENCY_CONFLICT", "Review identity has different input"
                        )
                    return previous.id
            identity = str(uuid4())
            db.add(
                InstructionEvidence(
                    id=identity,
                    candidate_id=row.id,
                    project_id=row.project_id,
                    principal_id=actor.principal_id,
                    session_id=actor.authentication_ref,
                    kind="REVIEW",
                    snapshot=command.model_dump(mode="json"),
                )
            )
            return identity

    def accept(self, actor: AuthenticatedContext, command: InstructionAccept) -> InstructionReceipt:
        payload = command.model_dump(mode="json")
        with transaction(self.engine) as db:
            require_project(db, actor, command.project_id, "accept")
            previous = retry(
                db, actor, "project.instructions.accept.v1", command.idempotency_key, payload
            )
            if previous:
                return previous
            pending = db.scalar(
                select(InstructionPublication).where(
                    InstructionPublication.project_id == command.project_id,
                    InstructionPublication.principal_id == actor.principal_id,
                    InstructionPublication.idempotency_key == command.idempotency_key,
                )
            )
            if pending:
                if pending.payload_hash != digest(payload):
                    raise DomainError(
                        "IDEMPOTENCY_CONFLICT", "Publication identity has different input"
                    )
                operation = pending.id
            else:
                binding, candidate, view = self.candidate(db, actor, command, "accept")
                policy = InstructionPolicy.model_validate(
                    stored(
                        db, ProjectInstructionPolicy, (binding.project_id, binding.policy_revision)
                    ).snapshot
                )
                if view.category not in policy.authorized_categories:
                    raise DomainError(
                        "DEPENDENCY_UNAVAILABLE",
                        "Instruction category requires explicit policy configuration",
                    )
                for prior in db.scalars(
                    select(InstructionEvidence).where(
                        InstructionEvidence.candidate_id == candidate.id,
                        InstructionEvidence.project_id == command.project_id,
                        InstructionEvidence.kind == "REVIEW",
                    )
                ):
                    if prior.snapshot.get("findings") or prior.snapshot.get("verdict") != "PASS":
                        raise DomainError(
                            "PERMISSION_DENIED",
                            "Open instruction review findings require a corrected candidate",
                        )
                passed = set()
                reviewed = False
                for identity in [*command.review_ids, *command.eval_ids]:
                    evidence = db.get(
                        InstructionEvidence, identity, options=[defer(InstructionEvidence.snapshot)]
                    )
                    if (
                        evidence is None
                        or evidence.project_id != command.project_id
                        or evidence.candidate_id != candidate.id
                    ):
                        raise DomainError(
                            "PERMISSION_DENIED", "Exact candidate evidence is required"
                        )
                    data = evidence.snapshot
                    if (
                        data["candidate_hash"] != view.candidate_hash
                        or data.get("policy_revision", data.get("expected_policy_revision"))
                        != binding.policy_revision
                    ):
                        raise DomainError("REVISION_CONFLICT", "Instruction evidence is stale")
                    if evidence.kind == "EVAL" and data["result"] == "PASS":
                        passed.add(data["suite"])
                    if (
                        evidence.kind == "REVIEW"
                        and evidence.principal_id != candidate.principal_id
                        and data["verdict"] == "PASS"
                        and not data["findings"]
                    ):
                        reviewed = True
                if not set(policy.required_evals) <= passed:
                    raise DomainError(
                        "PERMISSION_DENIED", "Passing associated instruction evals are required"
                    )
                if not view.automatic and policy.independent_review and not reviewed:
                    raise DomainError(
                        "PERMISSION_DENIED", "Independent instruction review is required"
                    )
                if not view.automatic and policy.require_confirmation:
                    from journeon.instruction_protected import verify_instruction_consent

                    verify_instruction_consent(db, actor, command, self.configuration)
                old = stored(db, ProjectInstructionRevision, (binding.project_id, binding.revision))
                operation = self.admit(
                    db,
                    actor,
                    binding,
                    "project.instructions.accept.v1",
                    command.idempotency_key,
                    payload,
                    old.snapshot["documents"],
                    candidate.snapshot["documents"],
                    candidate.snapshot["required_fragments"],
                    candidate.snapshot["reason"],
                )
        return self.publish(actor, operation)

    def admit(
        self,
        db: Session,
        actor: AuthenticatedContext,
        binding: ProjectInstructionBinding,
        command: str,
        key: str,
        payload: dict[str, Any],
        base: dict[str, str],
        target: dict[str, str],
        required: list[str],
        reason: str,
    ) -> str:
        if binding.active_operation:
            raise DomainError("REVISION_CONFLICT", "An instruction publication is already admitted")
        operation = str(uuid4())
        if payload.get("consent_request_id"):
            from journeon.instruction_protected import verify_instruction_consent

            consent = verify_instruction_consent(
                db, actor, InstructionAccept.model_validate(payload), self.configuration
            )
            operation = consent.operation_id
        binding.generation += 1
        binding.active_operation = operation
        db.add(
            InstructionPublication(
                id=operation,
                target_root_id=payload.get("root_id", binding.root_id),
                projection=command == "project.instructions.projection.v1",
                project_id=binding.project_id,
                principal_id=actor.principal_id,
                authentication_ref=actor.authentication_ref,
                principal_epoch=actor.principal_epoch,
                generation=binding.generation,
                idempotency_key=key,
                payload_hash=digest(payload),
                status="PENDING",
                snapshot={
                    "command": command,
                    "root_identities": {
                        identity: self.root_identity(db, actor, identity, binding.project_id)
                        for identity in {binding.root_id, payload.get("root_id", binding.root_id)}
                    },
                    "payload": payload,
                    "base": base,
                    "target": target,
                    "required_fragments": required,
                    "reason": reason,
                    "base_revision": binding.revision,
                    "policy_revision": binding.policy_revision,
                },
            )
        )
        return operation

    def root_identity(
        self, db: Session, actor: AuthenticatedContext, identity: str, project_id: str
    ) -> str:
        root = stored(db, InstructionRoot, identity)
        path = self.root_path(db, actor, identity, root.revision, project_id)
        return digest(
            [
                root.id,
                root.root_key,
                root.project_id,
                root.role,
                root.device,
                root.inode,
                root.git_identity,
                root.config_revision,
                str(path),
            ]
        )

    def recovery_roots(
        self, db: Session, actor: AuthenticatedContext, row: InstructionPublication
    ) -> dict[str, int]:
        require_project(db, actor, row.project_id, "accept")
        require_project(db, actor, row.project_id, "read")
        if row.projection:
            require_project(db, actor, row.project_id, "projection")
        binding = stored(db, ProjectInstructionBinding, row.project_id)
        identities = {
            identity: self.root_identity(db, actor, identity, row.project_id)
            for identity in {binding.root_id, row.target_root_id}
        }
        if row.snapshot.get("root_identities") != identities:
            raise DomainError("REVISION_CONFLICT", "Recovery root identity differs from admission")
        return {identity: stored(db, InstructionRoot, identity).revision for identity in identities}

    def publication_data(
        self,
        db: Session,
        actor: AuthenticatedContext,
        row: InstructionPublication,
        recovery: str | None,
    ) -> dict[str, Any]:
        data = dict(row.snapshot)
        if recovery and data.get("destination"):
            revisions = self.recovery_roots(db, actor, row)
            data["destination"] = {
                **data["destination"],
                "root_revision": revisions[row.target_root_id],
            }
        return data

    def journal(self, db: Session, operation: str) -> InstructionPublication:
        row = db.get(
            InstructionPublication, operation, options=[defer(InstructionPublication.snapshot)]
        )
        if row is None:
            raise DomainError("NOT_FOUND", "Publication is unavailable")
        return row

    def recovery_target(self, actor: AuthenticatedContext, project_id: str) -> RecoveryTarget:
        from journeon.permissions import current_owner

        with transaction(self.engine) as db:
            current_owner(db, actor)
            require_project(db, actor, project_id, "accept")
            require_project(db, actor, project_id, "read")
            binding = stored(db, ProjectInstructionBinding, project_id)
            if binding.active_operation is None:
                raise DomainError("NOT_FOUND", "No pending instruction publication exists")
            row = self.journal(db, binding.active_operation)
            if row.project_id != project_id:
                raise DomainError("DEPENDENCY_UNAVAILABLE", "Publication scope requires repair")
            revisions = self.recovery_roots(db, actor, row)
            data = row.snapshot
            if data["command"] == "project.instructions.projection.v1":
                require_project(db, actor, project_id, "projection")
            return RecoveryTarget(
                root_revisions=[
                    RecoveryRootRevision(root_id=identity, revision=revision)
                    for identity, revision in sorted(revisions.items())
                ],
                project_id=project_id,
                operation_id=row.id,
                expected_generation=row.generation,
                expected_binding_revision=binding.revision,
                expected_policy_revision=binding.policy_revision,
                publication_hash=row.payload_hash,
                target_hash=tree_hash(data["target"]),
            )

    def recover(
        self, actor: AuthenticatedContext, command: PublicationRecovery, request_id: str
    ) -> InstructionReceipt:
        with transaction(self.engine) as db:
            row = db.get(
                InstructionPublication,
                command.operation_id,
                options=[defer(InstructionPublication.snapshot)],
            )
            if row is None:
                raise DomainError("NOT_FOUND", "Publication is unavailable")
            self.publication_authority(db, actor, row, request_id)
            binding = stored(db, ProjectInstructionBinding, row.project_id)
            binding.root_revision = next(
                root.revision for root in command.root_revisions if root.root_id == binding.root_id
            )
            projection = row.snapshot["command"] == "project.instructions.projection.v1"
        return self.publish(actor, command.operation_id, projection=projection, recovery=request_id)

    def publication_authority(
        self,
        db: Session,
        actor: AuthenticatedContext,
        row: InstructionPublication,
        recovery: str | None,
    ) -> None:
        require_project(db, actor, row.project_id, "read")
        if recovery is None:
            if row.principal_id != actor.principal_id:
                raise DomainError("NOT_FOUND", "Publication is unavailable")
            return
        from journeon.instruction_protected import verify_recovery_consent

        _, effect = verify_recovery_consent(db, actor, recovery, self.configuration)
        revisions = self.recovery_roots(db, actor, row)
        binding = stored(db, ProjectInstructionBinding, row.project_id)
        if (
            effect.root_revisions
            != [
                RecoveryRootRevision(root_id=identity, revision=revision)
                for identity, revision in sorted(revisions.items())
            ]
            or effect.operation_id != row.id
            or effect.project_id != row.project_id
            or effect.publication_hash != row.payload_hash
            or effect.expected_generation != row.generation
            or binding.generation != row.generation
            or binding.active_operation != row.id
            or effect.expected_binding_revision != binding.revision
            or effect.expected_policy_revision != binding.policy_revision
        ):
            raise DomainError("REVISION_CONFLICT", "Recovery publication operands changed")
        data = row.snapshot
        if (
            effect.target_hash != tree_hash(data["target"])
            or data["base_revision"] != binding.revision
            or (
                effect.disposition == "FINISH_TARGET"
                and data["policy_revision"] != binding.policy_revision
            )
        ):
            raise DomainError("REVISION_CONFLICT", "Recovery target or policy changed")
        if data["command"] == "project.instructions.projection.v1":
            require_project(db, actor, row.project_id, "projection")

    def publication_consent(
        self,
        db: Session,
        actor: AuthenticatedContext,
        row: InstructionPublication,
        recovery: str | None,
        *,
        commit: bool = False,
    ) -> None:
        self.publication_authority(db, actor, row, recovery)
        consent = None
        if recovery:
            from journeon.instruction_protected import verify_recovery_consent

            consent, _ = verify_recovery_consent(db, actor, recovery, self.configuration)
        elif row.snapshot["payload"].get("consent_request_id"):
            from journeon.instruction_protected import verify_instruction_consent

            consent = verify_instruction_consent(
                db,
                actor,
                InstructionAccept.model_validate(row.snapshot["payload"]),
                self.configuration,
            )
        if commit and consent:
            consent.state = "COMMITTED"

    def publish(
        self,
        actor: AuthenticatedContext,
        operation: str,
        *,
        projection: bool = False,
        recovery: str | None = None,
    ) -> InstructionReceipt:
        import subprocess

        try:
            return self._leased_publish(actor, operation, projection=projection, recovery=recovery)
        except (OSError, ValueError, subprocess.SubprocessError, DomainError) as error:
            with transaction(self.engine) as db:
                journal = db.get(
                    InstructionPublication,
                    operation,
                    options=[defer(InstructionPublication.snapshot)],
                )
                if (
                    journal is not None
                    and journal.principal_id == actor.principal_id
                    and journal.status not in {"CANONICAL_COMMITTED", "ABANDONED"}
                ):
                    journal.status = "RECOVERY_NEEDED"
            if isinstance(error, DomainError):
                raise
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Instruction publication requires reconciliation"
            ) from error

    def _leased_publish(
        self,
        actor: AuthenticatedContext,
        operation: str,
        *,
        projection: bool = False,
        recovery: str | None = None,
    ) -> InstructionReceipt:
        import fcntl
        import os

        from journeon.instruction_files import ensure_directory

        with transaction(self.engine) as db:
            journal = db.get(
                InstructionPublication, operation, options=[defer(InstructionPublication.snapshot)]
            )
            if journal is None:
                raise DomainError("NOT_FOUND", "Publication is unavailable")
            self.publication_authority(db, actor, journal, recovery)
            require_project(db, actor, journal.project_id, "projection" if projection else "accept")
            if (
                not recovery
                and journal.status not in {"CANONICAL_COMMITTED", "ABANDONED"}
                and (
                    journal.principal_epoch != actor.principal_epoch
                    or journal.authentication_ref != actor.authentication_ref
                )
            ):
                raise DomainError(
                    "PERMISSION_DENIED", "Original publication authority is no longer current"
                )
            project_id = journal.project_id
        directory = Path(str(self.engine.url.database)).parent / ".instruction-publications"
        parent = ensure_directory(directory)
        descriptor = os.open(
            hashlib.sha256(project_id.encode()).hexdigest() + ".lock",
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        os.close(parent)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise DomainError(
                    "REVISION_CONFLICT", "Another instruction publisher owns the lease"
                ) from None
            if recovery:
                with transaction(self.engine) as db:
                    from journeon.instruction_protected import verify_recovery_consent

                    _, effect = verify_recovery_consent(db, actor, recovery, self.configuration)
                if effect.disposition == "RESTORE_BASE":
                    return self._abandon_locked(actor, operation, recovery)
            return (
                self._publish_projection_locked(actor, operation, recovery=recovery)
                if projection
                else self._publish_locked(actor, operation, recovery=recovery)
            )
        finally:
            os.close(descriptor)

    def _abandon_locked(
        self, actor: AuthenticatedContext, operation: str, recovery: str
    ) -> InstructionReceipt:
        from journeon.release_evidence import regular_bytes

        with transaction(self.engine) as db:
            row = db.get(
                InstructionPublication, operation, options=[defer(InstructionPublication.snapshot)]
            )
            if row is None:
                raise DomainError("NOT_FOUND", "Publication is unavailable")
            self.publication_authority(db, actor, row, recovery)
            binding = self.binding(db, actor, row.project_id, "accept")
            data = self.publication_data(db, actor, row, recovery)
            projection = data["command"] == "project.instructions.projection.v1"
            destination = data.get("destination")
            if projection:
                command = ProjectionCommand.model_validate(data["payload"])
                root_id, root_revision = command.root_id, command.expected_root_revision
                if recovery:
                    root_revision = self.recovery_roots(db, actor, row)[root_id]
            elif destination:
                root_id, root_revision = destination["root_id"], destination["root_revision"]
            else:
                root_id, root_revision = binding.root_id, binding.root_revision
            root = self.root_path(db, actor, root_id, root_revision, row.project_id)
            admitted = stored(db, InstructionRoot, root_id)
            anchor = (root, admitted.device, admitted.inode)
            path = (
                root
                if projection
                else (
                    root / ".journeon" / "instructions"
                    if (destination["owner"] if destination else binding.owner) == "PROJECT"
                    else root / "instructions" / "projects" / row.project_id
                )
            )

        def observed_tree() -> dict[str, str]:
            if not projection:
                return read_tree(path)
            try:
                return {
                    command.filename: regular_bytes(str(path / command.filename), 65536).decode()
                }
            except FileNotFoundError:
                return {}

        observed = observed_tree()
        for name in set(observed) | set(data["base"]) | set(data["target"]):
            if observed.get(name) not in (data["base"].get(name), data["target"].get(name)):
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE", "Unknown instruction edits require reconciliation"
                )
        for name in sorted(set(data["base"]) | set(data["target"])):
            with transaction(self.engine) as db:
                self.publication_consent(db, actor, self.journal(db, operation), recovery)
                self.root_path(db, actor, root_id, root_revision, row.project_id)
            if observed.get(name) != data["base"].get(name):
                replace_document(
                    path, name, observed.get(name), data["base"].get(name), anchor=anchor
                )
        if observed_tree() != data["base"]:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Instruction base did not converge")
        with transaction(self.engine) as db:
            journal = self.journal(db, operation)
            self.publication_consent(db, actor, journal, recovery, commit=True)
            self.root_path(db, actor, root_id, root_revision, row.project_id)
            binding = self.binding(db, actor, row.project_id, "accept")
            binding.active_operation = None
            journal.status = "ABANDONED"
            return record(
                db,
                actor,
                data["command"],
                row.idempotency_key,
                data["payload"],
                "project_instructions",
                row.project_id,
                binding.revision,
                binding.tree_hash,
                "PROJECT",
                operation_id=operation,
                origin=journal,
                abandoned=True,
            )

    def _publish_locked(
        self, actor: AuthenticatedContext, operation: str, *, recovery: str | None = None
    ) -> InstructionReceipt:
        with transaction(self.engine) as db:
            row = db.get(
                InstructionPublication, operation, options=[defer(InstructionPublication.snapshot)]
            )
            if row is None:
                raise DomainError("NOT_FOUND", "Publication is unavailable")
            self.publication_authority(db, actor, row, recovery)
            require_project(db, actor, row.project_id, "accept")
            binding = self.binding(db, actor, row.project_id)
            data = self.publication_data(db, actor, row, recovery)
            if row.status != "CANONICAL_COMMITTED":
                self.publication_consent(db, actor, row, recovery)
            generation = row.generation
            if row.status == "CANONICAL_COMMITTED":
                result = retry(db, actor, data["command"], row.idempotency_key, data["payload"])
                assert result is not None
                return result
            if (
                binding.active_operation != operation
                or binding.generation != generation
                or binding.policy_revision != data["policy_revision"]
            ):
                raise DomainError("REVISION_CONFLICT", "Publication generation or policy changed")
            path = self.location(db, actor, binding)
            destination = data.get("destination")
            if destination:
                root = self.root_path(
                    db, actor, destination["root_id"], destination["root_revision"], row.project_id
                )
                path = (
                    root / ".journeon" / "instructions"
                    if destination["owner"] == "PROJECT"
                    else root / "instructions" / "projects" / row.project_id
                )
            admitted = stored(
                db, InstructionRoot, destination["root_id"] if destination else binding.root_id
            )
            anchor = (
                self.root_path(db, actor, admitted.id, admitted.revision, row.project_id),
                admitted.device,
                admitted.inode,
            )
        try:
            stage = (
                Path(str(self.engine.url.database)).parent / ".instruction-publications" / operation
            )
            from journeon.instruction_files import git_checkpoint

            checkpoint = git_checkpoint(anchor[0], data["base"], stage.parent)
            with transaction(self.engine) as db:
                current = self.binding(db, actor, row.project_id, "accept")
                if current.generation != generation or current.active_operation != operation:
                    raise DomainError(
                        "REVISION_CONFLICT", "Checkpoint publication generation changed"
                    )
                journal = self.journal(db, operation)
                if "checkpoint" not in journal.snapshot:
                    journal.snapshot = {**journal.snapshot, "checkpoint": checkpoint}
            staged = read_tree(stage)
            for name, value in data["target"].items():
                if name in staged and staged[name] != value:
                    raise ValueError("Publication staging differs from admitted content")
                if name not in staged:
                    replace_document(stage, name, None, value)
            if read_tree(stage) != data["target"]:
                raise ValueError("Publication staging does not match admitted content")
            observed = read_tree(path)
            for name in set(observed) | set(data["base"]) | set(data["target"]):
                if observed.get(name) not in (data["base"].get(name), data["target"].get(name)):
                    raise ValueError("Unrecognized external instruction edit")
            for name in sorted(set(data["base"]) | set(data["target"])):
                with transaction(self.engine) as db:
                    current = self.binding(db, actor, row.project_id, "accept")
                    if current.generation != generation or current.active_operation != operation:
                        raise DomainError("REVISION_CONFLICT", "Publication lease changed")
                    self.location(db, actor, current)
                    self.publication_consent(db, actor, self.journal(db, operation), recovery)
                    if destination:
                        self.root_path(
                            db,
                            actor,
                            destination["root_id"],
                            destination["root_revision"],
                            row.project_id,
                        )
                value = data["target"].get(name)
                if observed.get(name) != value:
                    replace_document(path, name, observed.get(name), value, anchor=anchor)
            if read_tree(path) != data["target"]:
                raise ValueError("Instruction tree did not converge")
            with transaction(self.engine) as db:
                current = self.binding(db, actor, row.project_id, "accept")
                if (
                    current.generation != generation
                    or current.active_operation != operation
                    or current.policy_revision != data["policy_revision"]
                ):
                    raise DomainError("REVISION_CONFLICT", "Publication authority changed")
                self.publication_consent(
                    db, actor, self.journal(db, operation), recovery, commit=True
                )
                if destination:
                    self.root_path(
                        db,
                        actor,
                        destination["root_id"],
                        destination["root_revision"],
                        row.project_id,
                    )
                    current.root_id = destination["root_id"]
                    current.root_revision = destination["root_revision"]
                    current.owner = destination["owner"]
                    project = stored(db, Project, row.project_id)
                    if project.instruction_owner != current.owner:
                        project.instruction_owner = current.owner
                        project.revision += 1
                current.revision += 1
                current.tree_hash = tree_hash(data["target"])
                current.active_operation = None
                db.add(
                    ProjectInstructionRevision(
                        project_id=current.project_id,
                        revision=current.revision,
                        snapshot={
                            "documents": data["target"],
                            "document_refs": {
                                name: {
                                    "project_id": current.project_id,
                                    "revision": current.revision,
                                    "path": name,
                                    "content_hash": hashlib.sha256(content.encode()).hexdigest(),
                                }
                                for name, content in data["target"].items()
                            },
                            "required_fragments": data["required_fragments"],
                        },
                        tree_hash=current.tree_hash,
                        author=actor.principal_id,
                        reason=data["reason"],
                    )
                )
                self.write_entry(db, actor, current, data)
                self.journal(db, operation).status = "CANONICAL_COMMITTED"
                return record(
                    db,
                    actor,
                    data["command"],
                    row.idempotency_key,
                    data["payload"],
                    "project_instructions",
                    row.project_id,
                    current.revision,
                    current.tree_hash,
                    "PROJECT",
                    operation_id=operation,
                    origin=self.journal(db, operation),
                )
        except (OSError, ValueError):
            with transaction(self.engine) as db:
                failed_publication = self.journal(db, operation)
                failed_publication.status = "RECOVERY_NEEDED"
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Instruction publication requires reconciliation"
            ) from None

    def write_entry(
        self,
        db: Session,
        actor: AuthenticatedContext,
        binding: ProjectInstructionBinding,
        data: dict[str, Any],
    ) -> None:
        from datetime import UTC, datetime

        identity = "project-instructions:" + binding.project_id
        asset = db.get(InstructionAsset, identity)
        previous = None
        if asset:
            previous = stored(db, InstructionRevision, (identity, asset.revision)).content_hash
            asset.revision = binding.revision
        else:
            asset = InstructionAsset(
                id=identity,
                owner_kind="project",
                owner_id=binding.project_id,
                purpose="PROJECT",
                trust="CONFIGURATION",
                revision=binding.revision,
            )
            db.add(asset)
            db.flush()
        binding.entry_asset_id = identity
        content = "\n\n".join(
            data["target"][name] for name in ["INDEX.md", *data["required_fragments"]]
        )
        template = InstructionTemplate(
            template_id=identity,
            template=content,
            required_variables=[],
            eval_ids=["instruction-boundaries-v1"],
        )
        db.add(
            InstructionRevision(
                asset_id=identity,
                revision=binding.revision,
                template=template.model_dump(mode="json"),
                content_hash=digest(template.model_dump(mode="json")),
                previous_hash=previous,
                author=actor.principal_id,
                reason=data["reason"],
                created_at=datetime.now(UTC).isoformat(),
            )
        )

    def restore(self, actor: AuthenticatedContext, command: InstructionRestore) -> CandidateView:
        with transaction(self.engine) as db:
            self.binding(db, actor, command.project_id, "read")
            history = db.get(ProjectInstructionRevision, (command.project_id, command.revision))
            if history is None:
                raise DomainError("NOT_FOUND", "Instruction revision is unavailable")
            documents = history.snapshot["documents"]
            required = history.snapshot["required_fragments"]
        return self.propose(
            actor,
            InstructionPropose(
                idempotency_key=command.idempotency_key,
                project_id=command.project_id,
                expected_revision=command.expected_revision,
                expected_tree_hash=command.expected_tree_hash,
                documents=[Document(path=name, content=value) for name, value in documents.items()],
                required_fragments=required,
                reason=command.reason,
                source_refs=["revision:" + str(command.revision)],
                category="ORDINARY",
            ),
        )

    def projection(
        self, actor: AuthenticatedContext, command: ProjectionCommand, action: str
    ) -> ProjectionView:
        from journeon.instruction_contracts import ProjectionView
        from journeon.models import InstructionProjection

        payload = command.model_dump(mode="json")
        if action == "materialize":
            with transaction(self.engine) as db:
                self.binding(db, actor, command.project_id, "projection")
                pending = db.scalar(
                    select(InstructionPublication)
                    .options(defer(InstructionPublication.snapshot))
                    .where(
                        InstructionPublication.project_id == command.project_id,
                        InstructionPublication.principal_id == actor.principal_id,
                        InstructionPublication.idempotency_key == command.idempotency_key,
                    )
                )
                if pending:
                    if pending.payload_hash != digest(payload):
                        raise DomainError(
                            "IDEMPOTENCY_CONFLICT", "Projection identity has different input"
                        )
                    operation = pending.id
                else:
                    operation = None
            if operation:
                self.publish(actor, operation, projection=True)
                return self.projection(actor, command, "check")
        view = self.read(actor, command.project_id)
        if view.revision != command.expected_revision:
            raise DomainError("REVISION_CONFLICT", "Projection source changed")
        content = (
            f"<!-- Generated instruction projection v1; revision {view.revision}; "
            f"tree {view.tree_hash} -->\n"
            + "\n\n".join(item.content for item in view.selected_documents)
        )
        desired = hashlib.sha256(content.encode()).hexdigest()
        with transaction(self.engine) as db:
            binding = self.binding(db, actor, command.project_id, "projection")
            root = self.root_path(
                db, actor, command.root_id, command.expected_root_revision, command.project_id
            )
            record_key = (command.project_id, command.root_id, command.filename)
            owned = db.get(InstructionProjection, record_key)
            old_hash = owned.content_hash if owned else None
        destination = root / command.filename
        observed = None
        if destination.exists() or destination.is_symlink():
            from journeon.release_evidence import regular_bytes

            try:
                observed = hashlib.sha256(regular_bytes(str(destination), 65536)).hexdigest()
            except (OSError, ValueError):
                raise DomainError(
                    "DEPENDENCY_UNAVAILABLE", "Projection observation is unavailable"
                ) from None
        state = (
            "ABSENT"
            if observed is None
            else "UNMANAGED"
            if old_hash is None
            else "MATCH"
            if observed == desired
            else "DRIFT"
        )
        if action in {"preview", "check"}:
            return ProjectionView(
                desired_hash=desired,
                observed_hash=observed,
                owned=old_hash is not None,
                content=content,
                status=cast(Literal["MATCH", "DRIFT", "UNMANAGED", "ABSENT"], state),
            )
        if action != "materialize":
            raise DomainError("VALIDATION_FAILED", "Unsupported projection action")
        if observed != command.expected_observed_hash or (
            observed is not None and observed != old_hash
        ):
            raise DomainError(
                "REVISION_CONFLICT", "Unmanaged or changed native guidance is preserved"
            )
        from journeon.release_evidence import regular_bytes

        previous = regular_bytes(str(destination), 65536).decode() if observed is not None else None
        if previous is not None and hashlib.sha256(previous.encode()).hexdigest() != observed:
            raise DomainError("REVISION_CONFLICT", "Projection preimage changed")
        with transaction(self.engine) as db:
            binding = self.binding(db, actor, command.project_id, "projection")
            self.root_path(
                db, actor, command.root_id, command.expected_root_revision, command.project_id
            )
            require_project(db, actor, command.project_id, "receipt.read")
            if binding.revision != view.revision or binding.active_operation:
                raise DomainError("REVISION_CONFLICT", "Projection source changed")
            operation = self.admit(
                db,
                actor,
                binding,
                "project.instructions.projection.v1",
                command.idempotency_key,
                payload,
                {} if previous is None else {command.filename: previous},
                {command.filename: content},
                [],
                "Materialize exact canonical instruction projection",
            )
        self.publish(actor, operation, projection=True)
        return self.projection(actor, command, "check")

    def _publish_projection_locked(
        self, actor: AuthenticatedContext, operation: str, *, recovery: str | None = None
    ) -> InstructionReceipt:
        from journeon.models import InstructionProjection
        from journeon.release_evidence import regular_bytes

        with transaction(self.engine) as db:
            row = db.get(
                InstructionPublication, operation, options=[defer(InstructionPublication.snapshot)]
            )
            if row is None:
                raise DomainError("NOT_FOUND", "Projection publication is unavailable")
            self.publication_authority(db, actor, row, recovery)
            binding = self.binding(db, actor, row.project_id, "projection")
            data = self.publication_data(db, actor, row, recovery)
            if data["command"] != "project.instructions.projection.v1":
                raise DomainError("PERMISSION_DENIED", "Projection journal type differs")
            command = ProjectionCommand.model_validate(data["payload"])
            if recovery:
                command = command.model_copy(
                    update={
                        "expected_root_revision": self.recovery_roots(db, actor, row)[
                            command.root_id
                        ]
                    }
                )
            root = self.root_path(
                db, actor, command.root_id, command.expected_root_revision, command.project_id
            )
            admitted = stored(db, InstructionRoot, command.root_id)
            anchor = (root, admitted.device, admitted.inode)
            if row.status == "CANONICAL_COMMITTED":
                result = retry(db, actor, data["command"], row.idempotency_key, data["payload"])
                assert result is not None
                return result
            if (
                binding.active_operation != operation
                or binding.generation != row.generation
                or binding.revision != data["base_revision"]
                or binding.policy_revision != data["policy_revision"]
            ):
                raise DomainError("REVISION_CONFLICT", "Projection publication authority changed")
            generation = row.generation
        try:
            destination = root / command.filename
            try:
                previous = regular_bytes(str(destination), 65536).decode()
            except FileNotFoundError:
                previous = None
            target = data["target"][command.filename]
            if previous not in (data["base"].get(command.filename), target):
                raise ValueError("Projection external edit is preserved")
            if previous != target:
                replace_document(root, command.filename, previous, target, anchor=anchor)
            if regular_bytes(str(destination), 65536).decode() != target:
                raise ValueError("Projection publication did not converge")
            with transaction(self.engine) as db:
                binding = self.binding(db, actor, row.project_id, "projection")
                self.root_path(
                    db, actor, command.root_id, command.expected_root_revision, command.project_id
                )
                if (
                    binding.active_operation != operation
                    or binding.generation != generation
                    or binding.revision != data["base_revision"]
                    or binding.policy_revision != data["policy_revision"]
                ):
                    raise DomainError(
                        "REVISION_CONFLICT", "Projection authority changed after effect"
                    )
                self.publication_consent(
                    db, actor, self.journal(db, operation), recovery, commit=True
                )
                identity = (command.project_id, command.root_id, command.filename)
                owned = db.get(InstructionProjection, identity)
                content_hash = hashlib.sha256(target.encode()).hexdigest()
                if owned is None:
                    db.add(
                        InstructionProjection(
                            project_id=command.project_id,
                            root_id=command.root_id,
                            filename=command.filename,
                            revision=binding.revision,
                            content_hash=content_hash,
                        )
                    )
                else:
                    owned.revision = binding.revision
                    owned.content_hash = content_hash
                binding.active_operation = None
                self.journal(db, operation).status = "CANONICAL_COMMITTED"
                return record(
                    db,
                    actor,
                    data["command"],
                    row.idempotency_key,
                    data["payload"],
                    "project_instructions",
                    row.project_id,
                    binding.revision,
                    content_hash,
                    "PROJECT",
                    operation_id=operation,
                    origin=self.journal(db, operation),
                )
        except (OSError, ValueError):
            with transaction(self.engine) as db:
                self.journal(db, operation).status = "RECOVERY_NEEDED"
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Projection publication requires reconciliation"
            ) from None
