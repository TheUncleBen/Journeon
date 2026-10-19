# SPDX-License-Identifier: AGPL-3.0-only
"""Closed owning handlers invoked only by exact official confirmation."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from journeon.contracts import DomainError
from journeon.database import transaction
from journeon.installed_instructions import CandidateManifest, candidate_manifest
from journeon.instruction_config import (
    InstructionConfiguration,
    RootConfiguration,
    RootObservation,
    observe_root,
)
from journeon.instruction_contracts import (
    CandidateRegister,
    InstructionReceipt,
    PolicyConfigure,
    ProtectedEffect,
    ReleaseInstall,
    RootAdmit,
    RootInspect,
    RootRevoke,
)
from journeon.instruction_operations import record, retry
from journeon.models import (
    InstalledReleaseEvidence,
    InstructionAsset,
    InstructionInstallation,
    InstructionRevision,
    InstructionRoot,
    Project,
    ProjectInstructionBinding,
    ProjectInstructionPolicy,
)
from journeon.permissions import AuthenticatedContext, current_owner


class InstructionAdministration:
    def __init__(self, engine: Engine, configuration: InstructionConfiguration):
        self.engine = engine
        self.configuration = configuration
        self.release_observation: dict[str, Any] | None = None
        self.release_state: str | None = None

    def root_configuration(self, key: str) -> RootConfiguration:
        for root in self.configuration.roots:
            if root.key == key:
                return root
        raise DomainError("NOT_FOUND", "Configured root is unavailable")

    def inspect(self, actor: AuthenticatedContext, command: RootInspect) -> RootObservation:
        with transaction(self.engine) as db:
            current_owner(db, actor)
        root = self.root_configuration(command.root_key)
        if root.revision != command.config_revision:
            raise DomainError("REVISION_CONFLICT", "Root configuration changed")
        try:
            return observe_root(root)
        except ValueError:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Configured root is unavailable") from None

    def observe(
        self, actor: AuthenticatedContext, effect: ProtectedEffect
    ) -> RootObservation | CandidateManifest | None:
        if isinstance(effect, RootAdmit):
            return self.inspect(
                actor, RootInspect(root_key=effect.root_key, config_revision=effect.config_revision)
            )
        if isinstance(effect, ReleaseInstall):
            with transaction(self.engine) as db:
                current_owner(db, actor)
                evidence = db.get(InstalledReleaseEvidence, effect.evidence_id)
                if evidence is None or evidence.principal_id != actor.principal_id:
                    raise DomainError(
                        "PERMISSION_DENIED", "Verified installed release evidence is required"
                    )
                stored = evidence.snapshot
            from journeon.release_evidence import verify_current_evidence

            package = candidate_manifest()
            self.release_state = verify_current_evidence(
                self.engine, self.configuration, stored, actor
            )
            self.release_observation = stored
            return package
        if isinstance(effect, CandidateRegister):
            return candidate_manifest()
        return None

    def apply(
        self,
        db: Session,
        actor: AuthenticatedContext,
        effect: ProtectedEffect,
        observation: RootObservation | CandidateManifest | None,
        operation_id: str,
    ) -> InstructionReceipt:
        current_owner(db, actor)
        payload = effect.model_dump(mode="json")
        previous = retry(db, actor, effect.kind, effect.idempotency_key, payload)
        if previous:
            return previous
        if isinstance(effect, RootAdmit):
            if (
                not isinstance(observation, RootObservation)
                or observation.digest != effect.inspection_digest
            ):
                raise DomainError("REVISION_CONFLICT", "Inspected root changed")
            configuration = self.root_configuration(effect.root_key)
            if observe_root(configuration) != observation:
                raise DomainError("REVISION_CONFLICT", "Inspected root changed before admission")
            for other in db.scalars(
                select(InstructionRoot).where(InstructionRoot.enabled.is_(True))
            ):
                if other.root_key != effect.root_key and (other.device, other.inode) == (
                    observation.device,
                    observation.inode,
                ):
                    raise DomainError(
                        "PERMISSION_DENIED", "Root is already admitted under another identity"
                    )
            row = db.get(InstructionRoot, effect.root_key)
            if (row.revision if row else 0) != effect.expected_revision:
                raise DomainError("REVISION_CONFLICT", "Root binding changed")
            if (
                configuration.project_id is not None
                and db.get(Project, configuration.project_id) is None
            ):
                raise DomainError("NOT_FOUND", "Project is unavailable")
            if row is None:
                row = InstructionRoot(
                    id=effect.root_key,
                    root_key=effect.root_key,
                    revision=1,
                    config_revision=effect.config_revision,
                    project_id=configuration.project_id,
                    role=configuration.role,
                    device=observation.device,
                    inode=observation.inode,
                    git_identity=observation.git_identity,
                    enabled=True,
                )
                db.add(row)
            else:
                row.revision += 1
                row.enabled = True
                row.device, row.inode = observation.device, observation.inode
                row.config_revision = effect.config_revision
                row.git_identity = observation.git_identity
                row.project_id = configuration.project_id
                row.role = configuration.role
            return record(
                db,
                actor,
                effect.kind,
                effect.idempotency_key,
                payload,
                "instruction_root",
                row.id,
                row.revision,
                observation.digest,
                "ROOT",
                operation_id=operation_id,
            )
        if isinstance(effect, RootRevoke):
            row = db.get(InstructionRoot, effect.root_id)
            if row is None or row.revision != effect.expected_revision:
                raise DomainError("REVISION_CONFLICT", "Root binding changed")
            row.enabled = False
            row.revision += 1
            return record(
                db,
                actor,
                effect.kind,
                effect.idempotency_key,
                payload,
                "instruction_root",
                row.id,
                row.revision,
                None,
                "ROOT",
                operation_id=operation_id,
            )
        if isinstance(effect, PolicyConfigure):
            project = db.get(Project, effect.project_id)
            binding = db.get(ProjectInstructionBinding, effect.project_id)
            root = db.get(InstructionRoot, binding.root_id) if binding else None
            if (
                project is None
                or binding is None
                or root is None
                or not root.enabled
                or (project.revision, binding.revision, root.revision, binding.policy_revision)
                != (
                    effect.expected_project_revision,
                    effect.expected_binding_revision,
                    effect.expected_root_revision,
                    effect.expected_policy_revision,
                )
            ):
                raise DomainError(
                    "REVISION_CONFLICT", "Project instruction policy operands changed"
                )
            binding.policy_revision += 1
            db.add(
                ProjectInstructionPolicy(
                    project_id=project.id,
                    revision=binding.policy_revision,
                    snapshot=effect.policy.model_dump(mode="json"),
                    author=actor.principal_id,
                )
            )
            return record(
                db,
                actor,
                effect.kind,
                effect.idempotency_key,
                payload,
                "project_instructions",
                project.id,
                binding.policy_revision,
                None,
                "PROJECT",
                operation_id=operation_id,
            )
        if not isinstance(effect, (CandidateRegister, ReleaseInstall)) or not isinstance(
            observation, CandidateManifest
        ):
            raise DomainError("VALIDATION_FAILED", "Unsupported instruction effect")
        installation = db.get(InstructionInstallation, 1)
        if (
            effect.manifest_digest != observation.digest
            or (installation.revision if installation else 0) != effect.expected_revision
        ):
            raise DomainError("REVISION_CONFLICT", "Installed instruction package changed")
        provenance = "DEVELOPMENT_CANDIDATE"
        if isinstance(effect, ReleaseInstall):
            evidence = db.get(InstalledReleaseEvidence, effect.evidence_id)
            if (
                evidence is None
                or evidence.principal_id != actor.principal_id
                or evidence.manifest_digest != observation.digest
            ):
                raise DomainError(
                    "PERMISSION_DENIED", "Verified installed release evidence is required"
                )
            if evidence.snapshot != self.release_observation:
                raise DomainError(
                    "PERMISSION_DENIED", "Current verified release observation is required"
                )
            from journeon.release_qualification import state

            if state(db) != self.release_state:
                raise DomainError(
                    "PERMISSION_DENIED", "Release qualification changed before installation"
                )
            provenance = "VERIFIED_RELEASE"
        components = []
        for packaged in observation.assets:
            asset = db.get(InstructionAsset, packaged.asset_id)
            if asset:
                old = db.get(InstructionRevision, (asset.id, asset.revision))
                if (
                    old is None
                    or asset.owner_kind != "system"
                    or asset.owner_id != "running-package"
                    or asset.purpose != packaged.purpose
                    or asset.trust != "PROTECTED"
                ):
                    raise DomainError(
                        "PERMISSION_DENIED", "Protected asset is not owned by the installed package"
                    )
                if old.content_hash != packaged.content_hash:
                    previous_asset = (
                        next(
                            (
                                item
                                for item in installation.snapshot["manifest"]["assets"]
                                if item["asset_id"] == packaged.asset_id
                            ),
                            None,
                        )
                        if installation
                        else None
                    )
                    if previous_asset is None or tuple(
                        map(int, packaged.version.split("."))
                    ) <= tuple(map(int, previous_asset["version"].split("."))):
                        raise DomainError(
                            "REVISION_CONFLICT",
                            "Packaged instruction version has different content",
                        )
                    asset.revision += 1
                    db.add(
                        InstructionRevision(
                            asset_id=asset.id,
                            revision=asset.revision,
                            template=packaged.template.model_dump(mode="json"),
                            content_hash=packaged.content_hash,
                            previous_hash=old.content_hash,
                            author=actor.principal_id,
                            reason="Explicit versioned installed package registration",
                            created_at=datetime.now(UTC).isoformat(),
                        )
                    )
            else:
                asset = InstructionAsset(
                    id=packaged.asset_id,
                    owner_kind="system",
                    owner_id="running-package",
                    purpose=packaged.purpose,
                    trust="PROTECTED",
                    revision=1,
                )
                db.add(asset)
                db.flush()
                db.add(
                    InstructionRevision(
                        asset_id=asset.id,
                        revision=1,
                        template=packaged.template.model_dump(mode="json"),
                        content_hash=packaged.content_hash,
                        previous_hash=None,
                        author=actor.principal_id,
                        reason="Explicit installed package registration",
                        created_at=datetime.now(UTC).isoformat(),
                    )
                )
            components.append(
                dict(asset_id=asset.id, revision=asset.revision, content_hash=packaged.content_hash)
            )
        if installation is None:
            installation = InstructionInstallation(
                id=1,
                revision=1,
                manifest_digest=observation.digest,
                provenance=provenance,
                snapshot={
                    "components": components,
                    "manifest": observation.model_dump(mode="json"),
                },
            )
            db.add(installation)
        else:
            installation.revision += 1
            installation.manifest_digest = observation.digest
            installation.provenance = provenance
            installation.snapshot = {
                "components": components,
                "manifest": observation.model_dump(mode="json"),
            }
        return record(
            db,
            actor,
            effect.kind,
            effect.idempotency_key,
            payload,
            "instruction_install",
            "running-package",
            installation.revision,
            observation.digest,
            provenance,
            operation_id=operation_id,
        )
