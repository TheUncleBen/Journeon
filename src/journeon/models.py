# SPDX-License-Identifier: AGPL-3.0-only
"""Real foundation persistence; only owning services may mutate these records."""

from typing import Any

from sqlalchemy import JSON, Boolean, CheckConstraint, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Principal(Base):
    __tablename__ = "principals"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    role: Mapped[str] = mapped_column(String(20))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    authorization_epoch: Mapped[int] = mapped_column(Integer, default=1)
    __table_args__ = (
        CheckConstraint("role IN ('OWNER', 'SHARED_USER')", name="principal_role"),
        CheckConstraint("authorization_epoch >= 1", name="principal_epoch"),
        CheckConstraint("enabled IN (0, 1)", name="principal_enabled_boolean"),
        Index(
            "one_enabled_owner",
            "role",
            unique=True,
            sqlite_where=(role == "OWNER") & (enabled == True),  # noqa: E712
        ),
    )


class AccessGrant(Base):
    __tablename__ = "access_grants"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), index=True)
    capability: Mapped[str] = mapped_column(String(128))
    resource_kind: Mapped[str] = mapped_column(String(30))
    resource_id: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    expires_at: Mapped[str | None] = mapped_column(String(40))
    provenance: Mapped[str] = mapped_column(String(128))
    __table_args__ = (
        CheckConstraint("revision >= 1", name="grant_revision"),
        CheckConstraint("enabled IN (0, 1)", name="grant_enabled_boolean"),
        CheckConstraint("resource_kind IN ('deployment', 'project')", name="grant_resource_kind"),
    )


class DeploymentPolicy(Base):
    __tablename__ = "deployment_policy"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    revision: Mapped[int] = mapped_column(Integer)
    approval_id: Mapped[str | None] = mapped_column(String(128))
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("principals.id"))
    approved_providers: Mapped[list[str]] = mapped_column(JSON)
    verification_policy_ref: Mapped[str | None] = mapped_column(String(128))
    __table_args__ = (
        CheckConstraint("id = 1", name="single_deployment_policy"),
        CheckConstraint("revision >= 1", name="policy_revision"),
        CheckConstraint(
            "(approval_id IS NULL AND approved_by IS NULL) OR "
            "(approval_id IS NOT NULL AND approved_by IS NOT NULL)",
            name="approval_attribution",
        ),
    )


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    instruction_owner: Mapped[str] = mapped_column(String(30))
    instruction_authority_ref: Mapped[str] = mapped_column(String(128), unique=True)
    provider_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    verification_policy_ref: Mapped[str | None] = mapped_column(String(128))
    resource_refs: Mapped[list[str]] = mapped_column(JSON)
    created_at: Mapped[str] = mapped_column(String(40))
    __table_args__ = (
        CheckConstraint("revision >= 1", name="project_revision"),
        CheckConstraint("instruction_owner = 'ENVIRONMENT'", name="instruction_owner"),
    )


class Receipt(Base):
    __tablename__ = "operation_receipts"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    command: Mapped[str] = mapped_column(String(128))
    idempotency_key: Mapped[str] = mapped_column(String(128))
    payload_hash: Mapped[str] = mapped_column(String(64))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    authentication_ref: Mapped[str] = mapped_column(String(128))
    result: Mapped[dict[str, Any]] = mapped_column(JSON)
    __table_args__ = (
        Index(
            "receipt_operation_identity", "principal_id", "command", "idempotency_key", unique=True
        ),
    )


class OutboxEvent(Base):
    """Durable fact and audit attribution; transport delivery is not implemented."""

    __tablename__ = "outbox_events"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(128), unique=True)
    operation_id: Mapped[str] = mapped_column(ForeignKey("operation_receipts.id"), unique=True)
    event_type: Mapped[str] = mapped_column(String(128))
    schema_version: Mapped[int] = mapped_column(Integer)
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    committed_at: Mapped[str] = mapped_column(String(40))
