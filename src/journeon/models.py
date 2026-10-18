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


class BrowserSession(Base):
    __tablename__ = "browser_sessions"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), index=True)
    principal_epoch: Mapped[int] = mapped_column(Integer)
    authentication_method: Mapped[str] = mapped_column(String(128))
    client_label: Mapped[str] = mapped_column(String(128))
    issued_at: Mapped[int] = mapped_column(Integer)
    last_activity: Mapped[int] = mapped_column(Integer)
    last_observed: Mapped[int] = mapped_column(Integer)
    absolute_deadline: Mapped[int] = mapped_column(Integer)
    inactivity_seconds: Mapped[int] = mapped_column(Integer)
    strong_authenticated_at: Mapped[int | None] = mapped_column(Integer)
    strong_freshness_seconds: Mapped[int] = mapped_column(Integer)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (
        CheckConstraint("principal_epoch >= 1", name="session_principal_epoch"),
        CheckConstraint("revoked IN (0, 1)", name="session_revoked_boolean"),
        CheckConstraint(
            "issued_at >= 0 AND absolute_deadline > issued_at", name="session_deadline"
        ),
        CheckConstraint(
            "last_observed >= last_activity AND last_activity >= issued_at",
            name="session_activity_order",
        ),
        CheckConstraint("inactivity_seconds > 0", name="session_inactivity"),
        CheckConstraint("strong_freshness_seconds > 0", name="session_strong_freshness"),
        CheckConstraint(
            "strong_authenticated_at IS NULL OR "
            "(strong_authenticated_at >= issued_at AND strong_authenticated_at <= last_observed)",
            name="session_strong_time",
        ),
    )


class IdentityState(Base):
    __tablename__ = "identity_state"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_observed: Mapped[int] = mapped_column(Integer, default=0)
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("principals.id"))
    pending_principal_id: Mapped[str | None] = mapped_column(String(128))
    enrollment_hash: Mapped[str | None] = mapped_column(String(64))
    enrollment_deadline: Mapped[int | None] = mapped_column(Integer)
    __table_args__ = (CheckConstraint("id = 1", name="single_identity_state"),)


class Passkey(Base):
    __tablename__ = "passkeys"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    credential_id: Mapped[str] = mapped_column(Text, unique=True)
    credential_data: Mapped[str] = mapped_column(Text)
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), index=True)
    label: Mapped[str] = mapped_column(String(128))
    sign_count: Mapped[int] = mapped_column(Integer)
    backup_eligible: Mapped[bool] = mapped_column(Boolean)
    backed_up: Mapped[bool] = mapped_column(Boolean)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (
        CheckConstraint("sign_count >= 0", name="passkey_counter"),
        CheckConstraint("backup_eligible IN (0, 1)", name="passkey_eligible_boolean"),
        CheckConstraint("backed_up IN (0, 1)", name="passkey_backup_boolean"),
        CheckConstraint("revoked IN (0, 1)", name="passkey_revoked_boolean"),
        CheckConstraint("backed_up = 0 OR backup_eligible = 1", name="passkey_backup_state"),
    )


class AuthCeremony(Base):
    __tablename__ = "auth_ceremonies"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    purpose: Mapped[str] = mapped_column(String(16))
    subject_id: Mapped[str | None] = mapped_column(String(128))
    session_id: Mapped[str | None] = mapped_column(ForeignKey("browser_sessions.id"))
    enrollment_hash: Mapped[str | None] = mapped_column(String(64))
    label: Mapped[str] = mapped_column(String(128))
    state: Mapped[dict[str, Any]] = mapped_column(JSON)
    issued_at: Mapped[int] = mapped_column(Integer)
    last_observed: Mapped[int] = mapped_column(Integer)
    deadline: Mapped[int] = mapped_column(Integer)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (
        CheckConstraint(
            "purpose IN ('bootstrap', 'login', 'stepup', 'add')", name="ceremony_purpose"
        ),
        CheckConstraint("consumed IN (0, 1)", name="ceremony_consumed_boolean"),
        CheckConstraint("attempts >= 0", name="ceremony_attempts"),
        CheckConstraint(
            "deadline > issued_at AND last_observed >= issued_at", name="ceremony_time"
        ),
    )


class AuthRate(Base):
    __tablename__ = "auth_rates"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_start: Mapped[int] = mapped_column(Integer)
    last_observed: Mapped[int] = mapped_column(Integer)
    count: Mapped[int] = mapped_column(Integer)
    __table_args__ = (
        CheckConstraint("count >= 0 AND last_observed >= window_start", name="auth_rate_state"),
    )
