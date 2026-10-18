# SPDX-License-Identifier: AGPL-3.0-only
"""Real foundation persistence; only owning services may mutate these records."""

from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Principal(Base):
    __tablename__ = "principals"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    role: Mapped[str] = mapped_column(String(20))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    authorization_epoch: Mapped[int] = mapped_column(Integer, default=1)
    credential_revision: Mapped[int] = mapped_column(Integer, default=1)
    __table_args__ = (
        CheckConstraint("role IN ('OWNER', 'SHARED_USER')", name="principal_role"),
        CheckConstraint("authorization_epoch >= 1", name="principal_epoch"),
        CheckConstraint("credential_revision >= 1", name="principal_credential_revision"),
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
        CheckConstraint(
            "resource_kind IN ('deployment', 'project', 'profile', 'bot', 'team', "
            "'instruction_bundle', 'legacy_collection')",
            name="grant_resource_kind",
        ),
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
    project_id: Mapped[str | None] = mapped_column(ForeignKey("projects.id"))
    owner: Mapped[str] = mapped_column(String(30), default="projects")
    target_kind: Mapped[str] = mapped_column(String(30), default="project")
    target_id: Mapped[str] = mapped_column(String(128))
    authentication_ref: Mapped[str] = mapped_column(String(128))
    result: Mapped[dict[str, Any]] = mapped_column(JSON)
    __table_args__ = (
        CheckConstraint(
            "(owner = 'projects' AND target_kind = 'project' AND project_id IS NOT NULL "
            "AND target_id = project_id) OR (owner = 'identity' AND target_kind = 'passkey' "
            "AND project_id IS NULL) OR (owner = 'work' AND target_kind = 'task' "
            "AND project_id IS NOT NULL) OR (owner = 'agents' AND "
            "target_kind IN ('profile', 'bot', 'team') AND project_id IS NULL) OR "
            "(owner = 'instructions' AND target_kind = 'instruction_bundle' "
            "AND project_id IS NOT NULL)",
            name="receipt_target",
        ),
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
    project_id: Mapped[str | None] = mapped_column(ForeignKey("projects.id"))
    owner: Mapped[str] = mapped_column(String(30), default="projects")
    target_kind: Mapped[str] = mapped_column(String(30), default="project")
    target_id: Mapped[str] = mapped_column(String(128))
    committed_at: Mapped[str] = mapped_column(String(40))
    target_revision: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    __table_args__ = (
        CheckConstraint("target_revision >= 1", name="event_target_revision"),
        CheckConstraint(
            "(owner = 'projects' AND target_kind = 'project' AND project_id IS NOT NULL "
            "AND target_id = project_id) OR (owner = 'identity' AND target_kind = 'passkey' "
            "AND project_id IS NULL) OR (owner = 'work' AND target_kind = 'task' "
            "AND project_id IS NOT NULL) OR (owner = 'agents' AND "
            "target_kind IN ('profile', 'bot', 'team') AND project_id IS NULL) OR "
            "(owner = 'instructions' AND target_kind = 'instruction_bundle' "
            "AND project_id IS NOT NULL)",
            name="event_target",
        ),
        {"sqlite_autoincrement": True},
    )


class BrowserSession(Base):
    __tablename__ = "browser_sessions"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), index=True)
    principal_epoch: Mapped[int] = mapped_column(Integer)
    audience: Mapped[str] = mapped_column(String(30), default="unknown")
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
        CheckConstraint("audience IN ('unknown', 'official_browser')", name="session_audience"),
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
    rate_policy: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
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
    revision: Mapped[int] = mapped_column(Integer, default=1)
    sign_count: Mapped[int] = mapped_column(Integer)
    backup_eligible: Mapped[bool] = mapped_column(Boolean)
    backed_up: Mapped[bool] = mapped_column(Boolean)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (
        CheckConstraint("sign_count >= 0", name="passkey_counter"),
        CheckConstraint("revision >= 1", name="passkey_revision"),
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


class AuthRateEvent(Base):
    __tablename__ = "auth_rate_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    bucket: Mapped[str] = mapped_column(String(128), index=True)
    observed_at: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[int | None] = mapped_column(Integer, index=True)
    weight: Mapped[int] = mapped_column(Integer)
    __table_args__ = (
        CheckConstraint("observed_at >= 0 AND weight > 0", name="rate_event_values"),
        CheckConstraint("expires_at IS NULL OR expires_at > observed_at", name="rate_event_expiry"),
    )


class ProtectedRequest(Base):
    __tablename__ = "protected_requests"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    operation_id: Mapped[str] = mapped_column(String(128), unique=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    principal_epoch: Mapped[int] = mapped_column(Integer)
    session_id: Mapped[str] = mapped_column(ForeignKey("browser_sessions.id"))
    idempotency_key: Mapped[str] = mapped_column(String(128))
    command: Mapped[str] = mapped_column(String(128))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    payload_hash: Mapped[str] = mapped_column(String(64))
    credential_revision: Mapped[int] = mapped_column(Integer)
    policy_hash: Mapped[str] = mapped_column(String(64))
    issued_at: Mapped[int] = mapped_column(Integer)
    deadline: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(16), default="PENDING")
    approved_at: Mapped[int | None] = mapped_column(Integer)
    approval_deadline: Mapped[int | None] = mapped_column(Integer)
    strong_authenticated_at: Mapped[int | None] = mapped_column(Integer)
    nonce_hash: Mapped[str | None] = mapped_column(String(64))
    nonce_deadline: Mapped[int | None] = mapped_column(Integer)
    __table_args__ = (
        Index(
            "protected_operation_identity",
            "principal_id",
            "command",
            "idempotency_key",
            unique=True,
        ),
        CheckConstraint(
            "state IN ('PENDING', 'APPROVED', 'COMMITTED', 'CANCELLED', 'EXPIRED', 'INVALIDATED')",
            name="protected_state",
        ),
        CheckConstraint("deadline > issued_at AND issued_at >= 0", name="protected_deadline"),
        CheckConstraint("command = 'passkey.label.v1'", name="protected_command"),
    )


class Task(Base):
    __tablename__ = "tasks"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    initiating_principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    revision: Mapped[int] = mapped_column(Integer)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    __table_args__ = (CheckConstraint("revision >= 1", name="task_revision"),)


class AgentProfile(Base):
    __tablename__ = "agent_profiles"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(200))
    __table_args__ = (CheckConstraint("revision >= 1", name="profile_revision"),)


class ProfileRevision(Base):
    __tablename__ = "profile_revisions"
    profile_id: Mapped[str] = mapped_column(ForeignKey("agent_profiles.id"), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, primary_key=True)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    author: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    reason: Mapped[str] = mapped_column(String(200))
    content_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[str] = mapped_column(String(40))
    __table_args__ = (CheckConstraint("revision >= 1", name="profile_history_revision"),)


class Bot(Base):
    __tablename__ = "bots"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    profile_id: Mapped[str] = mapped_column(ForeignKey("agent_profiles.id"))
    team_id: Mapped[str | None] = mapped_column(
        ForeignKey(
            "teams.id",
            deferrable=True,
            initially="DEFERRED",
            use_alter=True,
            name="bot_team_membership",
        )
    )
    revision: Mapped[int] = mapped_column(Integer)
    namespace_ref: Mapped[str] = mapped_column(String(128), unique=True)
    memory_enabled: Mapped[bool] = mapped_column(Boolean)
    builtin_role: Mapped[str | None] = mapped_column(String(20))
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    __table_args__ = (
        CheckConstraint("revision >= 1", name="bot_revision"),
        UniqueConstraint("id", "team_id", name="bot_team_identity"),
        CheckConstraint("namespace_ref = 'bot:' || id", name="bot_namespace"),
        CheckConstraint("memory_enabled IN (0, 1)", name="bot_memory_boolean"),
        CheckConstraint(
            "builtin_role IS NULL OR (builtin_role IN ('RESEARCHER', 'LIBRARIAN') "
            "AND memory_enabled = 0)",
            name="bot_fixed_memory",
        ),
    )


class BotRevision(Base):
    __tablename__ = "bot_revisions"
    bot_id: Mapped[str] = mapped_column(ForeignKey("bots.id"), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, primary_key=True)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    author: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    reason: Mapped[str] = mapped_column(String(200))
    content_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[str] = mapped_column(String(40))
    __table_args__ = (CheckConstraint("revision >= 1", name="bot_history_revision"),)


class Team(Base):
    __tablename__ = "teams"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    revision: Mapped[int] = mapped_column(Integer)
    lead_bot_id: Mapped[str] = mapped_column(String(128))
    __table_args__ = (
        CheckConstraint("revision >= 1", name="team_revision"),
        ForeignKeyConstraint(
            ["lead_bot_id", "id"],
            ["bots.id", "bots.team_id"],
            deferrable=True,
            initially="DEFERRED",
            name="team_member_lead",
        ),
    )


class InstructionAsset(Base):
    __tablename__ = "instruction_assets"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    owner_kind: Mapped[str] = mapped_column(String(30))
    owner_id: Mapped[str] = mapped_column(String(128))
    purpose: Mapped[str] = mapped_column(String(30))
    trust: Mapped[str] = mapped_column(String(30))
    revision: Mapped[int] = mapped_column(Integer)
    __table_args__ = (
        CheckConstraint("revision >= 1", name="asset_revision"),
        CheckConstraint(
            "purpose IN ('CORE', 'NAVIGATION', 'PROFILE', 'BOT', 'PROJECT', "
            "'SKILLS', 'TASK', 'WORKFLOW')",
            name="asset_purpose",
        ),
        CheckConstraint("trust IN ('PROTECTED', 'CONFIGURATION')", name="asset_trust"),
        CheckConstraint(
            "(purpose IN ('CORE', 'NAVIGATION') "
            "AND owner_kind = 'system' AND trust = 'PROTECTED') OR "
            "(purpose NOT IN ('CORE', 'NAVIGATION') AND trust = 'CONFIGURATION')",
            name="asset_protected_owner",
        ),
    )


class InstructionRevision(Base):
    __tablename__ = "instruction_revisions"
    asset_id: Mapped[str] = mapped_column(ForeignKey("instruction_assets.id"), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, primary_key=True)
    template: Mapped[dict[str, Any]] = mapped_column(JSON)
    content_hash: Mapped[str] = mapped_column(String(64))
    previous_hash: Mapped[str | None] = mapped_column(String(64))
    author: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    reason: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[str] = mapped_column(String(40))
    __table_args__ = (CheckConstraint("revision >= 1", name="instruction_revision"),)


class InstructionBundle(Base):
    __tablename__ = "instruction_bundles"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    profile_id: Mapped[str] = mapped_column(ForeignKey("agent_profiles.id"))
    bot_id: Mapped[str | None] = mapped_column(ForeignKey("bots.id"))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    task_id: Mapped[str | None] = mapped_column(ForeignKey("tasks.id"))
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
