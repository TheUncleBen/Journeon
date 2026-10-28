# SPDX-License-Identifier: AGPL-3.0-only
"""Initial foundation. Downgrade destroys canonical records: deliberately unsupported."""

import sqlalchemy as sa
from alembic import op

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "principals",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("authorization_epoch", sa.Integer(), nullable=False),
        sa.CheckConstraint("role IN ('OWNER', 'SHARED_USER')", name="principal_role"),
        sa.CheckConstraint("authorization_epoch >= 1", name="principal_epoch"),
        sa.CheckConstraint("enabled IN (0, 1)", name="principal_enabled_boolean"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "one_enabled_owner",
        "principals",
        ["role"],
        unique=True,
        sqlite_where=sa.text("role = 'OWNER' AND enabled = 1"),
    )
    op.create_table(
        "access_grants",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("principal_id", sa.String(length=128), nullable=False),
        sa.Column("capability", sa.String(length=128), nullable=False),
        sa.Column("resource_kind", sa.String(length=30), nullable=False),
        sa.Column("resource_id", sa.String(length=128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.String(length=40), nullable=True),
        sa.Column("provenance", sa.String(length=128), nullable=False),
        sa.CheckConstraint(
            "resource_kind IN ('deployment', 'project')", name="grant_resource_kind"
        ),
        sa.CheckConstraint("revision >= 1", name="grant_revision"),
        sa.CheckConstraint("enabled IN (0, 1)", name="grant_enabled_boolean"),
        sa.ForeignKeyConstraint(
            ["principal_id"],
            ["principals.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_access_grants_principal_id"), "access_grants", ["principal_id"], unique=False
    )
    op.create_table(
        "deployment_policy",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("approval_id", sa.String(length=128), nullable=True),
        sa.Column("approved_by", sa.String(length=128), nullable=True),
        sa.Column("approved_providers", sa.JSON(), nullable=False),
        sa.Column("verification_policy_ref", sa.String(length=128), nullable=True),
        sa.CheckConstraint(
            "(approval_id IS NULL AND approved_by IS NULL) OR "
            "(approval_id IS NOT NULL AND approved_by IS NOT NULL)",
            name="approval_attribution",
        ),
        sa.CheckConstraint("id = 1", name="single_deployment_policy"),
        sa.CheckConstraint("revision >= 1", name="policy_revision"),
        sa.ForeignKeyConstraint(
            ["approved_by"],
            ["principals.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "projects",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("instruction_owner", sa.String(length=30), nullable=False),
        sa.Column("instruction_authority_ref", sa.String(length=128), nullable=False),
        sa.Column("provider_snapshot", sa.JSON(), nullable=False),
        sa.Column("verification_policy_ref", sa.String(length=128), nullable=True),
        sa.Column("resource_refs", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.CheckConstraint("instruction_owner = 'ENVIRONMENT'", name="instruction_owner"),
        sa.CheckConstraint("revision >= 1", name="project_revision"),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["principals.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("instruction_authority_ref"),
    )
    op.create_table(
        "operation_receipts",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("principal_id", sa.String(length=128), nullable=False),
        sa.Column("command", sa.String(length=128), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=128), nullable=False),
        sa.Column("authentication_ref", sa.String(length=128), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["principal_id"],
            ["principals.id"],
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "receipt_operation_identity",
        "operation_receipts",
        ["principal_id", "command", "idempotency_key"],
        unique=True,
    )
    op.create_table(
        "outbox_events",
        sa.Column("sequence", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_id", sa.String(length=128), nullable=False),
        sa.Column("operation_id", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("principal_id", sa.String(length=128), nullable=False),
        sa.Column("project_id", sa.String(length=128), nullable=False),
        sa.Column("committed_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["operation_id"],
            ["operation_receipts.id"],
        ),
        sa.ForeignKeyConstraint(
            ["principal_id"],
            ["principals.id"],
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
        ),
        sa.PrimaryKeyConstraint("sequence"),
        sa.UniqueConstraint("event_id"),
        sa.UniqueConstraint("operation_id"),
    )


def downgrade() -> None:
    raise RuntimeError("Destructive downgrade is unsupported; restore a coherent backup")
