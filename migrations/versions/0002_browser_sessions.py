# SPDX-License-Identifier: AGPL-3.0-only
"""Add durable sessions without changing existing principals or accepted operations."""

import sqlalchemy as sa
from alembic import op

revision = "0002_browser_sessions"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "browser_sessions",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("csrf_hash", sa.String(64), nullable=False),
        sa.Column("principal_id", sa.String(128), sa.ForeignKey("principals.id"), nullable=False),
        sa.Column("principal_epoch", sa.Integer(), nullable=False),
        sa.Column("authentication_method", sa.String(128), nullable=False),
        sa.Column("client_label", sa.String(128), nullable=False),
        sa.Column("issued_at", sa.Integer(), nullable=False),
        sa.Column("last_activity", sa.Integer(), nullable=False),
        sa.Column("last_observed", sa.Integer(), nullable=False),
        sa.Column("absolute_deadline", sa.Integer(), nullable=False),
        sa.Column("inactivity_seconds", sa.Integer(), nullable=False),
        sa.Column("strong_authenticated_at", sa.Integer(), nullable=True),
        sa.Column("strong_freshness_seconds", sa.Integer(), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.CheckConstraint("principal_epoch >= 1", name="session_principal_epoch"),
        sa.CheckConstraint("revoked IN (0, 1)", name="session_revoked_boolean"),
        sa.CheckConstraint(
            "issued_at >= 0 AND absolute_deadline > issued_at", name="session_deadline"
        ),
        sa.CheckConstraint(
            "last_observed >= last_activity AND last_activity >= issued_at",
            name="session_activity_order",
        ),
        sa.CheckConstraint("inactivity_seconds > 0", name="session_inactivity"),
        sa.CheckConstraint("strong_freshness_seconds > 0", name="session_strong_freshness"),
        sa.CheckConstraint(
            "strong_authenticated_at IS NULL OR "
            "(strong_authenticated_at >= issued_at AND strong_authenticated_at <= last_observed)",
            name="session_strong_time",
        ),
    )
    op.create_index("ix_browser_sessions_principal_id", "browser_sessions", ["principal_id"])


def downgrade() -> None:
    raise RuntimeError("Destructive downgrade is unsupported; restore a coherent backup")
