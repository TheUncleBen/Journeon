# SPDX-License-Identifier: AGPL-3.0-only
"""Preserve canonical operations while admitting typed identity targets."""

import sqlalchemy as sa
from alembic import op

revision = "0005_protected_operations"
down_revision = "0004_auth_rate_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "principals",
        sa.Column(
            "credential_revision",
            sa.Integer(),
            sa.CheckConstraint("credential_revision >= 1", name="principal_credential_revision"),
            nullable=False,
            server_default="1",
        ),
    )
    op.add_column(
        "passkeys",
        sa.Column(
            "revision",
            sa.Integer(),
            sa.CheckConstraint("revision >= 1", name="passkey_revision"),
            nullable=False,
            server_default="1",
        ),
    )
    op.add_column(
        "browser_sessions",
        sa.Column(
            "audience",
            sa.String(30),
            sa.CheckConstraint(
                "audience IN ('unknown', 'official_browser')", name="session_audience"
            ),
            nullable=False,
            server_default="unknown",
        ),
    )
    # Children move first so foreign keys remain enabled throughout the transaction.
    op.execute("CREATE TEMP TABLE retained_events AS SELECT * FROM outbox_events")
    op.drop_table("outbox_events")
    with op.batch_alter_table("operation_receipts") as batch:
        batch.alter_column("project_id", existing_type=sa.String(128), nullable=True)
        batch.add_column(
            sa.Column("owner", sa.String(30), nullable=False, server_default="projects")
        )
        batch.add_column(
            sa.Column("target_kind", sa.String(30), nullable=False, server_default="project")
        )
        batch.add_column(sa.Column("target_id", sa.String(128), nullable=True))
    op.execute("UPDATE operation_receipts SET target_id = project_id")
    with op.batch_alter_table("operation_receipts") as batch:
        batch.alter_column("target_id", existing_type=sa.String(128), nullable=False)
        batch.create_check_constraint(
            "receipt_target",
            "(owner = 'projects' AND target_kind = 'project' "
            "AND project_id IS NOT NULL AND target_id = project_id) OR "
            "(owner = 'identity' AND target_kind = 'passkey' AND project_id IS NULL)",
        )
    op.create_table(
        "outbox_events",
        sa.Column("sequence", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_id", sa.String(128), nullable=False, unique=True),
        sa.Column(
            "operation_id",
            sa.String(128),
            sa.ForeignKey("operation_receipts.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("principal_id", sa.String(128), sa.ForeignKey("principals.id"), nullable=False),
        sa.Column("project_id", sa.String(128), sa.ForeignKey("projects.id")),
        sa.Column("owner", sa.String(30), nullable=False),
        sa.Column("target_kind", sa.String(30), nullable=False),
        sa.Column("target_id", sa.String(128), nullable=False),
        sa.Column("committed_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "(owner = 'projects' AND target_kind = 'project' AND project_id IS NOT NULL "
            "AND target_id = project_id) OR (owner = 'identity' AND target_kind = 'passkey' "
            "AND project_id IS NULL)",
            name="event_target",
        ),
        sqlite_autoincrement=True,
    )
    op.execute(
        "INSERT INTO outbox_events SELECT sequence, event_id, operation_id, event_type, "
        "schema_version, principal_id, project_id, 'projects', 'project', project_id, committed_at "
        "FROM retained_events"
    )
    op.execute("DROP TABLE retained_events")

    op.create_table(
        "protected_requests",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("operation_id", sa.String(128), nullable=False, unique=True),
        sa.Column("principal_id", sa.String(128), sa.ForeignKey("principals.id"), nullable=False),
        sa.Column("principal_epoch", sa.Integer(), nullable=False),
        sa.Column(
            "session_id", sa.String(128), sa.ForeignKey("browser_sessions.id"), nullable=False
        ),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("command", sa.String(128), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("credential_revision", sa.Integer(), nullable=False),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("issued_at", sa.Integer(), nullable=False),
        sa.Column("deadline", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("approved_at", sa.Integer()),
        sa.Column("approval_deadline", sa.Integer()),
        sa.Column("strong_authenticated_at", sa.Integer()),
        sa.Column("nonce_hash", sa.String(64)),
        sa.Column("nonce_deadline", sa.Integer()),
        sa.CheckConstraint(
            "state IN ('PENDING', 'APPROVED', 'COMMITTED', 'CANCELLED', 'EXPIRED', 'INVALIDATED')",
            name="protected_state",
        ),
        sa.CheckConstraint("deadline > issued_at AND issued_at >= 0", name="protected_deadline"),
        sa.CheckConstraint("command = 'passkey.label.v1'", name="protected_command"),
    )

    op.create_index(
        "protected_operation_identity",
        "protected_requests",
        ["principal_id", "command", "idempotency_key"],
        unique=True,
    )


def downgrade() -> None:
    raise RuntimeError("Destructive downgrade is unsupported; restore a coherent backup")
