# SPDX-License-Identifier: AGPL-3.0-only
import sqlalchemy as sa
from alembic import op

revision = "0017_notification_presentation"
down_revision = "0016_identity_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_presentations",
        sa.Column("principal_id", sa.String(128), sa.ForeignKey("principals.id"), primary_key=True),
        sa.Column("attention_id", sa.String(128), sa.ForeignKey("attention.id"), primary_key=True),
        sa.Column(
            "operation_id",
            sa.String(128),
            sa.ForeignKey("operation_receipts.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("revision", sa.Integer(), primary_key=True),
        sa.Column("disposition", sa.String(16), nullable=False),
        sa.Column("source_revision", sa.Integer(), nullable=False),
        sa.CheckConstraint("revision >= 1 AND source_revision >= 1", name="presentation_versions"),
        sa.CheckConstraint("disposition = 'DISMISSED'", name="presentation_disposition"),
    )
    for action in ("UPDATE", "DELETE"):
        op.execute(
            f"CREATE TRIGGER immutable_notification_presentations_{action.lower()} "
            f"BEFORE {action} ON notification_presentations "
            "BEGIN SELECT RAISE(ABORT, 'Immutable presentation history'); END"
        )


def downgrade() -> None:
    raise RuntimeError("A coherent authorized restore is required")
