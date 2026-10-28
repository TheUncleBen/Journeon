# SPDX-License-Identifier: AGPL-3.0-only
import sqlalchemy as sa
from alembic import op

revision = "0014_review_completion"
down_revision = "0013_task_dispatch"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "review_policy_revisions",
        sa.Column("project_id", sa.String(128), sa.ForeignKey("projects.id"), primary_key=True),
        sa.Column("revision", sa.Integer(), primary_key=True),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.CheckConstraint("revision >= 1", name="review_policy_revision"),
    )
    op.create_table(
        "review_targets",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("project_id", sa.String(128), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("task_id", sa.String(128), sa.ForeignKey("tasks.id"), nullable=False),
        sa.Column("task_revision", sa.Integer(), nullable=False),
        sa.Column("attempt_id", sa.String(128), sa.ForeignKey("attempts.id"), nullable=False),
        sa.Column(
            "manifest_id", sa.String(128), sa.ForeignKey("attempt_manifests.id"), nullable=False
        ),
        sa.Column("review_policy_revision", sa.Integer(), nullable=False),
        sa.Column("principal_id", sa.String(128), sa.ForeignKey("principals.id"), nullable=False),
        sa.Column(
            "operation_id",
            sa.String(128),
            sa.ForeignKey("operation_receipts.id"),
            unique=True,
            nullable=False,
        ),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(
            ["task_id", "task_revision"], ["task_revisions.task_id", "task_revisions.revision"]
        ),
        sa.ForeignKeyConstraint(
            ["project_id", "review_policy_revision"],
            ["review_policy_revisions.project_id", "review_policy_revisions.revision"],
        ),
    )
    for action in ("UPDATE", "DELETE"):
        op.execute(
            f"CREATE TRIGGER review_target_no_{action.lower()} BEFORE {action} "
            "ON review_targets BEGIN SELECT RAISE(ABORT, 'Review targets are immutable'); END"
        )
    for action in ("UPDATE", "DELETE"):
        op.execute(
            f"CREATE TRIGGER review_policy_no_{action.lower()} BEFORE {action} "
            "ON review_policy_revisions BEGIN SELECT RAISE(ABORT, "
            "'Review policy history is immutable'); END"
        )


def downgrade() -> None:
    raise RuntimeError("A coherent authorized restore is required")
