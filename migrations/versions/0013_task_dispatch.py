# SPDX-License-Identifier: AGPL-3.0-only
import sqlalchemy as sa
from alembic import op

revision = "0013_task_dispatch"
down_revision = "0012_attempt_execution"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    connection.exec_driver_sql("PRAGMA defer_foreign_keys=ON")
    connection.exec_driver_sql(
        "CREATE TEMP TABLE retained_dispatch_attention AS SELECT * FROM attention"
    )
    connection.exec_driver_sql("DELETE FROM attention")
    with op.batch_alter_table("jobs", recreate="always") as batch:
        batch.alter_column("candidate_id", existing_type=sa.String(128), nullable=True)
        batch.add_column(sa.Column("task_id", sa.String(128), nullable=True))
        batch.create_foreign_key("job_task", "tasks", ["task_id"], ["id"])
        batch.drop_constraint("job_kind", type_="check")
        batch.create_check_constraint(
            "job_kind",
            "(kind = 'INSTRUCTION_NAVIGATION' AND candidate_id IS NOT NULL AND task_id IS NULL) "
            "OR (kind = 'TASK_VERIFICATION' AND candidate_id IS NULL AND task_id IS NOT NULL)",
        )
    connection.exec_driver_sql("INSERT INTO attention SELECT * FROM retained_dispatch_attention")
    connection.exec_driver_sql("DROP TABLE retained_dispatch_attention")
    connection.exec_driver_sql(
        "ALTER TABLE executions ADD COLUMN job_id VARCHAR(128) REFERENCES jobs(id)"
    )
    op.create_index("execution_job_identity", "executions", ["job_id"], unique=True)
    op.create_table(
        "task_verification_jobs",
        sa.Column("job_id", sa.String(128), sa.ForeignKey("jobs.id"), primary_key=True),
        sa.Column("attempt_id", sa.String(128), sa.ForeignKey("attempts.id"), nullable=False),
        sa.Column(
            "manifest_id", sa.String(128), sa.ForeignKey("attempt_manifests.id"), nullable=False
        ),
        sa.Column("principal_id", sa.String(128), sa.ForeignKey("principals.id"), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("step_id", sa.String(128), nullable=False),
        sa.Column("route_digest", sa.String(64), nullable=False),
        sa.Column("configuration_revision", sa.Integer(), nullable=False),
        sa.Column("inputs", sa.JSON(), nullable=False),
        sa.Column("execution_id", sa.String(128), sa.ForeignKey("executions.id"), unique=True),
        sa.Column("claim_fence", sa.Integer()),
        sa.Column("claim_owner", sa.String(128)),
        sa.Column("claim_incarnation", sa.String(128)),
        sa.UniqueConstraint("principal_id", "idempotency_key", name="task_dispatch_identity"),
        sa.UniqueConstraint("attempt_id", "step_id", name="task_dispatch_step"),
        sa.CheckConstraint(
            "(execution_id IS NULL AND claim_fence IS NULL AND claim_owner IS NULL "
            "AND claim_incarnation IS NULL) OR (execution_id IS NOT NULL "
            "AND claim_fence IS NOT NULL "
            "AND typeof(claim_fence) = 'integer' AND claim_fence >= 1 "
            "AND claim_owner IS NOT NULL AND claim_incarnation IS NOT NULL)",
            name="task_execution_claim",
        ),
    )
    op.create_table(
        "task_verification_evidence",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column(
            "job_id",
            sa.String(128),
            sa.ForeignKey("task_verification_jobs.job_id"),
            unique=True,
            nullable=False,
        ),
        sa.Column(
            "execution_id",
            sa.String(128),
            sa.ForeignKey("executions.id"),
            unique=True,
            nullable=False,
        ),
        sa.Column(
            "manifest_id", sa.String(128), sa.ForeignKey("attempt_manifests.id"), nullable=False
        ),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
    )
    for action in ("UPDATE", "DELETE"):
        op.execute(
            f"CREATE TRIGGER task_evidence_no_{action.lower()} BEFORE {action} "
            "ON task_verification_evidence BEGIN SELECT RAISE(ABORT, "
            "'Verification evidence is immutable'); END"
        )


def downgrade() -> None:
    raise RuntimeError("A coherent authorized restore is required")
