# SPDX-License-Identifier: AGPL-3.0-only
"""Add canonical Work without replacing existing operations or authentication."""

import sqlalchemy as sa
from alembic import op

revision = "0006_work"
down_revision = "0005_protected_operations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Retain the allocation ceiling even when the highest event was already pruned.
    op.execute(
        "CREATE TEMP TABLE event_ceiling AS SELECT seq FROM sqlite_sequence "
        "WHERE name = 'outbox_events'"
    )
    op.execute("CREATE TEMP TABLE work_retained_events AS SELECT * FROM outbox_events")
    op.drop_table("outbox_events")
    target = (
        "(owner = 'projects' AND target_kind = 'project' AND project_id IS NOT NULL "
        "AND target_id = project_id) OR (owner = 'identity' AND target_kind = 'passkey' "
        "AND project_id IS NULL) OR (owner = 'work' AND target_kind = 'task' "
        "AND project_id IS NOT NULL)"
    )
    with op.batch_alter_table("operation_receipts") as batch:
        batch.drop_constraint("receipt_target", type_="check")
        batch.create_check_constraint("receipt_target", target)
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
        sa.Column("target_revision", sa.Integer(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.CheckConstraint(target, name="event_target"),
        sa.CheckConstraint("target_revision >= 1", name="event_target_revision"),
        sqlite_autoincrement=True,
    )
    op.execute(
        "INSERT INTO outbox_events SELECT e.*, CASE e.owner "
        "WHEN 'projects' THEN json_extract(r.result, '$.project.revision') "
        "WHEN 'identity' THEN json_extract(r.result, '$.passkey.revision') END, r.result "
        "FROM work_retained_events e JOIN operation_receipts r ON r.id=e.operation_id"
    )
    op.execute(
        "UPDATE sqlite_sequence SET seq = max(seq, coalesce("
        "(SELECT max(seq) FROM event_ceiling), 0)) WHERE name='outbox_events'"
    )
    op.execute(
        "INSERT INTO sqlite_sequence(name,seq) SELECT 'outbox_events', max(seq) "
        "FROM event_ceiling HAVING max(seq) IS NOT NULL AND NOT EXISTS "
        "(SELECT 1 FROM sqlite_sequence WHERE name='outbox_events')"
    )
    op.execute("DROP TABLE work_retained_events")
    op.execute("DROP TABLE event_ceiling")
    op.create_table(
        "tasks",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("project_id", sa.String(128), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column(
            "initiating_principal_id",
            sa.String(128),
            sa.ForeignKey("principals.id"),
            nullable=False,
        ),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.CheckConstraint("revision >= 1", name="task_revision"),
    )
    op.create_index("ix_tasks_project_id", "tasks", ["project_id"])


def downgrade() -> None:
    raise RuntimeError("Destructive downgrade is unsupported; restore a coherent backup")
