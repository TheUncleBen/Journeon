# SPDX-License-Identifier: AGPL-3.0-only
from alembic import op

revision = "0011_task_admission"
down_revision = "0010_work_execution"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE TABLE verification_policy_revisions (project_id VARCHAR(128) NOT NULL, "
        "revision INTEGER NOT NULL, snapshot JSON NOT NULL, content_hash VARCHAR(64) NOT NULL, "
        "PRIMARY KEY (project_id, revision), FOREIGN KEY(project_id) REFERENCES projects(id), "
        "CONSTRAINT verification_policy_revision CHECK (revision >= 1))"
    )
    op.execute(
        "CREATE TABLE task_revisions (task_id VARCHAR(128) NOT NULL, revision INTEGER NOT NULL, "
        "snapshot JSON NOT NULL, operation_id VARCHAR(128), PRIMARY KEY (task_id, revision), "
        "FOREIGN KEY(task_id) REFERENCES tasks(id), "
        "FOREIGN KEY(operation_id) REFERENCES operation_receipts(id), "
        "CONSTRAINT task_history_revision CHECK (revision >= 1))"
    )
    op.execute("INSERT INTO task_revisions SELECT id, revision, snapshot, NULL FROM tasks")


def downgrade() -> None:
    raise RuntimeError("A coherent authorized restore is required")
