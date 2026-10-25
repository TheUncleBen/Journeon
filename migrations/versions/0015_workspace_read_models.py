# SPDX-License-Identifier: AGPL-3.0-only
from alembic import op

revision = "0015_workspace_read_models"
down_revision = "0014_review_completion"
branch_labels = None
depends_on = None


TARGET = (
    "(owner = 'projects' AND target_kind = 'project' AND project_id IS NOT NULL AND target_"
    "id = project_id) OR (owner = 'identity' AND target_kind = 'passkey' AND project_id IS "
    "NULL) OR (owner = 'work' AND target_kind IN ('task','attempt','execution') AND project"
    "_id IS NOT NULL) OR (owner = 'agents' AND target_kind IN ('profile', 'bot', 'team') AN"
    "D project_id IS NULL) OR (owner = 'instructions' AND target_kind = 'instruction_bundle"
    "' AND project_id IS NOT NULL) OR (owner = 'project_instructions' AND ((target_kind = '"
    "project_instructions' AND project_id IS NOT NULL AND project_id = target_id) OR (targe"
    "t_kind IN ('instruction_root','instruction_install') AND project_id IS NULL))) OR (own"
    "er = 'jobs' AND target_kind = 'job' AND project_id IS NOT NULL) OR (owner = 'lifecycle"
    "' AND target_kind = 'store' AND project_id IS NULL) OR (owner = 'permissions' AND targ"
    "et_kind = 'grant' AND project_id IS NULL) OR (owner = 'egress' AND target_kind = 'depl"
    "oyment_policy' AND target_id = 'deployment' AND project_id IS NULL)"
)
COMMANDS = (
    "command IN ('passkey.label.v1','project.root.admit.v1','project.root.revoke.v1','proje"
    "ct.instructions.policy.configure.v1','instruction.candidate.register.v1','instruction."
    "release.install.v1','project.instructions.accept.v1', 'project.instructions.recover.v1"
    "', 'lifecycle.restore.authorize.v1','permission.grant.set.v1','permission.grant.revoke"
    ".v1','egress.policy.initialize.v1')"
)


def upgrade() -> None:
    db = op.get_bind()
    db.exec_driver_sql("PRAGMA defer_foreign_keys=ON")
    ceiling = db.exec_driver_sql(
        "SELECT seq FROM sqlite_sequence WHERE name='outbox_events'"
    ).scalar_one_or_none()
    # Remove inbound references during the SQLite rebuild, then restore the exact rows.
    # Deferred checks alone retain DROP TABLE violations after a parent is recreated.
    retained_tables = (
        "outbox_events",
        "review_targets",
        "instruction_request_scopes",
        "restore_request_scopes",
    )
    retained_triggers: list[str] = []
    for table in retained_tables:
        db.exec_driver_sql(f"CREATE TEMP TABLE retained_workspace_{table} AS SELECT * FROM {table}")
        for trigger_name, trigger_sql in db.exec_driver_sql(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?",
            (table,),
        ).all():
            retained_triggers.append(trigger_sql)
            escaped = trigger_name.replace('"', '""')
            db.exec_driver_sql(f'DROP TRIGGER "{escaped}"')
        db.exec_driver_sql(f"DELETE FROM {table}")
    db.exec_driver_sql(
        "CREATE TEMP TABLE retained_workspace_revision_receipts AS "
        "SELECT task_id,revision,operation_id FROM task_revisions WHERE operation_id IS NOT NULL"
    )
    db.exec_driver_sql("UPDATE task_revisions SET operation_id=NULL")
    for table, name, expression in (
        ("operation_receipts", "receipt_target", TARGET),
        ("outbox_events", "event_target", TARGET),
        ("protected_requests", "protected_command", COMMANDS),
    ):
        triggers = list(
            db.exec_driver_sql(
                "SELECT sql FROM sqlite_master WHERE type='trigger' "
                "AND tbl_name=? AND sql IS NOT NULL",
                (table,),
            ).scalars()
        )
        options = {"sqlite_autoincrement": True} if table == "outbox_events" else {}
        with op.batch_alter_table(table, recreate="always", table_kwargs=options) as batch:
            batch.drop_constraint(name, type_="check")
            batch.create_check_constraint(name, expression)
        for sql in triggers:
            db.exec_driver_sql(sql)
    for table in retained_tables:
        db.exec_driver_sql(f"INSERT INTO {table} SELECT * FROM retained_workspace_{table}")
        db.exec_driver_sql(f"DROP TABLE retained_workspace_{table}")
    db.exec_driver_sql(
        "UPDATE task_revisions SET operation_id=(SELECT operation_id FROM "
        "retained_workspace_revision_receipts AS retained WHERE "
        "retained.task_id=task_revisions.task_id AND retained.revision=task_revisions.revision) "
        "WHERE (task_id,revision) IN "
        "(SELECT task_id,revision FROM retained_workspace_revision_receipts)"
    )
    db.exec_driver_sql("DROP TABLE retained_workspace_revision_receipts")
    for trigger_sql in retained_triggers:
        db.exec_driver_sql(trigger_sql)
    if ceiling is not None:
        db.exec_driver_sql(
            "UPDATE sqlite_sequence SET seq=max(seq,?) WHERE name='outbox_events'", (ceiling,)
        )
        db.exec_driver_sql(
            "INSERT INTO sqlite_sequence(name,seq) SELECT 'outbox_events',? "
            "WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name='outbox_events')",
            (ceiling,),
        )
    if db.exec_driver_sql("PRAGMA foreign_key_check").fetchone() is not None:
        raise RuntimeError("Workspace migration requires coherent retained references")


def downgrade() -> None:
    raise RuntimeError("A coherent authorized restore is required")
