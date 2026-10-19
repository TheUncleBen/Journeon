# SPDX-License-Identifier: AGPL-3.0-only
"""Preserve instruction history while requiring explicit Project scope."""

from alembic import op

revision = "0009_instruction_scope"
down_revision = "0008_project_instructions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    tables = ("outbox_events", "operation_receipts")
    definitions = {}
    objects = []
    ceiling = connection.exec_driver_sql(
        "SELECT seq FROM sqlite_sequence WHERE name='outbox_events'"
    ).scalar()
    for table in tables:
        sql = connection.exec_driver_sql(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).scalar_one()
        definitions[table] = sql.replace(
            "target_kind = 'project_instructions' AND project_id = target_id",
            "target_kind = 'project_instructions' AND project_id IS NOT NULL "
            "AND project_id = target_id",
        )
        objects.extend(
            connection.exec_driver_sql(
                "SELECT sql FROM sqlite_master WHERE tbl_name=? "
                "AND type IN ('index','trigger') AND sql IS NOT NULL",
                (table,),
            ).scalars()
        )
        connection.exec_driver_sql(f"CREATE TEMP TABLE retained_{table} AS SELECT * FROM {table}")
    connection.exec_driver_sql("PRAGMA defer_foreign_keys=ON")
    for table in tables:
        connection.exec_driver_sql(f"DROP TABLE {table}")
    for table in reversed(tables):
        connection.exec_driver_sql(definitions[table])
        connection.exec_driver_sql(f"INSERT INTO {table} SELECT * FROM retained_{table}")
        connection.exec_driver_sql(f"DROP TABLE retained_{table}")
    for sql in objects:
        connection.exec_driver_sql(sql)
    if ceiling is not None:
        connection.exec_driver_sql(
            "UPDATE sqlite_sequence SET seq=MAX(seq,?) WHERE name='outbox_events'", (ceiling,)
        )


def downgrade() -> None:
    raise RuntimeError("Restore a coherent backup to change instruction scope schema")
