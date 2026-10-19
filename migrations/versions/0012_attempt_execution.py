# SPDX-License-Identifier: AGPL-3.0-only
from alembic import op

revision = "0012_attempt_execution"
down_revision = "0011_task_admission"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    connection.exec_driver_sql("PRAGMA defer_foreign_keys=ON")
    ceiling = connection.exec_driver_sql(
        "SELECT seq FROM sqlite_sequence WHERE name='outbox_events'"
    ).scalar()
    # Remove inbound references before SQLite rebuilds the receipt table. Deferred
    # checks alone retain violations from DROP TABLE even after the rows return.
    connection.exec_driver_sql(
        "CREATE TEMP TABLE retained_execution_outbox AS SELECT * FROM outbox_events"
    )
    connection.exec_driver_sql(
        "CREATE TEMP TABLE retained_execution_revision_receipts AS "
        "SELECT task_id, revision, operation_id FROM task_revisions WHERE operation_id IS NOT NULL"
    )
    connection.exec_driver_sql("DELETE FROM outbox_events")
    connection.exec_driver_sql("UPDATE task_revisions SET operation_id=NULL")
    with op.batch_alter_table(
        "operation_receipts", recreate="always", table_kwargs={"sqlite_autoincrement": False}
    ) as batch:
        batch.drop_constraint("receipt_target", type_="check")
        batch.create_check_constraint(
            "receipt_target",
            "(owner = 'projects' AND target_kind = 'project' AND pro"
            "ject_id IS NOT NULL AND target_id = project_id) OR (own"
            "er = 'identity' AND target_kind = 'passkey' AND project"
            "_id IS NULL) OR (owner = 'work' AND target_kind IN ('ta"
            "sk','attempt','execution') AND project_id IS NOT NULL) "
            "OR (owner = 'agents' AND target_kind IN ('profile', 'bo"
            "t', 'team') AND project_id IS NULL) OR (owner = 'instru"
            "ctions' AND target_kind = 'instruction_bundle' AND proj"
            "ect_id IS NOT NULL) OR (owner = 'project_instructions' "
            "AND ((target_kind = 'project_instructions' AND project_"
            "id IS NOT NULL AND project_id = target_id) OR (target_k"
            "ind IN ('instruction_root','instruction_install') AND p"
            "roject_id IS NULL))) OR (owner = 'jobs' AND target_kind"
            " = 'job' AND project_id IS NOT NULL) OR (owner = 'lifec"
            "ycle' AND target_kind = 'store' AND project_id IS NULL)",
        )
    with op.batch_alter_table(
        "outbox_events", recreate="always", table_kwargs={"sqlite_autoincrement": True}
    ) as batch:
        batch.drop_constraint("event_target", type_="check")
        batch.create_check_constraint(
            "event_target",
            "(owner = 'projects' AND target_kind = 'project' AND pro"
            "ject_id IS NOT NULL AND target_id = project_id) OR (own"
            "er = 'identity' AND target_kind = 'passkey' AND project"
            "_id IS NULL) OR (owner = 'work' AND target_kind IN ('ta"
            "sk','attempt','execution') AND project_id IS NOT NULL) "
            "OR (owner = 'agents' AND target_kind IN ('profile', 'bo"
            "t', 'team') AND project_id IS NULL) OR (owner = 'instru"
            "ctions' AND target_kind = 'instruction_bundle' AND proj"
            "ect_id IS NOT NULL) OR (owner = 'project_instructions' "
            "AND ((target_kind = 'project_instructions' AND project_"
            "id IS NOT NULL AND project_id = target_id) OR (target_k"
            "ind IN ('instruction_root','instruction_install') AND p"
            "roject_id IS NULL))) OR (owner = 'jobs' AND target_kind"
            " = 'job' AND project_id IS NOT NULL) OR (owner = 'lifec"
            "ycle' AND target_kind = 'store' AND project_id IS NULL)",
        )
    connection.exec_driver_sql("INSERT INTO outbox_events SELECT * FROM retained_execution_outbox")
    connection.exec_driver_sql(
        "UPDATE task_revisions SET operation_id=(SELECT operation_id FROM "
        "retained_execution_revision_receipts AS retained "
        "WHERE retained.task_id=task_revisions.task_id "
        "AND retained.revision=task_revisions.revision) "
        "WHERE (task_id, revision) IN "
        "(SELECT task_id, revision FROM retained_execution_revision_receipts)"
    )
    connection.exec_driver_sql("DROP TABLE retained_execution_outbox")
    connection.exec_driver_sql("DROP TABLE retained_execution_revision_receipts")
    if ceiling is not None:
        connection.exec_driver_sql(
            "UPDATE sqlite_sequence SET seq=max(seq, ?) WHERE name='outbox_events'", (ceiling,)
        )
    op.execute(
        "\nCREATE TABLE attempts (\n\tid VARCHAR(128) NOT NULL, \n\tp"
        "roject_id VARCHAR(128) NOT NULL, \n\ttask_id VARCHAR(128)"
        " NOT NULL, \n\troot_id VARCHAR(128) NOT NULL, \n\troot_revi"
        "sion INTEGER NOT NULL, \n\tworkspace_key VARCHAR(128) NOT"
        " NULL, \n\tworkspace_revision INTEGER NOT NULL, \n\tconfigu"
        "ration_revision INTEGER NOT NULL, \n\tprincipal_id VARCHA"
        "R(128) NOT NULL, \n\tauthentication_ref VARCHAR(128) NOT "
        "NULL, \n\tprincipal_epoch INTEGER NOT NULL, \n\tidempotency"
        "_key VARCHAR(128) NOT NULL, \n\tpayload_hash VARCHAR(64) "
        "NOT NULL, \n\trevision INTEGER NOT NULL, \n\tsnapshot JSON "
        "NOT NULL, \n\tinputs JSON NOT NULL, \n\tPRIMARY KEY (id), \n"
        "\tCONSTRAINT attempt_identity UNIQUE (principal_id, idem"
        "potency_key), \n\tCONSTRAINT attempt_revision CHECK (revi"
        "sion >= 1 AND principal_epoch >= 1 AND root_revision >="
        " 1 AND workspace_revision >= 1 AND configuration_revisi"
        "on >= 1), \n\tFOREIGN KEY(project_id) REFERENCES projects"
        " (id), \n\tFOREIGN KEY(task_id) REFERENCES tasks (id), \n\t"
        "FOREIGN KEY(root_id) REFERENCES instruction_roots (id),"
        " \n\tFOREIGN KEY(principal_id) REFERENCES principals (id)"
        "\n)\n\n"
    )
    op.execute("CREATE INDEX ix_attempts_task_id ON attempts (task_id)")
    op.execute("CREATE INDEX ix_attempts_project_id ON attempts (project_id)")
    op.execute(
        "\nCREATE TABLE attempt_manifests (\n\tid VARCHAR(128) NOT "
        "NULL, \n\tattempt_id VARCHAR(128) NOT NULL, \n\tcontent_has"
        "h VARCHAR(64) NOT NULL, \n\tsnapshot JSON NOT NULL, \n\tPRI"
        "MARY KEY (id), \n\tUNIQUE (attempt_id), \n\tFOREIGN KEY(att"
        "empt_id) REFERENCES attempts (id)\n)\n\n"
    )
    op.execute(
        "\nCREATE TABLE attempt_effects (\n\tid VARCHAR(128) NOT NU"
        "LL, \n\tattempt_id VARCHAR(128) NOT NULL, \n\tfence INTEGER"
        " NOT NULL, \n\tkind VARCHAR(30) NOT NULL, \n\tstate VARCHAR"
        "(30) NOT NULL, \n\tsnapshot JSON NOT NULL, \n\tPRIMARY KEY "
        "(id), \n\tCONSTRAINT attempt_effect_fence CHECK (fence >="
        " 1), \n\tCONSTRAINT attempt_effect_state CHECK (state IN "
        "('PREPARED','APPLIED','UNKNOWN')), \n\tFOREIGN KEY(attemp"
        "t_id) REFERENCES attempts (id)\n)\n\n"
    )
    op.execute("CREATE INDEX ix_attempt_effects_attempt_id ON attempt_effects (attempt_id)")
    op.execute(
        "\nCREATE TABLE workspace_leases (\n\troot_id VARCHAR(128) "
        "NOT NULL, \n\tattempt_id VARCHAR(128) NOT NULL, \n\tfence I"
        "NTEGER NOT NULL, \n\tdeadline VARCHAR(40) NOT NULL, \n\tPRI"
        "MARY KEY (root_id), \n\tCONSTRAINT workspace_lease_fence "
        "CHECK (fence >= 1), \n\tFOREIGN KEY(root_id) REFERENCES i"
        "nstruction_roots (id), \n\tFOREIGN KEY(attempt_id) REFERE"
        "NCES attempts (id)\n)\n\n"
    )

    op.execute(
        "\nCREATE TABLE executions (\n\tid VARCHAR(128) NOT NULL, \n"
        "\troot_id VARCHAR(128) NOT NULL, \n\troot_revision INTEGER"
        " NOT NULL, \n\tproject_id VARCHAR(128) NOT NULL, \n\tprinci"
        "pal_id VARCHAR(128) NOT NULL, \n\tauthentication_ref VARC"
        "HAR(128) NOT NULL, \n\tprincipal_epoch INTEGER NOT NULL, "
        "\n\tidempotency_key VARCHAR(128) NOT NULL, \n\tpayload_hash"
        " VARCHAR(64) NOT NULL, \n\trevision INTEGER NOT NULL, \n\ts"
        "tate VARCHAR(30) NOT NULL, \n\tdrained BOOLEAN NOT NULL, "
        "\n\tmemory_bytes INTEGER NOT NULL, \n\tstorage_bytes INTEGE"
        "R NOT NULL, \n\tsnapshot JSON NOT NULL, \n\tinputs JSON NOT"
        " NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT execution_ident"
        "ity UNIQUE (principal_id, idempotency_key), \n\tCONSTRAIN"
        "T execution_revision CHECK (revision >= 1 AND principal"
        "_epoch >= 1 AND root_revision >= 1), \n\tCONSTRAINT execu"
        "tion_resources CHECK (memory_bytes > 0 AND storage_byte"
        "s > 0), \n\tCONSTRAINT execution_drained_boolean CHECK (drained IN (0, 1)), "
        "\n\tCONSTRAINT execution_state CHECK (state IN ('"
        "STARTING','RUNNING','COMPLETED','CANCELLED','UNKNOWN'))"
        ", \n\tFOREIGN KEY(root_id) REFERENCES instruction_roots ("
        "id), \n\tFOREIGN KEY(project_id) REFERENCES projects (id)"
        ", \n\tFOREIGN KEY(principal_id) REFERENCES principals (id"
        ")\n)\n\n"
    )
    op.execute(
        "\nCREATE TABLE execution_manifests (\n\texecution_id VARCH"
        "AR(128) NOT NULL, \n\tcontent_hash VARCHAR(64) NOT NULL, "
        "\n\tsnapshot JSON NOT NULL, \n\tPRIMARY KEY (execution_id),"
        " \n\tFOREIGN KEY(execution_id) REFERENCES executions (id)"
        "\n)\n\n"
    )
    op.execute(
        "\nCREATE TABLE execution_effects (\n\tid VARCHAR(128) NOT "
        "NULL, \n\texecution_id VARCHAR(128) NOT NULL, \n\trevision "
        "INTEGER NOT NULL, \n\tkind VARCHAR(30) NOT NULL, \n\tobserv"
        "ation JSON NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT e"
        "xecution_effect_identity UNIQUE (execution_id, revision"
        ", kind), \n\tCONSTRAINT execution_effect_revision CHECK ("
        "revision >= 1), \n\tCONSTRAINT execution_effect_kind CHEC"
        "K (kind IN ('INTENT','INPUT_BOUND','PREPARING','START_REQUESTED','STARTED','COMPLETED"
        "','UNKNOWN','RECONCILED')), \n\tFOREIGN KEY(execution_id)"
        " REFERENCES executions (id)\n)\n\n"
    )
    op.execute("CREATE INDEX ix_execution_effects_execution_id ON execution_effects (execution_id)")


def downgrade() -> None:
    raise RuntimeError("A coherent authorized restore is required")
