# SPDX-License-Identifier: AGPL-3.0-only
from alembic import op

revision = "0010_work_execution"
down_revision = "0009_instruction_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    ceiling = connection.exec_driver_sql(
        "SELECT seq FROM sqlite_sequence WHERE name='outbox_events'"
    ).scalar()
    for table in ("operation_receipts", "outbox_events", "protected_requests"):
        connection.exec_driver_sql(f"CREATE TEMP TABLE retained_{table} AS SELECT * FROM {table}")
    connection.exec_driver_sql("PRAGMA defer_foreign_keys=ON")
    op.drop_table("outbox_events")
    op.drop_table("operation_receipts")
    op.drop_table("protected_requests")
    op.execute(
        "\nCREATE TABLE operation_receipts (\n\tid VARCHAR(128) NOT NULL, \n\tp"
        "rincipal_id VARCHAR(128) NOT NULL, \n\tcommand VARCHAR(128) NOT NUL"
        "L, \n\tidempotency_key VARCHAR(128) NOT NULL, \n\tpayload_hash VARCHA"
        "R(64) NOT NULL, \n\tproject_id VARCHAR(128), \n\tauthentication_ref V"
        "ARCHAR(128) NOT NULL, \n\tresult JSON NOT NULL, \n\towner VARCHAR(30)"
        " NOT NULL, \n\ttarget_kind VARCHAR(30) NOT NULL, \n\ttarget_id VARCHA"
        "R(128) NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT receipt_target "
        "CHECK ((owner = 'projects' AND target_kind = 'project' AND projec"
        "t_id IS NOT NULL AND target_id = project_id) OR (owner = 'identit"
        "y' AND target_kind = 'passkey' AND project_id IS NULL) OR (owner "
        "= 'work' AND target_kind = 'task' AND project_id IS NOT NULL) OR "
        "(owner = 'agents' AND target_kind IN ('profile', 'bot', 'team') A"
        "ND project_id IS NULL) OR (owner = 'instructions' AND target_kind"
        " = 'instruction_bundle' AND project_id IS NOT NULL) OR (owner = '"
        "project_instructions' AND ((target_kind = 'project_instructions' "
        "AND project_id IS NOT NULL AND project_id = target_id) OR (target"
        "_kind IN ('instruction_root','instruction_install') AND project_i"
        "d IS NULL))) OR (owner = 'jobs' AND target_kind = 'job' AND proje"
        "ct_id IS NOT NULL) OR (owner = 'lifecycle' AND target_kind = 'sto"
        "re' AND project_id IS NULL)), \n\tFOREIGN KEY(principal_id) REFEREN"
        "CES principals (id), \n\tFOREIGN KEY(project_id) REFERENCES project"
        "s (id)\n)\n\n"
    )
    op.execute(
        "CREATE UNIQUE INDEX receipt_operation_identity ON operation_recei"
        "pts (principal_id, command, idempotency_key)"
    )
    op.execute(
        "\nCREATE TABLE outbox_events (\n\tsequence INTEGER NOT NULL PRIMARY "
        "KEY AUTOINCREMENT, \n\tevent_id VARCHAR(128) NOT NULL, \n\toperation_"
        "id VARCHAR(128) NOT NULL, \n\tevent_type VARCHAR(128) NOT NULL, \n\ts"
        "chema_version INTEGER NOT NULL, \n\tprincipal_id VARCHAR(128) NOT N"
        "ULL, \n\tproject_id VARCHAR(128), \n\towner VARCHAR(30) NOT NULL, \n\tt"
        "arget_kind VARCHAR(30) NOT NULL, \n\ttarget_id VARCHAR(128) NOT NUL"
        "L, \n\tcommitted_at VARCHAR(40) NOT NULL, \n\ttarget_revision INTEGER"
        " NOT NULL, \n\tpayload JSON NOT NULL, \n\tCONSTRAINT event_target_rev"
        "ision CHECK (target_revision >= 1 OR (target_revision = 0 AND own"
        "er = 'project_instructions' AND target_kind = 'project_instructio"
        "ns' AND event_type = 'project.instructions.bind.abandoned')), \n\tC"
        "ONSTRAINT event_target CHECK ((owner = 'projects' AND target_kind"
        " = 'project' AND project_id IS NOT NULL AND target_id = project_i"
        "d) OR (owner = 'identity' AND target_kind = 'passkey' AND project"
        "_id IS NULL) OR (owner = 'work' AND target_kind = 'task' AND proj"
        "ect_id IS NOT NULL) OR (owner = 'agents' AND target_kind IN ('pro"
        "file', 'bot', 'team') AND project_id IS NULL) OR (owner = 'instru"
        "ctions' AND target_kind = 'instruction_bundle' AND project_id IS "
        "NOT NULL) OR (owner = 'project_instructions' AND ((target_kind = "
        "'project_instructions' AND project_id IS NOT NULL AND project_id "
        "= target_id) OR (target_kind IN ('instruction_root','instruction_"
        "install') AND project_id IS NULL))) OR (owner = 'jobs' AND target"
        "_kind = 'job' AND project_id IS NOT NULL) OR (owner = 'lifecycle'"
        " AND target_kind = 'store' AND project_id IS NULL)), \n\tUNIQUE (ev"
        "ent_id), \n\tUNIQUE (operation_id), \n\tFOREIGN KEY(operation_id) REF"
        "ERENCES operation_receipts (id), \n\tFOREIGN KEY(principal_id) REFE"
        "RENCES principals (id), \n\tFOREIGN KEY(project_id) REFERENCES proj"
        "ects (id)\n)\n\n"
    )
    op.execute(
        "\nCREATE TABLE protected_requests (\n\tid VARCHAR(128) NOT NULL, \n\to"
        "peration_id VARCHAR(128) NOT NULL, \n\tprincipal_id VARCHAR(128) NO"
        "T NULL, \n\tprincipal_epoch INTEGER NOT NULL, \n\tsession_id VARCHAR("
        "128) NOT NULL, \n\tidempotency_key VARCHAR(128) NOT NULL, \n\tcommand"
        " VARCHAR(128) NOT NULL, \n\tpayload JSON NOT NULL, \n\tpayload_hash V"
        "ARCHAR(64) NOT NULL, \n\tcredential_revision INTEGER NOT NULL, \n\tpo"
        "licy_hash VARCHAR(64) NOT NULL, \n\tissued_at INTEGER NOT NULL, \n\td"
        "eadline INTEGER NOT NULL, \n\tstate VARCHAR(16) NOT NULL, \n\tapprove"
        "d_at INTEGER, \n\tapproval_deadline INTEGER, \n\tstrong_authenticated"
        "_at INTEGER, \n\tnonce_hash VARCHAR(64), \n\tnonce_deadline INTEGER, "
        "\n\tPRIMARY KEY (id), \n\tCONSTRAINT protected_state CHECK (state IN "
        "('PENDING', 'APPROVED', 'COMMITTED', 'CANCELLED', 'EXPIRED', 'INV"
        "ALIDATED')), \n\tCONSTRAINT protected_deadline CHECK (deadline > is"
        "sued_at AND issued_at >= 0), \n\tCONSTRAINT protected_command CHECK"
        " (command IN ('passkey.label.v1','project.root.admit.v1','project"
        ".root.revoke.v1','project.instructions.policy.configure.v1','inst"
        "ruction.candidate.register.v1','instruction.release.install.v1','"
        "project.instructions.accept.v1', 'project.instructions.recover.v1"
        "', 'lifecycle.restore.authorize.v1')), \n\tUNIQUE (operation_id), \n"
        "\tFOREIGN KEY(principal_id) REFERENCES principals (id), \n\tFOREIGN "
        "KEY(session_id) REFERENCES browser_sessions (id)\n)\n\n"
    )
    op.execute(
        "CREATE UNIQUE INDEX protected_operation_identity ON protected_req"
        "uests (principal_id, command, idempotency_key)"
    )
    op.execute(
        "\nCREATE TABLE store_identity (\n\tid INTEGER NOT NULL, \n\tstore_id V"
        "ARCHAR(128) NOT NULL, \n\tincarnation VARCHAR(128) NOT NULL, \n\trest"
        "ore_operation VARCHAR(128), \n\tdestination TEXT NOT NULL, \n\tsecuri"
        "ty_reconciled BOOLEAN NOT NULL, \n\tPRIMARY KEY (id),\n\tCONSTRAINT s"
        "tore_security_boolean CHECK (security_reconciled IN (0, 1)), \n\tCO"
        "NSTRAINT single_store_identity CHECK (id = 1)\n)\n\n"
    )
    op.execute(
        "\nCREATE TABLE jobs (\n\tid VARCHAR(128) NOT NULL, \n\tkind VARCHAR(40"
        ") NOT NULL, \n\tproject_id VARCHAR(128) NOT NULL, \n\tcandidate_id VA"
        "RCHAR(128) NOT NULL, \n\tinput_hash VARCHAR(64) NOT NULL, \n\tbinding"
        "_revision INTEGER NOT NULL, \n\tpolicy_revision INTEGER NOT NULL, \n"
        "\tprincipal_id VARCHAR(128) NOT NULL, \n\tprincipal_epoch INTEGER NO"
        "T NULL, \n\tsession_id VARCHAR(128) NOT NULL, \n\trevision INTEGER NO"
        "T NULL, \n\tstate VARCHAR(16) NOT NULL, \n\tfence INTEGER NOT NULL, \n"
        "\tclaim_owner VARCHAR(128), \n\tincarnation VARCHAR(128) NOT NULL, \n"
        "\tlease_deadline INTEGER, \n\tdue_at INTEGER NOT NULL, \n\tattempts IN"
        "TEGER NOT NULL, \n\tcancel_requested BOOLEAN NOT NULL, \n\treason VAR"
        "CHAR(128), \n\teffect VARCHAR(16) NOT NULL, \n\toperation_id VARCHAR("
        "128), \n\tadmission_id VARCHAR(128) NOT NULL, \n\tevidence_id VARCHAR"
        "(128), \n\tbyte_count INTEGER NOT NULL, \n\tPRIMARY KEY (id),\n\tCONSTR"
        "AINT job_cancel_boolean CHECK (cancel_requested IN (0, 1)), \n\tCON"
        "STRAINT job_kind CHECK (kind = 'INSTRUCTION_NAVIGATION'), \n\tCONST"
        "RAINT job_state CHECK (state IN ('QUEUED','RUNNING','SUCCEEDED','"
        "FAILED','CANCELLED','RETRY_WAIT')), \n\tCONSTRAINT job_effect CHECK"
        " (effect IN ('NONE','UNKNOWN','COMMITTED','ABANDONED')), \n\tCONSTR"
        "AINT job_versions CHECK (revision >= 1 AND fence >= 0 AND attempt"
        "s >= 0), \n\tFOREIGN KEY(project_id) REFERENCES projects (id), \n\tUN"
        "IQUE (candidate_id), \n\tFOREIGN KEY(candidate_id) REFERENCES instr"
        "uction_candidates (id), \n\tFOREIGN KEY(principal_id) REFERENCES pr"
        "incipals (id), \n\tFOREIGN KEY(session_id) REFERENCES browser_sessi"
        "ons (id), \n\tUNIQUE (operation_id), \n\tUNIQUE (admission_id)\n)\n\n"
    )
    op.execute(
        "\nCREATE TABLE attention (\n\tid VARCHAR(128) NOT NULL, \n\tjob_id VAR"
        "CHAR(128) NOT NULL, \n\tproject_id VARCHAR(128) NOT NULL, \n\treason "
        "VARCHAR(128) NOT NULL, \n\toccurrences INTEGER NOT NULL, \n\tdisposit"
        "ion VARCHAR(16) NOT NULL, \n\thistory JSON NOT NULL, \n\tPRIMARY KEY "
        "(id), \n\tCONSTRAINT attention_source_reason UNIQUE (job_id, reason"
        "), \n\tCONSTRAINT attention_disposition CHECK (disposition IN ('OPE"
        "N','DISMISSED','RESOLVED')), \n\tFOREIGN KEY(job_id) REFERENCES job"
        "s (id), \n\tFOREIGN KEY(project_id) REFERENCES projects (id)\n)\n\n"
    )
    op.execute(
        "\nCREATE TABLE restore_request_scopes (\n\trequest_id VARCHAR(128) N"
        "OT NULL, \n\tproject_id VARCHAR(128) NOT NULL, \n\tPRIMARY KEY (reque"
        "st_id, project_id), \n\tFOREIGN KEY(request_id) REFERENCES protecte"
        "d_requests (id), \n\tFOREIGN KEY(project_id) REFERENCES projects (i"
        "d)\n)\n\n"
    )
    columns = {
        "operation_receipts": "id,principal_id,command,idempotency_key,payload_hash,project_id,"
        "authentication_ref,result,owner,target_kind,target_id",
        "outbox_events": "sequence,event_id,operation_id,event_type,schema_version,principal_id,"
        "project_id,owner,target_kind,target_id,committed_at,target_revision,payload",
        "protected_requests": "id,operation_id,principal_id,principal_epoch,session_id,"
        "idempotency_key,command,payload,payload_hash,credential_revision,policy_hash,issued_at,"
        "deadline,state,approved_at,approval_deadline,strong_authenticated_at,nonce_hash,nonce_deadline",
    }
    for table, names in columns.items():
        connection.exec_driver_sql(
            f"INSERT INTO {table} ({names}) SELECT {names} FROM retained_{table}"
        )
        connection.exec_driver_sql(f"DROP TABLE retained_{table}")
    if ceiling is not None:
        connection.exec_driver_sql(
            "UPDATE sqlite_sequence SET seq=MAX(seq,?) WHERE name='outbox_events'", (ceiling,)
        )
    from uuid import uuid4

    destination = next(
        row[2] for row in connection.exec_driver_sql("PRAGMA database_list") if row[1] == "main"
    )
    connection.exec_driver_sql(
        "INSERT INTO store_identity (id,store_id,incarnation,destination,security_reconciled) "
        "VALUES (1,?,?,?,1)",
        (str(uuid4()), str(uuid4()), destination),
    )


def downgrade() -> None:
    raise RuntimeError("A coherent authorized restore is required")
