# SPDX-License-Identifier: AGPL-3.0-only
"Preserve the coherent instruction, identity and receipt store while extending ownership."

from alembic import op

revision = "0008_project_instructions"
down_revision = "0007_identity_instructions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE TEMP TABLE retained_event_ceiling AS SELECT seq FROM sqlit"
        "e_sequence WHERE name='outbox_events'"
    )
    op.execute("CREATE TEMP TABLE retained_principals AS SELECT * FROM principals")
    op.execute("CREATE TEMP TABLE retained_access_grants AS SELECT * FROM access_grants")
    op.execute("CREATE TEMP TABLE retained_deployment_policy AS SELECT * FROM deployment_policy")
    op.execute("CREATE TEMP TABLE retained_projects AS SELECT * FROM projects")
    op.execute("CREATE TEMP TABLE retained_operation_receipts AS SELECT * FROM operation_receipts")
    op.execute("CREATE TEMP TABLE retained_outbox_events AS SELECT * FROM outbox_events")
    op.execute("CREATE TEMP TABLE retained_browser_sessions AS SELECT * FROM browser_sessions")
    op.execute("CREATE TEMP TABLE retained_identity_state AS SELECT * FROM identity_state")
    op.execute("CREATE TEMP TABLE retained_passkeys AS SELECT * FROM passkeys")
    op.execute("CREATE TEMP TABLE retained_auth_ceremonies AS SELECT * FROM auth_ceremonies")
    op.execute("CREATE TEMP TABLE retained_auth_rates AS SELECT * FROM auth_rates")
    op.execute("CREATE TEMP TABLE retained_auth_rate_events AS SELECT * FROM auth_rate_events")
    op.execute("CREATE TEMP TABLE retained_protected_requests AS SELECT * FROM protected_requests")
    op.execute("CREATE TEMP TABLE retained_tasks AS SELECT * FROM tasks")
    op.execute("CREATE TEMP TABLE retained_agent_profiles AS SELECT * FROM agent_profiles")
    op.execute("CREATE TEMP TABLE retained_profile_revisions AS SELECT * FROM profile_revisions")
    op.execute("CREATE TEMP TABLE retained_bots AS SELECT * FROM bots")
    op.execute("CREATE TEMP TABLE retained_bot_revisions AS SELECT * FROM bot_revisions")
    op.execute("CREATE TEMP TABLE retained_teams AS SELECT * FROM teams")
    op.execute("CREATE TEMP TABLE retained_instruction_assets AS SELECT * FROM instruction_assets")
    op.execute(
        "CREATE TEMP TABLE retained_instruction_revisions AS SELECT * FROM instruction_revisions"
    )
    op.execute(
        "CREATE TEMP TABLE retained_instruction_bundles AS SELECT * FROM instruction_bundles"
    )
    op.execute("PRAGMA defer_foreign_keys=ON")
    op.drop_table("outbox_events")
    op.drop_table("instruction_bundles")
    op.drop_table("teams")
    op.drop_table("tasks")
    op.drop_table("protected_requests")
    op.drop_table("operation_receipts")
    op.drop_table("bot_revisions")
    op.drop_table("auth_ceremonies")
    op.drop_table("projects")
    op.drop_table("profile_revisions")
    op.drop_table("passkeys")
    op.drop_table("instruction_revisions")
    op.drop_table("identity_state")
    op.drop_table("deployment_policy")
    op.drop_table("browser_sessions")
    op.drop_table("bots")
    op.drop_table("access_grants")
    op.drop_table("principals")
    op.drop_table("instruction_assets")
    op.drop_table("auth_rates")
    op.drop_table("auth_rate_events")
    op.drop_table("agent_profiles")
    op.execute(
        "CREATE TABLE agent_profiles (         id VARCHAR(128) NOT NULL, r"
        "evision INTEGER NOT NULL,          name VARCHAR(200) NOT NULL, PR"
        "IMARY KEY (id),          CONSTRAINT profile_revision CHECK (revis"
        "ion >= 1) )"
    )
    op.execute(
        "CREATE TABLE auth_rate_events (\n\tid INTEGER NOT NULL, \n\tbucket VA"
        "RCHAR(128) NOT NULL, \n\tobserved_at INTEGER NOT NULL, \n\texpires_at"
        " INTEGER, \n\tweight INTEGER NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTR"
        "AINT rate_event_values CHECK (observed_at >= 0 AND weight > 0), \n"
        "\tCONSTRAINT rate_event_expiry CHECK (expires_at IS NULL OR expire"
        "s_at > observed_at)\n)"
    )
    op.execute(
        'CREATE TABLE auth_rates (\n\t"key" VARCHAR(64) NOT NULL, \n\twindow_s'
        "tart INTEGER NOT NULL, \n\tlast_observed INTEGER NOT NULL, \n\tcount "
        'INTEGER NOT NULL, \n\tPRIMARY KEY ("key"), \n\tCONSTRAINT auth_rate_s'
        "tate CHECK (count >= 0 AND last_observed >= window_start)\n)"
    )
    op.execute(
        "CREATE TABLE instruction_assets (         id VARCHAR(128) NOT NUL"
        "L, owner_kind VARCHAR(30) NOT NULL,          owner_id VARCHAR(128"
        ") NOT NULL,          purpose VARCHAR(30) NOT NULL,          trust"
        " VARCHAR(30) NOT NULL,          revision INTEGER NOT NULL,       "
        "   PRIMARY KEY (id), CONSTRAINT asset_revision CHECK (revision >="
        " 1),          CONSTRAINT asset_purpose CHECK (purpose IN ('CORE',"
        " 'NAVIGATION', 'PROFILE', 'BOT', 'PROJECT', 'SKILLS', 'TASK', 'WO"
        "RKFLOW')),          CONSTRAINT asset_trust CHECK (trust IN ('PROT"
        "ECTED', 'CONFIGURATION')), CONSTRAINT asset_protected_owner CHECK"
        " ((purpose IN ('CORE', 'NAVIGATION') AND owner_kind = 'system' AN"
        "D trust = 'PROTECTED') OR (purpose NOT IN ('CORE', 'NAVIGATION') "
        "AND trust = 'CONFIGURATION')) )"
    )
    op.execute(
        "\nCREATE TABLE instruction_installations (\n\tid INTEGER NOT NULL, \n"
        "\trevision INTEGER NOT NULL, \n\tmanifest_digest VARCHAR(64) NOT NUL"
        "L, \n\tprovenance VARCHAR(30) NOT NULL, \n\tsnapshot JSON NOT NULL, \n"
        "\tPRIMARY KEY (id), \n\tCONSTRAINT installation_revision CHECK (id ="
        " 1 AND revision >= 1), \n\tCONSTRAINT installation_provenance CHECK"
        " (provenance IN ('DEVELOPMENT_CANDIDATE','VERIFIED_RELEASE'))\n)\n\n"
    )
    op.execute(
        "CREATE TABLE principals (\n\tid VARCHAR(128) NOT NULL, \n\trole VARCH"
        "AR(20) NOT NULL, \n\tenabled BOOLEAN NOT NULL, \n\tauthorization_epoc"
        "h INTEGER NOT NULL, credential_revision INTEGER DEFAULT '1' NOT N"
        "ULL CONSTRAINT principal_credential_revision CHECK (credential_re"
        "vision >= 1), \n\tPRIMARY KEY (id), \n\tCONSTRAINT principal_role CHE"
        "CK (role IN ('OWNER', 'SHARED_USER')), \n\tCONSTRAINT principal_epo"
        "ch CHECK (authorization_epoch >= 1), \n\tCONSTRAINT principal_enabl"
        "ed_boolean CHECK (enabled IN (0, 1))\n)"
    )
    op.execute(
        'CREATE TABLE "access_grants" (\n\tid VARCHAR(128) NOT NULL, \n\tprinc'
        "ipal_id VARCHAR(128) NOT NULL, \n\tcapability VARCHAR(128) NOT NULL"
        ", \n\tresource_kind VARCHAR(30) NOT NULL, \n\tresource_id VARCHAR(128"
        ") NOT NULL, \n\tenabled BOOLEAN NOT NULL, \n\trevision INTEGER NOT NU"
        "LL, \n\texpires_at VARCHAR(40), \n\tprovenance VARCHAR(128) NOT NULL,"
        " \n\tPRIMARY KEY (id), \n\tCONSTRAINT grant_revision CHECK (revision "
        ">= 1), \n\tCONSTRAINT grant_enabled_boolean CHECK (enabled IN (0, 1"
        ")), \n\tCONSTRAINT grant_resource_kind CHECK (resource_kind IN ('de"
        "ployment', 'project', 'profile', 'bot', 'team', 'instruction_bund"
        "le', 'legacy_collection')), \n\tFOREIGN KEY(principal_id) REFERENCE"
        "S principals (id)\n)"
    )
    op.execute(
        "CREATE TABLE bots (         id VARCHAR(128) NOT NULL, profile_id "
        "VARCHAR(128) NOT NULL,          team_id VARCHAR(128), revision IN"
        "TEGER NOT NULL,          namespace_ref VARCHAR(128) NOT NULL, mem"
        "ory_enabled BOOLEAN NOT NULL,          builtin_role VARCHAR(20), "
        "snapshot JSON NOT NULL,          PRIMARY KEY (id),          CONST"
        "RAINT bot_revision CHECK (revision >= 1),          CONSTRAINT bot"
        "_team_identity UNIQUE (id, team_id),          CONSTRAINT bot_name"
        "space CHECK (namespace_ref = 'bot:' || id),          CONSTRAINT b"
        "ot_memory_boolean CHECK (memory_enabled IN (0, 1)),          CONS"
        "TRAINT bot_fixed_memory CHECK (builtin_role IS NULL OR (builtin_r"
        "ole IN ('RESEARCHER', 'LIBRARIAN') AND memory_enabled = 0)),     "
        "     FOREIGN KEY(profile_id) REFERENCES agent_profiles (id),     "
        "     FOREIGN KEY(team_id) REFERENCES teams (id) DEFERRABLE INITIA"
        "LLY DEFERRED, UNIQUE (namespace_ref) )"
    )
    op.execute(
        "CREATE TABLE browser_sessions (\n\tid VARCHAR(128) NOT NULL, \n\ttoke"
        "n_hash VARCHAR(64) NOT NULL, \n\tcsrf_hash VARCHAR(64) NOT NULL, \n\t"
        "principal_id VARCHAR(128) NOT NULL, \n\tprincipal_epoch INTEGER NOT"
        " NULL, \n\tauthentication_method VARCHAR(128) NOT NULL, \n\tclient_la"
        "bel VARCHAR(128) NOT NULL, \n\tissued_at INTEGER NOT NULL, \n\tlast_a"
        "ctivity INTEGER NOT NULL, \n\tlast_observed INTEGER NOT NULL, \n\tabs"
        "olute_deadline INTEGER NOT NULL, \n\tinactivity_seconds INTEGER NOT"
        " NULL, \n\tstrong_authenticated_at INTEGER, \n\tstrong_freshness_seco"
        "nds INTEGER NOT NULL, \n\trevoked BOOLEAN NOT NULL, audience VARCHA"
        "R(30) DEFAULT 'unknown' NOT NULL CONSTRAINT session_audience CHEC"
        "K (audience IN ('unknown', 'official_browser')), \n\tPRIMARY KEY (i"
        "d), \n\tCONSTRAINT session_principal_epoch CHECK (principal_epoch >"
        "= 1), \n\tCONSTRAINT session_revoked_boolean CHECK (revoked IN (0, "
        "1)), \n\tCONSTRAINT session_deadline CHECK (issued_at >= 0 AND abso"
        "lute_deadline > issued_at), \n\tCONSTRAINT session_activity_order C"
        "HECK (last_observed >= last_activity AND last_activity >= issued_"
        "at), \n\tCONSTRAINT session_inactivity CHECK (inactivity_seconds > "
        "0), \n\tCONSTRAINT session_strong_freshness CHECK (strong_freshness"
        "_seconds > 0), \n\tCONSTRAINT session_strong_time CHECK (strong_aut"
        "henticated_at IS NULL OR (strong_authenticated_at >= issued_at AN"
        "D strong_authenticated_at <= last_observed)), \n\tUNIQUE (token_has"
        "h), \n\tFOREIGN KEY(principal_id) REFERENCES principals (id)\n)"
    )
    op.execute(
        "CREATE TABLE deployment_policy (\n\tid INTEGER NOT NULL, \n\trevision"
        " INTEGER NOT NULL, \n\tapproval_id VARCHAR(128), \n\tapproved_by VARC"
        "HAR(128), \n\tapproved_providers JSON NOT NULL, \n\tverification_poli"
        "cy_ref VARCHAR(128), \n\tPRIMARY KEY (id), \n\tCONSTRAINT approval_at"
        "tribution CHECK ((approval_id IS NULL AND approved_by IS NULL) OR"
        " (approval_id IS NOT NULL AND approved_by IS NOT NULL)), \n\tCONSTR"
        "AINT single_deployment_policy CHECK (id = 1), \n\tCONSTRAINT policy"
        "_revision CHECK (revision >= 1), \n\tFOREIGN KEY(approved_by) REFER"
        "ENCES principals (id)\n)"
    )
    op.execute(
        "CREATE TABLE identity_state (\n\tid INTEGER NOT NULL, \n\tlast_observ"
        "ed INTEGER NOT NULL, \n\towner_id VARCHAR(128), \n\tpending_principal"
        "_id VARCHAR(128), \n\tenrollment_hash VARCHAR(64), \n\tenrollment_dea"
        "dline INTEGER, rate_policy JSON, \n\tPRIMARY KEY (id), \n\tCONSTRAINT"
        " single_identity_state CHECK (id = 1), \n\tFOREIGN KEY(owner_id) RE"
        "FERENCES principals (id)\n)"
    )
    op.execute(
        "\nCREATE TABLE installed_release_evidence (\n\tid VARCHAR(128) NOT N"
        "ULL, \n\tprincipal_id VARCHAR(128) NOT NULL, \n\tmanifest_digest VARC"
        "HAR(64) NOT NULL, \n\tsnapshot JSON NOT NULL, \n\tPRIMARY KEY (id), \n"
        "\tFOREIGN KEY(principal_id) REFERENCES principals (id)\n)\n\n"
    )
    op.execute(
        "CREATE TABLE instruction_revisions (         asset_id VARCHAR(128"
        ") NOT NULL,          revision INTEGER NOT NULL,          template"
        " JSON NOT NULL,          content_hash VARCHAR(64) NOT NULL,      "
        "    previous_hash VARCHAR(64),          author VARCHAR(128) NOT N"
        "ULL,          reason VARCHAR(200) NOT NULL,          created_at V"
        "ARCHAR(40) NOT NULL, PRIMARY KEY (asset_id, revision),          C"
        "ONSTRAINT instruction_revision CHECK (revision >= 1),          FO"
        "REIGN KEY(asset_id) REFERENCES instruction_assets (id),          "
        "FOREIGN KEY(author) REFERENCES principals (id) )"
    )
    op.execute(
        "CREATE TABLE passkeys (\n\tid VARCHAR(128) NOT NULL, \n\tcredential_i"
        "d TEXT NOT NULL, \n\tcredential_data TEXT NOT NULL, \n\tprincipal_id "
        "VARCHAR(128) NOT NULL, \n\tlabel VARCHAR(128) NOT NULL, \n\tsign_coun"
        "t INTEGER NOT NULL, \n\tbackup_eligible BOOLEAN NOT NULL, \n\tbacked_"
        "up BOOLEAN NOT NULL, \n\trevoked BOOLEAN NOT NULL, revision INTEGER"
        " DEFAULT '1' NOT NULL CONSTRAINT passkey_revision CHECK (revision"
        " >= 1), \n\tPRIMARY KEY (id), \n\tCONSTRAINT passkey_backup_state CHE"
        "CK (backed_up = 0 OR backup_eligible = 1), \n\tCONSTRAINT passkey_b"
        "ackup_boolean CHECK (backed_up IN (0, 1)), \n\tCONSTRAINT passkey_e"
        "ligible_boolean CHECK (backup_eligible IN (0, 1)), \n\tCONSTRAINT p"
        "asskey_revoked_boolean CHECK (revoked IN (0, 1)), \n\tCONSTRAINT pa"
        "sskey_counter CHECK (sign_count >= 0), \n\tFOREIGN KEY(principal_id"
        ") REFERENCES principals (id), \n\tUNIQUE (credential_id)\n)"
    )
    op.execute(
        "CREATE TABLE profile_revisions (         profile_id VARCHAR(128) "
        "NOT NULL,          revision INTEGER NOT NULL,          snapshot J"
        "SON NOT NULL,          author VARCHAR(128) NOT NULL,          rea"
        "son VARCHAR(200) NOT NULL,          content_hash VARCHAR(64) NOT "
        "NULL, created_at VARCHAR(40) NOT NULL,          PRIMARY KEY (prof"
        "ile_id, revision),          CONSTRAINT profile_history_revision C"
        "HECK (revision >= 1),          FOREIGN KEY(profile_id) REFERENCES"
        " agent_profiles (id), FOREIGN KEY(author) REFERENCES principals ("
        "id) )"
    )
    op.execute(
        "CREATE TABLE projects (\n\tid VARCHAR(128) NOT NULL, \n\trevision INT"
        "EGER NOT NULL, \n\tname VARCHAR(200) NOT NULL, \n\tdescription TEXT N"
        "OT NULL, \n\tcreated_by VARCHAR(128) NOT NULL, \n\tinstruction_owner "
        "VARCHAR(30) NOT NULL, \n\tinstruction_authority_ref VARCHAR(128) NO"
        "T NULL, \n\tprovider_snapshot JSON NOT NULL, \n\tverification_policy_"
        "ref VARCHAR(128), \n\tresource_refs JSON NOT NULL, \n\tcreated_at VAR"
        "CHAR(40) NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT instruction_o"
        "wner CHECK (instruction_owner IN ('ENVIRONMENT','PROJECT')), \n\tCO"
        "NSTRAINT project_revision CHECK (revision >= 1), \n\tFOREIGN KEY(cr"
        "eated_by) REFERENCES principals (id), \n\tUNIQUE (instruction_autho"
        "rity_ref)\n)"
    )
    op.execute(
        "CREATE TABLE auth_ceremonies (\n\tid VARCHAR(128) NOT NULL, \n\tpurpo"
        "se VARCHAR(16) NOT NULL, \n\tsubject_id VARCHAR(128), \n\tsession_id "
        "VARCHAR(128), \n\tenrollment_hash VARCHAR(64), \n\tlabel VARCHAR(128)"
        " NOT NULL, \n\tstate JSON NOT NULL, \n\tissued_at INTEGER NOT NULL, \n"
        "\tlast_observed INTEGER NOT NULL, \n\tdeadline INTEGER NOT NULL, \n\ta"
        "ttempts INTEGER NOT NULL, \n\tconsumed BOOLEAN NOT NULL, \n\tPRIMARY "
        "KEY (id), \n\tCONSTRAINT ceremony_purpose CHECK (purpose IN ('boots"
        "trap', 'login', 'stepup', 'add')), \n\tCONSTRAINT ceremony_attempts"
        " CHECK (attempts >= 0), \n\tCONSTRAINT ceremony_consumed_boolean CH"
        "ECK (consumed IN (0, 1)), \n\tCONSTRAINT ceremony_time CHECK (deadl"
        "ine > issued_at AND last_observed >= issued_at), \n\tFOREIGN KEY(se"
        "ssion_id) REFERENCES browser_sessions (id)\n)"
    )
    op.execute(
        "CREATE TABLE bot_revisions (         bot_id VARCHAR(128) NOT NULL"
        ", revision INTEGER NOT NULL,          snapshot JSON NOT NULL, aut"
        "hor VARCHAR(128) NOT NULL,          reason VARCHAR(200) NOT NULL,"
        " content_hash VARCHAR(64) NOT NULL,          created_at VARCHAR(4"
        "0) NOT NULL,          PRIMARY KEY (bot_id, revision),          CO"
        "NSTRAINT bot_history_revision CHECK (revision >= 1),          FOR"
        "EIGN KEY(bot_id) REFERENCES bots (id),          FOREIGN KEY(autho"
        "r) REFERENCES principals (id) )"
    )
    op.execute(
        "\nCREATE TABLE instruction_candidates (\n\tid VARCHAR(128) NOT NULL,"
        " \n\tproject_id VARCHAR(128) NOT NULL, \n\tprincipal_id VARCHAR(128) "
        "NOT NULL, \n\tidempotency_key VARCHAR(128) NOT NULL, \n\tpayload_hash"
        " VARCHAR(64) NOT NULL, \n\tsnapshot JSON NOT NULL, \n\tPRIMARY KEY (i"
        "d), \n\tCONSTRAINT instruction_candidate_identity UNIQUE (principal"
        "_id, project_id, idempotency_key), \n\tFOREIGN KEY(project_id) REFE"
        "RENCES projects (id), \n\tFOREIGN KEY(principal_id) REFERENCES prin"
        "cipals (id)\n)\n\n"
    )
    op.execute(
        "\nCREATE TABLE instruction_publications (\n\tid VARCHAR(128) NOT NUL"
        "L, \n\tproject_id VARCHAR(128) NOT NULL, \n\tprincipal_id VARCHAR(128"
        ") NOT NULL, \n\tauthentication_ref VARCHAR(128) NOT NULL, \n\tprincip"
        "al_epoch INTEGER NOT NULL, \n\tgeneration INTEGER NOT NULL, \n\tidemp"
        "otency_key VARCHAR(128) NOT NULL, \n\tpayload_hash VARCHAR(64) NOT "
        "NULL, \n\tstatus VARCHAR(30) NOT NULL, \n\tsnapshot JSON NOT NULL, \n\t"
        "PRIMARY KEY (id), \n\tCONSTRAINT publication_identity UNIQUE (princ"
        "ipal_id, project_id, idempotency_key), \n\tCONSTRAINT publication_s"
        "tatus CHECK (status IN ('PENDING','RECOVERY_NEEDED','CONFLICT','C"
        "ANONICAL_COMMITTED','ABANDONED')), \n\tFOREIGN KEY(project_id) REFERENCES proje"
        "cts (id), \n\tFOREIGN KEY(principal_id) REFERENCES principals (id)\n"
        ")\n\n"
    )
    op.execute(
        "CREATE TABLE instruction_roots (\n\tid VARCHAR(128) NOT NULL, \n\troo"
        "t_key VARCHAR(128) NOT NULL, \n\trevision INTEGER NOT NULL, \n\tconfi"
        "g_revision INTEGER NOT NULL, \n\tproject_id VARCHAR(128), \n\trole VA"
        "RCHAR(20) NOT NULL, \n\tdevice INTEGER NOT NULL, \n\tinode INTEGER NO"
        "T NULL, \n\tgit_identity VARCHAR(64) NOT NULL, \n\tenabled BOOLEAN NO"
        "T NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT root_revision CHECK (rev"
        "ision >= 1 AND config_revision >= 1), \n\tCONSTRAINT root_role CHEC"
        "K (role IN ('ENVIRONMENT','PROJECT')), \n\tCONSTRAINT root_enabled "
        "CHECK (enabled IN (0, 1)), \n\tUNIQUE (root_key), \n\tFOREIGN KEY(proj"
        "ect_id) REFERENCES projects (id)\n)"
    )
    op.execute(
        'CREATE TABLE "operation_receipts" (\n\tid VARCHAR(128) NOT NULL, \n\t'
        "principal_id VARCHAR(128) NOT NULL, \n\tcommand VARCHAR(128) NOT NU"
        "LL, \n\tidempotency_key VARCHAR(128) NOT NULL, \n\tpayload_hash VARCH"
        "AR(64) NOT NULL, \n\tproject_id VARCHAR(128), \n\tauthentication_ref "
        "VARCHAR(128) NOT NULL, \n\tresult JSON NOT NULL, \n\towner VARCHAR(30"
        ") DEFAULT 'projects' NOT NULL, \n\ttarget_kind VARCHAR(30) DEFAULT "
        "'project' NOT NULL, \n\ttarget_id VARCHAR(128) NOT NULL, \n\tPRIMARY "
        "KEY (id), \n\tCONSTRAINT receipt_target CHECK ((owner = 'projects' "
        "AND target_kind = 'project' AND project_id IS NOT NULL AND target"
        "_id = project_id) OR (owner = 'identity' AND target_kind = 'passk"
        "ey' AND project_id IS NULL) OR (owner = 'work' AND target_kind = "
        "'task' AND project_id IS NOT NULL) OR (owner = 'agents' AND targe"
        "t_kind IN ('profile', 'bot', 'team') AND project_id IS NULL) OR ("
        "owner = 'instructions' AND target_kind = 'instruction_bundle' AND"
        " project_id IS NOT NULL) OR (owner = 'project_instructions' AND ("
        "(target_kind = 'project_instructions' AND project_id = target_id)"
        " OR (target_kind IN ('instruction_root','instruction_install') AN"
        "D project_id IS NULL)))), \n\tFOREIGN KEY(principal_id) REFERENCES "
        "principals (id), \n\tFOREIGN KEY(project_id) REFERENCES projects (i"
        "d)\n)"
    )
    op.execute(
        "\nCREATE TABLE project_instruction_policies (\n\tproject_id VARCHAR("
        "128) NOT NULL, \n\trevision INTEGER NOT NULL, \n\tsnapshot JSON NOT N"
        "ULL, \n\tauthor VARCHAR(128) NOT NULL, \n\tPRIMARY KEY (project_id, r"
        "evision), \n\tCONSTRAINT instruction_policy_revision CHECK (revisio"
        "n >= 1), \n\tFOREIGN KEY(project_id) REFERENCES projects (id), \n\tFO"
        "REIGN KEY(author) REFERENCES principals (id)\n)\n\n"
    )
    op.execute(
        "\nCREATE TABLE project_instruction_revisions (\n\tproject_id VARCHAR"
        "(128) NOT NULL, \n\trevision INTEGER NOT NULL, \n\tsnapshot JSON NOT "
        "NULL, \n\ttree_hash VARCHAR(64) NOT NULL, \n\tauthor VARCHAR(128) NOT"
        " NULL, \n\treason TEXT NOT NULL, \n\tPRIMARY KEY (project_id, revisio"
        "n), \n\tCONSTRAINT project_instruction_history_revision CHECK (revi"
        "sion >= 1), \n\tFOREIGN KEY(project_id) REFERENCES projects (id), \n"
        "\tFOREIGN KEY(author) REFERENCES principals (id)\n)\n\n"
    )
    op.execute(
        "CREATE TABLE protected_requests (\n\tid VARCHAR(128) NOT NULL, \n\top"
        "eration_id VARCHAR(128) NOT NULL, \n\tprincipal_id VARCHAR(128) NOT"
        " NULL, \n\tprincipal_epoch INTEGER NOT NULL, \n\tsession_id VARCHAR(1"
        "28) NOT NULL, \n\tidempotency_key VARCHAR(128) NOT NULL, \n\tcommand "
        "VARCHAR(128) NOT NULL, \n\tpayload JSON NOT NULL, \n\tpayload_hash VA"
        "RCHAR(64) NOT NULL, \n\tcredential_revision INTEGER NOT NULL, \n\tpol"
        "icy_hash VARCHAR(64) NOT NULL, \n\tissued_at INTEGER NOT NULL, \n\tde"
        "adline INTEGER NOT NULL, \n\tstate VARCHAR(16) NOT NULL, \n\tapproved"
        "_at INTEGER, \n\tapproval_deadline INTEGER, \n\tstrong_authenticated_"
        "at INTEGER, \n\tnonce_hash VARCHAR(64), \n\tnonce_deadline INTEGER, \n"
        "\tPRIMARY KEY (id), \n\tCONSTRAINT protected_state CHECK (state IN ("
        "'PENDING', 'APPROVED', 'COMMITTED', 'CANCELLED', 'EXPIRED', 'INVA"
        "LIDATED')), \n\tCONSTRAINT protected_deadline CHECK (deadline > iss"
        "ued_at AND issued_at >= 0), \n\tCONSTRAINT protected_command CHECK "
        "(command IN ('passkey.label.v1','project.root.admit.v1','project."
        "root.revoke.v1','project.instructions.policy.configure.v1','instr"
        "uction.candidate.register.v1','instruction.release.install.v1','p"
        "roject.instructions.accept.v1', 'project.instructions.recover.v1')), "
        "\n\tUNIQUE (operation_id), \n\tFORE"
        "IGN KEY(principal_id) REFERENCES principals (id), \n\tFOREIGN KEY(s"
        "ession_id) REFERENCES browser_sessions (id)\n)"
    )
    op.execute(
        "CREATE TABLE tasks (\n\tid VARCHAR(128) NOT NULL, \n\tproject_id VARC"
        "HAR(128) NOT NULL, \n\tinitiating_principal_id VARCHAR(128) NOT NUL"
        "L, \n\trevision INTEGER NOT NULL, \n\tsnapshot JSON NOT NULL, \n\tPRIMA"
        "RY KEY (id), \n\tCONSTRAINT task_revision CHECK (revision >= 1), \n\t"
        "FOREIGN KEY(project_id) REFERENCES projects (id), \n\tFOREIGN KEY(i"
        "nitiating_principal_id) REFERENCES principals (id)\n)"
    )
    op.execute(
        "CREATE TABLE teams (         id VARCHAR(128) NOT NULL,          n"
        "ame VARCHAR(200) NOT NULL,          revision INTEGER NOT NULL, le"
        "ad_bot_id VARCHAR(128) NOT NULL,          PRIMARY KEY (id), CONST"
        "RAINT team_revision CHECK (revision >= 1),          CONSTRAINT te"
        "am_member_lead FOREIGN KEY(lead_bot_id, id) REFERENCES bots (id, "
        "team_id) DEFERRABLE INITIALLY DEFERRED )"
    )
    op.execute(
        "CREATE TABLE instruction_bundles (         id VARCHAR(128) NOT NU"
        "LL, principal_id VARCHAR(128) NOT NULL,          profile_id VARCH"
        "AR(128) NOT NULL,          bot_id VARCHAR(128),          project_"
        "id VARCHAR(128) NOT NULL, task_id VARCHAR(128), snapshot JSON NOT"
        " NULL, PRIMARY KEY (id), FOREIGN KEY(principal_id) REFERENCES pri"
        "ncipals (id),          FOREIGN KEY(profile_id) REFERENCES agent_p"
        "rofiles (id),          FOREIGN KEY(bot_id) REFERENCES bots (id), "
        "         FOREIGN KEY(project_id) REFERENCES projects (id), FOREIG"
        "N KEY(task_id) REFERENCES tasks (id) )"
    )
    op.execute(
        "\nCREATE TABLE instruction_evidence (\n\tid VARCHAR(128) NOT NULL, \n"
        "\tcandidate_id VARCHAR(128) NOT NULL, \n\tproject_id VARCHAR(128) NO"
        "T NULL, \n\tprincipal_id VARCHAR(128) NOT NULL, \n\tsession_id VARCHA"
        "R(128) NOT NULL, \n\tkind VARCHAR(16) NOT NULL, \n\tsnapshot JSON NOT"
        " NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT instruction_evidence_kind"
        " CHECK (kind IN ('REVIEW','EVAL')), \n\tFOREIGN KEY(candidate_id) R"
        "EFERENCES instruction_candidates (id), \n\tFOREIGN KEY(project_id) "
        "REFERENCES projects (id), \n\tFOREIGN KEY(principal_id) REFERENCES "
        "principals (id), \n\tFOREIGN KEY(session_id) REFERENCES browser_ses"
        "sions (id)\n)\n\n"
    )
    op.execute(
        "\nCREATE TABLE instruction_projections (\n\tproject_id VARCHAR(128) "
        "NOT NULL, \n\troot_id VARCHAR(128) NOT NULL, \n\tfilename VARCHAR(20)"
        " NOT NULL, \n\trevision INTEGER NOT NULL, \n\tcontent_hash VARCHAR(64"
        ") NOT NULL, \n\tPRIMARY KEY (project_id, root_id, filename), \n\tCONS"
        "TRAINT projection_filename CHECK (filename IN ('AGENTS.md','CLAUD"
        "E.md','GEMINI.md')), \n\tFOREIGN KEY(project_id) REFERENCES project"
        "s (id), \n\tFOREIGN KEY(root_id) REFERENCES instruction_roots (id)\n"
        ")\n\n"
    )
    op.execute(
        "CREATE TABLE outbox_events (         sequence INTEGER NOT NULL PR"
        "IMARY KEY AUTOINCREMENT,          event_id VARCHAR(128) NOT NULL,"
        " operation_id VARCHAR(128) NOT NULL,          event_type VARCHAR("
        "128) NOT NULL,          schema_version INTEGER NOT NULL,         "
        " principal_id VARCHAR(128) NOT NULL,          project_id VARCHAR("
        "128),          owner VARCHAR(30) NOT NULL,          target_kind V"
        "ARCHAR(30) NOT NULL, target_id VARCHAR(128) NOT NULL,          co"
        "mmitted_at VARCHAR(40) NOT NULL,          target_revision INTEGER"
        " NOT NULL,          payload JSON NOT NULL,          CONSTRAINT ev"
        "ent_target_revision CHECK (target_revision >= 1 OR (target_revision = 0 "
        "AND owner = 'project_instructions' AND target_kind = 'project_instructions' "
        "AND event_type = 'project.instructions.bind.abandoned')), CONSTR"
        "AINT event_target CHECK ((owner = 'projects' AND target_kind = 'p"
        "roject' AND project_id IS NOT NULL AND target_id = project_id) OR"
        " (owner = 'identity' AND target_kind = 'passkey' AND project_id I"
        "S NULL) OR (owner = 'work' AND target_kind = 'task' AND project_i"
        "d IS NOT NULL) OR (owner = 'agents' AND target_kind IN ('profile'"
        ", 'bot', 'team') AND project_id IS NULL) OR (owner = 'instruction"
        "s' AND target_kind = 'instruction_bundle' AND project_id IS NOT N"
        "ULL) OR (owner = 'project_instructions' AND ((target_kind = 'proj"
        "ect_instructions' AND project_id = target_id) OR (target_kind IN "
        "('instruction_root','instruction_install') AND project_id IS NULL"
        ")))),          UNIQUE (event_id),          UNIQUE (operation_id),"
        " FOREIGN KEY(operation_id) REFERENCES operation_receipts (id), FO"
        "REIGN KEY(principal_id) REFERENCES principals (id),          FORE"
        "IGN KEY(project_id) REFERENCES projects (id) )"
    )
    op.execute(
        "\nCREATE TABLE project_instruction_bindings (\n\tentry_asset_id VARC"
        "HAR(128), \n\tproject_id VARCHAR(128) NOT NULL, \n\troot_id VARCHAR(1"
        "28) NOT NULL, \n\troot_revision INTEGER NOT NULL, \n\towner VARCHAR(2"
        "0) NOT NULL, \n\trevision INTEGER NOT NULL, \n\ttree_hash VARCHAR(64)"
        " NOT NULL, \n\tpolicy_revision INTEGER NOT NULL, \n\tgeneration INTEG"
        "ER NOT NULL, \n\tactive_operation VARCHAR(128), \n\tPRIMARY KEY (proj"
        "ect_id), \n\tCONSTRAINT binding_revisions CHECK (revision >= 0 AND "
        "policy_revision >= 0 AND generation >= 1), \n\tCONSTRAINT binding_o"
        "wner CHECK (owner IN ('ENVIRONMENT','PROJECT')), \n\tFOREIGN KEY(en"
        "try_asset_id) REFERENCES instruction_assets (id), \n\tFOREIGN KEY(p"
        "roject_id) REFERENCES projects (id), \n\tFOREIGN KEY(root_id) REFER"
        "ENCES instruction_roots (id)\n)\n\n"
    )
    op.execute(
        "INSERT INTO agent_profiles (id, revision, name) SELECT id, revisi"
        "on, name FROM retained_agent_profiles"
    )
    op.execute(
        "INSERT INTO auth_rate_events (id, bucket, observed_at, expires_at"
        ", weight) SELECT id, bucket, observed_at, expires_at, weight FROM"
        " retained_auth_rate_events"
    )
    op.execute("CREATE INDEX ix_auth_rate_events_expires_at ON auth_rate_events (expires_at)")
    op.execute("CREATE INDEX ix_auth_rate_events_bucket ON auth_rate_events (bucket)")
    op.execute(
        "INSERT INTO auth_rates (key, window_start, last_observed, count) "
        "SELECT key, window_start, last_observed, count FROM retained_auth"
        "_rates"
    )
    op.execute(
        "INSERT INTO instruction_assets (id, owner_kind, owner_id, purpose"
        ", trust, revision) SELECT id, owner_kind, owner_id, purpose, trus"
        "t, revision FROM retained_instruction_assets"
    )
    op.execute(
        "INSERT INTO principals (id, role, enabled, authorization_epoch, c"
        "redential_revision) SELECT id, role, enabled, authorization_epoch"
        ", credential_revision FROM retained_principals"
    )
    op.execute(
        "CREATE UNIQUE INDEX one_enabled_owner ON principals (role) WHERE "
        "role = 'OWNER' AND enabled = 1"
    )
    op.execute(
        "INSERT INTO access_grants (id, principal_id, capability, resource"
        "_kind, resource_id, enabled, revision, expires_at, provenance) SE"
        "LECT id, principal_id, capability, resource_kind, resource_id, en"
        "abled, revision, expires_at, provenance FROM retained_access_gran"
        "ts"
    )
    op.execute("CREATE INDEX ix_access_grants_principal_id ON access_grants (principal_id)")
    op.execute(
        "INSERT INTO bots (id, profile_id, team_id, revision, namespace_re"
        "f, memory_enabled, builtin_role, snapshot) SELECT id, profile_id,"
        " team_id, revision, namespace_ref, memory_enabled, builtin_role, "
        "snapshot FROM retained_bots"
    )
    op.execute(
        "INSERT INTO browser_sessions (id, token_hash, csrf_hash, principa"
        "l_id, principal_epoch, audience, authentication_method, client_la"
        "bel, issued_at, last_activity, last_observed, absolute_deadline, "
        "inactivity_seconds, strong_authenticated_at, strong_freshness_sec"
        "onds, revoked) SELECT id, token_hash, csrf_hash, principal_id, pr"
        "incipal_epoch, audience, authentication_method, client_label, iss"
        "ued_at, last_activity, last_observed, absolute_deadline, inactivi"
        "ty_seconds, strong_authenticated_at, strong_freshness_seconds, re"
        "voked FROM retained_browser_sessions"
    )
    op.execute("CREATE INDEX ix_browser_sessions_principal_id ON browser_sessions (principal_id)")
    op.execute(
        "INSERT INTO deployment_policy (id, revision, approval_id, approve"
        "d_by, approved_providers, verification_policy_ref) SELECT id, rev"
        "ision, approval_id, approved_by, approved_providers, verification"
        "_policy_ref FROM retained_deployment_policy"
    )
    op.execute(
        "INSERT INTO identity_state (id, last_observed, rate_policy, owner"
        "_id, pending_principal_id, enrollment_hash, enrollment_deadline) "
        "SELECT id, last_observed, rate_policy, owner_id, pending_principa"
        "l_id, enrollment_hash, enrollment_deadline FROM retained_identity"
        "_state"
    )
    op.execute(
        "INSERT INTO instruction_revisions (asset_id, revision, template, "
        "content_hash, previous_hash, author, reason, created_at) SELECT a"
        "sset_id, revision, template, content_hash, previous_hash, author,"
        " reason, created_at FROM retained_instruction_revisions"
    )
    op.execute(
        "INSERT INTO passkeys (id, credential_id, credential_data, princip"
        "al_id, label, revision, sign_count, backup_eligible, backed_up, r"
        "evoked) SELECT id, credential_id, credential_data, principal_id, "
        "label, revision, sign_count, backup_eligible, backed_up, revoked "
        "FROM retained_passkeys"
    )
    op.execute("CREATE INDEX ix_passkeys_principal_id ON passkeys (principal_id)")
    op.execute(
        "INSERT INTO profile_revisions (profile_id, revision, snapshot, au"
        "thor, reason, content_hash, created_at) SELECT profile_id, revisi"
        "on, snapshot, author, reason, content_hash, created_at FROM retai"
        "ned_profile_revisions"
    )
    op.execute(
        "INSERT INTO projects (id, revision, name, description, created_by"
        ", instruction_owner, instruction_authority_ref, provider_snapshot"
        ", verification_policy_ref, resource_refs, created_at) SELECT id, "
        "revision, name, description, created_by, instruction_owner, instr"
        "uction_authority_ref, provider_snapshot, verification_policy_ref,"
        " resource_refs, created_at FROM retained_projects"
    )
    op.execute(
        "INSERT INTO auth_ceremonies (id, purpose, subject_id, session_id,"
        " enrollment_hash, label, state, issued_at, last_observed, deadlin"
        "e, attempts, consumed) SELECT id, purpose, subject_id, session_id"
        ", enrollment_hash, label, state, issued_at, last_observed, deadli"
        "ne, attempts, consumed FROM retained_auth_ceremonies"
    )
    op.execute(
        "INSERT INTO bot_revisions (bot_id, revision, snapshot, author, re"
        "ason, content_hash, created_at) SELECT bot_id, revision, snapshot"
        ", author, reason, content_hash, created_at FROM retained_bot_revi"
        "sions"
    )
    op.execute(
        "CREATE INDEX ix_instruction_candidates_project_id ON instruction_candidates (project_id)"
    )
    op.execute(
        "CREATE INDEX ix_instruction_publications_project_id ON instructio"
        "n_publications (project_id)"
    )
    op.execute(
        "INSERT INTO operation_receipts (id, principal_id, command, idempo"
        "tency_key, payload_hash, project_id, owner, target_kind, target_i"
        "d, authentication_ref, result) SELECT id, principal_id, command, "
        "idempotency_key, payload_hash, project_id, owner, target_kind, ta"
        "rget_id, authentication_ref, result FROM retained_operation_recei"
        "pts"
    )
    op.execute(
        "CREATE UNIQUE INDEX receipt_operation_identity ON operation_recei"
        "pts (principal_id, command, idempotency_key)"
    )
    op.execute(
        "INSERT INTO protected_requests (id, operation_id, principal_id, p"
        "rincipal_epoch, session_id, idempotency_key, command, payload, pa"
        "yload_hash, credential_revision, policy_hash, issued_at, deadline"
        ", state, approved_at, approval_deadline, strong_authenticated_at,"
        " nonce_hash, nonce_deadline) SELECT id, operation_id, principal_i"
        "d, principal_epoch, session_id, idempotency_key, command, payload"
        ", payload_hash, credential_revision, policy_hash, issued_at, dead"
        "line, state, approved_at, approval_deadline, strong_authenticated"
        "_at, nonce_hash, nonce_deadline FROM retained_protected_requests"
    )
    op.execute(
        "CREATE UNIQUE INDEX protected_operation_identity ON protected_req"
        "uests (principal_id, command, idempotency_key)"
    )
    op.execute(
        "INSERT INTO tasks (id, project_id, initiating_principal_id, revis"
        "ion, snapshot) SELECT id, project_id, initiating_principal_id, re"
        "vision, snapshot FROM retained_tasks"
    )
    op.execute("CREATE INDEX ix_tasks_project_id ON tasks (project_id)")
    op.execute(
        "INSERT INTO teams (id, name, revision, lead_bot_id) SELECT id, na"
        "me, revision, lead_bot_id FROM retained_teams"
    )
    op.execute(
        "INSERT INTO instruction_bundles (id, principal_id, profile_id, bo"
        "t_id, project_id, task_id, snapshot) SELECT id, principal_id, pro"
        "file_id, bot_id, project_id, task_id, snapshot FROM retained_inst"
        "ruction_bundles"
    )
    op.execute(
        "INSERT INTO outbox_events (sequence, event_id, operation_id, even"
        "t_type, schema_version, principal_id, project_id, owner, target_k"
        "ind, target_id, committed_at, target_revision, payload) SELECT se"
        "quence, event_id, operation_id, event_type, schema_version, princ"
        "ipal_id, project_id, owner, target_kind, target_id, committed_at,"
        " target_revision, payload FROM retained_outbox_events"
    )
    op.execute(
        "UPDATE sqlite_sequence SET seq=max(seq,coalesce((SELECT max(seq) "
        "FROM retained_event_ceiling),0)) WHERE name='outbox_events'"
    )
    op.execute(
        "INSERT INTO sqlite_sequence(name,seq) SELECT 'outbox_events',max("
        "seq) FROM retained_event_ceiling HAVING max(seq) IS NOT NULL AND "
        "NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name='outbox_even"
        "ts')"
    )
    op.execute("DROP TABLE retained_principals")
    op.execute("DROP TABLE retained_access_grants")
    op.execute("DROP TABLE retained_deployment_policy")
    op.execute("DROP TABLE retained_projects")
    op.execute("DROP TABLE retained_operation_receipts")
    op.execute("DROP TABLE retained_outbox_events")
    op.execute("DROP TABLE retained_browser_sessions")
    op.execute("DROP TABLE retained_identity_state")
    op.execute("DROP TABLE retained_passkeys")
    op.execute("DROP TABLE retained_auth_ceremonies")
    op.execute("DROP TABLE retained_auth_rates")
    op.execute("DROP TABLE retained_auth_rate_events")
    op.execute("DROP TABLE retained_protected_requests")
    op.execute("DROP TABLE retained_tasks")
    op.execute("DROP TABLE retained_agent_profiles")
    op.execute("DROP TABLE retained_profile_revisions")
    op.execute("DROP TABLE retained_bots")
    op.execute("DROP TABLE retained_bot_revisions")
    op.execute("DROP TABLE retained_teams")
    op.execute("DROP TABLE retained_instruction_assets")
    op.execute("DROP TABLE retained_instruction_revisions")
    op.execute("DROP TABLE retained_instruction_bundles")
    op.execute("DROP TABLE retained_event_ceiling")
    op.execute(
        "CREATE TRIGGER immutable_profile_revisions_update BEFORE UPDATE O"
        "N profile_revisions BEGIN SELECT RAISE(ABORT, 'Immutable history'"
        "); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_profile_revisions_delete BEFORE DELETE O"
        "N profile_revisions BEGIN SELECT RAISE(ABORT, 'Immutable history'"
        "); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_bot_revisions_update BEFORE UPDATE ON bo"
        "t_revisions BEGIN SELECT RAISE(ABORT, 'Immutable history'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_bot_revisions_delete BEFORE DELETE ON bo"
        "t_revisions BEGIN SELECT RAISE(ABORT, 'Immutable history'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_instruction_revisions_update BEFORE UPDA"
        "TE ON instruction_revisions BEGIN SELECT RAISE(ABORT, 'Immutable "
        "history'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_instruction_revisions_delete BEFORE DELE"
        "TE ON instruction_revisions BEGIN SELECT RAISE(ABORT, 'Immutable "
        "history'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_instruction_bundles_update BEFORE UPDATE"
        " ON instruction_bundles BEGIN SELECT RAISE(ABORT, 'Immutable hist"
        "ory'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_instruction_bundles_delete BEFORE DELETE"
        " ON instruction_bundles BEGIN SELECT RAISE(ABORT, 'Immutable hist"
        "ory'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_project_instruction_revisions_update BEF"
        "ORE UPDATE ON project_instruction_revisions BEGIN SELECT RAISE(AB"
        "ORT, 'Immutable history'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_project_instruction_revisions_delete BEF"
        "ORE DELETE ON project_instruction_revisions BEGIN SELECT RAISE(AB"
        "ORT, 'Immutable history'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_project_instruction_policies_update BEFO"
        "RE UPDATE ON project_instruction_policies BEGIN SELECT RAISE(ABOR"
        "T, 'Immutable history'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_project_instruction_policies_delete BEFO"
        "RE DELETE ON project_instruction_policies BEGIN SELECT RAISE(ABOR"
        "T, 'Immutable history'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_instruction_candidates_update BEFORE UPD"
        "ATE ON instruction_candidates BEGIN SELECT RAISE(ABORT, 'Immutabl"
        "e history'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_instruction_candidates_delete BEFORE DEL"
        "ETE ON instruction_candidates BEGIN SELECT RAISE(ABORT, 'Immutabl"
        "e history'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_instruction_evidence_update BEFORE UPDAT"
        "E ON instruction_evidence BEGIN SELECT RAISE(ABORT, 'Immutable hi"
        "story'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_instruction_evidence_delete BEFORE DELET"
        "E ON instruction_evidence BEGIN SELECT RAISE(ABORT, 'Immutable hi"
        "story'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_installed_release_evidence_update BEFORE"
        " UPDATE ON installed_release_evidence BEGIN SELECT RAISE(ABORT, '"
        "Immutable history'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_installed_release_evidence_delete BEFORE"
        " DELETE ON installed_release_evidence BEGIN SELECT RAISE(ABORT, '"
        "Immutable history'); END"
    )
    op.execute(
        "CREATE TRIGGER preserve_initialized_owner\n        BEFORE UPDATE O"
        "F role, enabled ON principals\n        WHEN OLD.id = (SELECT owner"
        "_id FROM identity_state WHERE id = 1)\n        AND (NEW.role != 'O"
        "WNER' OR NEW.enabled != 1)\n        BEGIN SELECT RAISE(ABORT, 'Ini"
        "tialized Owner requires dedicated recovery'); END"
    )
    op.execute(
        "CREATE TRIGGER preserve_owner_binding BEFORE UPDATE OF owner_id O"
        "N identity_state\n        WHEN OLD.owner_id IS NOT NULL AND (NEW.o"
        "wner_id IS NULL OR NEW.owner_id != OLD.owner_id)\n        BEGIN SE"
        "LECT RAISE(ABORT, 'Initialized Owner binding is immutable'); END"
    )
    op.execute(
        "CREATE TRIGGER preserve_identity_state BEFORE DELETE ON identity_"
        "state\n        WHEN OLD.owner_id IS NOT NULL\n        BEGIN SELECT "
        "RAISE(ABORT, 'Initialized identity state cannot be removed'); END"
    )
    op.execute(
        "CREATE TABLE instruction_request_scopes (\n\trequest_id VARCHAR(128"
        ") NOT NULL, \n\tproject_id VARCHAR(128) NOT NULL, \n\tPRIMARY KEY (re"
        "quest_id), \n\tFOREIGN KEY(request_id) REFERENCES protected_request"
        "s (id), \n\tFOREIGN KEY(project_id) REFERENCES projects (id)\n)"
    )
    op.execute(
        "ALTER TABLE instruction_request_scopes ADD COLUMN publication_id VARCHAR(128) "
        "REFERENCES instruction_publications(id)"
    )
    op.execute(
        "ALTER TABLE instruction_request_scopes ADD COLUMN projection BOOLEAN NOT NULL DEFAULT 0 "
        "CONSTRAINT request_scope_projection_boolean CHECK (projection IN (0, 1))"
    )
    op.execute(
        "ALTER TABLE instruction_publications ADD COLUMN target_root_id VARCHAR(128) "
        "NOT NULL REFERENCES instruction_roots(id)"
    )
    op.execute(
        "ALTER TABLE instruction_publications ADD COLUMN projection BOOLEAN NOT NULL DEFAULT 0 "
        "CONSTRAINT publication_projection_boolean CHECK (projection IN (0, 1))"
    )


def downgrade() -> None:
    raise RuntimeError("Destructive downgrade is unsupported; restore a coherent backup")
