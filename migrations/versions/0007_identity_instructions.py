# SPDX-License-Identifier: AGPL-3.0-only
"""Persist identity configuration and immutable instruction provenance."""

from alembic import op

revision = "0007_identity_instructions"
down_revision = "0006_work"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE TEMP TABLE identity_event_ceiling AS SELECT seq FROM "
        "sqlite_sequence WHERE name = 'outbox_events'"
    )
    op.execute("CREATE TEMP TABLE identity_retained_events AS SELECT * FROM outbox_events")
    op.drop_table("outbox_events")
    with op.batch_alter_table("operation_receipts") as batch:
        batch.drop_constraint("receipt_target", type_="check")
        batch.create_check_constraint(
            "receipt_target",
            (
                "(owner = 'projects' AND target_kind = 'project' AND project_id IS NOT "
                "NULL AND target_id = project_id) OR (owner = 'identity' AND target_kind "
                "= 'passkey' AND project_id IS NULL) OR (owner = 'work' AND target_kind = "
                "'task' AND project_id IS NOT NULL) OR (owner = 'agents' AND target_kind "
                "IN ('profile', 'bot', 'team') AND project_id IS NULL) OR (owner = "
                "'instructions' AND target_kind = 'instruction_bundle' AND project_id IS "
                "NOT NULL)"
            ),
        )
    with op.batch_alter_table("access_grants") as batch:
        batch.drop_constraint("grant_resource_kind", type_="check")
        batch.create_check_constraint(
            "grant_resource_kind",
            (
                "resource_kind IN ('deployment', 'project', 'profile', 'bot', 'team', "
                "'instruction_bundle', 'legacy_collection')"
            ),
        )
    op.execute(
        " CREATE TABLE outbox_events (         sequence INTEGER NOT NULL PRIMARY "
        "KEY AUTOINCREMENT,          event_id VARCHAR(128) NOT NULL, "
        "operation_id VARCHAR(128) NOT NULL,          event_type VARCHAR(128) NOT "
        "NULL,          schema_version INTEGER NOT NULL,          principal_id "
        "VARCHAR(128) NOT NULL,          project_id VARCHAR(128),          owner "
        "VARCHAR(30) NOT NULL,          target_kind VARCHAR(30) NOT NULL, "
        "target_id VARCHAR(128) NOT NULL,          committed_at VARCHAR(40) NOT "
        "NULL,          target_revision INTEGER NOT NULL,          payload JSON "
        "NOT NULL,          CONSTRAINT event_target_revision CHECK "
        "(target_revision >= 1),          CONSTRAINT event_target CHECK ((owner = "
        "'projects' AND target_kind = 'project' AND project_id IS NOT NULL AND "
        "target_id = project_id) OR (owner = 'identity' AND target_kind = "
        "'passkey' AND project_id IS NULL) OR (owner = 'work' AND target_kind = "
        "'task' AND project_id IS NOT NULL) OR (owner = 'agents' AND target_kind "
        "IN ('profile', 'bot', 'team') AND project_id IS NULL) OR (owner = "
        "'instructions' AND target_kind = 'instruction_bundle' AND project_id IS "
        "NOT NULL)),          UNIQUE (event_id),          UNIQUE (operation_id), "
        "FOREIGN KEY(operation_id) REFERENCES operation_receipts (id), "
        "FOREIGN KEY(principal_id) REFERENCES principals (id),          FOREIGN "
        "KEY(project_id) REFERENCES projects (id) )"
    )
    op.execute(
        " CREATE TABLE agent_profiles (         id VARCHAR(128) NOT NULL, "
        "revision INTEGER NOT NULL,          name VARCHAR(200) NOT NULL, "
        "PRIMARY KEY (id),          CONSTRAINT profile_revision CHECK (revision "
        ">= 1) )"
    )
    op.execute(
        " CREATE TABLE profile_revisions (         profile_id VARCHAR(128) NOT "
        "NULL,          revision INTEGER NOT NULL,          snapshot JSON NOT "
        "NULL,          author VARCHAR(128) NOT NULL,          reason "
        "VARCHAR(200) NOT NULL,          content_hash VARCHAR(64) NOT NULL, "
        "created_at VARCHAR(40) NOT NULL,          PRIMARY KEY (profile_id, "
        "revision),          CONSTRAINT profile_history_revision CHECK (revision "
        ">= 1),          FOREIGN KEY(profile_id) REFERENCES agent_profiles (id), "
        "FOREIGN KEY(author) REFERENCES principals (id) )"
    )
    op.execute(
        " CREATE TABLE teams (         id VARCHAR(128) NOT NULL,          name "
        "VARCHAR(200) NOT NULL,          revision INTEGER NOT NULL, "
        "lead_bot_id VARCHAR(128) NOT NULL,          PRIMARY KEY (id), "
        "CONSTRAINT team_revision CHECK (revision >= 1),          CONSTRAINT "
        "team_member_lead FOREIGN KEY(lead_bot_id, id) REFERENCES bots (id, "
        "team_id) DEFERRABLE INITIALLY DEFERRED )"
    )
    op.execute(
        " CREATE TABLE bots (         id VARCHAR(128) NOT NULL, "
        "profile_id VARCHAR(128) NOT NULL,          team_id VARCHAR(128), "
        "revision INTEGER NOT NULL,          namespace_ref VARCHAR(128) NOT NULL, "
        "memory_enabled BOOLEAN NOT NULL,          builtin_role VARCHAR(20), "
        "snapshot JSON NOT NULL,          PRIMARY KEY (id),          CONSTRAINT "
        "bot_revision CHECK (revision >= 1),          CONSTRAINT "
        "bot_team_identity UNIQUE (id, team_id),          CONSTRAINT "
        "bot_namespace CHECK (namespace_ref = 'bot:' || id),          CONSTRAINT "
        "bot_memory_boolean CHECK (memory_enabled IN (0, 1)),          CONSTRAINT "
        "bot_fixed_memory CHECK (builtin_role IS NULL OR (builtin_role IN "
        "('RESEARCHER', 'LIBRARIAN') AND memory_enabled = 0)),          FOREIGN "
        "KEY(profile_id) REFERENCES agent_profiles (id),          FOREIGN "
        "KEY(team_id) REFERENCES teams (id) DEFERRABLE INITIALLY DEFERRED, "
        "UNIQUE (namespace_ref) )"
    )
    op.execute(
        " CREATE TABLE bot_revisions (         bot_id VARCHAR(128) NOT NULL, "
        "revision INTEGER NOT NULL,          snapshot JSON NOT NULL, "
        "author VARCHAR(128) NOT NULL,          reason VARCHAR(200) NOT NULL, "
        "content_hash VARCHAR(64) NOT NULL,          created_at VARCHAR(40) NOT "
        "NULL,          PRIMARY KEY (bot_id, revision),          CONSTRAINT "
        "bot_history_revision CHECK (revision >= 1),          FOREIGN KEY(bot_id) "
        "REFERENCES bots (id),          FOREIGN KEY(author) REFERENCES principals "
        "(id) )"
    )
    op.execute(
        " CREATE TABLE instruction_assets (         id VARCHAR(128) NOT NULL, "
        "owner_kind VARCHAR(30) NOT NULL,          owner_id VARCHAR(128) NOT "
        "NULL,          purpose VARCHAR(30) NOT NULL,          trust VARCHAR(30) "
        "NOT NULL,          revision INTEGER NOT NULL,          PRIMARY KEY (id), "
        "CONSTRAINT asset_revision CHECK (revision >= 1),          CONSTRAINT "
        "asset_purpose CHECK (purpose IN ('CORE', 'NAVIGATION', 'PROFILE', 'BOT', "
        "'PROJECT', 'SKILLS', 'TASK', 'WORKFLOW')),          CONSTRAINT "
        "asset_trust CHECK (trust IN ('PROTECTED', 'CONFIGURATION')), "
        "CONSTRAINT asset_protected_owner CHECK ((purpose IN ('CORE', "
        "'NAVIGATION') AND owner_kind = 'system' AND trust = 'PROTECTED') OR "
        "(purpose NOT IN ('CORE', 'NAVIGATION') AND trust = 'CONFIGURATION')) )"
    )
    op.execute(
        " CREATE TABLE instruction_revisions (         asset_id VARCHAR(128) NOT "
        "NULL,          revision INTEGER NOT NULL,          template JSON NOT "
        "NULL,          content_hash VARCHAR(64) NOT NULL,          previous_hash "
        "VARCHAR(64),          author VARCHAR(128) NOT NULL,          reason "
        "VARCHAR(200) NOT NULL,          created_at VARCHAR(40) NOT NULL, "
        "PRIMARY KEY (asset_id, revision),          CONSTRAINT "
        "instruction_revision CHECK (revision >= 1),          FOREIGN "
        "KEY(asset_id) REFERENCES instruction_assets (id),          FOREIGN "
        "KEY(author) REFERENCES principals (id) )"
    )
    op.execute(
        " CREATE TABLE instruction_bundles (         id VARCHAR(128) NOT NULL, "
        "principal_id VARCHAR(128) NOT NULL,          profile_id VARCHAR(128) NOT "
        "NULL,          bot_id VARCHAR(128),          project_id VARCHAR(128) NOT "
        "NULL, task_id VARCHAR(128), snapshot JSON NOT NULL, PRIMARY KEY (id), "
        "FOREIGN KEY(principal_id) REFERENCES principals (id),          FOREIGN "
        "KEY(profile_id) REFERENCES agent_profiles (id),          FOREIGN "
        "KEY(bot_id) REFERENCES bots (id),          FOREIGN KEY(project_id) "
        "REFERENCES projects (id), FOREIGN KEY(task_id) REFERENCES tasks (id) )"
    )
    op.execute("INSERT INTO outbox_events SELECT * FROM identity_retained_events")
    op.execute(
        "UPDATE sqlite_sequence SET seq = max(seq, coalesce((SELECT max(seq) FROM "
        "identity_event_ceiling), 0)) WHERE name='outbox_events'"
    )
    op.execute(
        "INSERT INTO sqlite_sequence(name,seq) SELECT 'outbox_events', max(seq) "
        "FROM identity_event_ceiling HAVING max(seq) IS NOT NULL AND NOT EXISTS "
        "(SELECT 1 FROM sqlite_sequence WHERE name='outbox_events')"
    )
    op.execute("DROP TABLE identity_retained_events")
    op.execute("DROP TABLE identity_event_ceiling")
    op.execute(
        "CREATE TRIGGER immutable_profile_revisions_update BEFORE UPDATE ON "
        "profile_revisions BEGIN SELECT RAISE(ABORT, 'Immutable history'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_profile_revisions_delete BEFORE DELETE ON "
        "profile_revisions BEGIN SELECT RAISE(ABORT, 'Immutable history'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_bot_revisions_update BEFORE UPDATE ON "
        "bot_revisions BEGIN SELECT RAISE(ABORT, 'Immutable history'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_bot_revisions_delete BEFORE DELETE ON "
        "bot_revisions BEGIN SELECT RAISE(ABORT, 'Immutable history'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_instruction_revisions_update BEFORE UPDATE ON "
        "instruction_revisions BEGIN SELECT RAISE(ABORT, 'Immutable history'); "
        "END"
    )
    op.execute(
        "CREATE TRIGGER immutable_instruction_revisions_delete BEFORE DELETE ON "
        "instruction_revisions BEGIN SELECT RAISE(ABORT, 'Immutable history'); "
        "END"
    )
    op.execute(
        "CREATE TRIGGER immutable_instruction_bundles_update BEFORE UPDATE ON "
        "instruction_bundles BEGIN SELECT RAISE(ABORT, 'Immutable history'); END"
    )
    op.execute(
        "CREATE TRIGGER immutable_instruction_bundles_delete BEFORE DELETE ON "
        "instruction_bundles BEGIN SELECT RAISE(ABORT, 'Immutable history'); END"
    )


def downgrade() -> None:
    raise RuntimeError("Destructive downgrade is unsupported; restore a coherent backup")
