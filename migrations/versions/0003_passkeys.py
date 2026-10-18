# SPDX-License-Identifier: AGPL-3.0-only
"""Add passkey ceremonies and preserve the initialized Owner identity."""

import sqlalchemy as sa
from alembic import op

revision = "0003_passkeys"
down_revision = "0002_browser_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_rates",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("window_start", sa.Integer(), nullable=False),
        sa.Column("last_observed", sa.Integer(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.CheckConstraint("count >= 0 AND last_observed >= window_start", name="auth_rate_state"),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_table(
        "identity_state",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("last_observed", sa.Integer(), nullable=False),
        sa.Column("owner_id", sa.String(length=128), nullable=True),
        sa.Column("pending_principal_id", sa.String(length=128), nullable=True),
        sa.Column("enrollment_hash", sa.String(length=64), nullable=True),
        sa.Column("enrollment_deadline", sa.Integer(), nullable=True),
        sa.CheckConstraint("id = 1", name="single_identity_state"),
        sa.ForeignKeyConstraint(
            ["owner_id"],
            ["principals.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "passkeys",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("credential_id", sa.Text(), nullable=False),
        sa.Column("credential_data", sa.Text(), nullable=False),
        sa.Column("principal_id", sa.String(length=128), nullable=False),
        sa.Column("label", sa.String(length=128), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False),
        sa.Column("backup_eligible", sa.Boolean(), nullable=False),
        sa.Column("backed_up", sa.Boolean(), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.CheckConstraint("backed_up = 0 OR backup_eligible = 1", name="passkey_backup_state"),
        sa.CheckConstraint("backed_up IN (0, 1)", name="passkey_backup_boolean"),
        sa.CheckConstraint("backup_eligible IN (0, 1)", name="passkey_eligible_boolean"),
        sa.CheckConstraint("revoked IN (0, 1)", name="passkey_revoked_boolean"),
        sa.CheckConstraint("sign_count >= 0", name="passkey_counter"),
        sa.ForeignKeyConstraint(
            ["principal_id"],
            ["principals.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("credential_id"),
    )
    op.create_index(op.f("ix_passkeys_principal_id"), "passkeys", ["principal_id"], unique=False)
    op.create_table(
        "auth_ceremonies",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("purpose", sa.String(length=16), nullable=False),
        sa.Column("subject_id", sa.String(length=128), nullable=True),
        sa.Column("session_id", sa.String(length=128), nullable=True),
        sa.Column("enrollment_hash", sa.String(length=64), nullable=True),
        sa.Column("label", sa.String(length=128), nullable=False),
        sa.Column("state", sa.JSON(), nullable=False),
        sa.Column("issued_at", sa.Integer(), nullable=False),
        sa.Column("last_observed", sa.Integer(), nullable=False),
        sa.Column("deadline", sa.Integer(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("consumed", sa.Boolean(), nullable=False),
        sa.CheckConstraint(
            "purpose IN ('bootstrap', 'login', 'stepup', 'add')", name="ceremony_purpose"
        ),
        sa.CheckConstraint("attempts >= 0", name="ceremony_attempts"),
        sa.CheckConstraint("consumed IN (0, 1)", name="ceremony_consumed_boolean"),
        sa.CheckConstraint(
            "deadline > issued_at AND last_observed >= issued_at", name="ceremony_time"
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["browser_sessions.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.execute(
        "INSERT INTO identity_state (id, last_observed, owner_id) "
        "SELECT 1, 0, id FROM principals WHERE role = 'OWNER' AND enabled = 1"
    )
    op.execute("""CREATE TRIGGER preserve_initialized_owner
        BEFORE UPDATE OF role, enabled ON principals
        WHEN OLD.id = (SELECT owner_id FROM identity_state WHERE id = 1)
        AND (NEW.role != 'OWNER' OR NEW.enabled != 1)
        BEGIN SELECT RAISE(ABORT, 'Initialized Owner requires dedicated recovery'); END""")
    op.execute("""CREATE TRIGGER preserve_owner_binding BEFORE UPDATE OF owner_id ON identity_state
        WHEN OLD.owner_id IS NOT NULL AND (NEW.owner_id IS NULL OR NEW.owner_id != OLD.owner_id)
        BEGIN SELECT RAISE(ABORT, 'Initialized Owner binding is immutable'); END""")
    op.execute("""CREATE TRIGGER preserve_identity_state BEFORE DELETE ON identity_state
        WHEN OLD.owner_id IS NOT NULL
        BEGIN SELECT RAISE(ABORT, 'Initialized identity state cannot be removed'); END""")


def downgrade() -> None:
    raise RuntimeError("Destructive downgrade is unsupported; restore a coherent backup")
