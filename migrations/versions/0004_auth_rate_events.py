# SPDX-License-Identifier: AGPL-3.0-only
"""Preserve legacy start counts while adding durable rolling rate events."""

import sqlalchemy as sa
from alembic import op

revision = "0004_auth_rate_events"
down_revision = "0003_passkeys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("identity_state", sa.Column("rate_policy", sa.JSON(), nullable=True))
    op.create_table(
        "auth_rate_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("bucket", sa.String(128), nullable=False),
        sa.Column("observed_at", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=True),
        sa.Column("weight", sa.Integer(), nullable=False),
        sa.CheckConstraint("observed_at >= 0 AND weight > 0", name="rate_event_values"),
        sa.CheckConstraint(
            "expires_at IS NULL OR expires_at > observed_at", name="rate_event_expiry"
        ),
    )
    op.create_index("ix_auth_rate_events_bucket", "auth_rate_events", ["bucket"])
    op.create_index("ix_auth_rate_events_expires_at", "auth_rate_events", ["expires_at"])
    # The previous schema has counts, not individual timestamps. Keep that uncertainty explicit.
    op.execute(
        "INSERT INTO auth_rate_events (bucket, observed_at, expires_at, weight) "
        "SELECT 'source:' || key, last_observed, NULL, count FROM auth_rates WHERE count > 0"
    )
    op.execute(
        "UPDATE identity_state SET last_observed = max(last_observed, "
        "coalesce((SELECT max(last_observed) FROM auth_rates), 0))"
    )


def downgrade() -> None:
    raise RuntimeError("Destructive downgrade is unsupported; restore a coherent backup")
