# SPDX-License-Identifier: AGPL-3.0-only
"""Alembic uses the coordinator's configured local SQLite connection."""

from alembic import context

from journeon.models import Base

connection = context.config.attributes.get("connection")
if connection is None:
    raise RuntimeError("Use journeon.migrate.upgrade with an explicitly configured database")
context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True)
with context.begin_transaction():
    context.run_migrations()
