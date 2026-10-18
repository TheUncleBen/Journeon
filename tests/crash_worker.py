# SPDX-License-Identifier: AGPL-3.0-only
"""Subprocess fault injection only. No test hooks are present in production code."""

import os
import sys
from pathlib import Path

from sqlalchemy import event

from journeon.contracts import ProjectCreate
from journeon.database import create_database
from journeon.permissions import AuthenticatedContext
from journeon.projects import ProjectService

engine = create_database(Path(sys.argv[1]))
stage = sys.argv[2]
targets = {
    "project": "INSERT INTO projects",
    "receipt": "INSERT INTO operation_receipts",
    "outbox": "INSERT INTO outbox_events",
}

if stage in targets:

    @event.listens_for(engine, "after_cursor_execute")
    def crash_after_statement(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith(targets[stage]):
            os._exit(77)
elif stage == "before_commit":

    @event.listens_for(engine, "commit")
    def crash_before_commit(connection):
        os._exit(77)


ProjectService(engine).create(
    AuthenticatedContext("owner-test", 1, "synthetic-authentication"),
    ProjectCreate(
        schema_version=1,
        idempotency_key="create-1",
        name="Example project",
        expected_policy_revision=1,
    ),
)
if stage == "after_commit":
    os._exit(78)  # Committed but no response delivered to the caller.
raise RuntimeError("Fault injection did not reach the selected boundary")
