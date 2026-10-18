# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded deterministic foundation health, independent of optional services."""

from typing import Literal

from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import SQLAlchemyError

from journeon.contracts import Contract
from journeon.database import SCHEMA_REVISION
from journeon.models import Base


class FoundationHealth(Contract):
    database: Literal["AVAILABLE", "UNAVAILABLE"]
    schema_state: Literal["CURRENT", "MISSING_OR_INCOMPATIBLE", "UNKNOWN"]
    operational_authentication: Literal["NOT_ASSESSED"] = "NOT_ASSESSED"


def schema_and_database(engine: Engine) -> FoundationHealth:
    try:
        with engine.connect() as connection:
            names = set(inspect(connection).get_table_names())
            if not (set(Base.metadata.tables) | {"alembic_version"}) <= names:
                return FoundationHealth(
                    database="AVAILABLE", schema_state="MISSING_OR_INCOMPATIBLE"
                )
            revisions = connection.scalars(text("SELECT version_num FROM alembic_version")).all()
            return FoundationHealth(
                database="AVAILABLE",
                schema_state="CURRENT"
                if revisions == [SCHEMA_REVISION]
                else "MISSING_OR_INCOMPATIBLE",
            )
    except SQLAlchemyError:
        return FoundationHealth(database="UNAVAILABLE", schema_state="UNKNOWN")
