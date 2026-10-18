# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit migration entry point; no automatic service-start migration."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine


def configuration() -> Config:
    config = Config()
    config.set_main_option(
        "script_location", str(Path(__file__).resolve().parents[2] / "migrations")
    )
    return config


def upgrade(engine: Engine) -> None:
    config = configuration()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
