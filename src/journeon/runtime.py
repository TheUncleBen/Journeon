# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit local runtime binding; provisioning and migrations are separate operations."""

import argparse
import ipaddress
import json
import os
import sqlite3
import ssl
import stat
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, closing
from pathlib import Path
from typing import Self

import uvicorn
from alembic.script import ScriptDirectory
from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field, model_validator

from journeon.api import create_app
from journeon.browser_auth import BrowserAuth
from journeon.database import SCHEMA_REVISION, create_database
from journeon.migrate import configuration
from journeon.models import Base
from journeon.passkeys import STANDARD_PASSKEY_POLICY, PasskeyService


def regular_file(path: Path) -> Path:
    if not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("An absolute file path without symbolic links is required")
    mode = path.stat().st_mode
    if not stat.S_ISREG(mode) or not mode & 0o444:
        raise ValueError("A readable regular file is required")
    return path


class RuntimeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    host: str
    port: int = Field(ge=1, le=65535)
    origin: str
    rp_id: str
    database: str
    tls_certificate: str
    tls_private_key: str
    trusted_proxy_peers: list[str]
    busy_timeout_ms: int = Field(ge=1, le=60000)
    backlog: int = Field(gt=0)
    limit_concurrency: int = Field(gt=0)
    timeout_keep_alive: int = Field(ge=0)
    timeout_graceful_shutdown: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        ipaddress.ip_address(self.host)
        for peer in self.trusted_proxy_peers:
            ipaddress.ip_address(peer)
        BrowserAuth(self.origin)
        from urllib.parse import urlsplit

        if urlsplit(self.origin).hostname != self.rp_id:
            raise ValueError("Origin and relying party must match")
        for value in (self.database, self.tls_certificate, self.tls_private_key):
            regular_file(Path(value))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.tls_certificate, self.tls_private_key, password=lambda: "")
        return self


def read_config(path: Path) -> RuntimeConfig:
    return RuntimeConfig.model_validate_json(regular_file(path).read_bytes())


def application(config: RuntimeConfig) -> FastAPI:
    # Read-only inspection precedes the engine that can write WAL files.
    path = regular_file(Path(config.database))
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        if db.execute("SELECT version_num FROM alembic_version").fetchall() != [(SCHEMA_REVISION,)]:
            raise ValueError("Explicit offline migration is required")
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not set(Base.metadata.tables) <= tables:
            raise ValueError("Required database tables are unavailable")
    if ScriptDirectory.from_config(configuration()).get_heads() != [SCHEMA_REVISION]:
        raise ValueError("Release migrations do not match the runtime")
    engine = create_database(path, busy_timeout_ms=config.busy_timeout_ms)
    try:
        app = create_app(
            engine,
            browser_auth=BrowserAuth(config.origin),
            passkeys=PasskeyService(
                engine, rp_id=config.rp_id, origin=config.origin, policy=STANDARD_PASSKEY_POLICY
            ),
        )
    except BaseException:
        engine.dispose()
        raise

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            engine.dispose()
            print(json.dumps({"status": "STOPPED"}), flush=True)

    app.router.lifespan_context = lifespan
    return app


def factory() -> FastAPI:
    """Load only the explicitly named configuration file."""
    try:
        return application(read_config(Path(os.environ["JOURNEON_CONFIG"])))
    except Exception:
        raise RuntimeError("Runtime configuration or startup failed") from None


def server_config(config: RuntimeConfig, app: FastAPI) -> uvicorn.Config:
    return uvicorn.Config(
        app,
        host=config.host,
        port=config.port,
        loop="asyncio",
        http="h11",
        ws="none",
        lifespan="on",
        workers=1,
        reload=False,
        proxy_headers=bool(config.trusted_proxy_peers),
        forwarded_allow_ips=config.trusted_proxy_peers,
        ssl_certfile=config.tls_certificate,
        ssl_keyfile=config.tls_private_key,
        ssl_version=ssl.PROTOCOL_TLS_SERVER,
        backlog=config.backlog,
        limit_concurrency=config.limit_concurrency,
        timeout_keep_alive=config.timeout_keep_alive,
        timeout_graceful_shutdown=config.timeout_graceful_shutdown,
        access_log=False,
        log_config=None,
        server_header=False,
        date_header=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    try:
        config = read_config(args.config)
        app = application(config)
        server = uvicorn.Server(server_config(config, app))
        try:
            server.run()
        finally:
            app.state.engine.dispose()
        return 0 if server.started else 1
    except Exception:
        print(json.dumps({"status": "FAIL", "detail": "Runtime configuration or startup failed"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
