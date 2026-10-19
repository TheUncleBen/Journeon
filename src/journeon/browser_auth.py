# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit HTTPS origin binding; request headers cannot establish proxy trust."""

from dataclasses import dataclass
from urllib.parse import urlsplit

from fastapi import Request, Response
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError

from journeon.contracts import DomainError
from journeon.database import transaction
from journeon.permissions import AuthenticatedContext
from journeon.sessions import IssuedSession, denied, resolve_cookie

COOKIE_NAME = "__Host-journeon-session"


@dataclass(frozen=True)
class BrowserAuth:
    canonical_origin: str

    def __post_init__(self) -> None:
        parsed = urlsplit(self.canonical_origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.port == 0
            or parsed.netloc.endswith(":")
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
            or self.canonical_origin != f"https://{parsed.netloc}"
        ):
            raise ValueError("Browser authentication requires an exact HTTPS origin")

    def resolve(self, engine: Engine, request: Request) -> AuthenticatedContext:
        # Origin is validated independently of Host and untrusted forwarding headers.
        origin = request.headers.get("origin")
        mutation = request.method not in {"GET", "HEAD", "OPTIONS"}
        if (mutation and origin != self.canonical_origin) or (
            origin is not None and origin != self.canonical_origin
        ):
            raise denied()
        try:
            with transaction(engine) as session:
                record = resolve_cookie(
                    session,
                    request.cookies.get(COOKIE_NAME, ""),
                    csrf_token=request.headers.get("x-csrf-token"),
                    mutation=mutation,
                    activity=mutation
                    and getattr(request.scope.get("route"), "operation_id", None) != "replayEvents",
                )
                return AuthenticatedContext(record.principal_id, record.principal_epoch, record.id)
        except SQLAlchemyError:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "The authentication store is unavailable"
            ) from None

    def set_cookie(self, response: Response, issued: IssuedSession) -> None:
        response.set_cookie(
            COOKIE_NAME, issued.token, httponly=True, secure=True, samesite="lax", path="/"
        )
        response.headers["Cache-Control"] = "no-store"

    def clear_cookie(self, response: Response) -> None:
        response.delete_cookie(COOKIE_NAME, httponly=True, secure=True, samesite="lax", path="/")
        response.headers["Cache-Control"] = "no-store"
