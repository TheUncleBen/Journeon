# SPDX-License-Identifier: AGPL-3.0-only
"""Explicitly configured browser passkey routes."""

import json
from typing import Any, Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from journeon.browser_auth import BrowserAuth
from journeon.contracts import DomainError, ErrorEnvelope
from journeon.passkeys import PasskeyService, RejectedPasskeyInput


class PasskeyBegin(BaseModel):
    model_config = ConfigDict(extra="forbid")
    purpose: Literal["bootstrap", "login", "stepup"]
    label: str = Field(max_length=128)
    enrollment_secret: str = Field(default="", max_length=128, repr=False)


class PasskeyFinish(BaseModel):
    model_config = ConfigDict(extra="forbid")
    purpose: Literal["bootstrap", "login", "stepup"]
    ceremony_id: str = Field(max_length=128)
    credential_json: str = Field(repr=False)


class PasskeyChallenge(BaseModel):
    ceremony_id: str
    options_json: str


class PasskeyAuthenticated(BaseModel):
    csrf_token: str


def routes(service: PasskeyService | None, binding: BrowserAuth | None) -> APIRouter:
    router = APIRouter()

    def configured(request: Request) -> tuple[PasskeyService, BrowserAuth]:
        if service is None or binding is None:
            raise DomainError("DEPENDENCY_UNAVAILABLE", "Passkey authentication is not configured")
        if request.headers.get("origin") != service.origin:
            raise RejectedPasskeyInput()
        return service, binding

    errors: dict[int | str, dict[str, Any]] = {
        status: {"model": ErrorEnvelope} for status in (401, 413, 422, 503)
    }

    @router.post(
        "/api/v1/auth/passkeys/begin",
        response_model=PasskeyChallenge,
        operation_id="beginPasskey",
        responses=errors,
        openapi_extra={
            "x-journeon-owner": "identity",
            "x-journeon-authentication": "passkey.begin.v1",
        },
    )
    def begin(command: PasskeyBegin, request: Request, response: Response) -> PasskeyChallenge:
        active, auth = configured(request)
        source = request.client.host if request.client is not None else "unavailable"
        if command.purpose == "bootstrap":
            challenge = active.begin_bootstrap(
                command.enrollment_secret, label=command.label, source=source
            )
        elif command.purpose == "login":
            challenge = active.begin_login(source=source, label=command.label)
        else:
            actor = auth.resolve(active.engine, request)
            challenge = active.begin_stepup(actor.authentication_ref, source=source)
        response.headers["Cache-Control"] = "no-store"
        return PasskeyChallenge(
            ceremony_id=challenge.ceremony_id, options_json=json.dumps(challenge.options)
        )

    @router.post(
        "/api/v1/auth/passkeys/finish",
        response_model=PasskeyAuthenticated,
        operation_id="finishPasskey",
        responses=errors,
        openapi_extra={
            "x-journeon-owner": "identity",
            "x-journeon-authentication": "passkey.finish.v1",
        },
    )
    def finish(
        command: PasskeyFinish, request: Request, response: Response
    ) -> PasskeyAuthenticated:
        active, auth = configured(request)
        session_id = None
        if command.purpose == "stepup":
            session_id = auth.resolve(active.engine, request).authentication_ref
        try:
            credential = json.loads(command.credential_json)
            if not isinstance(credential, dict):
                raise ValueError
        except (ValueError, RecursionError):
            raise DomainError("VALIDATION_FAILED", "Invalid passkey response") from None
        issued = active.complete(
            command.ceremony_id,
            purpose=command.purpose,
            response=credential,
            session_id=session_id,
            source=request.client.host if request.client is not None else "unavailable",
        )
        auth.set_cookie(response, issued)
        return PasskeyAuthenticated(csrf_token=issued.csrf_token)

    return router
