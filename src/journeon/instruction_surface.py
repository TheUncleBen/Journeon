# SPDX-License-Identifier: AGPL-3.0-only
"""First-party exact-effect confirmation, isolated from untrusted content."""

import html
import json
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import Engine

from journeon.api import authenticated_context
from journeon.contracts import DomainError
from journeon.instruction_config import InstructionConfiguration
from journeon.instruction_protected import InstructionConfirmation

HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
}


def page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{html.escape(title)}</title>"
        '<link rel="stylesheet" href="/instructions/surface.css">'
        '<script src="/instructions/surface.js" defer></script><main>'
        f"<h1>{html.escape(title)}</h1>{body}"
        '<p id="status" role="status" tabindex="-1"></p></main></html>',
        headers=HEADERS,
    )


def bind_surface(app: FastAPI, engine: Engine, config: InstructionConfiguration | None) -> None:
    @app.get(
        "/instructions/surface.js",
        include_in_schema=False,
        operation_id="instructionSurfaceScript",
        openapi_extra={
            "x-journeon-surface": "instructionSurfaceScript",
            "x-journeon-owner": "project_instructions",
        },
    )
    def script() -> Response:
        return Response(
            Path(__file__).with_name("assets").joinpath("confirmation.js").read_text(),
            media_type="text/javascript",
            headers=HEADERS,
        )

    @app.get(
        "/instructions/surface.css",
        include_in_schema=False,
        operation_id="instructionSurfaceStyles",
        openapi_extra={
            "x-journeon-surface": "instructionSurfaceStyles",
            "x-journeon-owner": "project_instructions",
        },
    )
    def styles() -> Response:
        return Response(
            "body{font:1rem/1.6 system-ui;margin:1rem;color:#171717;background:#fff}"
            "main{max-width:55rem;margin:auto;overflow-wrap:anywhere}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere}"
            "button,a{font:inherit}button{padding:.7rem;margin:.5rem;border:2px solid #333}"
            ":focus-visible{outline:3px solid #005fcc;outline-offset:3px}"
            "@media(prefers-color-scheme:dark){body{color:#eee;background:#171717}"
            "button{color:#eee;background:#333;border-color:#aaa}"
            ":focus-visible{outline:3px solid #8dbdff;outline-offset:3px}}",
            media_type="text/css",
            headers=HEADERS,
        )

    @app.get(
        "/instructions/authenticate",
        include_in_schema=False,
        operation_id="instructionAuthenticationPage",
        openapi_extra={
            "x-journeon-surface": "instructionAuthenticationPage",
            "x-journeon-owner": "project_instructions",
        },
    )
    def authenticate() -> HTMLResponse:
        return page(
            "Authenticate for instruction administration",
            "<p>Sign in before preparing an instruction request. Refreshing authentication "
            "invalidates requests from the previous session; prepare a new req"
            "uest afterward.</p>"
            '<button id="login" type="button">Sign in with a passkey</button>'
            '<button id="stepup" type="button">Refresh authentication</button>',
        )

    @app.get(
        "/instructions/confirmation/{request_id}",
        include_in_schema=False,
        operation_id="instructionConfirmationPage",
        openapi_extra={
            "x-journeon-surface": "instructionConfirmationPage",
            "x-journeon-owner": "project_instructions",
        },
    )
    def confirmation(request_id: str, request: Request) -> HTMLResponse:
        try:
            actor = authenticated_context(request)
        except DomainError:
            response = page(
                "Authentication required",
                "<p>A current authenticated session is required to inspect this request.</p>"
                '<a href="/instructions/authenticate">Sign in and prepare a new request</a>',
            )
            response.status_code = 401
            return response
        if config is None:
            raise DomainError(
                "DEPENDENCY_UNAVAILABLE", "Explicit instruction runtime configuration is required"
            )
        try:
            preview = InstructionConfirmation(engine, config).preview(actor, request_id)
        except DomainError:
            return page(
                "Instruction confirmation unavailable",
                "<p>The request cannot currently be confirmed. It may have expired, changed, "
                "or lost authorization. No confirmation was performed by this page.</p>"
                '<a href="/instructions/authenticate">Authenticate and prepare a new request</a>',
            )
        descriptions = {
            "permission.grant.set.v1": (
                "Set this exact permission grant, including its enabled state and expiry."
            ),
            "permission.grant.revoke.v1": "Disable this exact permission grant.",
            "egress.policy.initialize.v1": (
                "Initialize the deployment policy for local-only operation "
                "with no approved providers."
            ),
            "identity.session.revoke.v1": "Revoke the selected human browser session.",
            "lifecycle.restore.authorize.v1": (
                "Authorize the exact offline recovery of missing instruction history below. "
                "The stopped-store command stages a new database and preserves current security "
                "state and newer unselected work. This confirmation does not "
                "restore or activate it."
            ),
            "instruction.candidate.register.v1": (
                "Register local instruction assets with DEVELOPMENT_CANDIDATE "
                "provenance. This does not verify an official release."
            ),
            "instruction.release.install.v1": (
                "Install the exact verified release instruction assets after "
                "current health and backup checks."
            ),
            "project.root.admit.v1": "Admit the inspected local root for instruction operations.",
            "project.root.revoke.v1": (
                "Revoke instruction access through this admitted root. Existing files are retained."
            ),
            "project.instructions.policy.configure.v1": (
                "Change this Project's instruction acceptance policy to the exact rules below."
            ),
            "project.instructions.accept.v1": (
                "Accept and publish this exact Project instruction candidate under current policy."
            ),
            "project.instructions.recover.v1": (
                "Reconcile the existing publication using the exact disposition "
                "below. This does not renew its earlier approval."
            ),
        }
        description = html.escape(descriptions[preview.effect.kind])
        operands = html.escape(json.dumps(preview.effect.model_dump(mode="json"), indent=2))
        fields = "".join(
            f'<input type="hidden" id="{name}" value="{html.escape(str(value), quote=True)}">'
            for name, value in {
                "request_id": preview.request_id,
                "request_hash": preview.request_hash,
                "nonce": preview.nonce,
                "deadline": preview.deadline,
            }.items()
        )
        return page(
            "Confirm instruction operation",
            "<p>Review the complete stored operation below. Confirm applies th"
            "is exact operation; "
            "signing in alone does not approve it. Cancel does not undo an operation "
            "already applied.</p>"
            f"<p>{description}</p><h2>Stored operation</h2><pre>{operands}</pre>{fields}"
            '<p id="expiry"></p><button id="confirm" type="button">Confirm thi'
            "s operation</button>"
            '<button id="cancel" type="button">Cancel request</button>'
            "<p>After expiry or refreshed authentication, prepare a new request. "
            "An interrupted publication requires its exact recovery operation.</p>",
        )
