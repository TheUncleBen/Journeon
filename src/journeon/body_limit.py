# SPDX-License-Identifier: AGPL-3.0-only
"""Bound HTTP input before framework JSON parsing, including chunked bodies."""

from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from journeon.contracts import ERROR_HTTP_STATUS, DomainError, ErrorEnvelope
from journeon.passkeys import PasskeyService

MAX_COMMAND_BYTES = 65536


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp, passkeys: PasskeyService | None = None) -> None:
        self.app = app
        self.passkeys = passkeys

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        service = self.passkeys
        reservation = None
        finalized = False
        if service is not None and scope.get("path", "").startswith("/api/v1/auth/passkeys/"):
            peer = scope.get("client")
            source = peer[0] if peer else "unavailable"
            try:
                reservation = await run_in_threadpool(service.reserve_http_source, source)
            except DomainError as exc:
                denied = JSONResponse(
                    status_code=ERROR_HTTP_STATUS[exc.code],
                    content=ErrorEnvelope(code=exc.code, reason=exc.reason).model_dump(),
                )
                await denied(scope, receive, send)
                return
            except SQLAlchemyError:
                denied = JSONResponse(
                    status_code=503,
                    content=ErrorEnvelope(
                        code="DEPENDENCY_UNAVAILABLE", reason="The service store is unavailable"
                    ).model_dump(),
                )
                await denied(scope, receive, send)
                return
            original_send = send

            async def account_rejection(message: Message) -> None:
                nonlocal finalized
                if message["type"] == "http.response.start":
                    rejected_input = message["status"] in {413, 422} or bool(
                        scope.get("journeon.rejected_passkey_input", False)
                    )
                    await run_in_threadpool(service.finish_http_source, reservation, rejected_input)
                    finalized = True
                await original_send(message)

            send = account_rejection
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > MAX_COMMAND_BYTES:
                response = JSONResponse(
                    status_code=413,
                    content=ErrorEnvelope(
                        code="VALIDATION_FAILED",
                        reason="Request exceeds the command body limit",
                    ).model_dump(),
                )
                await response(scope, receive, send)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        delivered = False

        async def bounded_receive() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        try:
            await self.app(scope, bounded_receive, send)
        except Exception:
            if service is not None and reservation is not None and not finalized:
                await run_in_threadpool(service.finish_http_source, reservation, False)
            raise
