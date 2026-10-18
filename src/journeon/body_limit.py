# SPDX-License-Identifier: AGPL-3.0-only
"""Bound HTTP input before framework JSON parsing, including chunked bodies."""

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from journeon.contracts import ErrorEnvelope

MAX_COMMAND_BYTES = 65536


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
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

        await self.app(scope, bounded_receive, send)
