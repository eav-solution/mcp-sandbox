# mcp_sandbox/middleware/auth_middleware.py
from __future__ import annotations

import json
from typing import Callable, Awaitable

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Scope, Receive, Send
from urllib.parse import parse_qs

from mcp_sandbox.utils.config import REQUIRE_AUTH, DEFAULT_USER_ID
from mcp_sandbox.db.database import db
from mcp_sandbox.utils.config import logger


class AuthMiddleware:
    """
    Lightweight ASGI middleware that enforces ?api_key=... on each request.

    Notes
    -----
    * It bypasses auth for:
        - static files `/static/*`
        - health check `/health`
    * SSE initial handshake `/sse` & JSON-RPC `/messages/`:
        `/sse` still requires api_key (same as previous logic);
        `/messages/` uses sessionId so middleware skips auth.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        # Only handle HTTP
        if scope["type"] != "http" or not REQUIRE_AUTH:
            await self.app(scope, receive, send)
            return

        path = scope["path"]

        # Paths that do not require authentication
        public_paths = ("/static/", "/health", "/messages/")
        if path.startswith(public_paths):
            await self.app(scope, receive, send)
            return

        # Get api_key from query string
        query_params = parse_qs(scope.get("query_string", b"").decode())
        api_key = (query_params.get("api_key") or [None])[0]

        if not api_key:
            await self._unauthorized(send, "API Key is required")
            return

        # Lookup user table
        user = next((u for u in db.get_all_users() if u["api_key"] == api_key), None)
        if not user:
            await self._unauthorized(send, "Invalid API Key")
            return

        # Log and attach user_id to scope for downstream handlers (as needed)
        logger.debug("Authenticated user %s", user["username"])
        scope["authenticated_user"] = user

        await self.app(scope, receive, send)

    # ------------------------------------------------------------------
    @staticmethod
    async def _unauthorized(send: Send, detail: str) -> None:
        """Send a minimal 401 JSON response and close connection."""
        body = json.dumps({"detail": detail}).encode()
        headers = [(b"content-type", b"application/json")]
        await send({"type": "http.response.start", "status": 401, "headers": headers})
        await send({"type": "http.response.body", "body": body})