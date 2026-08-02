"""ASGI middleware that makes core-vault's session the single sign-on for a
vault app's web UI. A no-op when ``CORE_VAULT_URL`` is unset, so unit/e2e
tests run with auth disabled and no mocking required.
"""

from __future__ import annotations

import os
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import RedirectResponse

from .client import CoreVaultClient, HttpCoreVaultClient
from .config import home_vault_url

DEFAULT_SKIP_PATHS = frozenset({"/health", "/ready", "/version"})
DEFAULT_SKIP_PREFIXES = ("/static/", "/shared-ui/")


class SharedSessionMiddleware:
    def __init__(
        self,
        app,
        *,
        client: CoreVaultClient | None = None,
        skip_paths: frozenset[str] = DEFAULT_SKIP_PATHS,
        skip_prefixes: tuple[str, ...] = DEFAULT_SKIP_PREFIXES,
    ) -> None:
        self.app = app
        self._client = client or HttpCoreVaultClient()
        self._skip_paths = skip_paths
        self._skip_prefixes = skip_prefixes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if not os.getenv("CORE_VAULT_URL"):
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive=receive)
        path = request.url.path
        if path in self._skip_paths or path.startswith(self._skip_prefixes):
            await self.app(scope, receive, send)
            return
        raw_session = request.cookies.get("context_vault_session")
        identity = await self._client.verify_session(cookie=raw_session)
        if identity:
            state = scope.setdefault("state", {})
            state["owner_user_id"] = str(identity.user_id)
            state["household_id"] = str(identity.household_id) if identity.household_id else None
            state["household_role"] = identity.household_role
            state["household_allow_member_edit"] = identity.household_allow_member_edit
            await self.app(scope, receive, send)
            return
        destination = f"{request.url.scheme}://{request.url.netloc}{path}"
        if request.url.query:
            destination += f"?{request.url.query}"
        response = RedirectResponse(
            f"{home_vault_url()}/login?next={quote(destination, safe='')}",
            status_code=303,
        )
        await response(scope, receive, send)
