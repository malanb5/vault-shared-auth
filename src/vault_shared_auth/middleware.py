"""ASGI middleware that makes core-vault's session the single sign-on for a
vault app's web UI. A no-op when ``CORE_VAULT_URL`` is unset, so unit/e2e
tests run with auth disabled and no mocking required.
"""

from __future__ import annotations

import html
import os
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .client import CoreVaultClient, HttpCoreVaultClient, VaultAccessDenied
from .config import home_vault_url, public_scheme, session_cookie_name

DEFAULT_SKIP_PATHS = frozenset({"/health", "/ready", "/version"})
DEFAULT_SKIP_PREFIXES = ("/static/", "/shared-ui/")

_FORBIDDEN_PAGE = (
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
    "<title>Not authorized</title></head><body><main><h1>Not authorized</h1>"
    "<p>Your account is not approved for this vault.</p>"
    "<p><a href=\"{home}\">Back to Vault Home</a></p></main></body></html>"
)


def is_user_activity(request: Request) -> bool:
    """Whether a request counts as user activity for an idle timeout.

    Only top-level navigations and form submissions renew the window.
    Anything a page does on its own -- fetch/XHR polling, subresource loads,
    prefetches, or a request explicitly marked ``X-Vault-Background`` -- is
    checked against the timeout but never extends it.
    """
    headers = request.headers
    if request.method == "HEAD" or "x-vault-background" in headers:
        return False
    purpose = f"{headers.get('sec-purpose', '')} {headers.get('purpose', '')}".lower()
    if "prefetch" in purpose or "prerender" in purpose:
        return False
    mode = headers.get("sec-fetch-mode")
    return mode is None or mode == "navigate"


class SharedSessionMiddleware:
    def __init__(
        self,
        app,
        *,
        client: CoreVaultClient | None = None,
        skip_paths: frozenset[str] = DEFAULT_SKIP_PATHS,
        skip_prefixes: tuple[str, ...] = DEFAULT_SKIP_PREFIXES,
        vault: str | None = None,
    ) -> None:
        """``vault`` opts this app into core-vault's per-vault gate: the
        session must belong to an account on that vault's allowlist and
        must not have been idle past that vault's timeout. Leave it unset
        for the plain shared-session check every other vault uses.
        """
        self.app = app
        self._client = client or HttpCoreVaultClient()
        self._skip_paths = skip_paths
        self._skip_prefixes = skip_prefixes
        self._vault = vault

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
        raw_session = request.cookies.get(session_cookie_name())
        if self._vault is None:
            identity = await self._client.verify_session(cookie=raw_session)
        else:
            try:
                identity = await self._client.verify_session(
                    cookie=raw_session,
                    vault=self._vault,
                    activity=is_user_activity(request),
                )
            except VaultAccessDenied:
                # Authenticated but not entitled: a login redirect would only
                # bounce the same account back here, so stop with a 403.
                response = HTMLResponse(
                    _FORBIDDEN_PAGE.format(home=html.escape(home_vault_url(), quote=True)),
                    status_code=403,
                    headers={"Cache-Control": "no-store"},
                )
                await response(scope, receive, send)
                return
        if identity:
            state = scope.setdefault("state", {})
            state["owner_user_id"] = str(identity.user_id)
            state["owner_email"] = identity.email
            state["household_id"] = str(identity.household_id) if identity.household_id else None
            state["household_role"] = identity.household_role
            state["household_allow_member_edit"] = identity.household_allow_member_edit
            await self.app(scope, receive, send)
            return
        # Not request.url.scheme: Tailscale Serve terminates TLS externally
        # and forwards plain HTTP to this container, so the request the app
        # sees is always "http" even when the client used https. Using that
        # here would send the post-login redirect into this app's
        # HTTPS-only public listener, which rejects it with "Client sent an
        # HTTP request to an HTTPS server."
        destination = f"{public_scheme()}://{request.url.netloc}{path}"
        if request.url.query:
            destination += f"?{request.url.query}"
        response = RedirectResponse(
            f"{home_vault_url()}/login?next={quote(destination, safe='')}",
            status_code=303,
        )
        await response(scope, receive, send)
