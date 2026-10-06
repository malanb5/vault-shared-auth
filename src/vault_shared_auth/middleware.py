"""ASGI middleware that makes core-vault's session the single sign-on for a
vault app's web UI. A no-op when ``CORE_VAULT_URL`` is unset, so unit/e2e
tests run with auth disabled and no mocking required.
"""

from __future__ import annotations

import html
import os
from urllib.parse import quote, urlsplit

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .client import CoreVaultClient, HttpCoreVaultClient, VaultAccessDenied
from .config import home_vault_url, public_scheme, session_cookie_name

DEFAULT_SKIP_PATHS = frozenset({"/health", "/ready", "/version"})
DEFAULT_SKIP_PREFIXES = ("/static/", "/shared-ui/")
# Explicit opt-out for a gated vault's unit tests / local dev when
# CORE_VAULT_URL is unset; without it a gated vault answers 503.
AUTH_DISABLED_ENV = "VAULT_SHARED_AUTH_DISABLED"


def _same_origin_referer_target(request: Request) -> str | None:
    """Path+query of the Referer when it is this same host, else None."""
    referer = request.headers.get("referer")
    if not referer:
        return None
    try:
        parsed = urlsplit(referer)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or parsed.netloc != request.url.netloc:
        return None
    if not parsed.path.startswith("/") or parsed.path.startswith("//"):
        return None
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")

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
        request = Request(scope, receive=receive)
        path = request.url.path
        if not os.getenv("CORE_VAULT_URL"):
            # Ungated vaults keep the historical no-op. A gated vault fails
            # closed instead: a missing CORE_VAULT_URL must never mean "no
            # allowlist, no idle timeout". Tests/local dev opt out explicitly.
            if (
                self._vault is None
                or os.getenv(AUTH_DISABLED_ENV) == "1"
                or path in self._skip_paths
                or path.startswith(self._skip_prefixes)
            ):
                await self.app(scope, receive, send)
                return
            response = HTMLResponse(
                "Authentication is not configured.",
                status_code=503,
                headers={"Cache-Control": "no-store"},
            )
            await response(scope, receive, send)
            return
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
        target = path + (f"?{request.url.query}" if request.url.query else "")
        if self._vault is not None and request.method not in ("GET", "HEAD"):
            # Don't send the user back to a POST-only URL after login.
            target = _same_origin_referer_target(request) or "/"
        destination = f"{public_scheme()}://{request.url.netloc}{target}"
        response = RedirectResponse(
            f"{home_vault_url()}/login?next={quote(destination, safe='')}",
            status_code=303,
        )
        await response(scope, receive, send)
