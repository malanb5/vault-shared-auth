"""Trust boundary for assistant-vault's direct, non-OAuth calls to a vault
app's MCP tools over the private ``vault-backend`` docker network.

Consolidates the near-identical ``internal_auth.py`` previously duplicated
in ``context-vault``, ``household-vault``, ``movie-vault``,
``nutrition-vault``, and ``shoe-vault``: a single static bearer secret is
the only gate, since there's exactly one caller (assistant-vault) today.
assistant-vault resolves the calling household member's identity itself
(from the browser's core-vault session, per :class:`SharedSessionMiddleware`)
and forwards it on ``X-Vault-Owner-Id``/``X-Vault-Household-Id`` -- this
middleware trusts those headers completely once the bearer check passes,
the same way core-vault's own internal endpoints trust a valid service
token to mean "the caller is really that sibling backend" (see
``core-vault/app/auth.py``'s ``get_service_credential`` and
``docs/CORE_VAULT_INTERNAL_SERVICE_API.md`` in the workspace root).

Every consumer historically used the same env var
(``ASSISTANT_VAULT_SHARED_SECRET``) and the same two headers, so those are
this middleware's defaults; they're still constructor overrides in case a
future consumer genuinely needs a different secret source or header names
rather than forking the class.
"""

from __future__ import annotations

import hmac
import os
from contextvars import ContextVar

from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

DEFAULT_SECRET_ENV_VAR = "ASSISTANT_VAULT_SHARED_SECRET"
DEFAULT_OWNER_HEADER = "x-vault-owner-id"
DEFAULT_HOUSEHOLD_HEADER = "x-vault-household-id"

# (owner_id, household_id) for the internal call currently in flight, set by
# InternalMcpAuthMiddleware and read by a consumer's own
# _owner_id()/_household_id() helpers in preference to the OAuth access
# token or stdio env vars. None outside an internal call. One ContextVar
# shared at the package level is safe across consumers: each vault app runs
# as its own process/interpreter, so there's no cross-app collision despite
# the single module-level object.
_internal_identity: ContextVar[tuple[str, str | None] | None] = ContextVar(
    "vault_shared_auth_internal_identity", default=None
)


def current_internal_identity() -> tuple[str, str | None] | None:
    """The (owner_id, household_id) an internal caller asserted for this
    request, or None if this request didn't come through the internal-MCP
    path."""
    return _internal_identity.get()


class InternalMcpAuthMiddleware:
    """Rejects every request unless it carries the shared-secret bearer
    token and an owner id, then sets that caller-supplied identity for the
    lifetime of the request.

    Parameters:
        app: the wrapped ASGI app.
        secret_env_var: env var holding the expected bearer secret. Read
            fresh on every request (not cached at import time) so tests can
            monkeypatch it without reloading the module.
        owner_header / household_header: header names the caller uses to
            assert the owner/household identity once the bearer check
            passes.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        secret_env_var: str = DEFAULT_SECRET_ENV_VAR,
        owner_header: str = DEFAULT_OWNER_HEADER,
        household_header: str = DEFAULT_HOUSEHOLD_HEADER,
    ) -> None:
        self._app = app
        self._secret_env_var = secret_env_var
        self._owner_header = owner_header
        self._household_header = household_header

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        request = Request(scope, receive)
        presented = request.headers.get("authorization", "")
        shared_secret = os.getenv(self._secret_env_var)
        expected = f"Bearer {shared_secret}" if shared_secret else None
        if not expected or not hmac.compare_digest(presented, expected):
            await Response("unauthorized", status_code=401)(scope, receive, send)
            return

        owner_id = request.headers.get(self._owner_header)
        if not owner_id:
            await Response(
                f"missing {self._owner_header}", status_code=400
            )(scope, receive, send)
            return
        household_id = request.headers.get(self._household_header) or None

        reset_token = _internal_identity.set((owner_id, household_id))
        try:
            await self._app(scope, receive, send)
        finally:
            _internal_identity.reset(reset_token)
