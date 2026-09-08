"""Storage-agnostic OAuth 2.1 authorization-flow base for a vault app's
remote (HTTP) MCP endpoint.

Consolidates the near-identical ``OAuthAuthorizationServerProvider``
implementations previously duplicated in ``nutrition-vault/oauth.py``,
``household-vault/oauth.py``, and ``context-vault/oauth.py``: client
registration, the authorization request/code/token life cycle, and the
scope-fallback + RFC 9207 ``iss`` handling are identical control flow
across all three -- only the persistence layer differs (nutrition-vault and
household-vault use sqlite3 directly; context-vault uses async
SQLAlchemy/Postgres and carries extra collection/person claims alongside
household ones).

:class:`OAuthProviderBase` implements that shared control flow against an
injected :class:`OAuthStorage` backend, so each app's schema and query
layer stays exactly as it was -- only wrapped in a small adapter (see
``nutrition_vault/oauth.py``, ``household_vault/oauth.py``, and
``context_vault``'s ``app/oauth.py`` for the concrete adapters). None of
this module reads or writes anything itself; it only round-trips whatever
``extra`` claims mapping the storage backend gives it.

The OAuth "subject" carried on codes/tokens is always the identity
provider's (core-vault, or context-vault standing in for it pre-split)
opaque ``user_id`` UUID as a string, resolved once at login time by each
app's own ``/login``-equivalent route -- this module never talks to
core-vault itself.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from typing import Any, Mapping, Protocol

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

CODE_TTL_SECONDS = 300
ACCESS_TOKEN_TTL_SECONDS = 3600
FLOW_TTL_SECONDS = 600


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_opaque_token(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


class OAuthStorage(Protocol):
    """Persistence backend an app plugs into :class:`OAuthProviderBase`.

    Every method is declared ``async`` so a synchronous backend (sqlite3,
    with nothing to actually await in its bodies) and a genuinely async one
    (SQLAlchemy/asyncpg) satisfy the same interface. Rows are passed and
    returned as plain ``dict``-like mappings with the keys documented on
    each method below; this module never assumes a specific row/ORM type
    beyond ``__getitem__``/``.get``.

    Every ``extra`` value is an opaque, app-defined ``Mapping[str, Any]`` of
    domain claims carried from the authorization code through to the
    issued access token (e.g. ``household_id``/``household_role``/
    ``household_allow_member_edit`` for nutrition-vault and household-vault;
    ``collection_id``/``household_id``/``person_id`` for context-vault).
    :class:`OAuthProviderBase` never inspects these keys itself, only
    round-trips them, so each app can carry whatever context its own tools
    need off ``get_access_token().claims``.
    """

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None: ...

    async def register_client(self, client_info: OAuthClientInformationFull) -> None: ...

    async def insert_authorization_request(self, row: Mapping[str, Any]) -> None:
        """``row`` keys: flow_id, client_id, redirect_uri, code_challenge,
        scope, state, resource, expires_at (epoch seconds)."""
        ...

    async def get_authorization_request(self, flow_id: str) -> Mapping[str, Any] | None:
        """Returned mapping keys: client_id, redirect_uri, code_challenge,
        scope, state, resource, expires_at (epoch seconds)."""
        ...

    async def delete_authorization_request(self, flow_id: str) -> None: ...

    async def insert_auth_code(self, row: Mapping[str, Any]) -> None:
        """``row`` keys: code_hash, client_id, redirect_uri, code_challenge,
        scope, resource, subject_user_id, expires_at (epoch seconds),
        extra (Mapping), used (bool)."""
        ...

    async def get_auth_code(self, code_hash: str) -> Mapping[str, Any] | None:
        """Returned mapping keys: client_id, redirect_uri, code_challenge,
        scope, resource, subject_user_id, expires_at (epoch seconds), used
        (bool), extra (Mapping)."""
        ...

    async def mark_auth_code_used(self, code_hash: str) -> None: ...

    async def get_refresh_token(self, token_hash: str) -> Mapping[str, Any] | None:
        """Returned mapping keys: client_id, scope, expires_at (epoch
        seconds or None), subject_user_id, revoked (bool)."""
        ...

    async def get_access_token(self, token_hash: str) -> Mapping[str, Any] | None:
        """Returned mapping keys: client_id, scope, resource, expires_at
        (epoch seconds or None), subject_user_id, revoked (bool), extra
        (Mapping)."""
        ...

    async def insert_tokens(self, access_row: Mapping[str, Any], refresh_row: Mapping[str, Any]) -> None:
        """Each row's keys: token_hash, client_id, subject_user_id, scope,
        resource, expires_at (epoch seconds or None), extra (Mapping)."""
        ...

    async def revoke_by_hash(self, token_hash: str) -> None:
        """Revoke whichever access or refresh token has this hash -- the
        original providers this consolidates always revoked by hash alone
        (a sha256 digest is unique enough in practice), regardless of kind.
        """
        ...


class OAuthProviderBase(OAuthAuthorizationServerProvider):
    """Generic OAuth 2.1 authorization-server provider for a vault app's
    remote MCP endpoint, storage delegated to an injected
    :class:`OAuthStorage`.

    PKCE verification, redirect_uri matching, and client-secret comparison
    are all handled by the mcp SDK's routes/handlers; this provider only
    needs to persist and faithfully return what it's given, plus resolve
    the identity-provider login hand-off (:func:`authorize` returns a
    redirect to ``login_path``; :func:`complete_oauth_authorization_flow`
    is called once that login completes).
    """

    def __init__(self, storage: OAuthStorage, *, token_prefix: str, login_path: str = "/login") -> None:
        self._storage = storage
        self._token_prefix = token_prefix
        self._login_path = login_path

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return await self._storage.get_client(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        await self._storage.register_client(client_info)

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        """Stash the pending request and hand off to the app's login route,
        which completes the flow (via :func:`complete_oauth_authorization_flow`)
        once the identity provider confirms the user's credentials.

        The mcp SDK's ``client.validate_scope()`` returns ``None`` (rather
        than the client's registered default scope) when the ``/authorize``
        request omits a scope param -- which is exactly what claude.ai's
        requests do -- so we fall back to the client's own registered scope
        here. Otherwise the issued token ends up scopeless and every /mcp
        call is rejected with 403 insufficient_scope even though the OAuth
        dance itself succeeded.
        """
        scope = " ".join(params.scopes) if params.scopes else client.scope
        flow_id = secrets.token_urlsafe(24)
        await self._storage.insert_authorization_request(
            {
                "flow_id": flow_id,
                "client_id": client.client_id,
                "redirect_uri": str(params.redirect_uri),
                "code_challenge": params.code_challenge,
                "scope": scope,
                "state": params.state,
                "resource": params.resource,
                "expires_at": time.time() + FLOW_TTL_SECONDS,
            }
        )
        return f"{self._login_path}?flow_id={flow_id}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        row = await self._storage.get_auth_code(hash_token(authorization_code))
        if row is None or row["client_id"] != client.client_id or row.get("used"):
            return None
        return AuthorizationCode(
            code=authorization_code,
            scopes=row["scope"].split(" ") if row["scope"] else [],
            expires_at=row["expires_at"],
            client_id=row["client_id"],
            code_challenge=row["code_challenge"],
            redirect_uri=row["redirect_uri"],
            redirect_uri_provided_explicitly=True,
            resource=row["resource"],
            subject=row["subject_user_id"],
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        code_hash = hash_token(authorization_code.code)
        # AuthorizationCode (the mcp SDK's pydantic model) carries no extra
        # claims, so re-fetch them off the row this code was issued
        # against, by the same hash load_authorization_code used.
        row = await self._storage.get_auth_code(code_hash)
        await self._storage.mark_auth_code_used(code_hash)
        extra = dict((row or {}).get("extra") or {})
        return await self._issue_tokens(
            client_id=client.client_id,
            subject_user_id=authorization_code.subject,
            scopes=authorization_code.scopes,
            resource=authorization_code.resource,
            extra=extra,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        row = await self._storage.get_refresh_token(hash_token(refresh_token))
        if row is None or row["client_id"] != client.client_id or row.get("revoked"):
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=row["client_id"],
            scopes=row["scope"].split(" ") if row["scope"] else [],
            expires_at=int(float(row["expires_at"])) if row.get("expires_at") else None,
            subject=row["subject_user_id"],
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Refreshing deliberately does not carry the previous token's extra
        claims forward -- the new access token's claims come back empty
        even if the token being refreshed had them. That context can change
        more often than identity itself (a household membership changes, a
        collection is deleted), and this provider has no way to re-verify
        it against the identity provider at refresh time (no bearer token
        or picker state is retained past the original login). A client
        that needs current context after a refresh must do a fresh login.
        """
        await self._storage.revoke_by_hash(hash_token(refresh_token.token))
        return await self._issue_tokens(
            client_id=client.client_id,
            subject_user_id=refresh_token.subject,
            scopes=scopes or refresh_token.scopes,
            resource=None,
            extra={},
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        row = await self._storage.get_access_token(hash_token(token))
        if row is None or row.get("revoked"):
            return None
        if row.get("expires_at") and float(row["expires_at"]) < time.time():
            return None
        return AccessToken(
            token=token,
            client_id=row["client_id"],
            scopes=row["scope"].split(" ") if row["scope"] else [],
            expires_at=int(float(row["expires_at"])) if row.get("expires_at") else None,
            resource=row["resource"],
            subject=row["subject_user_id"],
            # extra claims ride in AccessToken.claims (an SDK-provided
            # free-form dict) since the SDK's model has no concept of
            # household/collection/person scoping -- a consuming app's
            # tools read this back via get_access_token().claims.
            claims=dict(row.get("extra") or {}),
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        await self._storage.revoke_by_hash(hash_token(token.token))

    async def _issue_tokens(
        self,
        *,
        client_id: str,
        subject_user_id: str | None,
        scopes: list[str],
        resource: str | None,
        extra: Mapping[str, Any],
    ) -> OAuthToken:
        if subject_user_id is None:
            raise ValueError("cannot issue tokens without a resource-owner subject")
        access_token = new_opaque_token(f"{self._token_prefix}_at")
        refresh_token = new_opaque_token(f"{self._token_prefix}_rt")
        scope_str = " ".join(scopes) if scopes else None
        expires_at = time.time() + ACCESS_TOKEN_TTL_SECONDS
        await self._storage.insert_tokens(
            access_row={
                "token_hash": hash_token(access_token),
                "client_id": client_id,
                "subject_user_id": subject_user_id,
                "scope": scope_str,
                "resource": resource,
                "expires_at": expires_at,
                "extra": extra,
            },
            refresh_row={
                "token_hash": hash_token(refresh_token),
                "client_id": client_id,
                "subject_user_id": subject_user_id,
                "scope": scope_str,
                "resource": resource,
                "expires_at": None,
                "extra": {},
            },
        )
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL_SECONDS,
            scope=scope_str,
            refresh_token=refresh_token,
        )


async def complete_oauth_authorization_flow(
    storage: OAuthStorage,
    flow_id: str,
    subject_user_id: str,
    *,
    code_prefix: str,
    issuer: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> str | None:
    """Issue the authorization code for a pending ``/authorize`` request
    once the identity provider has confirmed ``subject_user_id``'s
    credentials, and return the redirect_uri (with code+state) the browser
    should follow next.

    ``issuer`` adds RFC 9207's ``iss`` parameter, which lets a client
    detect a mix-up attack. Pass it only when the app's metadata also
    advertises ``authorization_response_iss_parameter_supported``: that
    field is how section 3 says a server signals support, so a client has
    no reason to require ``iss`` without it, while a client that *does*
    receive one gets an extra value it will compare against whatever issuer
    string it recorded for us. An ``iss`` that disagrees with that record
    -- because the client cached an older rendering of our issuer, say --
    makes it abort the flow under section 2.4 rather than exchange the
    code. Omitting it removes that whole class of failure, which is why
    context-vault (which doesn't advertise that field) never passes one.

    Returns ``None`` if flow_id is unknown or its request has expired, in
    which case the caller should show an error instead of redirecting.
    """
    request = await storage.get_authorization_request(flow_id)
    if request is None or float(request["expires_at"]) < time.time():
        return None
    await storage.delete_authorization_request(flow_id)
    code = new_opaque_token(code_prefix)
    await storage.insert_auth_code(
        {
            "code_hash": hash_token(code),
            "client_id": request["client_id"],
            "redirect_uri": request["redirect_uri"],
            "code_challenge": request["code_challenge"],
            "scope": request["scope"],
            "resource": request["resource"],
            "subject_user_id": subject_user_id,
            "expires_at": time.time() + CODE_TTL_SECONDS,
            "extra": dict(extra or {}),
            "used": False,
        }
    )
    extra_redirect_params = {"iss": issuer} if issuer else {}
    return construct_redirect_uri(request["redirect_uri"], code=code, state=request["state"], **extra_redirect_params)
