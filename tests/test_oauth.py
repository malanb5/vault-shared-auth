from __future__ import annotations

import time

import pytest
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull

from vault_shared_auth.oauth import (
    OAuthProviderBase,
    complete_oauth_authorization_flow,
    hash_token,
)


class InMemoryOAuthStorage:
    """A minimal, dependency-free OAuthStorage backend for exercising
    OAuthProviderBase's control flow without a real database -- mirrors the
    dict-shaped contract each app's sqlite/SQLAlchemy adapter must satisfy.
    """

    def __init__(self):
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.requests: dict[str, dict] = {}
        self.codes: dict[str, dict] = {}
        self.tokens: dict[str, dict] = {}  # token_hash -> row (has "kind")

    async def get_client(self, client_id):
        return self.clients.get(client_id)

    async def register_client(self, client_info):
        self.clients[client_info.client_id] = client_info

    async def insert_authorization_request(self, row):
        self.requests[row["flow_id"]] = dict(row)

    async def get_authorization_request(self, flow_id):
        return self.requests.get(flow_id)

    async def delete_authorization_request(self, flow_id):
        self.requests.pop(flow_id, None)

    async def insert_auth_code(self, row):
        self.codes[row["code_hash"]] = dict(row)

    async def get_auth_code(self, code_hash):
        return self.codes.get(code_hash)

    async def mark_auth_code_used(self, code_hash):
        if code_hash in self.codes:
            self.codes[code_hash]["used"] = True

    async def get_refresh_token(self, token_hash):
        row = self.tokens.get(token_hash)
        return row if row and row.get("kind") == "refresh" else None

    async def get_access_token(self, token_hash):
        row = self.tokens.get(token_hash)
        return row if row and row.get("kind") == "access" else None

    async def insert_tokens(self, access_row, refresh_row):
        self.tokens[access_row["token_hash"]] = {**access_row, "kind": "access", "revoked": False}
        self.tokens[refresh_row["token_hash"]] = {**refresh_row, "kind": "refresh", "revoked": False}

    async def revoke_by_hash(self, token_hash):
        if token_hash in self.tokens:
            self.tokens[token_hash]["revoked"] = True


def _client(client_id="client-1", scope="vault:all") -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id=client_id,
        redirect_uris=["https://example.test/callback"],
        scope=scope,
    )


@pytest.fixture
def storage():
    return InMemoryOAuthStorage()


@pytest.fixture
def provider(storage):
    return OAuthProviderBase(storage, token_prefix="tv", login_path="/login")


@pytest.mark.asyncio
# AC: shared-oauth-helper-added
async def test_authorize_falls_back_to_client_scope_when_request_omits_scope(provider, storage):
    """Pins the claude.ai-connector fallback: an /authorize request with no
    explicit scope must not issue a scopeless flow."""
    client = _client(scope="vault:all")
    params = AuthorizationParams(
        redirect_uri="https://example.test/callback",
        redirect_uri_provided_explicitly=True,
        scopes=None,
        code_challenge="challenge",
        state="state-1",
        resource=None,
    )
    redirect = await provider.authorize(client, params)
    assert redirect.startswith("/login?flow_id=")
    flow_id = redirect.split("flow_id=", 1)[1]
    assert storage.requests[flow_id]["scope"] == "vault:all"


@pytest.mark.asyncio
# AC: shared-oauth-helper-added
async def test_full_authorization_code_flow_issues_working_access_token(provider, storage):
    client = _client()
    await storage.register_client(client)
    params = AuthorizationParams(
        redirect_uri="https://example.test/callback",
        redirect_uri_provided_explicitly=True,
        scopes=["vault:all"],
        code_challenge="challenge",
        state="state-1",
        resource="https://example.test/resource",
    )
    redirect = await provider.authorize(client, params)
    flow_id = redirect.split("flow_id=", 1)[1]

    redirect_uri = await complete_oauth_authorization_flow(
        storage,
        flow_id,
        "user-123",
        code_prefix="tv_code",
        extra={"household_id": "hh-1"},
    )
    assert redirect_uri is not None
    assert redirect_uri.startswith("https://example.test/callback?")
    assert "code=" in redirect_uri
    assert "state=state-1" in redirect_uri

    # The pending request is consumed -- a second completion attempt fails.
    assert await complete_oauth_authorization_flow(storage, flow_id, "user-123", code_prefix="tv_code") is None

    code = redirect_uri.split("code=", 1)[1].split("&", 1)[0]
    loaded_code = await provider.load_authorization_code(client, code)
    assert loaded_code is not None
    assert loaded_code.subject == "user-123"

    token = await provider.exchange_authorization_code(client, loaded_code)
    assert token.access_token.startswith("tv_at_")
    assert token.refresh_token.startswith("tv_rt_")

    access_token = await provider.load_access_token(token.access_token)
    assert access_token is not None
    assert access_token.subject == "user-123"
    assert access_token.claims == {"household_id": "hh-1"}

    # A used code cannot be exchanged again.
    assert await provider.load_authorization_code(client, code) is None


@pytest.mark.asyncio
async def test_complete_flow_returns_none_for_unknown_flow_id(storage):
    assert await complete_oauth_authorization_flow(storage, "no-such-flow", "user-1", code_prefix="tv_code") is None


@pytest.mark.asyncio
async def test_complete_flow_returns_none_for_expired_request(storage):
    await storage.insert_authorization_request(
        {
            "flow_id": "flow-1",
            "client_id": "client-1",
            "redirect_uri": "https://example.test/callback",
            "code_challenge": "c",
            "scope": "vault:all",
            "state": "s",
            "resource": None,
            "expires_at": time.time() - 10,
        }
    )
    assert await complete_oauth_authorization_flow(storage, "flow-1", "user-1", code_prefix="tv_code") is None


@pytest.mark.asyncio
async def test_complete_flow_adds_iss_only_when_issuer_given(storage):
    await storage.insert_authorization_request(
        {
            "flow_id": "flow-1",
            "client_id": "client-1",
            "redirect_uri": "https://example.test/callback",
            "code_challenge": "c",
            "scope": "vault:all",
            "state": "s",
            "resource": None,
            "expires_at": time.time() + 600,
        }
    )
    redirect_uri = await complete_oauth_authorization_flow(
        storage, "flow-1", "user-1", code_prefix="tv_code", issuer="https://issuer.test"
    )
    assert "iss=https" in redirect_uri


@pytest.mark.asyncio
async def test_complete_flow_omits_iss_by_default(storage):
    await storage.insert_authorization_request(
        {
            "flow_id": "flow-1",
            "client_id": "client-1",
            "redirect_uri": "https://example.test/callback",
            "code_challenge": "c",
            "scope": "vault:all",
            "state": "s",
            "resource": None,
            "expires_at": time.time() + 600,
        }
    )
    redirect_uri = await complete_oauth_authorization_flow(storage, "flow-1", "user-1", code_prefix="tv_code")
    assert "iss=" not in redirect_uri


@pytest.mark.asyncio
# AC: shared-oauth-helper-added
async def test_refresh_token_flow_does_not_carry_extra_claims_forward(provider, storage):
    client = _client()
    await storage.register_client(client)
    params = AuthorizationParams(
        redirect_uri="https://example.test/callback",
        redirect_uri_provided_explicitly=True,
        scopes=["vault:all"],
        code_challenge="challenge",
        state="state-1",
        resource=None,
    )
    redirect = await provider.authorize(client, params)
    flow_id = redirect.split("flow_id=", 1)[1]
    redirect_uri = await complete_oauth_authorization_flow(
        storage, flow_id, "user-1", code_prefix="tv_code", extra={"household_id": "hh-1"}
    )
    code = redirect_uri.split("code=", 1)[1].split("&", 1)[0]
    loaded_code = await provider.load_authorization_code(client, code)
    original_token = await provider.exchange_authorization_code(client, loaded_code)

    loaded_refresh = await provider.load_refresh_token(client, original_token.refresh_token)
    assert loaded_refresh is not None
    refreshed = await provider.exchange_refresh_token(client, loaded_refresh, [])

    refreshed_access = await provider.load_access_token(refreshed.access_token)
    assert refreshed_access.claims == {}

    # The old refresh token is revoked once exchanged.
    assert await provider.load_refresh_token(client, original_token.refresh_token) is None


@pytest.mark.asyncio
async def test_revoked_access_token_is_rejected(provider, storage):
    client = _client()
    await storage.register_client(client)
    params = AuthorizationParams(
        redirect_uri="https://example.test/callback",
        redirect_uri_provided_explicitly=True,
        scopes=["vault:all"],
        code_challenge="challenge",
        state="state-1",
        resource=None,
    )
    redirect = await provider.authorize(client, params)
    flow_id = redirect.split("flow_id=", 1)[1]
    redirect_uri = await complete_oauth_authorization_flow(storage, flow_id, "user-1", code_prefix="tv_code")
    code = redirect_uri.split("code=", 1)[1].split("&", 1)[0]
    loaded_code = await provider.load_authorization_code(client, code)
    token = await provider.exchange_authorization_code(client, loaded_code)

    access_token_obj = await provider.load_access_token(token.access_token)
    await provider.revoke_token(access_token_obj)

    assert await provider.load_access_token(token.access_token) is None


@pytest.mark.asyncio
async def test_expired_access_token_is_rejected(provider, storage):
    await storage.insert_tokens(
        access_row={
            "token_hash": hash_token("expired-token"),
            "client_id": "client-1",
            "subject_user_id": "user-1",
            "scope": "vault:all",
            "resource": None,
            "expires_at": time.time() - 1,
            "extra": {},
        },
        refresh_row={
            "token_hash": hash_token("expired-refresh"),
            "client_id": "client-1",
            "subject_user_id": "user-1",
            "scope": "vault:all",
            "resource": None,
            "expires_at": None,
            "extra": {},
        },
    )
    assert await provider.load_access_token("expired-token") is None


@pytest.mark.asyncio
async def test_load_access_token_rejects_unknown_token(provider):
    assert await provider.load_access_token("does-not-exist") is None


@pytest.mark.asyncio
async def test_exchange_tokens_requires_a_subject(provider):
    with pytest.raises(ValueError):
        await provider._issue_tokens(client_id="client-1", subject_user_id=None, scopes=[], resource=None, extra={})
