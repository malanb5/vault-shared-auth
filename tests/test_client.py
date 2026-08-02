from __future__ import annotations

from uuid import uuid4

import httpx
import pytest

from vault_shared_auth.client import HttpCoreVaultClient


@pytest.mark.asyncio
async def test_verify_session_full_household_fields(monkeypatch):
    user_id = str(uuid4())
    household_id = str(uuid4())

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/auth/session"
        assert request.headers.get("cookie") == "context_vault_session=abc"
        return httpx.Response(
            200,
            json={
                "user_id": user_id,
                "email": "owner@example.com",
                "household_id": household_id,
                "household_role": "member",
                "household_allow_member_edit": True,
            },
        )

    monkeypatch.setattr(httpx, "AsyncClient", _mock_async_client(handler))
    result = await HttpCoreVaultClient(base_url="http://core-vault.test").verify_session(cookie="abc")

    assert result is not None
    assert str(result.user_id) == user_id
    assert result.email == "owner@example.com"
    assert str(result.household_id) == household_id
    assert result.household_role == "member"
    assert result.household_allow_member_edit is True


@pytest.mark.asyncio
async def test_verify_session_no_household(monkeypatch):
    user_id = str(uuid4())

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"user_id": user_id, "email": "solo@example.com"})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_async_client(handler))
    result = await HttpCoreVaultClient(base_url="http://core-vault.test").verify_session(cookie="abc")

    assert result is not None
    assert result.household_id is None
    assert result.household_role is None
    assert result.household_allow_member_edit is None


@pytest.mark.asyncio
async def test_verify_session_unauthorized(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    monkeypatch.setattr(httpx, "AsyncClient", _mock_async_client(handler))
    result = await HttpCoreVaultClient(base_url="http://core-vault.test").verify_session(cookie="bad")

    assert result is None


@pytest.mark.asyncio
async def test_verify_session_network_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    monkeypatch.setattr(httpx, "AsyncClient", _mock_async_client(handler))
    result = await HttpCoreVaultClient(base_url="http://core-vault.test").verify_session(cookie="abc")

    assert result is None


@pytest.mark.asyncio
async def test_verify_session_no_credentials_short_circuits():
    result = await HttpCoreVaultClient(base_url="http://core-vault.test").verify_session()
    assert result is None


@pytest.mark.asyncio
async def test_verify_session_bearer(monkeypatch):
    user_id = str(uuid4())

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("authorization") == "Bearer token123"
        return httpx.Response(200, json={"user_id": user_id, "email": "bearer@example.com"})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_async_client(handler))
    result = await HttpCoreVaultClient(base_url="http://core-vault.test").verify_session(bearer="token123")

    assert result is not None
    assert result.email == "bearer@example.com"


def _mock_async_client(handler):
    real_async_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    return factory
