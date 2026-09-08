from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from vault_shared_auth.internal_auth import (
    InternalMcpAuthMiddleware,
    current_internal_identity,
)


def _build_app(**middleware_kwargs) -> FastAPI:
    app = FastAPI()
    app.add_middleware(InternalMcpAuthMiddleware, **middleware_kwargs)

    @app.get("/mcp-internal/whoami")
    def whoami():
        identity = current_internal_identity()
        return {
            "owner_id": identity[0] if identity else None,
            "household_id": identity[1] if identity else None,
        }

    return app


def test_rejects_missing_bearer(monkeypatch):
    monkeypatch.setenv("ASSISTANT_VAULT_SHARED_SECRET", "s3cret")
    client = TestClient(_build_app())
    response = client.get(
        "/mcp-internal/whoami", headers={"x-vault-owner-id": "owner-1"}
    )
    assert response.status_code == 401


def test_rejects_wrong_bearer(monkeypatch):
    monkeypatch.setenv("ASSISTANT_VAULT_SHARED_SECRET", "s3cret")
    client = TestClient(_build_app())
    response = client.get(
        "/mcp-internal/whoami",
        headers={
            "authorization": "Bearer wrong",
            "x-vault-owner-id": "owner-1",
        },
    )
    assert response.status_code == 401


def test_rejects_when_secret_unset(monkeypatch):
    # No caller from outside the trusted network can ever satisfy this: an
    # unset secret means "Bearer None" never compares equal to anything a
    # caller could present.
    monkeypatch.delenv("ASSISTANT_VAULT_SHARED_SECRET", raising=False)
    client = TestClient(_build_app())
    response = client.get(
        "/mcp-internal/whoami",
        headers={"authorization": "Bearer ", "x-vault-owner-id": "owner-1"},
    )
    assert response.status_code == 401


def test_rejects_missing_owner_id(monkeypatch):
    monkeypatch.setenv("ASSISTANT_VAULT_SHARED_SECRET", "s3cret")
    client = TestClient(_build_app())
    response = client.get(
        "/mcp-internal/whoami", headers={"authorization": "Bearer s3cret"}
    )
    assert response.status_code == 400


def test_accepts_valid_call_and_sets_identity(monkeypatch):
    monkeypatch.setenv("ASSISTANT_VAULT_SHARED_SECRET", "s3cret")
    client = TestClient(_build_app())
    response = client.get(
        "/mcp-internal/whoami",
        headers={
            "authorization": "Bearer s3cret",
            "x-vault-owner-id": "owner-1",
            "x-vault-household-id": "household-1",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["owner_id"] == "owner-1"
    assert body["household_id"] == "household-1"


def test_household_id_optional(monkeypatch):
    monkeypatch.setenv("ASSISTANT_VAULT_SHARED_SECRET", "s3cret")
    client = TestClient(_build_app())
    response = client.get(
        "/mcp-internal/whoami",
        headers={"authorization": "Bearer s3cret", "x-vault-owner-id": "owner-1"},
    )
    assert response.status_code == 200
    assert response.json()["household_id"] is None


def test_identity_not_leaked_outside_request(monkeypatch):
    monkeypatch.setenv("ASSISTANT_VAULT_SHARED_SECRET", "s3cret")
    client = TestClient(_build_app())
    client.get(
        "/mcp-internal/whoami",
        headers={"authorization": "Bearer s3cret", "x-vault-owner-id": "owner-1"},
    )
    assert current_internal_identity() is None


def test_custom_secret_env_var_and_headers(monkeypatch):
    monkeypatch.setenv("CUSTOM_SECRET", "s3cret")
    client = TestClient(
        _build_app(
            secret_env_var="CUSTOM_SECRET",
            owner_header="x-caller-owner-id",
            household_header="x-caller-household-id",
        )
    )
    response = client.get(
        "/mcp-internal/whoami",
        headers={
            "authorization": "Bearer s3cret",
            "x-caller-owner-id": "owner-9",
            "x-caller-household-id": "household-9",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["owner_id"] == "owner-9"
    assert body["household_id"] == "household-9"


def test_non_http_scope_passthrough():
    # Middleware must not choke on lifespan/websocket scopes -- it only
    # gates HTTP requests.
    async def inner_app(scope, receive, send):
        assert scope["type"] == "lifespan"

    middleware = InternalMcpAuthMiddleware(inner_app)

    async def _run():
        await middleware({"type": "lifespan"}, None, None)

    import asyncio

    asyncio.run(_run())
