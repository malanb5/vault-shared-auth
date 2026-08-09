from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from vault_shared_auth.client import SessionInfo
from vault_shared_auth.middleware import SharedSessionMiddleware


class _FakeClient:
    def __init__(self, session: SessionInfo | None) -> None:
        self._session = session

    async def verify_session(self, *, cookie=None, bearer=None):
        return self._session if cookie else None


def _build_app(session: SessionInfo | None) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SharedSessionMiddleware, client=_FakeClient(session))

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.get("/whoami")
    def whoami(request: Request):
        return {
            "owner_user_id": getattr(request.state, "owner_user_id", None),
            "owner_email": getattr(request.state, "owner_email", None),
            "household_role": getattr(request.state, "household_role", None),
        }

    return app


def test_skips_health_without_session(monkeypatch):
    monkeypatch.setenv("CORE_VAULT_URL", "http://core-vault.test")
    client = TestClient(_build_app(None))
    response = client.get("/health")
    assert response.status_code == 200


def test_redirects_to_home_vault_login_when_unauthenticated(monkeypatch):
    monkeypatch.setenv("CORE_VAULT_URL", "http://core-vault.test")
    client = TestClient(_build_app(None), follow_redirects=False)
    response = client.get("/whoami")
    assert response.status_code == 303
    assert "/login?next=" in response.headers["location"]


def test_populates_request_state_when_authenticated(monkeypatch):
    monkeypatch.setenv("CORE_VAULT_URL", "http://core-vault.test")
    session = SessionInfo(
        user_id=uuid4(),
        email="owner@example.com",
        household_role="admin",
    )
    client = TestClient(_build_app(session))
    response = client.get("/whoami", cookies={"context_vault_session": "abc"})
    assert response.status_code == 200
    body = response.json()
    assert body["owner_user_id"] == str(session.user_id)
    assert body["owner_email"] == "owner@example.com"
    assert body["household_role"] == "admin"


def test_redirect_destination_uses_public_scheme_not_request_scheme(monkeypatch):
    # Tailscale Serve terminates TLS externally and forwards plain HTTP to
    # the app, so the request this middleware sees is always "http" even
    # when the client used https. The "next" destination it builds must
    # still come out https, or the post-login redirect lands on this app's
    # HTTPS-only public listener as plaintext and gets rejected with
    # "Client sent an HTTP request to an HTTPS server."
    monkeypatch.setenv("CORE_VAULT_URL", "http://core-vault.test")
    monkeypatch.setenv("VAULT_PUBLIC_HOST", "mattdesktop.tail5510ea.ts.net")
    monkeypatch.setenv("VAULT_PUBLIC_SCHEME", "https")
    client = TestClient(_build_app(None), follow_redirects=False)
    response = client.get(
        "/whoami", headers={"host": "mattdesktop.tail5510ea.ts.net:8771"}
    )
    assert response.status_code == 303
    location = response.headers["location"]
    assert "next=https%3A%2F%2Fmattdesktop.tail5510ea.ts.net%3A8771" in location


def test_noop_when_core_vault_url_unset(monkeypatch):
    monkeypatch.delenv("CORE_VAULT_URL", raising=False)
    client = TestClient(_build_app(None))
    response = client.get("/whoami")
    assert response.status_code == 200
