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


class _GatedFakeClient:
    def __init__(self, outcome) -> None:
        self.outcome = outcome
        self.calls: list[dict] = []

    async def verify_session(self, *, cookie=None, bearer=None, vault=None, activity=False):
        self.calls.append({"cookie": cookie, "vault": vault, "activity": activity})
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome if cookie else None


def _build_gated_app(client) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SharedSessionMiddleware, client=client, vault="video-vault")

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.api_route("/page", methods=["GET", "POST", "HEAD"])
    def page(request: Request):
        return {"owner_email": request.state.owner_email}

    return app


_SESSION = SessionInfo(user_id=uuid4(), email="owner@example.com")


# AC: vv-gate-other-vaults-unchanged
def test_ungated_middleware_keeps_the_legacy_call_shape(monkeypatch):
    monkeypatch.setenv("CORE_VAULT_URL", "http://core-vault.test")
    # _FakeClient only accepts cookie/bearer: an ungated vault must never
    # pass vault=/activity=, so legacy consumers' fakes keep working.
    client = TestClient(_build_app(_SESSION))
    client.cookies.set("context_vault_session", "abc")
    assert client.get("/whoami").status_code == 200


# AC: vv-gate-allowlist
def test_gated_forbidden_account_gets_403_not_a_login_loop(monkeypatch):
    from vault_shared_auth import VaultAccessDenied

    monkeypatch.setenv("CORE_VAULT_URL", "http://core-vault.test")
    monkeypatch.setenv("HOME_VAULT_PUBLIC_URL", "https://home.example.test")
    fake = _GatedFakeClient(VaultAccessDenied("video-vault"))
    client = TestClient(_build_gated_app(fake), follow_redirects=False)
    client.cookies.set("context_vault_session", "abc")
    response = client.get("/page")
    assert response.status_code == 403
    assert "location" not in response.headers
    assert "https://home.example.test" in response.text
    assert "owner@example.com" not in response.text


# AC: vv-gate-login-redirect
def test_gated_idle_expired_session_redirects_to_login_with_destination(monkeypatch):
    monkeypatch.setenv("CORE_VAULT_URL", "http://core-vault.test")
    monkeypatch.setenv("HOME_VAULT_PUBLIC_URL", "https://home.example.test")
    fake = _GatedFakeClient(None)
    client = TestClient(_build_gated_app(fake), follow_redirects=False)
    client.cookies.set("context_vault_session", "abc")
    response = client.get("/page?x=1")
    assert response.status_code == 303
    assert response.headers["location"].startswith("https://home.example.test/login?next=")
    assert "%2Fpage%3Fx%3D1" in response.headers["location"]


# AC: vv-gate-exempt-paths
def test_gated_health_is_exempt(monkeypatch):
    monkeypatch.setenv("CORE_VAULT_URL", "http://core-vault.test")
    fake = _GatedFakeClient(None)
    client = TestClient(_build_gated_app(fake))
    assert client.get("/health").status_code == 200
    assert fake.calls == []


# AC: vv-gate-idle-timeout
@pytest.mark.parametrize(
    "method,headers,expected",
    [
        ("GET", {}, True),
        ("GET", {"Sec-Fetch-Mode": "navigate"}, True),
        ("POST", {"Sec-Fetch-Mode": "navigate"}, True),
        ("GET", {"Sec-Fetch-Mode": "cors"}, False),
        ("GET", {"Sec-Fetch-Mode": "same-origin"}, False),
        ("GET", {"Sec-Fetch-Mode": "no-cors"}, False),
        ("GET", {"X-Vault-Background": "1"}, False),
        ("GET", {"Sec-Fetch-Mode": "navigate", "Sec-Purpose": "prefetch"}, False),
        ("GET", {"Purpose": "prefetch"}, False),
        ("HEAD", {}, False),
    ],
)
def test_gated_activity_excludes_background_requests(monkeypatch, method, headers, expected):
    monkeypatch.setenv("CORE_VAULT_URL", "http://core-vault.test")
    fake = _GatedFakeClient(_SESSION)
    client = TestClient(_build_gated_app(fake))
    client.cookies.set("context_vault_session", "abc")
    response = client.request(method, "/page", headers=headers)
    assert response.status_code == 200
    assert fake.calls == [{"cookie": "abc", "vault": "video-vault", "activity": expected}]


# AC: vv-gate-fail-closed-config
def test_gated_vault_without_core_vault_url_fails_closed(monkeypatch):
    monkeypatch.delenv("CORE_VAULT_URL", raising=False)
    monkeypatch.delenv("VAULT_SHARED_AUTH_DISABLED", raising=False)
    fake = _GatedFakeClient(_SESSION)
    client = TestClient(_build_gated_app(fake), follow_redirects=False)
    response = client.get("/page")
    assert response.status_code == 503
    assert client.post("/page").status_code == 503
    assert client.get("/health").status_code == 200
    assert fake.calls == []


# AC: vv-gate-fail-closed-config
def test_gated_vault_explicit_test_opt_out(monkeypatch):
    monkeypatch.delenv("CORE_VAULT_URL", raising=False)
    monkeypatch.setenv("VAULT_SHARED_AUTH_DISABLED", "1")
    client = TestClient(_build_gated_app(_GatedFakeClient(_SESSION)), follow_redirects=False)
    # Auth skipped entirely (no request.state identity), as for ungated vaults.
    assert client.get("/health").status_code == 200


# AC: vv-gate-other-vaults-unchanged
def test_ungated_vault_without_core_vault_url_is_still_a_no_op(monkeypatch):
    monkeypatch.delenv("CORE_VAULT_URL", raising=False)
    monkeypatch.delenv("VAULT_SHARED_AUTH_DISABLED", raising=False)
    client = TestClient(_build_app(None))
    assert client.get("/whoami").status_code == 200


# AC: vv-gate-login-redirect
@pytest.mark.parametrize(
    "referer,expected_target",
    [
        ("http://testserver/manage/videos/1/edit?x=1", "/manage/videos/1/edit?x=1"),
        ("https://testserver/manage/people", "/manage/people"),
        ("https://evil.example/manage/videos", "/"),
        ("http://testserver//evil.example/x", "/"),
        ("javascript:alert(1)", "/"),
        (None, "/"),
    ],
)
def test_gated_idle_expired_post_returns_to_referer_or_root(monkeypatch, referer, expected_target):
    from urllib.parse import quote

    monkeypatch.setenv("CORE_VAULT_URL", "http://core-vault.test")
    monkeypatch.setenv("HOME_VAULT_PUBLIC_URL", "https://home.example.test")
    monkeypatch.setenv("VAULT_PUBLIC_SCHEME", "https")
    client = TestClient(_build_gated_app(_GatedFakeClient(None)), follow_redirects=False)
    client.cookies.set("context_vault_session", "abc")
    headers = {"Referer": referer} if referer else {}
    response = client.post("/page", headers=headers)
    assert response.status_code == 303
    destination = quote(f"https://testserver{expected_target}", safe="")
    assert response.headers["location"] == f"https://home.example.test/login?next={destination}"


# AC: vv-gate-other-vaults-unchanged
def test_ungated_post_redirect_keeps_the_post_url(monkeypatch):
    monkeypatch.setenv("CORE_VAULT_URL", "http://core-vault.test")
    app = _build_app(None)

    @app.post("/submit")
    def submit():
        return {}

    client = TestClient(app, follow_redirects=False)
    response = client.post("/submit", headers={"Referer": "http://testserver/elsewhere"})
    assert "%2Fsubmit" in response.headers["location"]
