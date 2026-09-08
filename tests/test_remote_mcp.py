from __future__ import annotations

import json

import pytest

from vault_shared_auth.remote_mcp import (
    apply_metadata_canonicalization,
    canonicalize_oauth_metadata_urls,
    public_host_and_origin,
    remote_mcp_transport_security,
)


def test_public_host_and_origin_derives_from_issuer_url():
    host, origin = public_host_and_origin("https://myhost.ts.net:8443")
    assert host == "myhost.ts.net:8443"
    assert origin == "https://myhost.ts.net:8443"


def test_public_host_and_origin_http_scheme():
    host, origin = public_host_and_origin("http://127.0.0.1:8772")
    assert host == "127.0.0.1:8772"
    assert origin == "http://127.0.0.1:8772"


# AC: shared-oauth-helper-added
def test_remote_mcp_transport_security_allowlists_issuer_host_only():
    """Pins the Tailscale-Funnel DNS-rebinding host-allowlist workaround:
    FastMCP only auto-enables its DNS-rebinding Host/Origin allowlist for
    host="127.0.0.1" (localhost-only), which rejects every real request
    once reached through Tailscale Funnel's public hostname. This function
    must enable the protection explicitly (not disable it) while
    allowlisting exactly the issuer's own host/origin -- disabling
    protection outright, or allowlisting something broader than the
    issuer's own host, would both silently defeat the workaround this
    exists to pin.
    """
    settings = remote_mcp_transport_security("https://vault-nutrition.ts.net:8443")

    assert settings.enable_dns_rebinding_protection is True
    assert settings.allowed_hosts == ["vault-nutrition.ts.net:8443"]
    assert settings.allowed_origins == ["https://vault-nutrition.ts.net:8443"]


# AC: shared-oauth-helper-added
def test_remote_mcp_transport_security_does_not_allowlist_other_hosts():
    settings = remote_mcp_transport_security("https://vault-nutrition.ts.net:8443")

    assert "127.0.0.1" not in settings.allowed_hosts
    assert "localhost" not in settings.allowed_hosts
    assert "evil.example.test" not in settings.allowed_hosts


class _RecordingAsgiApp:
    def __init__(self, status: int, payload: dict | None, headers: list[tuple[bytes, bytes]] | None = None):
        self._status = status
        self._payload = payload
        self._headers = headers or [(b"content-type", b"application/json"), (b"cache-control", b"public, max-age=3600")]

    async def __call__(self, scope, receive, send):
        body = json.dumps(self._payload).encode() if self._payload is not None else b""
        await send({"type": "http.response.start", "status": self._status, "headers": self._headers})
        await send({"type": "http.response.body", "body": body})


async def _run(app, scope=None):
    scope = scope or {"type": "http"}
    sent = []

    async def receive():
        return {"type": "http.request"}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent


@pytest.mark.asyncio
# AC: shared-oauth-helper-added
async def test_canonicalize_rewrites_bare_authority_urls():
    inner = _RecordingAsgiApp(
        200,
        {
            "issuer": "https://vault-nutrition.ts.net:8443/",
            "authorization_servers": ["https://vault-nutrition.ts.net:8443/"],
        },
    )
    wrapped = canonicalize_oauth_metadata_urls(
        inner,
        {"issuer": "https://vault-nutrition.ts.net:8443"},
        {"authorization_servers": ["https://vault-nutrition.ts.net:8443"]},
    )
    sent = await _run(wrapped)
    body = json.loads(sent[1]["body"])
    assert body["issuer"] == "https://vault-nutrition.ts.net:8443"
    assert body["authorization_servers"] == ["https://vault-nutrition.ts.net:8443"]


@pytest.mark.asyncio
async def test_canonicalize_forces_no_store_cache_control():
    inner = _RecordingAsgiApp(200, {"issuer": "https://host/"})
    wrapped = canonicalize_oauth_metadata_urls(inner, {"issuer": "https://host"}, {})
    sent = await _run(wrapped)
    headers = dict(sent[0]["headers"])
    assert headers[b"cache-control"] == b"no-store"


@pytest.mark.asyncio
async def test_canonicalize_passes_through_non_200_untouched():
    inner = _RecordingAsgiApp(404, None)
    wrapped = canonicalize_oauth_metadata_urls(inner, {"issuer": "https://host"}, {})
    sent = await _run(wrapped)
    assert sent[0]["status"] == 404
    assert sent[1]["body"] == b""


@pytest.mark.asyncio
async def test_canonicalize_passes_through_non_http_scope():
    calls = []

    async def inner(scope, receive, send):
        calls.append(scope["type"])

    wrapped = canonicalize_oauth_metadata_urls(inner, {}, {})
    await wrapped({"type": "lifespan"}, None, None)
    assert calls == ["lifespan"]


def test_apply_metadata_canonicalization_wraps_only_known_metadata_paths():
    class _Route:
        def __init__(self, path):
            self.path = path
            self.app = _RecordingAsgiApp(200, {"issuer": "https://host/"})
            self.original_app = self.app

    metadata_route = _Route("/.well-known/oauth-authorization-server")
    other_route = _Route("/mcp")
    routes = [metadata_route, other_route]

    apply_metadata_canonicalization(routes, canonical_issuer="https://host", canonical_resource="https://host")

    assert metadata_route.app is not metadata_route.original_app
    assert other_route.app is other_route.original_app
