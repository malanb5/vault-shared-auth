"""Shared scaffolding for a vault app's remote (HTTP), OAuth-protected MCP
endpoint: the RFC 8414/9207 URL-canonicalization ASGI wrapper for the mcp
SDK's rendered ``.well-known`` metadata documents, and the Tailscale-Funnel
DNS-rebinding host-allowlist workaround for FastMCP's ``transport_security``.

Consolidates nutrition-vault's and household-vault's byte-for-byte
identical ``mcp_http.py`` helpers of the same name, and generalizes
context-vault's own already-parametrized ``app/oauth_metadata.py`` version
(context-vault split its OAuth metadata routes from FastMCP's own transport
for reasons specific to how it mounts ``/mcp``, so it calls
:func:`canonicalize_oauth_metadata_urls` directly with its own field maps
instead of :func:`apply_metadata_canonicalization` -- see that module).
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from mcp.server.transport_security import TransportSecuritySettings

_METADATA_PATHS = ("/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource")


def public_host_and_origin(issuer_url: str) -> tuple[str, str]:
    """The bare ``host:port`` and ``scheme://host:port`` FastMCP's
    DNS-rebinding Host/Origin allowlist needs, derived from ``issuer_url``.

    FastMCP only auto-enables that allowlist when constructed with the
    default ``host="127.0.0.1"``, restricting it to localhost -- which
    rejects every real request once reached through Tailscale Funnel's
    public hostname. A server reachable only at ``issuer_url``'s host
    (loopback-only otherwise, per each app's compose override) allowlists
    that host explicitly instead of disabling the protection outright.
    """
    parsed = urlparse(issuer_url)
    host = parsed.netloc
    origin = f"{parsed.scheme}://{host}"
    return host, origin


def remote_mcp_transport_security(issuer_url: str) -> TransportSecuritySettings:
    """``TransportSecuritySettings`` enabling DNS-rebinding protection with
    ``issuer_url``'s own host/origin allowlisted -- the Tailscale-Funnel
    workaround this package's tests pin. See :func:`public_host_and_origin`.
    """
    host, origin = public_host_and_origin(issuer_url)
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[host],
        allowed_origins=[origin],
    )


def canonicalize_oauth_metadata_urls(
    asgi_app: Any, url_fields: dict[str, str], list_fields: dict[str, list[str]]
):
    """Rewrite our own identity URLs in an SDK-rendered OAuth metadata
    response so a bare-authority issuer/resource URL a client was
    configured with (no trailing "/") matches what we publish.

    The mcp SDK renders ``.well-known`` metadata documents from pydantic
    ``AnyHttpUrl`` values, which append "/" to a bare-authority URL -- so
    ``https://host:8443`` would get published as ``https://host:8443/``,
    while a client configured with the slash-free string holds that as the
    issuer identifier it expects back. RFC 8414 section 3.3 has the client
    compare the two for equality, and RFC 9207 section 2.4 requires it to
    abort the flow when a callback's ``iss`` doesn't match -- producing
    exactly the observed failure this was written to fix, where login
    succeeds, the app redirects back with a valid code, and the client
    never calls ``/token``.

    Wrapping the SDK's rendered response (rather than rebuilding the
    document) keeps every other field in sync with the SDK. This wraps at
    the ASGI layer because the SDK serves these routes through
    ``CORSMiddleware``, so the route's callable is an ASGI app rather than
    a request -> response endpoint.
    """

    async def canonicalized(scope, receive, send):
        if scope["type"] != "http":
            await asgi_app(scope, receive, send)
            return

        start: dict = {}
        chunks: list[bytes] = []

        async def capture(message):
            if message["type"] == "http.response.start":
                start.update(message)
                return
            if message["type"] != "http.response.body":
                await send(message)
                return
            chunks.append(message.get("body", b""))
            if message.get("more_body", False):
                return

            body = b"".join(chunks)
            if start.get("status") == 200 and body:
                payload = json.loads(body)
                for field, canonical in url_fields.items():
                    if field in payload:
                        payload[field] = canonical
                for field, canonical in list_fields.items():
                    if field in payload:
                        payload[field] = canonical
                body = json.dumps(payload).encode()

            # The SDK serves these with a hardcoded "public, max-age=3600".
            # A cached copy of our identity outliving a change to it is its
            # own outage -- a client that cached the pre-canonicalization
            # issuer keeps failing iss validation for an hour after the fix
            # is live. These documents are tiny and rarely fetched, so the
            # revalidation traffic is not worth that failure mode.
            headers = [
                (key, value)
                for key, value in start["headers"]
                if key.lower() not in {b"content-length", b"cache-control"}
            ]
            headers.append((b"content-length", str(len(body)).encode()))
            headers.append((b"cache-control", b"no-store"))
            await send({**start, "headers": headers})
            await send({"type": "http.response.body", "body": body})

        await asgi_app(scope, receive, capture)

    return canonicalized


def apply_metadata_canonicalization(routes: list[Any], *, canonical_issuer: str, canonical_resource: str) -> None:
    """Wrap the two well-known OAuth metadata routes in ``routes`` (a
    Starlette app's ``.routes`` list) with
    :func:`canonicalize_oauth_metadata_urls`, in place, for an app that
    mounts the FastMCP-rendered metadata routes directly -- the
    nutrition-vault/household-vault shape, where both metadata documents
    are served by the one FastMCP-built Starlette app and share the same
    ``issuer``/``resource``/``authorization_servers`` field names.

    Context-vault's routes are laid out differently (issuer and resource
    metadata are two separate routes needing different canonical field
    maps) and calls :func:`canonicalize_oauth_metadata_urls` directly
    instead -- see its ``app/oauth_metadata.py``.
    """
    url_fields = {"issuer": canonical_issuer, "resource": canonical_resource}
    list_fields = {"authorization_servers": [canonical_issuer]}
    for route in routes:
        if getattr(route, "path", None) in _METADATA_PATHS:
            route.app = canonicalize_oauth_metadata_urls(route.app, url_fields, list_fields)
