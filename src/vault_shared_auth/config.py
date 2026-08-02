from __future__ import annotations

import os


def core_vault_url(default: str = "http://127.0.0.1:8100") -> str:
    """Resolve core-vault's base URL from ``CORE_VAULT_URL``.

    ``default`` intentionally has no single workspace-wide value: consumers
    disagree on what to fall back to when the env var is unset
    (``context-vault``/``shoe-vault``/``household-vault`` use
    ``127.0.0.1``; ``movie-vault``/``nutrition-vault`` use the Tailscale
    IP). Pass the app's own historical default explicitly rather than
    relying on this function's default, to avoid silently changing
    fallback behavior when a consumer migrates to this package.
    """
    return os.getenv("CORE_VAULT_URL", default).rstrip("/")


def home_vault_url() -> str:
    """Resolve home-vault's public URL for cross-vault redirects (login, etc).

    VAULT_PUBLIC_SCHEME is an optional override. Left unset, the scheme is
    derived from VAULT_PUBLIC_HOST: a Tailscale MagicDNS name (*.ts.net) is
    only ever reachable through the tailnet's TLS-terminated serve/Funnel
    ports, so defaulting to "http" there sends the redirect into an
    HTTPS-only listener, which rejects it with "Client sent an HTTP request
    to an HTTPS server." A bare IP or localhost (local dev) still defaults
    to http.
    """
    host = os.getenv("VAULT_PUBLIC_HOST", "100.104.3.103")
    scheme = os.getenv(
        "VAULT_PUBLIC_SCHEME", "https" if host.endswith(".ts.net") else "http"
    )
    return f"{scheme}://{host}:8080"
