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


def public_scheme() -> str:
    """Scheme this app's own public-facing origin uses.

    VAULT_PUBLIC_SCHEME is an optional override. Left unset, the scheme is
    derived from VAULT_PUBLIC_HOST: a Tailscale MagicDNS name (*.ts.net) is
    only ever reachable through the tailnet's TLS-terminated serve/Funnel
    ports, so defaulting to "http" there sends a redirect into an
    HTTPS-only listener, which rejects it with "Client sent an HTTP request
    to an HTTPS server." A bare IP or localhost (local dev) still defaults
    to http.
    """
    host = os.getenv("VAULT_PUBLIC_HOST", "100.104.3.103")
    return os.getenv(
        "VAULT_PUBLIC_SCHEME", "https" if host.endswith(".ts.net") else "http"
    )


def session_cookie_name() -> str:
    """Name of the shared SSO session cookie.

    Prod and staging share a hostname and cookies aren't port-scoped, so a
    plain "context_vault_session" cookie minted by one environment's
    home-vault gets presented to the other environment's apps too --
    those verify it against a core-vault that has never issued it, which
    always fails closed (looks identical to "not logged in"). Suffixing
    the name by VAULT_ENV keeps the two session spaces from colliding.
    """
    env = os.getenv("VAULT_ENV", "prod")
    return "context_vault_session" if env == "prod" else f"context_vault_session_{env}"


def home_vault_url() -> str:
    """Resolve home-vault's public URL for cross-vault redirects (login, etc).

    HOME_VAULT_PUBLIC_URL takes priority when set: staging deployments run
    home-vault on a different public port than production (e.g. 18080 vs
    8080), so hardcoding 8080 sends a staging app's login redirect to
    production's home-vault -- a different origin the browser's fetch()
    can't follow, surfacing as a bare "Failed to fetch" in the caller.
    """
    override = os.getenv("HOME_VAULT_PUBLIC_URL")
    if override:
        return override.rstrip("/")
    host = os.getenv("VAULT_PUBLIC_HOST", "100.104.3.103")
    return f"{public_scheme()}://{host}:8080"
