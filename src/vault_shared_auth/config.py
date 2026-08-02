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
    scheme = os.getenv("VAULT_PUBLIC_SCHEME", "http")
    host = os.getenv("VAULT_PUBLIC_HOST", "100.104.3.103")
    return f"{scheme}://{host}:8080"
