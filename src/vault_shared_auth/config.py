from __future__ import annotations

import os


def core_vault_url() -> str:
    return os.getenv("CORE_VAULT_URL", "http://100.104.3.103:8100").rstrip("/")


def home_vault_url() -> str:
    scheme = os.getenv("VAULT_PUBLIC_SCHEME", "http")
    host = os.getenv("VAULT_PUBLIC_HOST", "100.104.3.103")
    return f"{scheme}://{host}:8080"
