from __future__ import annotations

from vault_shared_auth.config import core_vault_url, home_vault_url


def test_core_vault_url_default(monkeypatch):
    monkeypatch.delenv("CORE_VAULT_URL", raising=False)
    assert core_vault_url() == "http://127.0.0.1:8100"


def test_core_vault_url_custom_default(monkeypatch):
    monkeypatch.delenv("CORE_VAULT_URL", raising=False)
    assert core_vault_url(default="http://100.104.3.103:8100") == "http://100.104.3.103:8100"


def test_core_vault_url_env_override(monkeypatch):
    monkeypatch.setenv("CORE_VAULT_URL", "http://example.test:9000/")
    assert core_vault_url() == "http://example.test:9000"


def test_home_vault_url_default(monkeypatch):
    monkeypatch.delenv("VAULT_PUBLIC_HOST", raising=False)
    monkeypatch.delenv("VAULT_PUBLIC_SCHEME", raising=False)
    assert home_vault_url() == "http://100.104.3.103:8080"
