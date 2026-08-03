from __future__ import annotations

from vault_shared_auth.config import (
    core_vault_url,
    home_vault_url,
    public_vault_url,
    public_vault_urls,
)


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


def test_home_vault_url_derives_https_for_tailscale_host(monkeypatch):
    monkeypatch.setenv("VAULT_PUBLIC_HOST", "mattdesktop.tail5510ea.ts.net")
    monkeypatch.delenv("VAULT_PUBLIC_SCHEME", raising=False)
    assert home_vault_url() == "https://mattdesktop.tail5510ea.ts.net:8080"


def test_home_vault_url_respects_explicit_scheme_override(monkeypatch):
    monkeypatch.setenv("VAULT_PUBLIC_HOST", "mattdesktop.tail5510ea.ts.net")
    monkeypatch.setenv("VAULT_PUBLIC_SCHEME", "http")
    assert home_vault_url() == "http://mattdesktop.tail5510ea.ts.net:8080"


def test_public_vault_url_builds_any_port_and_path(monkeypatch):
    monkeypatch.setenv("VAULT_PUBLIC_HOST", "mattdesktop.tail5510ea.ts.net")
    monkeypatch.delenv("VAULT_PUBLIC_SCHEME", raising=False)
    assert (
        public_vault_url(8100, "/portal/profile")
        == "https://mattdesktop.tail5510ea.ts.net:8100/portal/profile"
    )


def test_public_vault_urls_returns_canonical_navigation_map(monkeypatch):
    monkeypatch.setenv("VAULT_PUBLIC_HOST", "mattdesktop.tail5510ea.ts.net")
    monkeypatch.delenv("VAULT_PUBLIC_SCHEME", raising=False)
    urls = public_vault_urls()
    assert urls["home"] == "https://mattdesktop.tail5510ea.ts.net:8080"
    assert urls["core"] == "https://mattdesktop.tail5510ea.ts.net:8100"
    assert urls["context"] == "https://mattdesktop.tail5510ea.ts.net:8000"
    assert urls["movies"] == "https://mattdesktop.tail5510ea.ts.net:8770"
    assert urls["nutrition"] == "https://mattdesktop.tail5510ea.ts.net:8771"
    assert urls["shoes"] == "https://mattdesktop.tail5510ea.ts.net:8766"
    assert urls["household"] == "https://mattdesktop.tail5510ea.ts.net:8772"
