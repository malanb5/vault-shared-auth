# vault-shared-auth code map
Shared SSO/auth library (not an app) used by every vault: core-vault session check, internal-MCP bearer auth, remote-MCP OAuth scaffolding.

## Entry points
- No server/CLI; import `vault_shared_auth` (public API in `src/vault_shared_auth/__init__.py` `__all__`)

## Modules
- `middleware.py`: `SharedSessionMiddleware` (cookie -> core-vault verify -> `request.state`; else redirect to home-vault `/login?next=`; opt-in `vault=` gate: 403 if not entitled), `is_user_activity`
- `client.py`: `SessionInfo`, `CoreVaultClient` Protocol, `HttpCoreVaultClient`, `get_core_vault_client`
- `config.py`: `core_vault_url`, `public_scheme`, `session_cookie_name`, `home_vault_url`
- `internal_auth.py`: `InternalMcpAuthMiddleware`, `current_internal_identity` (assistant-vault `/mcp-internal`)
- `oauth.py`: `OAuthProviderBase`, `OAuthStorage` Protocol, `complete_oauth_authorization_flow`
- `remote_mcp.py`: transport security + OAuth metadata URL canonicalization

## Models / DB
- None; consumers implement `OAuthStorage`

## Tests
- `tests/test_{middleware,client,config,oauth,internal_auth,remote_mcp}.py`

## Gate
- `./vaultctl test vault-shared-auth` -> `uv run pytest` (`make test`)

## Gotchas
- Auth trust boundary for all consumers: `SessionInfo` fields and `request.state` keys (`owner_user_id`, `owner_email`, `household_id`, `household_role`, `household_allow_member_edit`) are a cross-app contract.
- Consumers pin exact tags (`vX.Y.Z`); behavior changes need a new tag + deliberate consumer bumps. Never depend on `main`.
- Cookie name is env-suffixed: `context_vault_session` in prod, `context_vault_session_<VAULT_ENV>` otherwise.
- Env: `CORE_VAULT_URL` (default `http://127.0.0.1:8100`), `HOME_VAULT_PUBLIC_URL`, `VAULT_PUBLIC_HOST`, `VAULT_ENV`.
- Keep deps light (`fastapi`, `httpx`) and free of per-app logic.
