# vault-shared-auth

Shared core-vault SSO client and ASGI middleware, consumed by the deployable
apps in [`vault-workspace`](https://github.com/malanb5/vault-workspace):
`context-vault`, `shoe-vault`, `movie-vault`, `nutrition-vault`, and
`household-vault`. All of them trust the same `context_vault_session` cookie
issued by core-vault's login page; this package is the single implementation
of that trust relationship instead of five copy-pasted ones.

This is the one deliberate exception to `vault-workspace`'s "no shared
source packages between independent apps" convention — see that repo's
top-level `AGENTS.md` for why the exception is scoped to this package only.

## What it provides

- `SessionInfo` — the identity core-vault returns: `user_id`, `email`, and
  optional `household_id` / `household_role` / `household_allow_member_edit`.
- `CoreVaultClient` (Protocol) / `HttpCoreVaultClient` — calls core-vault's
  `GET /auth/session` with a session cookie and/or a bearer token.
- `core_vault_url()` / `home_vault_url()` — resolve the two workspace
  services from `CORE_VAULT_URL` / `VAULT_PUBLIC_SCHEME` / `VAULT_PUBLIC_HOST`,
  each with the same defaults every consumer already used.
- `SharedSessionMiddleware` — a FastAPI/Starlette ASGI middleware that
  verifies the session cookie on every request, populates
  `request.state.owner_user_id` / `household_id` / `household_role` /
  `household_allow_member_edit`, and redirects unauthenticated browser
  requests to home-vault's login page. A no-op when `CORE_VAULT_URL` is
  unset, so app test suites run with auth disabled without mocking.

## Usage

```python
from fastapi import FastAPI
from vault_shared_auth import SharedSessionMiddleware

app = FastAPI()
app.add_middleware(
    SharedSessionMiddleware,
    skip_paths=frozenset({"/health", "/ready", "/version"}),
    skip_prefixes=("/static/", "/shared-ui/"),
)
```

Apps that use dependency injection instead of middleware (e.g. shoe-vault)
can use `HttpCoreVaultClient` directly:

```python
from vault_shared_auth import HttpCoreVaultClient

client = HttpCoreVaultClient()
session = await client.verify_session(cookie=raw_cookie)
```

## Versioning

Consumers pin an exact tag in their `pyproject.toml`
(`vault-shared-auth @ git+https://github.com/malanb5/vault-shared-auth.git@vX.Y.Z`),
never a branch. See `AGENTS.md` for the release/update process — this
package sits on every consuming app's auth trust boundary, so a change here
is a change to five apps' authentication at once.

## Development

```bash
make test
```
