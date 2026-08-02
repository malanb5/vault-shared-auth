# vault-shared-auth contribution rules

This package sits on the auth trust boundary of every consuming vault app
(`context-vault`, `shoe-vault`, `movie-vault`, `nutrition-vault`,
`household-vault`). A bug here is a simultaneous vulnerability in all of
them — this is the whole reason `vault-workspace/AGENTS.md` normally rules
out shared source packages between independent apps, and this repo is the
single, deliberate exception. Treat changes with the same care as
core-vault's own `/auth/session` contract:

- Run `make test` before every commit; do not weaken or skip the
  cookie/bearer/error-path coverage in `tests/`.
- Never change `SessionInfo`'s field meanings or `SharedSessionMiddleware`'s
  `request.state` keys without updating every consumer in the same change —
  a silent field rename here breaks five apps' auth at once, not one.
- Cut a new tag (`vX.Y.Z`) for every change that consumers need, and bump
  the pinned tag in each consumer's `pyproject.toml` deliberately. Consumers
  must never depend on a branch (e.g. `main`) — only exact tags, so an
  in-progress change here can't silently roll out to a running app's next
  Docker build.
- Keep this package dependency-light (`fastapi`, `httpx`) and free of any
  per-app domain logic. If a consumer needs behavior specific to itself
  (e.g. shoe-vault's `AuthenticatedUser` wrapper), that belongs in the
  consuming app, not here.
