"""HTTP client for core-vault's ``GET /auth/session``, the single source of
truth for the shared browser session trusted by every vault app.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

import httpx

from .config import core_vault_url


@dataclass(frozen=True)
class SessionInfo:
    user_id: UUID
    email: str
    household_id: UUID | None = None
    household_role: str | None = None
    household_allow_member_edit: bool | None = None


class CoreVaultClient(Protocol):
    async def verify_session(
        self, *, cookie: str | None = None, bearer: str | None = None
    ) -> SessionInfo | None: ...


class HttpCoreVaultClient:
    # One pooled client for the instance's lifetime (an app typically
    # constructs exactly one of these, at middleware-setup time), so
    # concurrent verify_session calls -- e.g. the burst of ~10 parallel
    # requests a page fires on initial load, each independently needing
    # session verification -- reuse warm keep-alive connections instead of
    # each opening its own new TCP/TLS connection to core-vault. Under that
    # burst, opening N simultaneous fresh connections made it more likely
    # one would miss the timeout, which surfaced as a spurious "could not
    # load" error on first login.
    def __init__(self, base_url: str | None = None, timeout: float = 2.0) -> None:
        self._client = httpx.AsyncClient(base_url=base_url or core_vault_url(), timeout=timeout)

    async def verify_session(
        self, *, cookie: str | None = None, bearer: str | None = None
    ) -> SessionInfo | None:
        if not cookie and not bearer:
            return None
        try:
            response = await self._client.get(
                "/auth/session",
                cookies={"context_vault_session": cookie} if cookie else None,
                headers={"Authorization": f"Bearer {bearer}"} if bearer else None,
            )
        except httpx.HTTPError:
            return None
        if response.status_code != 200:
            return None
        body = response.json()
        user_id = body.get("user_id")
        email = body.get("email")
        if not user_id or not email:
            return None
        household_id = body.get("household_id")
        return SessionInfo(
            user_id=UUID(user_id),
            email=email,
            household_id=UUID(household_id) if household_id else None,
            household_role=body.get("household_role"),
            household_allow_member_edit=body.get("household_allow_member_edit"),
        )

    async def aclose(self) -> None:
        await self._client.aclose()


def get_core_vault_client() -> CoreVaultClient:
    return HttpCoreVaultClient()
