"""Concrete fresh installed Gmail backend for the actual identity-only gateway."""

from __future__ import annotations

from typing import Any

from zacai.connectors.account_preflight import PreflightPlan, Provider, VerifiedCredential
from zacai.connectors.gmail_installation import GmailInstallation
from zacai.connectors.gmail_recovery_authorization import _closed
from zacai.policy import TrustBoundary


class GmailInstalledAuthority:
    @_closed
    def __init__(self, *, installation: GmailInstallation) -> None:
        if type(installation) is not GmailInstallation:
            raise ValueError("actual installed authority required")
        self._installation = self._original_installation = installation

    def _current(self, plan: Any) -> None:
        installed = self._installation
        if installed is not self._original_installation:
            raise ValueError("original installed backend required")
        installed.current_active()
        expected = installed._plan
        if (
            type(plan) is not PreflightPlan
            or expected is None
            or plan != expected
            or plan.metadata is not False
            or plan.provider is not Provider.GMAIL
            or plan.grant_profile != "read"
        ):
            raise ValueError("exact private identity-only preflight required")
        installed.current_active()

    @_closed
    def attest(self, plan: Any) -> None:
        self._current(plan)

    @_closed
    def generation(self, plan: Any) -> str:
        self._current(plan)
        generation = self._installation.generation
        if type(generation) is not str:
            raise ValueError("exact native generation required")
        return generation

    @_closed
    def credential(self, plan: Any, generation: str) -> VerifiedCredential:
        self._current(plan)
        installed = self._installation
        if generation != installed.generation:
            raise ValueError("exact installed generation required")
        token = installed.read_current()
        self._current(plan)
        return VerifiedCredential(
            token=token,
            provider=Provider.GMAIL,
            client_id=installed._configuration.client_id,
            subject_id=installed.subject,
            scopes=installed._configuration.scopes,
            token_kind="oauth_access",
            boundary=TrustBoundary.BRAINSTORM,
            expires_at=installed._expiry,
        )

    @_closed
    def quarantine(self, plan: Any, generation: str) -> None:
        installed = self._installation
        if (
            installed is not self._original_installation
            or installed._plan is None
            or plan != installed._plan
            or generation != installed.generation
        ):
            raise ValueError("exact installed quarantine generation required")
        installed.quarantine()
