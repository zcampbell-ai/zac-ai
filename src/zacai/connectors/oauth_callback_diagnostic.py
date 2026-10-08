"""Fixed execution phases only; no response values or authority are recorded."""

from __future__ import annotations

_PHASES = frozenset(
    {
        "not_started",
        "callback_current",
        "callback_owner",
        "callback_query",
        "callback_spend",
        "exchange_release",
        "exchange_credential",
        "exchange_provider",
        "exchange_current",
        "tokeninfo_provider",
        "evidence_configuration",
        "evidence_observation",
        "evidence_response",
        "evidence_exchange",
        "evidence_subject",
        "evidence_client",
        "evidence_scope",
        "evidence_time",
        "evidence_optional",
        "profile_current",
        "profile_provider",
        "native_hold",
        "hold_preservation",
        "held_receipt",
    }
)


class OAuthCallbackDiagnostic:
    """A phase is the operation reached, never a proven cause or permission."""

    def __init__(self) -> None:
        self._value: str = "not_started"

    @property
    def phase(self) -> str:
        value = self._value
        return value if type(value) is str and value in _PHASES else "unavailable"

    def __repr__(self) -> str:
        return "OAuthCallbackDiagnostic()"


def _phase(diagnostic: object, value: str) -> None:
    # Foreign objects cannot run diagnostic hooks inside an authority boundary.
    if type(diagnostic) is OAuthCallbackDiagnostic:
        diagnostic._value = value if type(value) is str and value in _PHASES else "unavailable"
