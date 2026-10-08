"""Pure invented evidence and fixed phase telemetry; no owner storage or providers."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from zacai.connectors.account_preflight import Provider
from zacai.connectors.oauth_callback_diagnostic import OAuthCallbackDiagnostic, _phase
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.provider_oauth_evidence import OAuthEvidenceError, parse_google_oauth_evidence
from zacai.interfaces.gmail_recovery_host import GmailRecoveryHostPlan

NOW = datetime(2026, 10, 7, tzinfo=UTC)


def inputs() -> tuple[OAuthConfiguration, dict[str, Any], dict[str, Any]]:
    config = OAuthConfiguration(
        provider=Provider.GMAIL,
        registration_id="invented-project",
        client_id="123-invented.apps.googleusercontent.com",
        private_origin="https://caz.example",
        grant_profile="approved_communications",
    )
    exchange = {
        "access_token": "invented-access-only",
        "refresh_token": "invented-refresh-only",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": " ".join(config.scopes),
    }
    info = {
        "aud": config.client_id,
        "sub": "123456789",
        "scope": " ".join(config.scopes),
        "expires_in": "3598",
    }
    return config, exchange, info


@pytest.mark.parametrize(
    ("field", "value", "stage"),
    [
        ("sub", None, "evidence_subject"),
        ("aud", "wrong-invented-client", "evidence_client"),
        ("scope", "https://mail.google.com/", "evidence_scope"),
        ("expires_in", "1", "evidence_time"),
        ("email_verified", False, "evidence_optional"),
    ],
)
def test_exact_reached_predicate_and_unchanged_denial(field: str, value: Any, stage: str) -> None:
    config, exchange, info = inputs()
    info[field] = value
    diagnostic = OAuthCallbackDiagnostic()
    with pytest.raises(OAuthEvidenceError, match="^OAuth response candidate unavailable$"):
        parse_google_oauth_evidence(
            config,
            json.dumps(exchange).encode(),
            json.dumps(info).encode(),
            expected_subject=None,
            exchange_observed_at=NOW,
            evidence_observed_at=NOW + timedelta(seconds=2),
            diagnostic=diagnostic,
        )
    assert diagnostic.phase == stage
    assert repr(diagnostic) == "OAuthCallbackDiagnostic()"
    assert "invented" not in repr(diagnostic)


def test_subject_phase_is_not_claim_of_single_cause_or_fallback() -> None:
    config, exchange, info = inputs()
    del info["sub"]
    info["aud"] = "also-wrong-client"
    diagnostic = OAuthCallbackDiagnostic()
    with pytest.raises(OAuthEvidenceError):
        parse_google_oauth_evidence(
            config,
            json.dumps(exchange).encode(),
            json.dumps(info).encode(),
            expected_subject=None,
            exchange_observed_at=NOW,
            evidence_observed_at=NOW + timedelta(seconds=2),
            diagnostic=diagnostic,
        )
    # Original order remains: this only identifies the reached subject predicate.
    assert diagnostic.phase == "evidence_subject"


def test_valid_candidate_is_still_uninstalled_and_trace_cannot_supply_identity() -> None:
    config, exchange, info = inputs()
    diagnostic = OAuthCallbackDiagnostic()
    candidate = parse_google_oauth_evidence(
        config,
        json.dumps(exchange).encode(),
        json.dumps(info).encode(),
        expected_subject=None,
        exchange_observed_at=NOW,
        evidence_observed_at=NOW + timedelta(seconds=2),
        diagnostic=diagnostic,
    )
    assert candidate.installed is False and candidate.subject_pin_verified is False
    assert candidate.subject_id == "123456789"
    assert diagnostic.phase == "evidence_optional"


def test_foreign_and_spoofed_values_never_execute_hooks_or_render() -> None:
    class Foreign:
        @property
        def phase(self) -> str:
            raise AssertionError("foreign diagnostic hook")

        def __eq__(self, other: object) -> bool:
            raise AssertionError("foreign comparison")

        def __repr__(self) -> str:
            raise AssertionError("foreign rendering")

    foreign = Foreign()
    _phase(foreign, "callback_owner")
    diagnostic = OAuthCallbackDiagnostic()
    diagnostic._value = foreign  # type: ignore[assignment]
    assert diagnostic.phase == "unavailable"
    host = object.__new__(GmailRecoveryHostPlan)
    host._callback_diagnostic = foreign  # type: ignore[assignment]
    assert host.callback_stage == "unavailable"
    host._callback_diagnostic = diagnostic
    assert host.callback_stage == "unavailable"
    _phase(diagnostic, "native_hold")
    assert host.callback_stage == "native_hold"
    _phase(diagnostic, "arbitrary-private-response")
    assert host.callback_stage == "unavailable"


@pytest.mark.parametrize("cancel", [False, True])
@pytest.mark.parametrize("hold_failure", [False, True])
def test_exchange_failed_release_retains_phase_and_original_hold_category(
    monkeypatch: pytest.MonkeyPatch, cancel: bool, hold_failure: bool
) -> None:
    from pydantic import SecretStr

    import zacai.connectors.oauth_exchange as exchange_module
    from zacai.connectors.oauth_transactions import OAuthExchangeOperation

    diagnostic = OAuthCallbackDiagnostic()
    operation = object.__new__(OAuthExchangeOperation)
    calls: list[str] = []

    def fail_release(_: object) -> Any:
        raise KeyboardInterrupt() if cancel else ValueError("invented-private-error")

    def hold() -> None:
        calls.append("hold")
        if hold_failure:
            raise ValueError("invented-private-cleanup-error")

    operation.hold = hold  # type: ignore[method-assign]
    operation.halt_unconfirmed = lambda: calls.append("halt")  # type: ignore[method-assign]
    monkeypatch.setattr(exchange_module, "_profile_operation", fail_release)
    expected = (
        exchange_module.OAuthExchangeCancellationHoldUnconfirmed
        if cancel and hold_failure
        else exchange_module.OAuthExchangeCancelled
        if cancel
        else exchange_module.OAuthExchangeHoldUnconfirmed
        if hold_failure
        else exchange_module.OAuthExchangeError
    )
    with pytest.raises(expected) as failure:
        exchange_module.exchange_initial(
            operation,
            transport=exchange_module.OAuthExchangeTransport(),
            client_secret_loader=lambda _: SecretStr("unused-invented-secret"),
            diagnostic=diagnostic,
        )
    assert calls == (["hold", "halt"] if hold_failure else ["hold"])
    assert diagnostic.phase == ("hold_preservation" if hold_failure else "exchange_release")
    assert "invented" not in str(failure.value)


@pytest.mark.parametrize(
    "failure_stage", ["callback_current", "callback_owner", "callback_query", "callback_spend"]
)
def test_actual_callback_entry_fixed_failure_phases_without_storage(
    monkeypatch: pytest.MonkeyPatch, failure_stage: str
) -> None:
    from types import SimpleNamespace

    from starlette.requests import Request

    from zacai.connectors.gmail_recovery_consumer import GmailRecoveryAdmission
    from zacai.connectors.oauth_transactions import OAuthTransactionAuthority, OAuthTransactionError

    diagnostic = OAuthCallbackDiagnostic()
    authority = object.__new__(OAuthTransactionAuthority)
    admission = object.__new__(GmailRecoveryAdmission)
    config, _, _ = inputs()

    def fail() -> Any:
        raise ValueError("invented-private-fault")

    # Fault injection isolates phase propagation; no authority is granted and
    # the real callback parser still runs for the query/spend cases.
    monkeypatch.setattr(
        authority, "_ready", fail if failure_stage == "callback_current" else lambda: None
    )
    monkeypatch.setattr(authority, "_configuration", lambda *_: (config, "invented-account"))
    monkeypatch.setattr(authority, "_scope", lambda *_: None)
    monkeypatch.setattr(authority, "_locked", fail)
    object.__setattr__(admission, "_authority", authority)
    object.__setattr__(admission, "_consumer", SimpleNamespace(_diagnostic=diagnostic))
    object.__setattr__(
        admission,
        "validate_callback",
        (lambda _: fail()) if failure_stage == "callback_owner" else lambda _: None,
    )
    object.__setattr__(
        admission,
        "_action",
        SimpleNamespace(
            _hr_operation=SimpleNamespace(
                establish=lambda: SimpleNamespace(binding_digest="invented-binding")
            )
        ),
    )
    raw = (
        b"malformed%query"
        if failure_stage == "callback_query"
        else b"state=" + b"a" * 43 + b"&code=invented-code"
    )
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": "/connections/gmail/callback",
            "query_string": raw,
            "headers": [],
        }
    )
    with pytest.raises(OAuthTransactionError) as failure:
        authority.consume_recovery_callback(config, request=request, admission=admission)
    assert diagnostic.phase == failure_stage
    assert "invented" not in str(failure.value)
