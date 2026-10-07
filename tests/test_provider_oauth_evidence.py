"""Invented provider responses only. No OAuth, network, Keychain or grants."""

from __future__ import annotations

import json
import traceback
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

import zacai.connectors.provider_oauth_evidence as evidence
from zacai.connectors.account_preflight import Provider
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.provider_oauth_evidence import (
    OAuthEvidenceCancelled,
    OAuthEvidenceError,
    SlackRotation,
    parse_google_oauth_evidence,
    parse_slack_oauth_evidence,
)

NOW = datetime(2026, 10, 6, 12, tzinfo=UTC)
ACCESS = "invented-access-only"
REFRESH = "invented-refresh-only"
SUBJECT = "123456789012345678901"
USER = "U12345678"


def google() -> OAuthConfiguration:
    return OAuthConfiguration(
        provider=Provider.GMAIL,
        registration_id="invented-project",
        client_id="123-invented.apps.googleusercontent.com",
        private_origin="https://caz.example",
        grant_profile="approved_communications",
    )


def slack() -> OAuthConfiguration:
    return OAuthConfiguration(
        provider=Provider.SLACK,
        registration_id="A12345678",
        client_id="123456.123456",
        private_origin="https://caz.example",
        grant_profile="approved_communications",
        slack_team_id="T12345678",
    )


def data(value: Any) -> bytes:
    return json.dumps(value).encode()


def google_responses() -> tuple[dict[str, Any], dict[str, Any]]:
    config = google()
    return (
        {
            "access_token": ACCESS,
            "refresh_token": REFRESH,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": " ".join(sorted(config.scopes)),
        },
        {
            "azp": config.client_id,
            "aud": config.client_id,
            "sub": SUBJECT,
            "scope": " ".join(sorted(config.scopes)),
            "exp": str(int(NOW.timestamp()) + 3600),
            "expires_in": "3598",
            "access_type": "offline",
        },
    )


def gmail_result(exchange: dict[str, Any], info: dict[str, Any]) -> Any:
    return parse_google_oauth_evidence(
        google(),
        data(exchange),
        data(info),
        expected_subject=SUBJECT,
        exchange_observed_at=NOW,
        evidence_observed_at=NOW + timedelta(seconds=2),
    )


def slack_response(rotating: bool = True) -> dict[str, Any]:
    user: dict[str, Any] = {
        "id": USER,
        "scope": ",".join(sorted(slack().scopes)),
        "token_type": "user",
        "access_token": ACCESS,
    }
    if rotating:
        user.update(refresh_token=REFRESH, expires_in=43200)
    return {
        "ok": True,
        "app_id": "A12345678",
        "team": {"id": "T12345678"},
        "authed_user": user,
        "enterprise": None,
        "is_enterprise_install": False,
    }


def slack_result(value: dict[str, Any], rotation: SlackRotation = SlackRotation.ROTATING) -> Any:
    return parse_slack_oauth_evidence(
        slack(), data(value), expected_user_id=USER, rotation=rotation, observed_at=NOW
    )


def test_google_decimal_tokeninfo_exact_response_remains_uninstalled() -> None:
    exchange, info = google_responses()
    candidate = gmail_result(exchange, info)
    assert (
        candidate.subject_id == SUBJECT
        and candidate.configuration_digest == google().configuration_digest
    )
    assert candidate.access_token.get_secret_value() == ACCESS
    assert candidate.refresh_token.get_secret_value() == REFRESH
    assert candidate.expires_at == NOW + timedelta(hours=1)
    assert (
        not candidate.installed
        and not candidate.read_identity_verified
        and not candidate.live_access_proven
    )
    assert ACCESS not in repr(candidate) and REFRESH not in repr(candidate)


@pytest.mark.parametrize(
    "field,value",
    [
        ("sub", "other-owner"),
        ("sub", None),
        ("azp", "wrong-client"),
        ("aud", "wrong-client"),
        ("scope", "https://mail.google.com/"),
        ("expires_in", True),
        ("expires_in", "3e3"),
        ("expires_in", "+3598"),
        ("expires_in", " 3598"),
        ("expires_in", "-1"),
        ("expires_in", "0"),
        ("expires_in", "3601"),
        ("expires_in", 3598.0),
        ("exp", "999999999999"),
        ("email", "other@example.test"),
        ("email_verified", 1),
    ],
)
def test_google_account_client_grant_and_expiry_mismatch_hold(field: str, value: Any) -> None:
    exchange, info = google_responses()
    info[field] = value
    with pytest.raises(OAuthEvidenceError):
        gmail_result(exchange, info)


@pytest.mark.parametrize("field", ["access_token", "refresh_token", "expires_in", "token_type"])
def test_google_missing_lifecycle_material_never_falls_back(field: str) -> None:
    exchange, info = google_responses()
    del exchange[field]
    with pytest.raises(OAuthEvidenceError):
        gmail_result(exchange, info)


def test_google_requires_client_evidence_and_expiry_agreement() -> None:
    exchange, info = google_responses()
    del info["azp"], info["aud"]
    with pytest.raises(OAuthEvidenceError):
        gmail_result(exchange, info)
    exchange, info = google_responses()
    info["expires_in"] = "2000"
    with pytest.raises(OAuthEvidenceError):
        gmail_result(exchange, info)


def test_google_omitted_exchange_scope_uses_actual_tokeninfo_not_requested_scope() -> None:
    exchange, info = google_responses()
    del exchange["scope"]
    assert gmail_result(exchange, info).scopes == google().scopes
    info["scope"] = ""
    with pytest.raises(OAuthEvidenceError):
        gmail_result(exchange, info)


@pytest.mark.parametrize(
    "value",
    [
        b'{"error":"invented-access-only"}',
        b'{"access_token":"a","access_token":"b"}',
        b'{"expires_in":NaN}',
        b"[]",
        b"x" * 65537,
    ],
)
def test_google_invalid_raw_response_is_secret_safe(value: bytes) -> None:
    _, info = google_responses()
    with pytest.raises(OAuthEvidenceError) as failure:
        parse_google_oauth_evidence(
            google(),
            value,
            data(info),
            expected_subject=SUBJECT,
            exchange_observed_at=NOW,
            evidence_observed_at=NOW,
        )
    assert failure.value.__context__ is None
    assert ACCESS not in "".join(traceback.format_exception(failure.value))
    parser_frame = failure.value.__traceback__.tb_next
    assert parser_frame is not None
    assert "exchange_bytes" not in parser_frame.tb_frame.f_locals
    assert "tokeninfo_bytes" not in parser_frame.tb_frame.f_locals


@pytest.mark.parametrize("rotation", [SlackRotation.ROTATING, SlackRotation.NONROTATING])
def test_slack_actual_user_shape_and_reviewed_rotation(rotation: SlackRotation) -> None:
    candidate = slack_result(slack_response(rotation is SlackRotation.ROTATING), rotation)
    assert candidate.subject_id == USER and candidate.slack_team_id == "T12345678"
    assert not candidate.installed and not candidate.live_access_proven
    assert (candidate.refresh_token is not None) is (rotation is SlackRotation.ROTATING)
    assert (candidate.expires_at is not None) is (rotation is SlackRotation.ROTATING)
    assert ACCESS not in repr(candidate)


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "U87654321"),
        ("token_type", "bot"),
        ("scope", "chat:write"),
        ("access_token", "bad\nsecret"),
        ("expires_in", True),
        ("expires_in", 43201),
        ("refresh_token", None),
    ],
)
def test_slack_wrong_user_kind_grant_and_lifecycle_hold(field: str, value: Any) -> None:
    response = slack_response()
    response["authed_user"][field] = value
    with pytest.raises(OAuthEvidenceError):
        slack_result(response)


@pytest.mark.parametrize(
    "field,value",
    [
        ("app_id", "A87654321"),
        ("team", {"id": "T87654321"}),
        ("is_enterprise_install", True),
        ("ok", 1),
        ("access_token", "invented-bot"),
        ("scope", "chat:write"),
    ],
)
def test_slack_rejects_workspace_app_mismatch_and_bot_default(field: str, value: Any) -> None:
    response = slack_response()
    response[field] = value
    with pytest.raises(OAuthEvidenceError):
        slack_result(response)


def test_slack_never_infers_rotation_or_initial_from_refresh_shape() -> None:
    with pytest.raises(OAuthEvidenceError):
        slack_result(slack_response(False))
    with pytest.raises(OAuthEvidenceError):
        slack_result(slack_response(), SlackRotation.NONROTATING)
    initial = slack_response()
    refresh_shape = initial["authed_user"] | {
        "ok": True,
        "app_id": initial["app_id"],
        "team": initial["team"],
    }
    with pytest.raises(OAuthEvidenceError):
        slack_result(refresh_shape)


@pytest.mark.parametrize("failure", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("provider", [Provider.GMAIL, Provider.SLACK])
def test_parser_cancellation_discards_secret_frames(
    monkeypatch: Any, failure: Any, provider: Provider
) -> None:
    def interrupt(raw: bytes) -> Any:
        private = ACCESS
        assert private
        raise failure(private)

    monkeypatch.setattr(evidence, "_object", interrupt)
    with pytest.raises(OAuthEvidenceCancelled) as caught:
        if provider is Provider.GMAIL:
            gmail_result(*google_responses())
        else:
            slack_result(slack_response())
    assert caught.value.__context__ is None
    assert ACCESS not in "".join(traceback.format_exception(caught.value))
    tb = caught.value.__traceback__
    while tb is not None:
        assert tb.tb_frame.f_code.co_name != "interrupt"
        tb = tb.tb_next


@pytest.mark.parametrize("provider", [Provider.GMAIL, Provider.SLACK])
def test_first_install_discovers_candidate_without_owner_identity_mapping(
    provider: Provider,
) -> None:
    if provider is Provider.GMAIL:
        exchange, info = google_responses()
        candidate = parse_google_oauth_evidence(
            google(),
            data(exchange),
            data(info),
            expected_subject=None,
            exchange_observed_at=NOW,
            evidence_observed_at=NOW + timedelta(seconds=2),
        )
        assert candidate.subject_id == SUBJECT
    else:
        candidate = parse_slack_oauth_evidence(
            slack(),
            data(slack_response()),
            expected_user_id=None,
            rotation=SlackRotation.ROTATING,
            observed_at=NOW,
        )
        assert candidate.subject_id == USER
    assert candidate.subject_pin_verified is False
    assert (
        not candidate.installed
        and not candidate.live_access_proven
        and not candidate.read_identity_verified
    )


@pytest.mark.parametrize("provider", [Provider.GMAIL, Provider.SLACK])
def test_discovery_still_requires_actual_subject_and_pinned_app_client_team(
    provider: Provider,
) -> None:
    if provider is Provider.GMAIL:
        exchange, info = google_responses()
        del info["sub"]
        with pytest.raises(OAuthEvidenceError):
            parse_google_oauth_evidence(
                google(),
                data(exchange),
                data(info),
                expected_subject=None,
                exchange_observed_at=NOW,
                evidence_observed_at=NOW,
            )
    else:
        response = slack_response()
        response["team"]["id"] = "T87654321"
        with pytest.raises(OAuthEvidenceError):
            parse_slack_oauth_evidence(
                slack(),
                data(response),
                expected_user_id=None,
                rotation=SlackRotation.ROTATING,
                observed_at=NOW,
            )


def test_pin_match_is_not_a_usable_credential_or_same_token_identity_check() -> None:
    candidate = gmail_result(*google_responses())
    assert candidate.subject_pin_verified is True
    assert candidate.installed is False and candidate.read_identity_verified is False
    assert not hasattr(candidate, "generation")


@pytest.mark.parametrize("value", [True, 0, 3601, "3600", 3600.0, -1])
def test_exchange_lifetime_must_be_actual_bounded_integer(value: Any) -> None:
    exchange, info = google_responses()
    exchange["expires_in"] = value
    with pytest.raises(OAuthEvidenceError):
        gmail_result(exchange, info)


def test_google_unexpected_id_token_holds_even_with_valid_access_material() -> None:
    exchange, info = google_responses()
    exchange["id_token"] = "invented-id-token"
    with pytest.raises(OAuthEvidenceError):
        gmail_result(exchange, info)


@pytest.mark.parametrize("value", [None, "", 1, True, "bad\nsecret", "non-ascii-🔑", "x" * 4097])
def test_google_malformed_access_material_holds_without_id_token_field(value: Any) -> None:
    exchange, info = google_responses()
    exchange["access_token"] = value
    with pytest.raises(OAuthEvidenceError):
        gmail_result(exchange, info)


def test_out_of_order_or_expired_observation_and_naive_clock_hold() -> None:
    exchange, info = google_responses()
    for observed in (
        NOW - timedelta(seconds=1),
        NOW + timedelta(minutes=6),
        NOW.replace(tzinfo=None),
    ):
        with pytest.raises(OAuthEvidenceError):
            parse_google_oauth_evidence(
                google(),
                data(exchange),
                data(info),
                expected_subject=SUBJECT,
                exchange_observed_at=NOW,
                evidence_observed_at=observed,
            )


@pytest.mark.parametrize("exchange_seconds", [1, 2])
def test_google_expiry_tolerance_never_accepts_expired_exchange_candidate(
    exchange_seconds: int,
) -> None:
    exchange, info = google_responses()
    exchange["expires_in"] = exchange_seconds
    # Tokeninfo still says one second remains, inside the consistency tolerance,
    # but the earlier exchange expiry is already past or exactly the observation.
    info["exp"] = str(int(NOW.timestamp()) + 3)
    info["expires_in"] = "1"
    with pytest.raises(OAuthEvidenceError):
        gmail_result(exchange, info)


@pytest.mark.parametrize("opaque_text", ["Bearer", "bot", "ID-token"])
def test_opaque_access_spelling_cannot_prove_kind_or_same_token_identity(opaque_text: str) -> None:
    exchange, info = google_responses()
    exchange["access_token"] = opaque_text
    candidate = gmail_result(exchange, info)
    assert candidate.access_token.get_secret_value() == opaque_text
    assert (
        not candidate.installed
        and not candidate.read_identity_verified
        and not candidate.live_access_proven
    )
    # Pure parsing cannot prove these separately supplied bytes came from an
    # introspection of this token. The trusted adapter must establish that link.
    from zacai.connectors.account_preflight import VerifiedCredential

    assert not isinstance(candidate, VerifiedCredential)
