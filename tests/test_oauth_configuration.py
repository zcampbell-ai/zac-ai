"""Invented configuration only; no OAuth call, provider or real credential."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import pytest
from pydantic import SecretStr, ValidationError

from zacai.connectors.account_preflight import (
    GMAIL_COMMUNICATION_SCOPES,
    GMAIL_SCOPES,
    SLACK_COMMUNICATION_SCOPES,
    SLACK_SCOPES,
    Provider,
)
from zacai.connectors.oauth_configuration import (
    OAuthConfiguration,
    OAuthConfigurationCancelled,
    OAuthConfigurationError,
    prepare_consent,
)


def gmail(**changes: object) -> OAuthConfiguration:
    return OAuthConfiguration.model_validate(
        {
            "provider": "gmail",
            "registration_id": "invented-project",
            "client_id": "invented.apps.googleusercontent.com",
            "private_origin": "https://invented.example",
            **changes,
        }
    )


def slack(**changes: object) -> OAuthConfiguration:
    return OAuthConfiguration.model_validate(
        {
            "provider": "slack",
            "registration_id": "A123456789",
            "client_id": "123456789.987654321",
            "private_origin": "https://invented.example",
            "slack_team_id": "T123456789",
            **changes,
        }
    )


STATE = SecretStr("s" * 43)
VERIFIER = SecretStr("v" * 43)


def test_google_fixed_callback_pkce_and_exact_read_grants() -> None:
    config = gmail()
    request = prepare_consent(config, state=STATE, google_code_verifier=VERIFIER)
    parsed = urlsplit(request.url.get_secret_value())
    parameters = parse_qs(parsed.query, strict_parsing=True)
    assert parsed.scheme == "https"
    assert parsed.netloc == "accounts.google.com"
    assert parsed.path == "/o/oauth2/v2/auth"
    assert parameters["redirect_uri"] == ["https://invented.example/connections/gmail/callback"]
    assert set(parameters) == {
        "client_id",
        "redirect_uri",
        "state",
        "response_type",
        "scope",
        "code_challenge",
        "code_challenge_method",
        "access_type",
        "include_granted_scopes",
        "login_hint",
        "prompt",
    }
    assert parameters["login_hint"] == [config.gmail_mailbox]
    assert parameters["prompt"] == ["consent"]
    assert parameters["scope"] == [" ".join(sorted(GMAIL_SCOPES))]
    expected = base64.urlsafe_b64encode(hashlib.sha256(b"v" * 43).digest()).decode().rstrip("=")
    assert parameters["code_challenge"] == [expected]
    assert parameters["code_challenge_method"] == ["S256"]
    assert parameters["include_granted_scopes"] == ["false"]
    assert parameters["access_type"] == ["offline"]
    assert parameters["state"] == ["s" * 43]
    assert "v" * 43 not in request.url.get_secret_value()
    assert "s" * 43 not in repr(request)
    assert request.configuration_digest == config.configuration_digest


def test_explicit_communication_upgrade_changes_config_digest_and_grants() -> None:
    first = gmail()
    upgraded = gmail(grant_profile="approved_communications")
    assert first.configuration_digest != upgraded.configuration_digest
    request = prepare_consent(upgraded, state=STATE, google_code_verifier=VERIFIER)
    assert parse_qs(urlsplit(request.url.get_secret_value()).query)["scope"] == [
        " ".join(sorted(GMAIL_COMMUNICATION_SCOPES))
    ]


def test_slack_user_only_confidential_exact_team() -> None:
    config = slack(grant_profile="approved_communications")
    request = prepare_consent(config, state=STATE)
    parsed = urlsplit(request.url.get_secret_value())
    params = parse_qs(parsed.query)
    assert parsed.netloc == "slack.com"
    assert parsed.path == "/oauth/v2/authorize"
    assert set(params) == {"client_id", "redirect_uri", "state", "user_scope", "team"}
    assert params["team"] == ["T123456789"]
    assert params["user_scope"] == [",".join(sorted(SLACK_COMMUNICATION_SCOPES))]
    assert request.provider is Provider.SLACK
    assert config.oauth_mode == "confidential"


@pytest.mark.parametrize(
    "origin",
    [
        "http://invented.example",
        "https://invented.example/",
        "https://invented.example/path",
        "https://invented.example?x=1",
        "https://invented.example#x",
        "https://user@invented.example",
        "https://invented.example:443",
        "https://INVENTED.example",
        "https://invented.example.",
        "https://localhost",
        "https://invented.example\\@evil.example",
        "https://invented.example\n",
        "https://127.0.0.1",
        "https://0x7f.1",
        "https://a.1",
        "https://0x7f.0x1",
        "https://" + "a" * 64 + ".example",
    ],
)
def test_origin_cannot_change_callback_target(origin: str) -> None:
    with pytest.raises(ValidationError):
        gmail(private_origin=origin)


@pytest.mark.parametrize(
    "changes",
    [
        {"gmail_mailbox": "other@invented.example"},
        {"client_id": "other.example"},
        {"client_id": ".apps.googleusercontent.com"},
        {"slack_team_id": "T123456789"},
        {"oauth_mode": "public_pkce"},
        {"grant_profile": "all"},
        {"callback": "https://evil.example"},
        {"scopes": ["https://mail.google.com/"]},
    ],
)
def test_google_registration_cannot_expand_or_replace_config(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        gmail(**changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"client_id": "invented.apps.googleusercontent.com"},
        {"slack_team_id": None},
        {"slack_team_id": "U123456789"},
        {"oauth_mode": "public_pkce"},
    ],
)
def test_slack_actual_client_team_mode_required(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        slack(**changes)


@pytest.mark.parametrize(
    "state", [SecretStr("short"), SecretStr("x" * 129), SecretStr("?" * 43), "s" * 43]
)
def test_malformed_state_fails_without_chained_error(state: object) -> None:
    with pytest.raises(OAuthConfigurationError) as raised:
        prepare_consent(gmail(), state=state, google_code_verifier=VERIFIER)  # type: ignore[arg-type]
    assert raised.value.__context__ is None
    assert "short" not in str(raised.value)


@pytest.mark.parametrize(
    "verifier", [None, SecretStr("short"), SecretStr("x" * 129), SecretStr("?" * 43)]
)
def test_google_verifier_required_and_bounded(verifier: SecretStr | None) -> None:
    with pytest.raises(OAuthConfigurationError):
        prepare_consent(gmail(), state=STATE, google_code_verifier=verifier)


def test_confidential_slack_does_not_silently_switch_pkce_mode() -> None:
    with pytest.raises(OAuthConfigurationError):
        prepare_consent(slack(), state=STATE, google_code_verifier=VERIFIER)


def test_bypassed_model_validation_is_rechecked_at_boundary() -> None:
    invalid = gmail().model_copy(update={"private_origin": "https://evil.example/path"})
    with pytest.raises(OAuthConfigurationError):
        prepare_consent(invalid, state=STATE, google_code_verifier=VERIFIER)


def test_cancellation_discards_inner_exception_and_frames(monkeypatch: pytest.MonkeyPatch) -> None:
    def cancelled(*args: object, **kwargs: object) -> object:
        private_material = "invented-private-cancellation-detail"
        raise KeyboardInterrupt(private_material)

    monkeypatch.setattr("zacai.connectors.oauth_configuration._prepare_consent", cancelled)
    with pytest.raises(OAuthConfigurationCancelled) as raised:
        prepare_consent(gmail(), state=STATE, google_code_verifier=VERIFIER)
    assert raised.value.__context__ is None
    frames = []
    current = raised.value.__traceback__
    while current is not None:
        frames.append(current.tb_frame.f_code.co_name)
        current = current.tb_next
    assert "cancelled" not in frames
    assert "invented-private" not in str(raised.value)


def test_subclass_cannot_replace_scope_or_callback_properties() -> None:
    class Altered(OAuthConfiguration):
        @property
        def scopes(self) -> frozenset[str]:
            return frozenset({"https://mail.google.com/"})

    config = Altered.model_validate(gmail().model_dump())
    with pytest.raises(OAuthConfigurationError):
        prepare_consent(config, state=STATE, google_code_verifier=VERIFIER)


def test_slack_read_profile_stays_exact_and_digest_matches() -> None:
    config = slack()
    request = prepare_consent(config, state=STATE)
    assert parse_qs(urlsplit(request.url.get_secret_value()).query)["user_scope"] == [
        ",".join(sorted(SLACK_SCOPES))
    ]
    assert request.configuration_digest == config.configuration_digest


def test_changed_effective_scope_or_fixed_policy_changes_review_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from zacai.connectors import oauth_configuration as module

    config = gmail()
    reviewed = config.configuration_digest
    monkeypatch.setattr(module, "GMAIL_SCOPES", GMAIL_SCOPES | {"https://mail.google.com/"})
    assert config.configuration_digest != reviewed
    assert (
        prepare_consent(config, state=STATE, google_code_verifier=VERIFIER).configuration_digest
        == config.configuration_digest
    )
    changed_scope = config.configuration_digest
    original = module._public_request

    def changed(selected: OAuthConfiguration) -> tuple[str, dict[str, str]]:
        endpoint, parameters = original(selected)
        return endpoint, parameters | {"prompt": "select_account"}

    monkeypatch.setattr(module, "_public_request", changed)
    assert config.configuration_digest != changed_scope


def test_invalid_copied_configuration_cannot_supply_review_digest() -> None:
    invalid = gmail().model_copy(update={"private_origin": "https://evil.example/path"})
    with pytest.raises(ValidationError):
        _ = invalid.configuration_digest
