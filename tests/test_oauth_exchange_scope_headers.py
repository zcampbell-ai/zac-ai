"""Invented fixed-host scope envelopes; no actual provider or credential IO."""

from __future__ import annotations

import pytest

from tests.test_oauth_exchange import Fixture, Response, safe
from zacai.connectors.oauth_exchange import (
    OAuthExchangeCancelled,
    OAuthExchangeError,
    _CheckedConnection,
    _headers,
)

READ = "https://www.googleapis.com/auth/gmail.readonly"
SEND = "https://www.googleapis.com/auth/gmail.send"
GOOGLE = ("oauth2.googleapis.com", "gmail.googleapis.com")


def response(scope):
    return Response({}, headers=[("Content-Type", "application/json"), ("X-OAuth-Scopes", scope)])


@pytest.mark.parametrize("host", GOOGLE)
@pytest.mark.parametrize("scopes", [READ, SEND, READ + ", " + SEND])
def test_google_fixed_host_accepts_only_known_uri_envelope(host, scopes):
    _headers(response(scopes), provider_host=host)


@pytest.mark.parametrize("host", GOOGLE)
@pytest.mark.parametrize(
    "scopes",
    [
        "channels:history",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://mail.google.com/",
        "http://www.googleapis.com/auth/gmail.readonly",
        "https://evil.invalid/auth/gmail.readonly",
        READ + "/",
        READ + "?scope=extra",
        READ + "#fragment",
        READ + ", " + READ,
        "",
        READ + ",",
        READ + "\r\nX-Injected: yes",
    ],
)
def test_google_does_not_accept_slack_or_arbitrary_uri_by_loosened_grammar(host, scopes):
    with pytest.raises(ValueError):
        _headers(response(scopes), provider_host=host)


@pytest.mark.parametrize(
    "scopes",
    [
        READ,
        SEND,
        READ + ", " + SEND,
        "channels/history",
        "channels:history,channels:history",
        "channels:history\n",
        "",
        "scope" * 33,
    ],
)
def test_slack_retains_original_grammar_and_rejects_google_uri(scopes):
    with pytest.raises(ValueError):
        _headers(response(scopes), provider_host="slack.com")


def test_slack_bounded_original_tokens_remain_supported():
    _headers(response("channels:history, groups:history, im:history"), provider_host="slack.com")


@pytest.mark.parametrize(
    "host",
    [
        "googleapis.com",
        "gmail.googleapis.com.evil.invalid",
        "https://gmail.googleapis.com",
        "slack.com:443",
        "GMAIL.GOOGLEAPIS.COM",
        None,
    ],
)
def test_host_context_is_validated_before_response_callback(host):
    class Connection:
        def getresponse(self):
            raise AssertionError("Invalid host must not call response")

    with pytest.raises(ValueError):
        _CheckedConnection(Connection(), provider_host=host)


@pytest.mark.parametrize("host", GOOGLE)
def test_duplicate_scope_header_name_is_rejected_case_insensitively(host):
    reply = response(READ)
    reply.headers.append(("x-oauth-scopes", READ))
    with pytest.raises(ValueError):
        _headers(reply, provider_host=host)


def test_known_google_header_cannot_replace_exact_body_scope_candidate(tmp_path):
    f = Fixture(tmp_path)
    f.responses[1].headers.append(("X-OAuth-Scopes", READ + ", " + SEND))
    # The configured candidate includes BOTH; header metadata cannot repair
    # tokeninfo reporting only one or act as independent installation authority.
    import json

    info = json.loads(f.responses[1].body)
    info["scope"] = READ
    f.responses[1].body = json.dumps(info).encode()
    with pytest.raises(OAuthExchangeError) as raised:
        f.execute()
    safe(raised.value)
    assert f.row()["state"] == "held" and len(f.calls) == 2
    assert all(connection.closed for connection in f.connections)


@pytest.mark.parametrize("scope", ["channels:history", READ + "/"])
def test_invalid_google_profile_header_denies_before_body_read_and_holds(tmp_path, scope):
    f = Fixture(tmp_path)
    f.responses[2].headers.append(("X-OAuth-Scopes", scope))
    with pytest.raises(OAuthExchangeError) as raised:
        f.execute()
    safe(raised.value)
    assert not f.responses[2].reads and f.row()["state"] == "held"
    assert len(f.calls) == 3 and all(connection.closed for connection in f.connections)


def test_header_callback_cancellation_stays_private_safe_and_held(tmp_path, monkeypatch):
    f = Fixture(tmp_path)

    def cancelled():
        raise KeyboardInterrupt("invented-private-header-prose")

    monkeypatch.setattr(f.responses[2], "getheaders", cancelled)
    with pytest.raises(OAuthExchangeCancelled) as raised:
        f.execute()
    safe(raised.value)
    assert "invented-private-header-prose" not in str(raised.value)
    assert f.row()["state"] == "held" and not f.responses[2].reads
    assert all(connection.closed for connection in f.connections)
