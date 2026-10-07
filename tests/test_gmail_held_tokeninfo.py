"""Pure invented old-token claims; no exchange, credential, provider or native IO."""

from __future__ import annotations

import ctypes
import json
import socket
import subprocess
from datetime import UTC, datetime, timedelta, timezone, tzinfo

import pytest

from tests.test_oauth_configuration import gmail, slack
from zacai.connectors.gmail_held_tokeninfo import (
    GmailHeldTokenInfoCancelled,
    GmailHeldTokenInfoError,
    parse_held_gmail_tokeninfo,
)

NOW = datetime(2026, 10, 7, 12, tzinfo=UTC)
SUBJECT = "invented-independent-gmail-subject"
EXPIRY = NOW + timedelta(seconds=600)


def response(config=None):
    config = config or gmail()
    return {
        "azp": config.client_id,
        "aud": config.client_id,
        "sub": SUBJECT,
        "scope": " ".join(sorted(config.scopes)),
        "exp": str(int(EXPIRY.timestamp())),
        "expires_in": "600",
        "access_type": "offline",
    }


def parse(value=None, **changes):
    fields = {
        "configuration": gmail(),
        "expected_subject": None,
        "recorded_expires_at": EXPIRY,
        "request_started_at": NOW,
        "response_observed_at": NOW + timedelta(seconds=2),
    }
    fields.update(changes)
    raw = (
        value
        if isinstance(value, (bytes, bytearray, str))
        else json.dumps(response() if value is None else value).encode()
    )
    return parse_held_gmail_tokeninfo(raw, **fields)


def safe(error):
    assert error.__cause__ is None and error.__context__ is None
    assert SUBJECT not in str(error) + repr(error)
    tb = error.__traceback__
    while tb:
        if tb.tb_frame.f_globals.get("__name__") == "zacai.connectors.gmail_held_tokeninfo":
            assert tb.tb_frame.f_code.co_name == "call"
            assert not {"args", "kwargs", "data", "value", "subject"} & tb.tb_frame.f_locals.keys()
        tb = tb.tb_next


@pytest.mark.parametrize("expected", [None, SUBJECT])
def test_opaque_metadata_only_no_io_or_credential_candidate(monkeypatch, expected):
    def forbidden(*args, **kwargs):
        raise AssertionError("Pure parser must not perform IO")

    for target, name in ((ctypes, "CDLL"), (subprocess, "run"), (socket, "socket")):
        monkeypatch.setattr(target, name, forbidden)
    item = parse(expected_subject=expected)
    assert item.subject_id_hint == SUBJECT and item.client_id == gmail().client_id
    assert (
        item.scopes == gmail().scopes and item.configuration_digest == gmail().configuration_digest
    )
    assert item.expires_at == EXPIRY
    assert item.expected_subject_matches is (True if expected else None)
    assert item.held is True
    for flag in (
        "installed",
        "subject_pin_verified",
        "read_identity_verified",
        "live_access_proven",
        "native_material_verified",
        "original_actor_verified",
        "source_subject_verified",
        "credential_authority",
        "provenance_verified",
        "processing_authorized",
        "execution_authorized",
    ):
        assert getattr(item, flag) is False
    assert SUBJECT not in repr(item) and gmail().client_id not in repr(item)
    assert not any(
        hasattr(item, name)
        for name in ("access_token", "refresh_token", "credential", "resume", "install")
    )


@pytest.mark.parametrize("omit", ["azp", "aud", "exp", "expires_in"])
def test_single_client_and_single_expiry_supported_without_fabricating_exchange(omit):
    value = response()
    del value[omit]
    assert parse(value).expires_at == EXPIRY


@pytest.mark.parametrize(
    "field,value",
    [
        ("sub", None),
        ("sub", ""),
        ("sub", "a" * 256),
        ("sub", "bad subject"),
        ("sub", "bad/subject"),
        ("sub", 123),
        ("azp", None),
        ("azp", "wrong"),
        ("aud", "wrong"),
        ("aud", [gmail().client_id]),
        ("scope", ""),
        ("scope", "https://mail.google.com/"),
        ("scope", " ".join(gmail().scopes) + " " + " ".join(gmail().scopes)),
        ("scope", " " + " ".join(gmail().scopes)),
        ("scope", " ".join(gmail().scopes) + " extra"),
        ("scope", list(gmail().scopes)),
        ("access_type", "online"),
        ("email", "foreign@example.invalid"),
        ("email_verified", 1),
    ],
)
def test_client_subject_scope_and_optional_claim_conflicts_deny(field, value):
    info = response()
    info[field] = value
    with pytest.raises(GmailHeldTokenInfoError) as raised:
        parse(info)
    safe(raised.value)


@pytest.mark.parametrize(
    "field",
    ["error", "access_token", "refresh_token", "token_type", "unknown", "subject_pin_verified"],
)
def test_error_unknown_or_token_fields_never_become_claims(field):
    info = response()
    info[field] = "invented-private-token"
    with pytest.raises(GmailHeldTokenInfoError) as raised:
        parse(info)
    safe(raised.value)
    assert "invented-private-token" not in repr(raised.value)


@pytest.mark.parametrize("missing", [("azp", "aud"), ("exp", "expires_in"), ("sub",), ("scope",)])
def test_missing_required_evidence_denies(missing):
    info = response()
    for field in missing:
        del info[field]
    with pytest.raises(GmailHeldTokenInfoError):
        parse(info)


@pytest.mark.parametrize("field", ["expires_in", "exp"])
@pytest.mark.parametrize(
    "number",
    [
        True,
        False,
        None,
        600.0,
        "600.0",
        "+600",
        "-600",
        " 600",
        "600 ",
        "6e2",
        "0600",
        "",
        [],
        "9" * 1000,
    ],
)
def test_expiry_exact_bounded_integer_or_canonical_decimal_only(field, number):
    info = response()
    info[field] = number
    with pytest.raises(GmailHeldTokenInfoError) as raised:
        parse(info)
    safe(raised.value)


@pytest.mark.parametrize("number", [0, -1, 3601, "0", "3601"])
def test_ttl_bounds_deny(number):
    info = response()
    info["expires_in"] = number
    with pytest.raises(GmailHeldTokenInfoError):
        parse(info)


@pytest.mark.parametrize(
    "value",
    [
        b"",
        b"[]",
        b"null",
        b"1",
        b"not json",
        b"{" + b" " * 65536 + b"}",
        bytearray(b"{}"),
        "{}",
        b'{"scope":NaN}',
        b'{"scope":Infinity}',
        b'{"scope":-Infinity}',
    ],
)
def test_invalid_bounded_json_closed(value):
    with pytest.raises(GmailHeldTokenInfoError) as raised:
        parse(value)
    safe(raised.value)


def test_duplicate_valid_claim_is_rejected_independently_of_value_validity():
    raw = json.dumps(response()).encode()
    raw = raw[:-1] + b',"sub":"' + SUBJECT.encode() + b'"}'
    with pytest.raises(GmailHeldTokenInfoError):
        parse(raw)


@pytest.mark.parametrize("expected", ["different-invented-subject", "", "bad subject", 123])
def test_optional_independent_subject_comparison_does_not_fall_back(expected):
    with pytest.raises(GmailHeldTokenInfoError):
        parse(expected_subject=expected)


def test_relative_observation_interval_does_not_extend_original_expiry():
    info = response()
    del info["exp"]
    info["expires_in"] = 598
    result = parse(info)
    assert result.expires_at == NOW + timedelta(seconds=598)
    assert result.expires_at < EXPIRY


@pytest.mark.parametrize("delta", [-11, 13])
def test_recorded_expiry_disagrees_with_relative_interval(delta):
    info = response()
    del info["exp"]
    with pytest.raises(GmailHeldTokenInfoError):
        parse(info, recorded_expires_at=EXPIRY + timedelta(seconds=delta))


@pytest.mark.parametrize("delta", [-11, 11])
def test_absolute_recorded_expiry_disagreement_denies(delta):
    info = response()
    del info["expires_in"]
    with pytest.raises(GmailHeldTokenInfoError):
        parse(info, recorded_expires_at=EXPIRY + timedelta(seconds=delta))


def test_absolute_and_relative_cannot_independently_match_recorded_but_disagree():
    info = response()
    info["exp"] = str(int((EXPIRY - timedelta(seconds=10)).timestamp()))
    info["expires_in"] = 610
    with pytest.raises(GmailHeldTokenInfoError):
        parse(info)


@pytest.mark.parametrize("ttl,end", [(2, 2), (1, 2), (300, 300)])
def test_conservative_expiry_must_survive_response_completion(ttl, end):
    info = response()
    del info["exp"]
    info["expires_in"] = ttl
    with pytest.raises(GmailHeldTokenInfoError):
        parse(
            info,
            recorded_expires_at=NOW + timedelta(seconds=ttl + 5),
            response_observed_at=NOW + timedelta(seconds=end),
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_started_at", NOW.replace(tzinfo=None)),
        ("response_observed_at", NOW.replace(tzinfo=None)),
        ("recorded_expires_at", EXPIRY.replace(tzinfo=None)),
        ("request_started_at", NOW + timedelta(seconds=3)),
        ("response_observed_at", NOW + timedelta(seconds=301)),
        ("request_started_at", "invented-time"),
        ("recorded_expires_at", None),
    ],
)
def test_explicit_aware_ordered_bounded_observations(field, value):
    with pytest.raises(GmailHeldTokenInfoError) as raised:
        parse(**{field: value})
    safe(raised.value)


def test_nonutc_explicit_datetimes_normalize_without_reading_clock():
    offset = timezone(timedelta(hours=4))
    result = parse(
        recorded_expires_at=EXPIRY.astimezone(offset),
        request_started_at=NOW.astimezone(offset),
        response_observed_at=(NOW + timedelta(seconds=2)).astimezone(offset),
    )
    assert result.recorded_expires_at == EXPIRY and result.recorded_expires_at.tzinfo is UTC
    assert result.request_started_at == NOW and result.response_observed_at.tzinfo is UTC


@pytest.mark.parametrize(
    "configuration", [slack(), gmail(grant_profile="approved_communications"), object()]
)
def test_exact_read_gmail_configuration_required(configuration):
    with pytest.raises(GmailHeldTokenInfoError):
        parse(configuration=configuration)


def test_timezone_callback_mutating_actual_config_cannot_return_claims():
    configuration = gmail()

    class Mutation(tzinfo):
        def utcoffset(self, dt):
            object.__setattr__(configuration, "registration_id", "invented-other-registration")
            return timedelta(0)

        def dst(self, dt):
            return timedelta(0)

    with pytest.raises(GmailHeldTokenInfoError):
        parse(configuration=configuration, request_started_at=NOW.replace(tzinfo=Mutation()))


@pytest.mark.parametrize("failure", [KeyboardInterrupt, SystemExit])
def test_timezone_cancellation_erases_private_callback_and_parser_frames(failure):
    class Cancellation(tzinfo):
        def utcoffset(self, dt):
            private = SUBJECT
            raise failure(private)

        def dst(self, dt):
            return timedelta(0)

    with pytest.raises(GmailHeldTokenInfoCancelled) as raised:
        parse(request_started_at=NOW.replace(tzinfo=Cancellation()))
    safe(raised.value)
    tb = raised.value.__traceback__
    while tb:
        assert tb.tb_frame.f_code.co_name != "utcoffset"
        tb = tb.tb_next


@pytest.mark.parametrize("remaining", [3601, 86400])
def test_absolute_only_cannot_claim_new_long_access_lifetime(remaining):
    info = response()
    del info["expires_in"]
    end = NOW + timedelta(seconds=2)
    far = end + timedelta(seconds=remaining)
    info["exp"] = str(int(far.timestamp()))
    with pytest.raises(GmailHeldTokenInfoError):
        parse(info, recorded_expires_at=far)


def test_absolute_only_maximum_remaining_boundary_is_metadata_only():
    info = response()
    del info["expires_in"]
    expiry = NOW + timedelta(seconds=3602)
    info["exp"] = str(int(expiry.timestamp()))
    item = parse(info, recorded_expires_at=expiry)
    assert item.expires_at == expiry and item.live_access_proven is False


@pytest.mark.parametrize("recorded_delta", [-10, 12])
def test_relative_rounding_tolerance_boundary_preserves_conservative_ceiling(recorded_delta):
    info = response()
    del info["exp"]
    recorded = EXPIRY + timedelta(seconds=recorded_delta)
    result = parse(info, recorded_expires_at=recorded)
    assert result.expires_at == min(recorded, EXPIRY)


def test_explicit_zero_duration_observation_is_permitted():
    assert parse(response_observed_at=NOW).expires_at == EXPIRY


@pytest.mark.parametrize("failure", [KeyboardInterrupt, SystemExit])
def test_json_parser_cancellation_erases_raw_response_frames(monkeypatch, failure):
    import zacai.connectors.gmail_held_tokeninfo as source

    def interrupt(data):
        private = data
        assert SUBJECT.encode() in private
        raise failure(private)

    monkeypatch.setattr(source, "_object", interrupt)
    with pytest.raises(GmailHeldTokenInfoCancelled) as raised:
        parse()
    safe(raised.value)
    tb = raised.value.__traceback__
    while tb:
        assert tb.tb_frame.f_code.co_name != "interrupt"
        tb = tb.tb_next
