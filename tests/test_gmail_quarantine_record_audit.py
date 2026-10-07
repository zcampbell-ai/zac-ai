"""Independent invented quarantine claims; no commit, storage or grant authority."""

from __future__ import annotations

import copy
import hashlib
import json

import pytest

from tests.test_oauth_configuration import gmail
from zacai.connectors.gmail_quarantine_record import (
    GmailQuarantineRecordError,
    parse_gmail_quarantine_record,
)

CONFIGURATION = gmail()
STATE = "1" * 64
DOMAIN = b"zac-gmail-held-generation-v1\x00"


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def record():
    account = hashlib.sha256(
        encoded({"provider": "gmail", "account": CONFIGURATION.gmail_mailbox})
    ).hexdigest()
    return {
        "version": 1,
        "action": "quarantine_only",
        "configuration_digest": CONFIGURATION.configuration_digest,
        "account_digest": account,
        "state_hash": STATE,
        "native_generation": hashlib.sha256(DOMAIN + STATE.encode()).hexdigest()[:32],
        "original_row": {
            "configuration": CONFIGURATION.configuration_digest,
            "account": account,
            "binding": "2" * 64,
            "generation": "invented-original-registration-generation",
            "rotation": None,
            "expires": "2026-01-01T00:00:00+00:00",
            "state": "held",
            "verifier": None,
            "execution": "3" * 64,
            "loaded": True,
        },
        "reviewer": {
            "issuer": "https://accounts.google.com",
            "subject": "invented-current-reviewer-subject",
            "binding_digest": "4" * 64,
            "review_generation": "invented-new-review-generation",
            "reviewed_at": "2026-10-08T00:00:00+00:00",
        },
        "remote_grant_status": "unknown",
    }


def parse(value=None, **changes):
    data = value if type(value) is bytes else encoded(record() if value is None else value)
    return parse_gmail_quarantine_record(
        data, configuration=changes.get("configuration", CONFIGURATION)
    )


def safe(error):
    assert error.__cause__ is error.__context__ is None
    assert "invented-current-reviewer-subject" not in repr(error) + str(error)
    tb = error.__traceback__
    while tb:
        if tb.tb_frame.f_globals.get("__name__") == "zacai.connectors.gmail_quarantine_record":
            assert tb.tb_frame.f_code.co_name == "call"
            assert (
                not {"args", "kwargs", "data", "value", "row", "reviewer"}
                & tb.tb_frame.f_locals.keys()
            )
        tb = tb.tb_next


def test_original_row_preserved_and_reviewer_claims_never_become_authority():
    original = record()
    result = parse(original)
    assert json.loads(result.original_row_bytes) == original["original_row"]
    assert json.loads(result.canonical_record_bytes) == original
    assert original["original_row"]["generation"] != original["native_generation"]
    assert original["original_row"]["binding"] != original["reviewer"]["binding_digest"]
    for flag in (
        "installed",
        "quarantine_committed",
        "recovery_authorized",
        "credential_authority",
        "processing_authorized",
        "execution_authorized",
        "original_actor_verified",
        "source_subject_verified",
        "native_material_verified",
    ):
        assert getattr(result, flag) is False
    assert "invented-current-reviewer-subject" not in repr(result)
    assert STATE not in repr(result) and original["native_generation"] not in repr(result)


def test_original_aware_expiry_literal_is_not_rewritten_as_current_or_review_expiry():
    value = record()
    value["original_row"]["expires"] = "2026-01-01 04:00:00+04:00"
    value["reviewer"]["reviewed_at"] = "2099-01-01T00:00:00+00:00"
    parsed = parse(value)
    assert json.loads(parsed.original_row_bytes) == value["original_row"]
    assert parsed.recovery_authorized is False


@pytest.mark.parametrize("section", [None, "original_row", "reviewer"])
@pytest.mark.parametrize("change", ["extra", "missing"])
def test_exact_schema_at_every_layer(section, change):
    value = record()
    target = value if section is None else value[section]
    if change == "extra":
        target["invented_extra"] = "invented-private-content"
    else:
        target.pop(next(iter(target)))
    with pytest.raises(GmailQuarantineRecordError) as raised:
        parse(value)
    safe(raised.value)


@pytest.mark.parametrize(
    "section,key", [(None, "action"), ("original_row", "loaded"), ("reviewer", "subject")]
)
def test_duplicate_otherwise_valid_fields_are_not_last_value_admission(section, key):
    value = record()
    if section is None:
        raw = encoded(value)
        raw = raw[:-1] + b',"action":"quarantine_only"}'
    else:
        part = encoded(value[section])
        duplicate = part[:-1] + b"," + encoded(key) + b":" + encoded(value[section][key]) + b"}"
        raw = encoded(value).replace(part, duplicate)
    with pytest.raises(GmailQuarantineRecordError):
        parse(raw)


@pytest.mark.parametrize(
    "field,bad",
    [
        ("version", True),
        ("version", 1.0),
        ("version", 2),
        ("action", "recover"),
        ("action", "install"),
        ("remote_grant_status", "revoked"),
        ("remote_grant_status", "active"),
        ("remote_grant_status", False),
        ("state_hash", "A" * 64),
        ("state_hash", "1" * 63),
        ("native_generation", "a" * 32),
        ("configuration_digest", "b" * 64),
        ("account_digest", "c" * 64),
    ],
)
def test_outer_admission_or_correlation_confusion_denied(field, bad):
    value = record()
    value[field] = bad
    with pytest.raises(GmailQuarantineRecordError) as raised:
        parse(value)
    safe(raised.value)


@pytest.mark.parametrize(
    "field,bad",
    [
        ("configuration", "a" * 64),
        ("account", "b" * 64),
        ("binding", "a" * 63),
        ("binding", None),
        ("generation", "a" * 129),
        ("generation", "bad generation"),
        ("rotation", "rotating"),
        ("verifier", "v" * 43),
        ("execution", None),
        ("execution", "e" * 63),
        ("state", "exchange_started"),
        ("state", "pending"),
        ("state", "denied"),
        ("loaded", False),
        ("loaded", 1),
        ("expires", "2026-01-01T00:00:00"),
    ],
)
def test_original_row_requires_exact_consumed_held_metadata(field, bad):
    value = record()
    value["original_row"][field] = bad
    with pytest.raises(GmailQuarantineRecordError):
        parse(value)


@pytest.mark.parametrize(
    "field,bad",
    [
        ("issuer", "https://evil.invalid"),
        ("subject", ""),
        ("subject", "bad subject"),
        ("subject", "s" * 256),
        ("binding_digest", "f" * 63),
        ("review_generation", "review with spaces"),
        ("review_generation", None),
        ("reviewed_at", "2026-10-08T00:00:00"),
        ("reviewed_at", "2026-10-08T00:00:00Z"),
        ("reviewed_at", True),
    ],
)
def test_reviewer_shape_does_not_admit_approval_lookalikes(field, bad):
    value = record()
    value["reviewer"][field] = bad
    with pytest.raises(GmailQuarantineRecordError):
        parse(value)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"[]",
        b"null",
        b"broken",
        b'{"version":NaN}',
        b'{"version":Infinity}',
        b'{"version":-Infinity}',
        b" " * 16385,
    ],
)
def test_bounded_json_failure_is_private_safe(raw):
    with pytest.raises(GmailQuarantineRecordError) as raised:
        parse(raw)
    safe(raised.value)


def test_recomputed_native_generation_cannot_repair_wrong_original_config_or_account():
    value = record()
    value["state_hash"] = "f" * 64
    value["native_generation"] = hashlib.sha256(DOMAIN + value["state_hash"].encode()).hexdigest()[
        :32
    ]
    assert parse(value).quarantine_committed is False
    other = copy.deepcopy(value)
    other["account_digest"] = other["original_row"]["account"] = "a" * 64
    with pytest.raises(GmailQuarantineRecordError):
        parse(other)


def test_pure_parser_calls_no_native_provider_storage_or_clock(monkeypatch):
    import builtins
    import ctypes
    import socket
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("No IO from quarantine metadata parsing")

    for target, name in (
        (builtins, "open"),
        (ctypes, "CDLL"),
        (socket, "socket"),
        (subprocess, "run"),
    ):
        monkeypatch.setattr(target, name, forbidden)
    result = parse()
    assert result.remote_grant_status == "unknown"
    for flag in (
        "quarantine_authorized",
        "current_reviewer_verified",
        "live_access_proven",
        "remote_grant_verified",
    ):
        assert getattr(result, flag) is False


@pytest.mark.parametrize(
    "configuration", [gmail(grant_profile="approved_communications"), object()]
)
def test_read_only_exact_configuration_required(configuration):
    with pytest.raises(GmailQuarantineRecordError):
        parse(configuration=configuration)


@pytest.mark.parametrize("failure", [KeyboardInterrupt, SystemExit])
def test_interrupted_untrusted_json_cannot_leak_record_context_or_frames(monkeypatch, failure):
    import zacai.connectors.gmail_quarantine_record as source
    from zacai.connectors.gmail_quarantine_record import GmailQuarantineRecordCancelled

    def interrupt(data, **kwargs):
        private = data
        assert "invented-current-reviewer-subject" in private
        raise failure(private)

    monkeypatch.setattr(source.json, "loads", interrupt)
    with pytest.raises(GmailQuarantineRecordCancelled) as raised:
        parse()
    safe(raised.value)
    tb = raised.value.__traceback__
    while tb:
        assert tb.tb_frame.f_code.co_name != "interrupt"
        tb = tb.tb_next


@pytest.mark.parametrize("target", ["caller", "retained"])
def test_configuration_changed_between_canonical_encoding_and_return_denied(monkeypatch, target):
    import zacai.connectors.gmail_quarantine_record as source

    config = gmail()
    original = source._json
    original_configuration = source._configuration
    selected = []

    def checked(configuration):
        result = original_configuration(configuration)
        selected.append(result)
        return result

    monkeypatch.setattr(source, "_configuration", checked)

    def changed(value):
        raw = original(value)
        if type(value) is dict and "binding" in value:
            object.__setattr__(
                config if target == "caller" else selected[0],
                "registration_id",
                "invented-changed-registration",
            )
        return raw

    monkeypatch.setattr(source, "_json", changed)
    with pytest.raises(GmailQuarantineRecordError):
        parse(configuration=config)
