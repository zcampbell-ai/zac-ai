"""Pure invented quarantine-intent metadata; no original records or live I/O."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError

import pytest

from tests.test_oauth_configuration import gmail
from zacai.connectors.gmail_quarantine_record import (
    GmailQuarantineRecordCancelled,
    GmailQuarantineRecordError,
    ParsedGmailQuarantineRecord,
    parse_gmail_quarantine_record,
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def sample():
    configuration = gmail()
    account = hashlib.sha256(
        canonical({"provider": "gmail", "account": configuration.gmail_mailbox})
    ).hexdigest()
    state_hash = hashlib.sha256(b"invented-original-quarantine-state").hexdigest()
    row = {
        "configuration": configuration.configuration_digest,
        "account": account,
        "binding": "a" * 64,
        "generation": "invented-original-registration-review",
        "rotation": None,
        "expires": "2024-01-01T01:02:03+00:00",
        "state": "held",
        "verifier": None,
        "execution": "b" * 64,
        "loaded": True,
    }
    reviewer = {
        "issuer": "https://accounts.google.com",
        "subject": "invented-current-reviewer",
        "binding_digest": "c" * 64,
        "review_generation": "invented-quarantine-intent-review",
        "reviewed_at": "2026-10-07T12:30:00+00:00",
    }
    record = {
        "version": 1,
        "action": "quarantine_only",
        "configuration_digest": configuration.configuration_digest,
        "account_digest": account,
        "state_hash": state_hash,
        "native_generation": hashlib.sha256(
            b"zac-gmail-held-generation-v1\x00" + state_hash.encode()
        ).hexdigest()[:32],
        "original_row": row,
        "reviewer": reviewer,
        "remote_grant_status": "unknown",
    }
    return configuration, record


def test_complete_original_row_is_retained_and_review_claims_grant_nothing():
    configuration, record = sample()
    parsed = parse_gmail_quarantine_record(canonical(record), configuration=configuration)
    assert parsed.original_row_bytes == canonical(record["original_row"])
    assert parsed.canonical_record_bytes == canonical(record)
    assert parsed.native_generation != record["original_row"]["generation"]
    assert parsed.reviewer_binding_claim != record["original_row"]["binding"]
    assert parsed.reviewer_subject_hint == record["reviewer"]["subject"]
    assert parsed.action == "quarantine_only" and parsed.remote_grant_status == "unknown"
    for name in (
        "installed",
        "quarantine_committed",
        "quarantine_authorized",
        "recovery_authorized",
        "original_actor_verified",
        "current_reviewer_verified",
        "source_subject_verified",
        "native_material_verified",
        "live_access_proven",
        "remote_grant_verified",
        "credential_authority",
        "processing_authorized",
        "execution_authorized",
    ):
        assert getattr(parsed, name) is False
    assert repr(parsed) == "ParsedGmailQuarantineRecord()"
    with pytest.raises(FrozenInstanceError):
        parsed.native_generation = "d" * 32
    with pytest.raises(TypeError):
        ParsedGmailQuarantineRecord()


@pytest.mark.parametrize(
    "expiry", ["2024-01-01T01:02:03Z", "20240101T010203+0530", "2024-01-01 01:02:03-07:00"]
)
def test_expired_original_expiry_literal_is_preserved_without_currentness_policy(expiry):
    configuration, record = sample()
    record["original_row"]["expires"] = expiry
    record["reviewer"]["reviewed_at"] = "2099-01-01T00:00:00+00:00"
    parsed = parse_gmail_quarantine_record(canonical(record), configuration=configuration)
    assert json.loads(parsed.original_row_bytes)["expires"] == expiry
    assert parsed.reviewed_at_claim.year == 2099
    assert not parsed.current_reviewer_verified and not parsed.quarantine_authorized


@pytest.mark.parametrize(
    "group,key,value",
    [
        (None, "version", True),
        (None, "version", 1.0),
        (None, "action", "retry_authorized"),
        (None, "remote_grant_status", "revoked"),
        (None, "configuration_digest", "d" * 64),
        (None, "account_digest", "d" * 64),
        (None, "state_hash", "d" * 64),
        (None, "native_generation", "d" * 32),
        ("original_row", "configuration", "d" * 64),
        ("original_row", "account", "d" * 64),
        ("original_row", "binding", "invalid"),
        ("original_row", "generation", "invalid:registration"),
        ("original_row", "state", "denied"),
        ("original_row", "loaded", False),
        ("original_row", "loaded", 1),
        ("original_row", "execution", None),
        ("original_row", "verifier", "invented-secret-code"),
        ("original_row", "rotation", "rotating"),
        ("original_row", "expires", "2024-01-01T00:00:00"),
        ("reviewer", "issuer", "https://wrong.example"),
        ("reviewer", "subject", "bad.subject"),
        ("reviewer", "binding_digest", "invalid"),
        ("reviewer", "review_generation", "invalid review"),
        ("reviewer", "reviewed_at", "2026-10-07T12:30:00Z"),
    ],
)
def test_correlations_original_shape_and_unverified_reviewer_schema_deny(group, key, value):
    configuration, record = sample()
    (record if group is None else record[group])[key] = value
    with pytest.raises(GmailQuarantineRecordError):
        parse_gmail_quarantine_record(canonical(record), configuration=configuration)


@pytest.mark.parametrize("group", [None, "original_row", "reviewer"])
@pytest.mark.parametrize("change", ["extra", "missing", "duplicate"])
def test_exact_schema_at_every_level_rejects_credential_fields_missing_and_duplicates(
    group, change
):
    configuration, record = sample()
    selected = record if group is None else record[group]
    key = next(iter(selected))
    if change == "extra":
        selected["access_token"] = "invented-private-token"
    elif change == "missing":
        del selected[key]
    data = canonical(record)
    if change == "duplicate":
        needle = json.dumps(key).encode() + b":"
        value = canonical(selected[key])
        data = data.replace(needle + value, needle + value + b"," + needle + value, 1)
    with pytest.raises(GmailQuarantineRecordError) as caught:
        parse_gmail_quarantine_record(data, configuration=configuration)
    assert "invented-private" not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__context__ is None


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        b" " * 16385,
        bytearray(b"{}"),
        b"[]",
        b"null",
        b'{"version":NaN}',
        b'{"version":Infinity}',
        b"\xff",
    ],
)
def test_bounded_exact_finite_json_only(bad):
    configuration, _ = sample()
    with pytest.raises(GmailQuarantineRecordError):
        parse_gmail_quarantine_record(bad, configuration=configuration)


@pytest.mark.parametrize("target", ["original", "retained"])
def test_wrong_configuration_type_and_changed_configuration_digest_deny(monkeypatch, target):
    import zacai.connectors.gmail_quarantine_record as module

    configuration, record = sample()
    with pytest.raises(GmailQuarantineRecordError):
        parse_gmail_quarantine_record(canonical(record), configuration=object())
    original = module._json
    original_configuration = module._configuration
    retained = []

    def checked(value):
        result = original_configuration(value)
        if not retained:
            retained.append(result)
        return result

    monkeypatch.setattr(module, "_configuration", checked)

    def encode(value):
        result = original(value)
        if type(value) is dict and "loaded" in value:
            object.__setattr__(
                configuration if target == "original" else retained[0],
                "registration_id",
                "invented-changed-registration",
            )
        return result

    monkeypatch.setattr(module, "_json", encode)
    with pytest.raises(GmailQuarantineRecordError):
        parse_gmail_quarantine_record(canonical(record), configuration=configuration)


def test_interruption_is_sanitized_without_retaining_argument_frames(monkeypatch):
    import zacai.connectors.gmail_quarantine_record as module

    configuration, record = sample()

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt("invented-private-interruption-text")

    monkeypatch.setattr(module.json, "loads", interrupted)
    with pytest.raises(GmailQuarantineRecordCancelled) as caught:
        parse_gmail_quarantine_record(canonical(record), configuration=configuration)
    assert "invented-private" not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    frames = []
    traceback = caught.value.__traceback__
    while traceback:
        frame = traceback.tb_frame
        if frame.f_code.co_filename == module.__file__:
            frames.append(frame)
        traceback = traceback.tb_next
    assert frames and all(
        "args" not in frame.f_locals and "kwargs" not in frame.f_locals for frame in frames
    )


def test_no_filesystem_native_subprocess_or_clock_access(monkeypatch):
    import ctypes
    import os
    import subprocess
    from pathlib import Path

    configuration, record = sample()

    def forbidden(*args, **kwargs):
        raise AssertionError("pure parser attempted runtime I/O")

    for target, name in ((Path, "open"), (os, "open"), (subprocess, "run"), (ctypes, "CDLL")):
        monkeypatch.setattr(target, name, forbidden)
    parsed = parse_gmail_quarantine_record(canonical(record), configuration=configuration)
    assert parsed.original_row_bytes == canonical(record["original_row"])
