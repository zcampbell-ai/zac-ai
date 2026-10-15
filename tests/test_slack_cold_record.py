"""Invented persistence controls; parsing never establishes a live capability."""

import json
import os
from uuid import UUID

import pytest
from cryptography.exceptions import InvalidTag

from zacai.connectors.slack_native_installation import (
    _V2_COMMON,
    _v2_cipher,
    _v2_correlate,
    _v2_encode,
    _v2_read,
)

KEY = b"k" * 32
CONTEXT = b"invented-owner-continuity"


def record(state="pending"):
    value = dict.fromkeys(_V2_COMMON, "a" * 64)
    value.update(
        version=2,
        state=state,
        account="UINVENTED",
        team="TINVENTED",
        generation="b" * 32,
        original_sdk_attempt_id=str(UUID(int=1)),
    )
    if state == "active":
        value.update(
            native_identity_digest="c" * 64,
            original_sdk_completed_row_digest="d" * 64,
            access_expires_at="2026-10-16T12:00:00+00:00",
        )
    return value


def save(tmp_path, encoded, state="pending"):
    tmp_path.chmod(0o700)
    path = tmp_path / ("slack-installation-" + state + ".bin")
    path.write_bytes(encoded)
    path.chmod(0o600)
    return path


def read(tmp_path, state="pending", key=KEY, context=CONTEXT):
    return _v2_read(tmp_path, state=state, key=key, context=context)


@pytest.mark.parametrize("state", ["pending", "active"])
def test_new_parser_reads_authenticated_exact_state(tmp_path, state):
    value = record(state)
    encoded = _v2_encode(value, state=state, key=KEY, context=CONTEXT)
    save(tmp_path, encoded, state)
    assert read(tmp_path, state) == value
    assert b"UINVENTED" not in encoded


@pytest.mark.parametrize("fault", ["key", "context", "tag", "state"])
def test_wrong_authentication_cannot_load(tmp_path, fault):
    encoded = _v2_encode(record(), state="pending", key=KEY, context=CONTEXT)
    if fault == "tag":
        encoded = encoded[:-1] + bytes([encoded[-1] ^ 1])
    save(tmp_path, encoded, "active" if fault == "state" else "pending")
    with pytest.raises(InvalidTag):
        read(
            tmp_path,
            "active" if fault == "state" else "pending",
            b"x" * 32 if fault == "key" else KEY,
            b"wrong-context" if fault == "context" else CONTEXT,
        )


@pytest.mark.parametrize("fault", ["duplicate", "extra", "v1", "boolean", "noncanonical", "expiry"])
def test_authenticated_but_invalid_records_denied(tmp_path, fault):
    value = record("active")
    if fault == "extra":
        value["access_token"] = "forbidden-invented"
    elif fault in {"v1", "boolean"}:
        value["version"] = 1 if fault == "v1" else True
    elif fault == "expiry":
        value["access_expires_at"] = "2026-10-16T12:00:00"
    payload = json.dumps(value).encode()
    if fault == "duplicate":
        payload = b'{"version":2,' + payload[1:]
    cipher, aad = _v2_cipher(KEY, CONTEXT)
    nonce = b"n" * 12
    save(tmp_path, nonce + cipher.encrypt(nonce, payload, aad + b"active"), "active")
    with pytest.raises(ValueError):
        read(tmp_path, "active")


@pytest.mark.parametrize("fault", ["missing", "symlink", "hardlink", "mode", "oversize"])
def test_unsafe_exact_file_denied_without_repair(tmp_path, fault):
    encoded = _v2_encode(record(), state="pending", key=KEY, context=CONTEXT)
    path = save(tmp_path, encoded)
    if fault == "missing":
        path.unlink()
    elif fault == "symlink":
        original = tmp_path / "other.bin"
        path.rename(original)
        path.symlink_to(original)
    elif fault == "hardlink":
        os.link(path, tmp_path / "other.bin")
    elif fault == "mode":
        path.chmod(0o644)
    elif fault == "oversize":
        path.write_bytes(b"x" * 16385)
    before = sorted(p.name for p in tmp_path.iterdir())
    with pytest.raises((ValueError, OSError)):
        read(tmp_path)
    assert sorted(p.name for p in tmp_path.iterdir()) == before


@pytest.mark.parametrize("field", sorted(_V2_COMMON - {"state", "version"}))
def test_each_original_witness_must_match(field):
    pending, active = record(), record("active")
    _v2_correlate(pending, active)
    if field == "original_sdk_attempt_id":
        active[field] = str(UUID(int=2))
    else:
        active[field] = "e" * len(active[field])
    with pytest.raises(ValueError):
        _v2_correlate(pending, active)
