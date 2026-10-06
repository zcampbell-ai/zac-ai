"""ROOT ONLY: actual age with ephemeral invented keys/data; not import/custody.

Do not include in ordinary pure runner. Hosts disable traceback-local capture.
No private user data/account/grant/Source/database/model/remote service is used.
"""

import os
import re
import subprocess

import pytest

from zacai import backup_artifacts as m


@pytest.fixture
def invented_key(tmp_path):
    os.chmod(tmp_path, 0o700)
    key = tmp_path / "invented-age-identity"
    generated = subprocess.run(["age-keygen", "-o", str(key)], capture_output=True, check=False)
    assert generated.returncode == 0, "invented key generation unavailable"
    os.chmod(key, 0o600)
    match = re.search(rb"^Public key: (age1[0-9a-z]+)$", generated.stderr, re.MULTILINE)
    assert match is not None, "invented recipient unavailable"
    try:
        yield key, match[1].decode("ascii")
    finally:
        key.unlink(missing_ok=True)


@pytest.mark.parametrize("size", [0, 4, 8_500_001, 100_000_000])
def test_genuine_bounded_age_exact_original_roundtrip(invented_key, size):
    key, recipient = invented_key
    unit = b"invented original bytes\x00"
    raw = (unit * (size // len(unit) + 1))[:size]
    assert len(raw) == size
    # Deliberately generous fixture resource bounds, NOT production cipher policy.
    output_bound = 2 * len(raw) + 4096
    cipher = m.age_encrypt_bounded(
        raw,
        recipient,
        max_input_bytes=max(1, len(raw)),
        max_output_bytes=output_bound,
        max_stderr_bytes=4096,
        timeout_seconds=30,
    )
    if size > 8_500_000:
        assert len(cipher) > 8_500_000
    recovered = m.age_decrypt_bounded(
        cipher,
        key,
        max_input_bytes=len(cipher),
        max_output_bytes=max(1, len(raw)),
        max_stderr_bytes=4096,
        timeout_seconds=30,
    )
    assert len(recovered) == len(raw), "bounded roundtrip length mismatch"
    assert m.content_hash_of(recovered) == m.content_hash_of(raw)


def test_genuine_bounded_decrypt_output_limit_holds(invented_key):
    key, recipient = invented_key
    raw = b"invented output cap"
    cipher = m.age_encrypt_bounded(
        raw,
        recipient,
        max_input_bytes=len(raw),
        max_output_bytes=4096,
        max_stderr_bytes=4096,
        timeout_seconds=10,
    )
    with pytest.raises(m.DecryptionError, match="^bounded age decryption unavailable$"):
        m.age_decrypt_bounded(
            cipher,
            key,
            max_input_bytes=len(cipher),
            max_output_bytes=len(raw) - 1,
            max_stderr_bytes=4096,
            timeout_seconds=10,
        )


def test_genuine_truncated_cipher_fixed_hold(invented_key):
    key, recipient = invented_key
    cipher = m.age_encrypt_bounded(
        b"invented",
        recipient,
        max_input_bytes=8,
        max_output_bytes=4096,
        max_stderr_bytes=4096,
        timeout_seconds=10,
    )
    with pytest.raises(m.DecryptionError) as error:
        m.age_decrypt_bounded(
            cipher[:-1],
            key,
            max_input_bytes=len(cipher),
            max_output_bytes=4096,
            max_stderr_bytes=4096,
            timeout_seconds=10,
        )
    assert error.value.__cause__ is error.value.__context__ is None


def test_genuine_wrong_identity_fixed_hold(invented_key):
    key, recipient = invented_key
    other = key.parent / "invented-wrong-age-identity"
    generated = subprocess.run(["age-keygen", "-o", str(other)], capture_output=True, check=False)
    assert generated.returncode == 0, "invented wrong key generation unavailable"
    os.chmod(other, 0o600)
    try:
        cipher = m.age_encrypt_bounded(
            b"invented",
            recipient,
            max_input_bytes=8,
            max_output_bytes=4096,
            max_stderr_bytes=4096,
            timeout_seconds=10,
        )
        with pytest.raises(m.DecryptionError, match="^bounded age decryption unavailable$"):
            m.age_decrypt_bounded(
                cipher,
                other,
                max_input_bytes=len(cipher),
                max_output_bytes=4096,
                max_stderr_bytes=4096,
                timeout_seconds=10,
            )
    finally:
        other.unlink(missing_ok=True)
