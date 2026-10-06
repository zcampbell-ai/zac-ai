"""Root-only genuine crypto/local-object join with disposable invented data."""

import pytest

from tests.test_bounded_age_crypto import invented_key as invented_key  # noqa: PLC0414
from zacai.backup_artifacts import (
    BackupArtifactsError,
    LocalDirectoryBackupStore,
    age_decrypt_bounded,
    age_encrypt_bounded,
)
from zacai.ingestion.artifact_store import content_hash_of


def test_large_original_bounded_encrypt_store_read_decrypt(invented_key, tmp_path):
    key, recipient = invented_key
    # Resource numbers are invented fixture bounds, not an approved custody profile.
    size = 100_000_000
    unit = b"invented whole-original\x00"
    original = (unit * (size // len(unit) + 1))[:size]
    cipher_bound = 2 * size + 4096
    encrypted = age_encrypt_bounded(
        original,
        recipient,
        max_input_bytes=size,
        max_output_bytes=cipher_bound,
        max_stderr_bytes=4096,
        timeout_seconds=20,
    )
    store = LocalDirectoryBackupStore(tmp_path / "objects")
    location = "PERSONAL/invented-original.age"
    store.put_object(location, encrypted)
    readback = store.get_object_bounded(location, max_bytes=cipher_bound)
    assert content_hash_of(readback) == content_hash_of(encrypted)
    with pytest.raises(BackupArtifactsError):
        store.get_object_bounded(location, max_bytes=len(encrypted) - 1)
    assert (
        age_decrypt_bounded(
            readback,
            key,
            max_input_bytes=cipher_bound,
            max_output_bytes=size,
            max_stderr_bytes=4096,
            timeout_seconds=20,
        )
        == original
    )
