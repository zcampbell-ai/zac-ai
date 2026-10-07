"""ROOT ONLY: actual age/local files, invented data; SQLite backend explicitly mocked.

No PostgreSQL/current owner/recovery authority. Not part of helper pure execution.
"""

import os
import re
import subprocess
from dataclasses import replace

import pytest

from tests.test_personal_bounded_backup import fixture as fixture  # noqa: PLC0414 - pytest fixture
from tests.test_personal_bounded_backup import run
from zacai import backup_artifacts as b
from zacai.ingestion.artifact_store import content_hash_of
from zacai.policy import TrustBoundary as B

REAL_ENCRYPT = b.age_encrypt_bounded


@pytest.mark.skipif(os.environ.get("CAZ_RUN_INVENTED_AGE") != "1", reason="root-only actual age")
@pytest.mark.parametrize(
    "profile", ["personal-full-original-backup-v1", "personal-encrypted-custody-backup-v2"]
)
def test_actual_age_failed_rerun_preserves_last_good_manifest(
    fixture, tmp_path, monkeypatch, profile
):
    f = fixture
    identity = tmp_path / "disposable-identity"
    generated = subprocess.run(
        ["age-keygen", "-o", str(identity)], capture_output=True, check=False
    )
    assert generated.returncode == 0, "disposable key generation failed"
    os.chmod(identity, 0o600)
    match = re.search(rb"^Public key: (age1[0-9a-z]+)$", generated.stderr, re.MULTILINE)
    assert match is not None, "disposable recipient unavailable"
    recipient = match[1].decode("ascii")
    plan = replace(f["plan"], profile=profile)
    monkeypatch.setattr(b, "age_encrypt_bounded", REAL_ENCRYPT)
    assert run(f, personal_plan=plan, recipient=recipient).backed_up == 1
    old_manifest = f["remote"].get_object(b.manifest_key_for(B.PERSONAL))

    def decrypt(cipher):
        return b.age_decrypt_bounded(
            cipher,
            identity,
            max_input_bytes=101_000_000,
            max_output_bytes=100_000_000,
            max_stderr_bytes=65_536,
            timeout_seconds=30.0,
        )

    manifest = b.Manifest.from_json_bytes(decrypt(old_manifest))
    entry = manifest.entries[f["digest"]]
    old_cipher = f["remote"].get_object(entry.backup_object_key)
    assert content_hash_of(old_cipher) == entry.ciphertext_sha256
    assert decrypt(old_cipher) == f["raw"]
    uploads = []
    put = f["remote"].put_object

    def observed_put(key, raw):
        put(key, raw)
        uploads.append((key, raw))

    def fail_manifest(raw, recipient, **limits):
        if limits["max_input_bytes"] == 1_000_000:
            raise RuntimeError("invented failure after genuine randomized artifact upload")
        return REAL_ENCRYPT(raw, recipient, **limits)

    monkeypatch.setattr(f["remote"], "put_object", observed_put)
    monkeypatch.setattr(b, "age_encrypt_bounded", fail_manifest)
    with pytest.raises(b.BackupArtifactsError):
        run(f, personal_plan=plan, recipient=recipient)
    assert len(uploads) == 1
    assert (
        uploads[0][1] != old_cipher
    )  # Real randomized ciphertext, milestone before preservation assertions.
    assert f["remote"].get_object(b.manifest_key_for(B.PERSONAL)) == old_manifest
    assert f["remote"].get_object(entry.backup_object_key) == old_cipher
    assert (
        content_hash_of(f["remote"].get_object(entry.backup_object_key)) == entry.ciphertext_sha256
    )
    assert decrypt(f["remote"].get_object(entry.backup_object_key)) == f["raw"]
    identity.unlink()
