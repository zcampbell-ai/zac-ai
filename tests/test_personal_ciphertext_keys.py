"""Invented SQLite/files and mocked crypto; no owner or PostgreSQL proof."""

import hashlib
from dataclasses import replace

import pytest

from tests.test_personal_bounded_backup import (
    fixture as fixture,  # noqa: PLC0414 - pytest fixture export
)
from tests.test_personal_bounded_backup import run
from zacai import backup_artifacts as b
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
from zacai.policy import TrustBoundary as B


def randomized(monkeypatch):
    plaintexts = {}

    def encrypt(raw, recipient, **limits):
        cipher = b"invented-randomized:" + str(len(plaintexts)).encode() + b":" + raw
        plaintexts[cipher] = raw
        return cipher

    monkeypatch.setattr(b, "age_encrypt_bounded", encrypt)
    return plaintexts


def manifest(f, plaintexts):
    return b.Manifest.from_json_bytes(
        plaintexts[f["remote"].get_object(b.manifest_key_for(B.PERSONAL))]
    )


def v2(f):
    return replace(f["plan"], profile="personal-encrypted-custody-backup-v2")


@pytest.mark.parametrize(
    "profile", ["personal-full-original-backup-v1", "personal-encrypted-custody-backup-v2"]
)
def test_failed_rerun_preserves_prior_cipher_and_manifest(fixture, monkeypatch, profile):
    f = fixture
    plaintexts = randomized(monkeypatch)
    assert run(f, personal_plan=replace(f["plan"], profile=profile)).backed_up == 1
    oldmanifest = f["remote"].get_object(b.manifest_key_for(B.PERSONAL))
    oldentry = manifest(f, plaintexts).entries[f["digest"]]
    oldcipher = f["remote"].get_object(oldentry.backup_object_key)
    encrypt = b.age_encrypt_bounded
    artifact_uploads = []
    put = f["remote"].put_object

    def observed_put(key, data):
        put(key, data)
        artifact_uploads.append(key)

    def fail_manifest(raw, recipient, **limits):
        if limits["max_input_bytes"] == 1_000_000:
            raise RuntimeError("invented failure after new artifact upload")
        return encrypt(raw, recipient, **limits)

    monkeypatch.setattr(f["remote"], "put_object", observed_put)
    monkeypatch.setattr(b, "age_encrypt_bounded", fail_manifest)
    with pytest.raises(b.BackupArtifactsError):
        run(f, personal_plan=replace(f["plan"], profile=profile))
    assert len(artifact_uploads) == 1
    assert f["remote"].get_object(b.manifest_key_for(B.PERSONAL)) == oldmanifest
    assert f["remote"].get_object(oldentry.backup_object_key) == oldcipher
    assert hashlib.sha256(oldcipher).hexdigest() == oldentry.ciphertext_sha256
    assert artifact_uploads[0] != oldentry.backup_object_key


def test_interleaved_completed_run_survives_other_run_hold(fixture, monkeypatch):
    f = fixture
    plaintexts = randomized(monkeypatch)
    put = f["remote"].put_object
    read = f["remote"].get_object_bounded
    entered = False
    outer_uploaded = False
    completed = []

    def interleaved_put(key, data):
        nonlocal entered, outer_uploaded
        if key != b.manifest_key_for(B.PERSONAL) and not entered:
            entered = True
            # The inner run fully commits BEFORE the outer artifact put.
            assert run(f, personal_plan=v2(f)).backed_up == 1
            completed.append(manifest(f, plaintexts))
            put(key, data)
            outer_uploaded = True
            return
        put(key, data)

    def hold_outer_readback(key, **limits):
        if outer_uploaded and key != b.manifest_key_for(B.PERSONAL):
            raise RuntimeError("invented outer hold after interleaved committed manifest")
        return read(key, **limits)

    monkeypatch.setattr(f["remote"], "put_object", interleaved_put)
    monkeypatch.setattr(f["remote"], "get_object_bounded", hold_outer_readback)
    with pytest.raises(b.BackupArtifactsError):
        run(f, personal_plan=v2(f))
    assert entered and outer_uploaded and len(completed) == 1
    actual = manifest(f, plaintexts)
    assert actual.to_json_bytes() == completed[0].to_json_bytes()
    for entry in actual.entries.values():
        assert (
            hashlib.sha256(f["remote"].get_object(entry.backup_object_key)).hexdigest()
            == entry.ciphertext_sha256
        )


@pytest.mark.parametrize("old_locator", [False, True])
def test_reader_restores_historical_and_new_ciphertext_locators(
    fixture, tmp_path, monkeypatch, old_locator
):
    f = fixture
    plaintexts = randomized(monkeypatch)
    if old_locator:
        # Seed the historical manifest format through public contracts. This
        # models an already accepted backup, without executing a predecessor.
        cipher = b.age_encrypt_bounded(f["raw"], "invented recipient")
        key = b.backup_object_key_for(B.PERSONAL, f["digest"])
        f["remote"].put_object(key, cipher)
        entry = b.ManifestEntry(
            f["digest"],
            f["source"].content_location,
            key,
            len(cipher),
            hashlib.sha256(cipher).hexdigest(),
            "2026-10-07T00:00:00+00:00",
        )
        body = b.Manifest(
            B.PERSONAL.value, "2026-10-07T00:00:00+00:00", {f["digest"]: entry}
        ).to_json_bytes()
        encrypted = b.age_encrypt_bounded(body, "invented recipient")
        f["remote"].put_object(b.manifest_key_for(B.PERSONAL), encrypted)
    else:
        assert run(f, personal_plan=v2(f)).backed_up == 1
    monkeypatch.setattr(b, "age_decrypt", lambda cipher, identity: plaintexts[cipher])
    target = LocalFilesystemArtifactStore(tmp_path / "artifact_restore_test")
    outcome = b.restore_boundary_artifacts(
        trust_boundary=B.PERSONAL,
        backup_store=f["remote"],
        identity_path=tmp_path / "invented-unused-identity",
        restore_target=target,
        live_artifact_root=f["local"].root,
        expected_source_hashes={f["digest"]},
    )
    assert outcome.successful
    assert outcome.reconciliation.verified == frozenset({f["digest"]})
    assert target.get(B.PERSONAL, f["source"].content_location) == f["raw"]
