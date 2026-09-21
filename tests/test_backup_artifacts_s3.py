"""Tests for zacai.backup_artifacts_s3 (D031B Phase 1): the S3-compatible
`BackupObjectStore` backend, entirely hermetic via `moto` - no real
network, no real provider account, no real credential. Also proves
compatibility with D031A's `backup_boundary`/`restore_boundary_artifacts`
without any change to their semantics.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws
from sqlalchemy.orm import Session

from zacai.backup_artifacts import (
    ObjectStat,
    backup_boundary,
    restore_boundary_artifacts,
    source_hashes_for_boundary,
)
from zacai.backup_artifacts_s3 import RemoteBackupError, S3CompatibleBackupObjectStore
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.policy import DataClassification, TrustBoundary
from zacai.state import SourceSystem
from zacai.state_repository import record_source

_BUCKET = "zacai-test-artifact-backup"
_REGION = "us-east-1"
_FAKE_ACCESS_KEY_ID = "test-only-access-key-id"
_FAKE_SECRET_ACCESS_KEY = "test-only-secret-access-key-do-not-use"
_BOUNDARY = TrustBoundary.SHARED  # see tests/test_backup_artifacts.py for why SHARED is used


@pytest.fixture
def moto_bucket() -> Iterator[None]:
    with mock_aws():
        client = boto3.client("s3", region_name=_REGION)
        client.create_bucket(Bucket=_BUCKET)
        yield


@pytest.fixture
def store(moto_bucket: None) -> S3CompatibleBackupObjectStore:
    return S3CompatibleBackupObjectStore(
        bucket=_BUCKET,
        region=_REGION,
        access_key_id=_FAKE_ACCESS_KEY_ID,
        secret_access_key=_FAKE_SECRET_ACCESS_KEY,
    )


# --- basic put/get/exists/stat/idempotency -----------------------------------


def test_put_then_get_round_trips_exact_bytes(store: S3CompatibleBackupObjectStore) -> None:
    store.put_object("a/b.age", b"encrypted bytes, opaque to the provider")
    assert store.get_object("a/b.age") == b"encrypted bytes, opaque to the provider"


def test_exists_true_and_false(store: S3CompatibleBackupObjectStore) -> None:
    assert store.exists("missing.age") is False
    store.put_object("present.age", b"data")
    assert store.exists("present.age") is True


def test_stat_returns_size(store: S3CompatibleBackupObjectStore) -> None:
    store.put_object("k.age", b"12345")
    assert store.stat("k.age") == ObjectStat(size=5)


def test_overwrite_is_idempotent_last_write_wins(store: S3CompatibleBackupObjectStore) -> None:
    store.put_object("k.age", b"first")
    store.put_object("k.age", b"second")
    assert store.get_object("k.age") == b"second"
    assert store.stat("k.age").size == len(b"second")


# --- not-found / error translation -------------------------------------------


def test_stat_missing_raises_remote_backup_error(store: S3CompatibleBackupObjectStore) -> None:
    with pytest.raises(RemoteBackupError):
        store.stat("missing.age")


def test_get_missing_raises_remote_backup_error(store: S3CompatibleBackupObjectStore) -> None:
    with pytest.raises(RemoteBackupError):
        store.get_object("missing.age")


def test_client_error_on_put_is_translated_to_remote_backup_error(
    store: S3CompatibleBackupObjectStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise(*_args: object, **_kwargs: object) -> None:
        raise ClientError({"Error": {"Code": "InternalError", "Message": "simulated provider failure"}}, "PutObject")

    monkeypatch.setattr(store._client, "put_object", _raise)
    with pytest.raises(RemoteBackupError, match="InternalError"):
        store.put_object("k.age", b"data")


def test_client_error_on_get_is_translated_to_remote_backup_error(
    store: S3CompatibleBackupObjectStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise(*_args: object, **_kwargs: object) -> None:
        raise ClientError({"Error": {"Code": "SlowDown", "Message": "simulated throttling"}}, "GetObject")

    monkeypatch.setattr(store._client, "get_object", _raise)
    with pytest.raises(RemoteBackupError, match="SlowDown"):
        store.get_object("k.age")


# --- security: credentials never leak into exceptions ------------------------


def test_credential_values_never_appear_in_not_found_exception_text(
    store: S3CompatibleBackupObjectStore,
) -> None:
    with pytest.raises(RemoteBackupError) as excinfo:
        store.get_object("missing.age")
    message = str(excinfo.value)
    assert _FAKE_ACCESS_KEY_ID not in message
    assert _FAKE_SECRET_ACCESS_KEY not in message


def test_credential_values_never_appear_in_translated_client_error_text(
    store: S3CompatibleBackupObjectStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise(*_args: object, **_kwargs: object) -> None:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "simulated access denied"}}, "PutObject"
        )

    monkeypatch.setattr(store._client, "put_object", _raise)
    with pytest.raises(RemoteBackupError) as excinfo:
        store.put_object("k.age", b"data")
    message = str(excinfo.value)
    assert _FAKE_ACCESS_KEY_ID not in message
    assert _FAKE_SECRET_ACCESS_KEY not in message


# --- D031A compatibility: backup_boundary / restore_boundary_artifacts ------


@dataclass(frozen=True)
class _AgeKeypair:
    recipient: str
    identity_path: Path


def _generate_age_keypair(tmp_path: Path, name: str) -> _AgeKeypair:
    identity_path = tmp_path / f"{name}.key"
    proc = subprocess.run(
        ["age-keygen", "-o", str(identity_path)], capture_output=True, text=True, check=True
    )
    output = proc.stdout + proc.stderr
    for line in output.splitlines():
        if line.startswith("Public key:"):
            return _AgeKeypair(recipient=line.split(":", 1)[1].strip(), identity_path=identity_path)
    raise RuntimeError(f"could not parse age-keygen output: {output!r}")


def test_backup_and_restore_round_trip_against_s3_compatible_backend(
    db_session: Session, tmp_path: Path, moto_bucket: None
) -> None:
    """Proves `S3CompatibleBackupObjectStore` is a drop-in replacement
    for `LocalDirectoryBackupStore` from `backup_boundary`'s and
    `restore_boundary_artifacts`'s point of view - no change to either
    function was needed (D031B). Encrypted object/manifest behavior is
    unchanged: real `age` encryption with a throwaway keypair, exactly
    as in tests/test_backup_artifacts.py."""
    key = _generate_age_keypair(tmp_path, "brainstorm")
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = S3CompatibleBackupObjectStore(
        bucket=_BUCKET, region=_REGION,
        access_key_id=_FAKE_ACCESS_KEY_ID, secret_access_key=_FAKE_SECRET_ACCESS_KEY,
    )

    digests = set()
    for i, payload in enumerate([b"s3-backend drill artifact one", b"s3-backend drill artifact two"]):
        digest = content_hash_of(payload)
        location = artifact_store.put(_BOUNDARY, digest, payload)
        record_source(
            db_session, trust_boundary=_BOUNDARY, data_classification=DataClassification.CONFIDENTIAL,
            system=SourceSystem.FIREFLIES, content_hash=digest, content_location=location,
            external_ref=f"s3-backend-{i}",
        )
        digests.add(digest)

    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )
    all_hashes = source_hashes_for_boundary(db_session, trust_boundary=_BOUNDARY)
    assert digests <= all_hashes

    # Independently confirm the objects are genuinely retrievable from
    # the (mocked) remote backend via a fresh client - not merely that
    # backup_boundary's own call happened to succeed.
    verify_client = boto3.client(
        "s3", region_name=_REGION, aws_access_key_id=_FAKE_ACCESS_KEY_ID, aws_secret_access_key=_FAKE_SECRET_ACCESS_KEY
    )
    for digest in digests:
        key_name = f"{_BOUNDARY.value}/{digest[:2]}/{digest}.age"
        assert verify_client.head_object(Bucket=_BUCKET, Key=key_name)["ContentLength"] > 0

    restore_target = LocalFilesystemArtifactStore(tmp_path / "restore")
    outcome = restore_boundary_artifacts(
        trust_boundary=_BOUNDARY, backup_store=backup_store, identity_path=key.identity_path,
        restore_target=restore_target, expected_source_hashes=digests,
    )
    assert outcome.successful
    assert outcome.reconciliation.missing == frozenset()
    assert outcome.reconciliation.unexpected == frozenset()
    assert outcome.reconciliation.verified == frozenset(digests)
    for digest in digests:
        location = restore_target.location_for(digest)
        assert content_hash_of(restore_target.get(_BOUNDARY, location)) == digest


def test_wrong_boundary_identity_fails_against_s3_compatible_backend(
    db_session: Session, tmp_path: Path, moto_bucket: None
) -> None:
    brainstorm_key = _generate_age_keypair(tmp_path, "brainstorm")
    personal_key = _generate_age_keypair(tmp_path, "personal")
    artifact_store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    backup_store = S3CompatibleBackupObjectStore(
        bucket=_BUCKET, region=_REGION,
        access_key_id=_FAKE_ACCESS_KEY_ID, secret_access_key=_FAKE_SECRET_ACCESS_KEY,
    )
    digest = content_hash_of(b"wrong identity drill artifact")
    location = artifact_store.put(_BOUNDARY, digest, b"wrong identity drill artifact")
    record_source(
        db_session, trust_boundary=_BOUNDARY, data_classification=DataClassification.CONFIDENTIAL,
        system=SourceSystem.FIREFLIES, content_hash=digest, content_location=location,
        external_ref="s3-backend-wrong-identity",
    )
    backup_boundary(
        db_session, trust_boundary=_BOUNDARY, artifact_store=artifact_store, backup_store=backup_store,
        recipient=brainstorm_key.recipient, local_manifest_cache_path=tmp_path / "cache.json",
    )

    from zacai.backup_artifacts import DecryptionError

    restore_target = LocalFilesystemArtifactStore(tmp_path / "restore")
    with pytest.raises(DecryptionError):
        restore_boundary_artifacts(
            trust_boundary=_BOUNDARY, backup_store=backup_store, identity_path=personal_key.identity_path,
            restore_target=restore_target, expected_source_hashes={digest},
        )
