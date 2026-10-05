"""Invented offline seam only: no database, network or real identities."""

import subprocess
from uuid import uuid4

import pytest

from zacai.backup_artifacts import ObjectStat
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
from zacai.personal_recovery_drill import (
    PersonalDrillError,
    PersonalDrillReceipt,
    run_synthetic_personal_drill,
)


class MemoryStore:
    def __init__(self, objects):
        self.objects = objects
        self.puts = []

    def exists(self, key):
        return key in self.objects

    def stat(self, key):
        return ObjectStat(len(self.objects[key]))

    def get_object(self, key):
        return self.objects[key]

    def put_object(self, key, data):
        self.puts.append(key)
        self.objects[key] = data


class MemoryState:
    def __init__(self):
        self.calls = []

    def seed_and_export(self, expected):
        self.calls.append("seed")
        return expected

    def restore_and_export(self, expected):
        self.calls.append("restore")
        return expected


@pytest.fixture
def scope(tmp_path):
    identities = []
    recipients = []
    for name in ("personal", "wrong"):
        path = tmp_path / (name + ".agekey")
        subprocess.run(["age-keygen", "-o", str(path)], capture_output=True, check=True)
        result = subprocess.run(["age-keygen", "-y", str(path)], capture_output=True, check=True)
        identities.append(path)
        recipients.append(result.stdout.decode().strip())
    objects = {}
    return {
        "run_id": uuid4(),
        "writer": MemoryStore(objects),
        "independent_reader": MemoryStore(objects),
        "state": MemoryState(),
        "original_artifacts": LocalFilesystemArtifactStore(tmp_path / "original"),
        "restore_artifacts": LocalFilesystemArtifactStore(tmp_path / "restored"),
        "recipient": recipients[0],
        "identity_path": identities[0],
        "wrong_identity_path": identities[1],
    }


def test_exact_offline_round_trip_retains_ciphertext_without_readiness_claim(scope):
    result = run_synthetic_personal_drill(**scope)
    assert len(result.object_keys) == 4
    assert len(result.artifact_hashes) == 2
    assert all(
        key.startswith(f"PERSONAL/recovery-drills/{result.run_id}/") for key in result.object_keys
    )
    assert "PERSONAL/manifest.age" not in scope["writer"].objects
    assert scope["state"].calls == ["seed", "restore"]
    assert result.synthetic_round_trip_verified
    assert not result.real_off_device_verified
    assert not result.database_restore_verified
    assert not result.key_escrow_verified
    assert not result.real_ingestion_authorized
    assert all(b"invented personal" not in value for value in scope["writer"].objects.values())


def test_refuse_run_reuse_before_seed_or_writes(scope):
    run_synthetic_personal_drill(**scope)
    scope["state"].calls.clear()
    prior = dict(scope["writer"].objects)
    with pytest.raises(PersonalDrillError):
        run_synthetic_personal_drill(**scope)
    assert scope["writer"].objects == prior
    assert scope["state"].calls == []


@pytest.mark.parametrize(
    "change", ["same_reader", "same_identity", "same_root", "wrong_restore_key"]
)
def test_independence_and_target_failures_are_closed(scope, change):
    if change == "same_reader":
        scope["independent_reader"] = scope["writer"]
    elif change == "same_identity":
        scope["wrong_identity_path"] = scope["identity_path"]
    elif change == "same_root":
        scope["restore_artifacts"] = scope["original_artifacts"]
    else:
        scope["identity_path"], scope["wrong_identity_path"] = (
            scope["wrong_identity_path"],
            scope["identity_path"],
        )
    with pytest.raises(PersonalDrillError) as error:
        run_synthetic_personal_drill(**scope)
    assert str(error.value) == "synthetic personal recovery drill rejected; no readiness claim"
    assert error.value.__context__ is None
    if change != "wrong_restore_key":
        assert not scope["writer"].objects
        assert not scope["state"].calls


@pytest.mark.parametrize("method", ["seed_and_export", "restore_and_export"])
def test_state_exact_bytes_checked_and_partial_remote_objects_retained(scope, method):
    setattr(scope["state"], method, lambda expected: expected + b"tampered")
    with pytest.raises(PersonalDrillError):
        run_synthetic_personal_drill(**scope)
    assert bool(scope["writer"].objects) == (method == "restore_and_export")


def test_tampered_reader_ciphertext_fails_without_deleting_remote_objects(scope):
    scope["independent_reader"].get_object = lambda key: b"tampered"
    with pytest.raises(PersonalDrillError):
        run_synthetic_personal_drill(**scope)
    assert len(scope["writer"].objects) == 4


def test_receipt_cannot_be_promoted_to_ingestion_authority(scope):
    receipt = run_synthetic_personal_drill(**scope)
    with pytest.raises(TypeError):
        PersonalDrillReceipt(
            receipt.run_id,
            receipt.object_keys,
            receipt.artifact_hashes,
            receipt.synthetic_state_hash,
            real_ingestion_authorized=True,
        )
