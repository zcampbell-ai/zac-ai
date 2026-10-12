"""Root-only genuine PG/native age/full State+journal recovery; all data invented.

No model/provider transport. Fault wrappers retain actual producers and explicit
milestones; cleanup uncertainty is injected AFTER real restoration returns.
"""

import subprocess
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select

from tests.native_personal_recovery_sql_support import (
    native_custody_case as native_custody_case,  # noqa: PLC0414
)
from tests.test_complete_history_contextual_storage_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.chatgpt_native_protection import protect_personal_chatgpt_native_pair
from zacai.contextual_protection import (
    ContextualProtectionError,
    PersonalFragmentCleanupUncertain,
    PersonalHistoryFragmentProtector,
)
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier, ReviewProtectionCleanupUncertain
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source


def add_unrelated(f):
    raw = b"Invented unrelated whole-boundary context; not selected text."
    digest = content_hash_of(raw)
    location = f.artifacts.put(B.PERSONAL, digest, raw)
    with f.factory() as session, session.begin():
        row, new = record_source(
            session,
            trust_boundary=B.PERSONAL,
            data_classification=C.HIGHLY_RESTRICTED,
            system=SourceSystem.MANUAL,
            external_ref=f"invented-native-recovery-unrelated/{uuid4()}",
            content_hash=digest,
            content_location=location,
            captured_at=f.now,
        )
        assert new
        sid = row.id
    return sid


@pytest.fixture
def recovery_case(native_custody_case, tmp_path):
    f = native_custody_case()
    loaded = f.capture(f.action())  # actual strict POST, atomic pair and clean reopen
    unrelated = add_unrelated(f)
    identity = tmp_path / "invented-recovery.agekey"
    subprocess.run(["age-keygen", "-o", str(identity)], capture_output=True, check=True, timeout=15)
    recipient = (
        subprocess.run(
            ["age-keygen", "-y", str(identity)], capture_output=True, check=True, timeout=15
        )
        .stdout.decode()
        .strip()
    )
    writer = LocalDirectoryBackupStore(tmp_path / "native-ciphertexts")
    reader = LocalDirectoryBackupStore(tmp_path / "native-ciphertexts")
    engine = f.factory.kw["bind"]

    def protect(cold_name, *, read_existing=False):
        protector = PersonalHistoryFragmentProtector(
            factory=f.factory,
            engine=engine,
            artifacts=f.artifacts,
            cold_artifacts=LocalFilesystemArtifactStore(tmp_path / cold_name),
            objects=writer,
            verification_objects=reader,
            recipient=recipient,
            identity_path=identity,
            manifest_cache=tmp_path / "native-manifest.json",
            operation=f.operation,
            clock=f.clock,
            restoration=DisposableStateRestoreVerifier(),
        )
        return protect_personal_chatgpt_native_pair(
            protector,
            inputs=f.inputs,
            capture_id=loaded.capture_id,
            original_reference=loaded.original_reference,
            companion_reference=loaded.companion_reference,
            expected_companion=loaded.companion,
            read_existing=read_existing,
        )

    try:
        yield SimpleNamespace(
            f=f, loaded=loaded, unrelated=unrelated, writer=writer, protect=protect, root=tmp_path
        )
    finally:
        identity.unlink(missing_ok=True)


def observe_restore(monkeypatch, action=None):
    actual = DisposableStateRestoreVerifier.verify_personal
    milestones = []

    def observed(verifier, *args, **kwargs):
        result = actual(verifier, *args, **kwargs)
        milestones.append("actual-State-and-journal-restoration-returned")
        if action:
            action()
            milestones.append("post-restoration-fault-applied")
        return result

    monkeypatch.setattr(DisposableStateRestoreVerifier, "verify_personal", observed)
    return milestones


def test_real_native_pair_whole_inventory_restore_and_read_existing(recovery_case, monkeypatch):
    x = recovery_case
    milestones = observe_restore(monkeypatch)
    first = x.protect("cold-first")
    with x.f.factory() as session, session.begin():
        expected = {
            row.id: row.content_hash
            for row in session.scalars(select(Source).where(Source.trust_boundary == B.PERSONAL))
        }
    assert len(expected) == 3 and x.unrelated in expected
    assert dict(first.full_boundary_source_hashes) == expected
    assert {sid for sid, _ in first.full_boundary_source_fingerprints} == set(expected)
    assert first.capture_id == x.loaded.capture_id and first.reported_role == "USER"
    assert first.source_captured_at == x.loaded.source_captured_at
    assert not first.processing_authorized and not first.owner_admitted
    writes = []

    def forbidden(*args, **kwargs):
        writes.append(True)
        raise AssertionError("read-existing must not remint or repair")

    monkeypatch.setattr(x.writer, "put_object", forbidden)
    second = x.protect("cold-reopened", read_existing=True)
    assert second == first and not writes and len(milestones) == 2


def test_real_current_owner_revoked_after_restore(recovery_case, monkeypatch):
    x = recovery_case
    milestones = observe_restore(monkeypatch, x.f.owners.revoke)
    with pytest.raises(ContextualProtectionError, match="stop and reconcile"):
        x.protect("cold-owner-revoked")
    assert len(milestones) == 2
    with pytest.raises(ValueError, match="owner enrollment unavailable"):
        x.f.owners.load()
    assert not tuple((x.root / "native-ciphertexts").rglob("receipt-*.age"))


def test_real_original_expiry_after_restore(recovery_case, monkeypatch):
    x = recovery_case
    expiry = x.f.operation.establish().effective_expires_at

    def expire():
        x.f.times[0] = expiry + timedelta(microseconds=1)

    milestones = observe_restore(monkeypatch, expire)
    with pytest.raises(ContextualProtectionError, match="stop and reconcile"):
        x.protect("cold-expired")
    assert len(milestones) == 2
    assert not tuple((x.root / "native-ciphertexts").rglob("receipt-*.age"))


def test_real_inventory_changed_after_restore(recovery_case, monkeypatch):
    x = recovery_case
    added = []
    milestones = observe_restore(monkeypatch, lambda: added.append(add_unrelated(x.f)))
    with pytest.raises(ContextualProtectionError, match="stop and reconcile"):
        x.protect("cold-inventory-changed")
    assert len(milestones) == 2 and len(added) == 1
    with x.f.factory() as session, session.begin():
        assert session.get(Source, added[0]) is not None


def test_real_corrupt_receipt_no_repair(recovery_case, monkeypatch):
    x = recovery_case
    milestones = observe_restore(monkeypatch)
    first = x.protect("cold-before-corruption")
    path = x.writer._path(first.receipt_object)
    assert path.is_file()
    path.write_bytes(b"invented corrupt ciphertext, never private plaintext")
    writes = []

    def forbidden(*args, **kwargs):
        writes.append(True)
        raise AssertionError("corrupt custody cannot auto-repair")

    monkeypatch.setattr(x.writer, "put_object", forbidden)
    with pytest.raises(ContextualProtectionError, match="stop and reconcile"):
        x.protect("cold-corrupt-receipt", read_existing=True)
    assert len(milestones) == 1 and not writes
    assert path.read_bytes() == b"invented corrupt ciphertext, never private plaintext"


def test_actual_restore_then_cleanup_uncertainty_preserved(recovery_case, monkeypatch):
    x = recovery_case
    actual = DisposableStateRestoreVerifier.verify_personal
    milestones = []

    def uncertain(verifier, *args, **kwargs):
        actual(verifier, *args, **kwargs)
        milestones.append("actual-restoration-complete-before-injected-uncertainty")
        raise ReviewProtectionCleanupUncertain("invented private diagnostic")

    monkeypatch.setattr(DisposableStateRestoreVerifier, "verify_personal", uncertain)
    with pytest.raises(PersonalFragmentCleanupUncertain) as e:
        x.protect("cold-cleanup-uncertain")
    assert str(e.value) == "PERSONAL native cleanup uncertain; operator review required"
    assert e.value.__cause__ is None and e.value.__context__ is None
    assert len(milestones) == 1


def test_actual_ciphertext_change_after_restore_before_publication(recovery_case, monkeypatch):
    x = recovery_case
    actual = DisposableStateRestoreVerifier.verify_personal
    put = x.writer.put_object
    milestones, receipts = [], []

    def observed_put(key, raw):
        if "/receipt-" in key:
            receipts.append(key)
        return put(key, raw)

    def mutate(verifier, *args, **kwargs):
        result = actual(verifier, *args, **kwargs)
        files = list((x.root / "native-ciphertexts").rglob("state-*.age"))
        assert len(files) == 1
        previous = files[0].read_bytes()
        files[0].write_bytes(b"Invented actual ciphertext mutation after genuine restoration")
        assert files[0].read_bytes() != previous
        milestones.append("actual-State-journal-restoration-then-real-ciphertext-mutation")
        return result

    monkeypatch.setattr(x.writer, "put_object", observed_put)
    monkeypatch.setattr(DisposableStateRestoreVerifier, "verify_personal", mutate)
    with pytest.raises(ContextualProtectionError, match="stop and reconcile") as e:
        x.protect("cold-mutated-after-restore")
    assert milestones and not receipts
    assert not tuple((x.root / "native-ciphertexts").rglob("receipt-*.age"))
    assert e.value.__cause__ is None and e.value.__context__ is None
