"""Canonical locator discovery, throwaway age keys and independent local reads."""

import json
from uuid import uuid4

import pytest
from sqlalchemy import select

from tests.test_contextual_storage import stored as stored_fixture
from tests.test_fireflies_protection import keypair
from zacai import backup_artifacts, contextual_protection
from zacai.backup_artifacts import LocalDirectoryBackupStore, age_decrypt, age_encrypt
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.contextual_recovery_record import load_contextual_recovery_receipt
from zacai.ingestion.artifact_store import content_hash_of
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import Source
from zacai.state_repository import elevate_source_classification


@pytest.fixture
def protected(test_session_factory, tmp_path, monkeypatch):
    f = stored_fixture.__wrapped__(test_session_factory, tmp_path)
    factory, store, payload, sid, _, baseline = f

    def rows(session, *, trust_boundary):
        found = session.execute(
            select(Source.id, Source.content_hash, Source.content_location).where(
                Source.trust_boundary == trust_boundary
            )
        ).all()
        return [(h, loc) for source_id, h, loc in found if source_id not in baseline]

    def hashes(conn):
        found = conn.execute(
            select(Source.id, Source.content_hash).where(Source.trust_boundary == B.BRAINSTORM)
        ).all()
        return {h for source_id, h in found if source_id not in baseline and h is not None}

    monkeypatch.setattr(backup_artifacts, "_source_rows_for_boundary", rows)
    monkeypatch.setattr(contextual_protection, "_snapshot_artifact_hashes", hashes)
    identity = tmp_path / "throwaway.key"
    recipient = keypair(identity)
    writer = LocalDirectoryBackupStore(tmp_path / "objects")
    reader = LocalDirectoryBackupStore(tmp_path / "objects")
    protector = BrainstormContextualProtector(
        factory=factory,
        engine=factory.kw["bind"],
        artifacts=store,
        objects=writer,
        verification_objects=reader,
        recipient=recipient,
        identity_path=identity,
        manifest_cache=tmp_path / "manifest",
        restoration=DisposableStateRestoreVerifier(),
    )
    receipt = protector.protect(sid, content_hash_of(payload))
    return f, receipt, reader, writer, identity, recipient


def load(f, **changes):
    setup, receipt, reader, _writer, identity, _recipient = f
    args = {
        "locator_source_id": receipt.locator_source_id,
        "expected_locator_digest": receipt.locator_digest,
        "authorized_boundaries": frozenset({B.BRAINSTORM}),
        "allowed_classifications": frozenset({C.CONFIDENTIAL}),
        "verification_objects": reader,
        "identity_path": identity,
    }
    args.update(changes)
    with setup[0]() as session:
        return load_contextual_recovery_receipt(session, **args)


def test_exact_receipt_is_discoverable_from_snapshot_canonical_locator(protected):
    setup, receipt, reader, _, identity, _ = protected
    assert load(protected) == receipt
    snapshot = age_decrypt(reader.get_object(receipt.state_object), identity)
    assert str(receipt.locator_source_id).encode() in snapshot
    assert receipt.locator_digest.encode() in snapshot
    with setup[0]() as session:
        source = session.get(Source, receipt.locator_source_id)
        raw = setup[1].get(B.BRAINSTORM, source.content_location)
        # Canonical planned locator is a pointer, never an assertion of success.
        assert b"SUCCEEDED" not in raw and b"verified_at" not in raw
        assert (
            source.external_ref
            == f"contextual-recovery-locator/{receipt.locator.packet_source_id}/{receipt.locator.locator_id}"
        )


@pytest.mark.parametrize("change", ["boundary", "classification", "hash", "elevation"])
def test_denied_locator_never_reads_objects(protected, change):
    setup, receipt = protected[:2]
    args = {}
    if change == "boundary":
        args["authorized_boundaries"] = frozenset({B.PERSONAL})
    elif change == "classification":
        args["allowed_classifications"] = frozenset()
    elif change == "hash":
        args["expected_locator_digest"] = "0" * 64
    else:
        with setup[0]() as session:
            elevate_source_classification(
                session,
                source_id=receipt.locator_source_id,
                trust_boundary=B.BRAINSTORM,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="invented elevation",
                elevated_by="fixture",
            )
            session.commit()

    class NoReads:
        def stat(self, *args):
            pytest.fail("denied metadata must precede all object I/O")

    args["verification_objects"] = NoReads()
    with pytest.raises(ValueError) as error:
        load(protected, **args)
    assert error.value.__context__ is None


@pytest.mark.parametrize("object_type", ["state", "journal", "receipt"])
def test_lost_or_corrupt_recovery_objects_reject_receipt(protected, monkeypatch, object_type):
    receipt, reader = protected[1:3]
    key = {
        "state": receipt.state_object,
        "journal": receipt.journal_object,
        "receipt": receipt.locator.receipt_object,
    }[object_type]
    original = reader.get_object
    monkeypatch.setattr(
        reader,
        "get_object",
        lambda actual: b"PRIVATE corrupted bytes" if actual == key else original(actual),
    )
    with pytest.raises(ValueError) as error:
        load(protected)
    assert "PRIVATE" not in str(error.value) and error.value.__context__ is None


def test_crypto_valid_receipt_for_wrong_locator_cannot_be_rebound(protected):
    _, receipt, reader, writer, identity, recipient = protected
    data = json.loads(age_decrypt(reader.get_object(receipt.locator.receipt_object), identity))
    data["locator_source_id"] = str(uuid4())
    writer.put_object(
        receipt.locator.receipt_object,
        age_encrypt(json.dumps(data, sort_keys=True, separators=(",", ":")).encode(), recipient),
    )
    with pytest.raises(ValueError) as error:
        load(protected)
    assert error.value.__context__ is None


def test_receipt_hashes_exact_state_and_operational_journal(protected):
    _, receipt, reader, _, identity, _ = protected
    state_ciphertext = reader.get_object(receipt.state_object)
    journal_ciphertext = reader.get_object(receipt.journal_object)
    assert content_hash_of(state_ciphertext) == receipt.state_ciphertext_hash
    assert content_hash_of(age_decrypt(state_ciphertext, identity)) == receipt.state_plaintext_hash
    assert content_hash_of(journal_ciphertext) == receipt.journal_ciphertext_hash
    assert (
        content_hash_of(age_decrypt(journal_ciphertext, identity)) == receipt.journal_plaintext_hash
    )


def find(f):
    from zacai.contextual_recovery_record import find_contextual_recovery_receipt

    setup, receipt, reader, _, identity, _ = f
    with setup[0]() as session:
        return find_contextual_recovery_receipt(
            session,
            packet_source_id=receipt.locator.packet_source_id,
            expected_packet_digest=receipt.locator.packet_digest,
            authorized_boundaries=frozenset({B.BRAINSTORM}),
            allowed_classifications=frozenset({C.CONFIDENTIAL}),
            verification_objects=reader,
            identity_path=identity,
        )


def add_locator(f):
    from zacai.backup_artifacts import backup_object_key_for
    from zacai.contextual_recovery_record import RecoveryLocator
    from zacai.ingestion.artifact_store import canonical_bytes
    from zacai.state import SourceSystem
    from zacai.state_repository import record_source

    setup, receipt, _, writer, _, recipient = f
    locator = RecoveryLocator(**{**receipt.locator.model_dump(), "locator_id": uuid4()})
    raw = canonical_bytes(locator.model_dump(mode="json"))
    digest = content_hash_of(raw)
    location = setup[1].put(B.BRAINSTORM, digest, raw)
    with setup[0]() as session:
        source, _ = record_source(
            session,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            system=SourceSystem.MANUAL,
            content_hash=digest,
            content_location=location,
            external_ref=f"contextual-recovery-locator/{locator.packet_source_id}/{locator.locator_id}",
            captured_at=locator.created_at,
        )
        sid = source.id
        session.commit()
    writer.put_object(backup_object_key_for(B.BRAINSTORM, digest), age_encrypt(raw, recipient))
    return locator, sid, digest


def test_packet_index_lookup_skips_only_orphan_plans(protected):
    assert find(protected) == protected[1]
    add_locator(protected)
    assert find(protected) == protected[1]


def test_packet_index_lookup_rejects_ambiguous_receipts(protected):
    from zacai.contextual_recovery_record import encode_recovery_receipt

    locator, sid, digest = add_locator(protected)
    receipt = protected[1].model_copy(
        update={"locator": locator, "locator_source_id": sid, "locator_digest": digest}
    )
    protected[3].put_object(
        locator.receipt_object, age_encrypt(encode_recovery_receipt(receipt), protected[5])
    )
    with pytest.raises(ValueError, match="lookup unavailable or ambiguous") as error:
        find(protected)
    assert error.value.__context__ is None
