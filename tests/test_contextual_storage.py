"""Guarded test DB, invented evidence, throwaway crypto/local object stores."""

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from tests.test_contextual_review import fixture
from tests.test_fireflies_protection import keypair
from zacai import backup_artifacts, contextual_protection
from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.contextual_protection import BrainstormContextualProtector, ContextualProtectionError
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.contextual_evaluation import encode_contextual_packet
from zacai.intelligence.contextual_storage import capture_contextual_packet, load_contextual_packet
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import Source, SourceSystem
from zacai.state_repository import elevate_source_classification


@pytest.fixture
def stored(test_session_factory, tmp_path):
    factory = test_session_factory
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    context, review, _, _ = fixture()
    with factory() as session:
        baseline = set(session.scalars(select(Source.id)))
        items = []
        for item in context.task.context:
            raw = item.untrusted_text.encode()
            digest = content_hash_of(raw)
            location = store.put(B.BRAINSTORM, digest, raw)
            ref = item.reference.model_copy(
                update={
                    "trust_boundary": B.BRAINSTORM,
                    "effective_classification": C.CONFIDENTIAL,
                    "content_hash": digest,
                }
            )
            session.add(
                Source(
                    id=ref.source_id,
                    trust_boundary=B.BRAINSTORM,
                    data_classification=C.CONFIDENTIAL,
                    system=SourceSystem.MANUAL,
                    external_ref=f"synthetic-evidence/{uuid4()}",
                    content_hash=digest,
                    content_location=location,
                )
            )
            items.append(item.model_copy(update={"reference": ref}))
        session.commit()
    event = context.task.event.model_copy(
        update={
            "trust_boundary": B.BRAINSTORM,
            "data_classification": C.CONFIDENTIAL,
            "provenance": tuple(i.reference for i in items),
        }
    )
    task = context.task.model_copy(update={"context": tuple(items), "event": event})
    context = type(context)(task, context.meeting_source_id, context.related_source_ids)
    review = review.model_copy(update={"data_classification": C.CONFIDENTIAL})
    payload = encode_contextual_packet(
        review, context, builder_id=uuid4(), created_at=event.observed_at + timedelta(seconds=1)
    )
    with factory() as session:
        sid = capture_contextual_packet(
            session,
            artifacts=store,
            payload=payload,
            authorized_boundaries=frozenset({B.BRAINSTORM}),
            allowed_classifications=frozenset({C.CONFIDENTIAL}),
        )
        session.commit()
    return factory, store, payload, sid, context, baseline


def load(session, store, payload, sid, **changes):
    args = {
        "artifacts": store,
        "source_id": sid,
        "expected_digest": content_hash_of(payload),
        "authorized_boundaries": frozenset({B.BRAINSTORM}),
        "allowed_classifications": frozenset({C.CONFIDENTIAL}),
    }
    args.update(changes)
    return load_contextual_packet(session, **args)


def test_exact_capture_reuses_canonical_source_and_owner_only_artifact(stored):
    factory, store, payload, sid, context, _ = stored
    with factory() as session:
        restored = load(session, store, payload, sid)
        assert restored.context() == context
        again = capture_contextual_packet(
            session,
            artifacts=store,
            payload=payload,
            authorized_boundaries=frozenset({B.BRAINSTORM}),
            allowed_classifications=frozenset({C.CONFIDENTIAL}),
        )
        assert again == sid
        session.commit()
        source = session.get(Source, sid)
        path = store.root / B.BRAINSTORM.value / source.content_location
        assert path.stat().st_mode & 0o777 == 0o600
        assert source.system == SourceSystem.MANUAL and source.excerpt is None
        assert store.get(B.BRAINSTORM, source.content_location) == payload


@pytest.mark.parametrize("change", ["boundary", "classification", "hash", "elevation"])
def test_denied_metadata_never_reads_packet(stored, change):
    factory, _store, payload, sid, _, _ = stored
    changes = {}
    with factory() as session:
        if change == "boundary":
            changes["authorized_boundaries"] = frozenset({B.PERSONAL})
        elif change == "classification":
            changes["allowed_classifications"] = frozenset({C.PUBLIC})
        elif change == "hash":
            changes["expected_digest"] = "0" * 64
        else:
            elevate_source_classification(
                session,
                source_id=sid,
                trust_boundary=B.BRAINSTORM,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="invented elevation",
                elevated_by="test",
            )
            session.commit()

        class NoReads:
            def get(self, *args):
                pytest.fail("denial must precede packet read")

        with pytest.raises(ValueError, match="unavailable or mismatched"):
            load(session, NoReads(), payload, sid, **changes)


def test_copied_evidence_elevation_blocks_reuse(stored):
    factory, store, payload, sid, context, _ = stored
    with factory() as session:
        elevate_source_classification(
            session,
            source_id=context.meeting_source_id,
            trust_boundary=B.BRAINSTORM,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="invented source elevation",
            elevated_by="test",
        )
        session.commit()
        with pytest.raises(ValueError):
            load(session, store, payload, sid)

        class NoWrites:
            def put(self, *args):
                pytest.fail("stale evidence must reject before packet write")

        with pytest.raises(ValueError):
            capture_contextual_packet(
                session,
                artifacts=NoWrites(),
                payload=payload,
                authorized_boundaries=frozenset({B.BRAINSTORM}),
                allowed_classifications=frozenset({C.CONFIDENTIAL}),
            )


@pytest.mark.parametrize(
    "failure", [None, "artifact", "state", "journal", "restore", "coverage", "identity"]
)
def test_throwaway_crypto_and_full_state_recovery(stored, tmp_path, monkeypatch, failure):
    factory, store, payload, sid, _, baseline = stored

    def rows(session, *, trust_boundary):
        found = session.execute(
            select(Source.id, Source.content_hash, Source.content_location).where(
                Source.trust_boundary == trust_boundary
            )
        ).all()
        return [(h, loc) for source_id, h, loc in found if source_id not in baseline]

    monkeypatch.setattr(backup_artifacts, "_source_rows_for_boundary", rows)

    # Existing synthetic fixtures use unrelated ephemeral artifact roots. Scope
    # inventory recovery to this test's new Sources; production has no filter.
    def scoped_hashes(conn):
        found = conn.execute(
            select(Source.id, Source.content_hash).where(Source.trust_boundary == B.BRAINSTORM)
        ).all()
        return {h for source_id, h in found if source_id not in baseline and h is not None}

    monkeypatch.setattr(contextual_protection, "_snapshot_artifact_hashes", scoped_hashes)
    identity = tmp_path / "throwaway.key"
    recipient = keypair(identity)
    if failure == "identity":
        recipient = keypair(tmp_path / "different-identity.key")
    writer = LocalDirectoryBackupStore(tmp_path / "objects")
    reader = LocalDirectoryBackupStore(tmp_path / "objects")
    restore = DisposableStateRestoreVerifier()
    protector = BrainstormContextualProtector(
        factory=factory,
        engine=factory.kw["bind"],
        artifacts=store,
        objects=writer,
        verification_objects=reader,
        recipient=recipient,
        identity_path=identity,
        manifest_cache=tmp_path / "manifest",
        restoration=restore,
    )
    if failure in ("artifact", "state", "journal"):
        original = reader.get_object

        def corrupt(key):
            if (
                (failure == "journal" and "/journal-" in key)
                or (failure == "state" and "/state/" in key and "/journal-" not in key)
                or (failure == "artifact" and "/state/" not in key)
            ):
                return b"corrupt ciphertext"
            return original(key)

        monkeypatch.setattr(reader, "get_object", corrupt)
    elif failure == "coverage":
        original_backup = contextual_protection.run_artifact_backup

        def add_source_after_backup(*args, **kwargs):
            result = original_backup(*args, **kwargs)
            raw = b"Synthetic source committed between backup and snapshot"
            digest = content_hash_of(raw)
            location = store.put(B.BRAINSTORM, digest, raw)
            with factory() as session:
                session.add(
                    Source(
                        trust_boundary=B.BRAINSTORM,
                        data_classification=C.CONFIDENTIAL,
                        system=SourceSystem.MANUAL,
                        external_ref=f"late-source/{uuid4()}",
                        content_hash=digest,
                        content_location=location,
                    )
                )
                session.commit()
            return result

        monkeypatch.setattr(contextual_protection, "run_artifact_backup", add_source_after_backup)
    elif failure == "restore":

        def rejected(*args, **kwargs):
            raise ValueError("private sentinel")

        monkeypatch.setattr(restore, "verify", rejected)
    if failure:
        with pytest.raises(
            ContextualProtectionError, match="^contextual recovery verification failed$"
        ) as error:
            protector.protect(sid, content_hash_of(payload))
        assert error.value.__context__ is None
    else:
        protector.protect(sid, content_hash_of(payload))
        encrypted = list((tmp_path / "objects" / "BRAINSTORM" / "state").rglob("*.age"))
        assert len(encrypted) == 3
        assert b"Reporting validation" not in encrypted[0].read_bytes()
        assert not list(tmp_path.rglob("*.csv"))


def test_real_backup_selector_includes_manual_packet_sources(stored):
    factory, _, payload, _, _, _ = stored
    with factory() as session:
        assert content_hash_of(payload) in backup_artifacts.source_hashes_for_boundary(
            session, trust_boundary=B.BRAINSTORM
        )


def test_capture_failure_rolls_back_savepoint(stored, monkeypatch):
    from types import SimpleNamespace

    from zacai.intelligence import contextual_storage
    from zacai.intelligence.contextual_evaluation import decode_contextual_packet

    factory, store, payload, _, _, _ = stored
    packet = decode_contextual_packet(payload)
    changed = packet.review.model_copy(
        update={
            "overview": (
                packet.review.overview[0].model_copy(
                    update={"text": "Changed draft for rollback test."}
                ),
            )
        }
    )
    new_payload = encode_contextual_packet(
        changed, packet.context(), builder_id=packet.builder_id, created_at=packet.created_at
    )
    original = contextual_storage.record_source

    def bad_record(*args, **kwargs):
        _source, new = original(*args, **kwargs)
        return SimpleNamespace(content_location="wrong"), new

    monkeypatch.setattr(contextual_storage, "record_source", bad_record)
    with factory() as session:
        before = set(session.scalars(select(Source.id)))
        with pytest.raises(ValueError):
            capture_contextual_packet(
                session,
                artifacts=store,
                payload=new_payload,
                authorized_boundaries=frozenset({B.BRAINSTORM}),
                allowed_classifications=frozenset({C.CONFIDENTIAL}),
            )
        session.commit()
        assert set(session.scalars(select(Source.id))) == before
