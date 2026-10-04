"""Invented escrow receipts, throwaway keys, local clients and guarded DBs."""

import io
import json
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select

from tests import test_review_authorization as auth_tests
from tests.test_fireflies_protection import keypair
from tests.test_review_host import NOW, Runtime, run
from zacai import backup
from zacai.backup_artifacts import (
    LocalDirectoryBackupStore,
    age_decrypt,
    age_encrypt,
    backup_object_key_for,
)
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.review_host import ReviewHostError
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import CanonicalReviewAuthorization, record_review_consent
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.review_recovery import (
    BrainstormReviewRecoveryGate,
    ReviewRecoveryCheckpoint,
    ReviewRecoveryError,
)
from zacai.state import Source, SourceSystem
from zacai.state_repository import elevate_source_classification, record_source


def export(factory):
    out = io.BytesIO()
    backup.export_boundary_stream(factory.kw["bind"], B.BRAINSTORM, out)
    return out.getvalue()


def checkpoint(objects, snapshot, receipt_hash):
    encrypted = age_encrypt(snapshot, objects.recipient)
    digest = content_hash_of(encrypted)
    key = f"BRAINSTORM/state/{uuid4()}/{digest}.age"
    objects.put_object(key, encrypted)
    return ReviewRecoveryCheckpoint(
        state_object=key,
        ciphertext_hash=digest,
        plaintext_hash=content_hash_of(snapshot),
        recovered_key_receipt_hash=receipt_hash,
    )


def scope_for(consent, point):
    return consent.model_copy(
        update={
            "id": uuid4(),
            "state_recovery_reference": point.state_reference,
            "artifact_recovery_reference": point.artifact_reference,
            "credential_recovery_reference": point.credential_reference,
        }
    )


@pytest.fixture
def recovery(test_session_factory, tmp_path):
    setup = next(auth_tests.host_fixture.__wrapped__(test_session_factory, tmp_path / "artifacts"))
    issued = auth_tests.issued.__wrapped__(setup)
    factory, store, captured, _ = setup
    identity = tmp_path / "invented-local.key"
    recipient = keypair(identity)
    objects = LocalDirectoryBackupStore(tmp_path / "objects")
    objects.recipient = recipient
    reader = LocalDirectoryBackupStore(tmp_path / "objects")
    snapshot = export(factory)
    point = checkpoint(objects, snapshot, "0" * 64)
    expected = {}
    with factory() as session:
        for sid in (
            captured.raw_source_id,
            captured.account_source_id,
            captured.normalized_source_id,
        ):
            source = session.get(Source, sid)
            raw = store.get(B.BRAINSTORM, source.content_location)
            objects.put_object(
                backup_object_key_for(B.BRAINSTORM, source.content_hash),
                age_encrypt(raw, recipient),
            )
            expected[sid] = source.content_hash
    # This fixture's escrow is invented, not a real 1Password or B2 claim. Its
    # independent-copy decrypt/full-restore mechanics are real throwaway tests.
    recovered = tmp_path / "invented-recovered.key"
    recovered.write_bytes(identity.read_bytes())
    restored = age_decrypt(reader.get_object(point.state_object), recovered)
    verifier = DisposableStateRestoreVerifier()
    verifier.verify(restored, expected)
    recovered.unlink()
    proof = {
        "format": "zac-existing-state-recovery-v1",
        "boundary": "BRAINSTORM",
        "state_object": point.state_object,
        "ciphertext_hash": point.ciphertext_hash,
        "plaintext_hash": point.plaintext_hash,
        "full_row_field_comparison": "passed",
        "target_cleaned": True,
        "off_device_retrieval": True,
        "recovered_identity_from_password_manager": True,
        "temporary_recovered_key_removed": True,
    }
    receipt = tmp_path / "invented-escrow-receipt.json"
    with os.fdopen(os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
        json.dump(proof, file)
    # Independent key drill and current checkpoint are separate protected objects.
    point = checkpoint(objects, snapshot, content_hash_of(receipt.read_bytes()))

    def gate(point=point, **changes):
        values = {
            "factory": factory,
            "engine": factory.kw["bind"],
            "verification_objects": reader,
            "recipient": recipient,
            "identity_path": identity,
            "recovered_key_receipt": receipt,
            "checkpoint": point,
            "restoration": verifier,
        }
        values.update(changes)
        return BrainstormReviewRecoveryGate(**values)

    return issued, gate, point, reader, objects, identity, receipt, snapshot


def test_real_recovery_gate_through_one_shot_host_all_rechecks(recovery):
    issued, make_gate, point, _, _, _, _, _ = recovery
    factory, store = issued[0][:2]
    scope = scope_for(issued[1], point)
    with factory() as session:
        approval = record_review_consent(session, store=store, consent=scope)
        session.commit()
    gate = make_gate()
    ready = False
    calls = 0
    with factory() as session:
        selected_locations = {
            session.get(Source, sid).content_location
            for sid in (issued[0][2].normalized_source_id, issued[0][2].raw_source_id)
        }

    class ObservedGate:
        def preflight(self, scope):
            nonlocal ready, calls
            gate.preflight(scope)
            calls += 1
            ready = True

    class GuardedStore:
        def get(self, boundary, location):
            if location in selected_locations:
                assert ready, "selected context must follow actual recovery verification"
            return store.get(boundary, location)

        def put(self, *args):
            return store.put(*args)

    auth = CanonicalReviewAuthorization(
        factory=factory,
        store=GuardedStore(),
        approval_id=approval,
        recovery=ObservedGate(),
        clock=lambda: NOW,
    )
    runtime = Runtime(factory, store)
    result = run(issued[0], artifacts=GuardedStore(), authorization=auth, runtime=runtime)
    assert result.review.summary and runtime.calls == 1
    assert calls == 5  # preflight, claim, pre-dispatch and two release rechecks


@pytest.mark.parametrize("failure", ["state", "artifact", "receipt", "identity", "reference"])
def test_recovery_failure_releases_no_context_or_model_call(
    recovery, failure, tmp_path, monkeypatch
):
    issued, make_gate, point, _, objects, _, receipt, _ = recovery
    scope = scope_for(issued[1], point)
    options = {}
    if failure == "state":
        objects.put_object(point.state_object, b"invented corrupt state")
    elif failure == "artifact":
        with issued[0][0]() as session:
            source = session.get(Source, issued[0][2].normalized_source_id)
        objects.put_object(
            backup_object_key_for(B.BRAINSTORM, source.content_hash), b"invented corrupt artifact"
        )
    elif failure == "receipt":
        receipt.write_text("invented private receipt diagnostic")
    elif failure == "identity":
        wrong = tmp_path / "wrong.key"
        keypair(wrong)
        options["identity_path"] = wrong
    else:
        scope = scope.model_copy(update={"state_recovery_reference": "invented false reference"})
    with pytest.raises(ReviewRecoveryError) as error:
        make_gate(**options).preflight(scope)
    assert "invented" not in str(error.value)
    assert error.value.__suppress_context__
    factory, store, captured, baseline = issued[0]
    with factory() as session:
        approval = record_review_consent(session, store=store, consent=scope)
        session.commit()
        blocked = {
            session.get(Source, sid).content_location
            for sid in (captured.normalized_source_id, captured.raw_source_id)
        }
    original_get = store.get

    def guarded_get(boundary, location):
        assert location not in blocked, "failed recovery must precede local context reads"
        return original_get(boundary, location)

    monkeypatch.setattr(store, "get", guarded_get)
    auth = CanonicalReviewAuthorization(
        factory=factory,
        store=store,
        approval_id=approval,
        recovery=make_gate(**options),
        clock=lambda: NOW,
    )
    runtime = Runtime(factory, store)
    with pytest.raises(ReviewHostError, match="no draft released"):
        run(issued[0], authorization=auth, runtime=runtime)
    assert runtime.calls == 0
    with factory() as session:
        denials = session.scalars(
            select(Source).where(
                Source.external_ref.startswith("meeting-review-pre-context-audit/"),
                Source.id.not_in(baseline),
            )
        ).all()
    assert len(denials) == 1


def test_changed_original_source_field_rejects_even_with_equal_hashes_ids_counts(recovery):
    issued, make_gate, point, _, objects, _, _, snapshot = recovery
    changed = snapshot.replace(b"normalized-v1/transcript/", b"normalized-v2/transcript/", 1)
    assert changed != snapshot and len(changed) == len(snapshot)
    tampered = checkpoint(objects, changed, point.recovered_key_receipt_hash)
    with pytest.raises(ReviewRecoveryError):
        make_gate(tampered).preflight(scope_for(issued[1], tampered))


def test_current_label_change_rejects_old_checkpoint(recovery):
    issued, make_gate, point, *_ = recovery
    with issued[0][0]() as session:
        elevate_source_classification(
            session,
            source_id=issued[0][2].raw_source_id,
            trust_boundary=B.BRAINSTORM,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="invented correction",
            elevated_by="synthetic human",
        )
        session.commit()
    with pytest.raises(ReviewRecoveryError):
        make_gate().preflight(scope_for(issued[1], point))


def test_unused_additional_source_does_not_create_authority_backup_cycle(recovery):
    issued, make_gate, point, *_ = recovery
    with issued[0][0]() as session:
        record_source(
            session,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            system=SourceSystem.MANUAL,
            external_ref=f"invented-unused/{uuid4()}",
            content_hash=None,
            content_location=None,
        )
        session.commit()
    make_gate().preflight(scope_for(issued[1], point))


def test_gate_refuses_other_targets_before_connection(recovery):
    _, make_gate, *_ = recovery
    unsafe = create_engine("postgresql+psycopg://127.0.0.1:5432/another_database")
    try:
        with pytest.raises(RuntimeError, match="local review state"):
            make_gate(engine=unsafe)
    finally:
        unsafe.dispose()


def test_unrelated_business_change_requires_a_fresh_checkpoint(recovery):
    from tests.test_backup import _make_source
    from zacai.state_repository import EvidenceInput, EvidenceStance, create_person

    issued, make_gate, point, *_ = recovery
    with issued[0][0]() as session:
        sid = _make_source(session, trust_boundary=B.BRAINSTORM)
        create_person(
            session,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            display_name="Invented new business person",
            evidence=[EvidenceInput(source_id=sid, stance=EvidenceStance.SUPPORTS, confidence=1.0)],
        )
        session.commit()
    with pytest.raises(ReviewRecoveryError):
        make_gate().preflight(scope_for(issued[1], point))


def test_project_context_dependencies_are_independently_recovered(recovery, tmp_path):
    from tests import test_project_review_context as projects
    from zacai.intelligence.project_review_context import ReviewedProjectEvidence
    from zacai.intelligence.review_context import MeetingEvidence
    from zacai.intelligence.review_host import ReviewSelection

    issued, make_gate, point, _, objects, *_ = recovery
    factory = issued[0][0]
    with factory() as session:
        before = set(session.scalars(select(Source.id)))
        f = projects.project_setup.__wrapped__(session, tmp_path / "projects")
        session.commit()
        selection = ReviewSelection(
            MeetingEvidence(f["current"].meeting_id, f["current"].normalized_source_id),
            earlier=(
                MeetingEvidence(f["previous"].meeting_id, f["previous"].normalized_source_id),
            ),
            projects=(ReviewedProjectEvidence(f["primary_link"].id, f["brief"].id),),
        )
        # All stored project/meeting dependencies are protected. The bare company
        # fixture Source has no artifact and is canonical metadata only.
        own_ids = set(session.scalars(select(Source.id))) - before
        for sid in own_ids:
            source = session.get(Source, sid)
            if source.content_hash and source.content_location:
                raw = f["store"].get(B.BRAINSTORM, source.content_location)
                objects.put_object(
                    backup_object_key_for(B.BRAINSTORM, source.content_hash),
                    age_encrypt(raw, objects.recipient),
                )
        # Account Source deduplication may predate this fixture; protect it too.
        for capture in (f["current"], f["previous"]):
            for sid in (
                capture.raw_source_id,
                capture.normalized_source_id,
                capture.account_source_id,
            ):
                source = session.get(Source, sid)
                raw = f["store"].get(B.BRAINSTORM, source.content_location)
                objects.put_object(
                    backup_object_key_for(B.BRAINSTORM, source.content_hash),
                    age_encrypt(raw, objects.recipient),
                )
        for source in (f["brief"], f["confirmation"]):
            raw = f["store"].get(B.BRAINSTORM, source.content_location)
            objects.put_object(
                backup_object_key_for(B.BRAINSTORM, source.content_hash),
                age_encrypt(raw, objects.recipient),
            )
        brief_hash = f["brief"].content_hash
    fresh = checkpoint(objects, export(factory), point.recovered_key_receipt_hash)
    scope = scope_for(issued[1], fresh).model_copy(update={"selection": selection})
    make_gate(fresh).preflight(scope)
    objects.put_object(
        backup_object_key_for(B.BRAINSTORM, brief_hash), b"invented missing project proof"
    )
    with pytest.raises(ReviewRecoveryError):
        make_gate(fresh).preflight(scope)


def test_schema_0004_cannot_silently_omit_checkpoint_associations(recovery):
    from pathlib import Path

    from alembic import command
    from alembic.config import Config

    from tests.test_meeting_project_association import _add, _fixture

    issued, make_gate, point, _, objects, *_ = recovery
    factory = issued[0][0]
    with factory() as session:
        project, meeting, confirmation = _fixture(session)
        _add(session, project, meeting, confirmation)
        session.commit()
    fresh = checkpoint(objects, export(factory), point.recovered_key_receipt_hash)
    # D027-guarded zacai_test only; return its schema to 0005 even on failure.
    config = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", factory.kw["bind"].url.render_as_string())
    assert factory.kw["bind"].url.database == "zacai_test"
    try:
        command.downgrade(config, "0004")
        with pytest.raises(ReviewRecoveryError):
            make_gate(fresh).preflight(scope_for(issued[1], fresh))
    finally:
        command.upgrade(config, "0005")
