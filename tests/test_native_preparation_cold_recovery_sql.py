"""ROOT ONLY: invented providers/owner, actual age/State/journal/PG restoration.

Local object clients are not off-device. Key-evidence escrow assertions are
explicitly fabricated test metadata; referenced State is genuinely encrypted,
decrypted and cold-restored. No model, production consent or private inputs.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import text

from tests.conftest import assert_safe_test_database_url
from tests.test_fireflies_protection import keypair
from tests.test_native_contextual_assembly_sql import (
    private_store as private_store,  # noqa: PLC0414
)
from tests.test_native_preparation_retention_sql import prepare
from zacai import backup
from zacai.backup_artifacts import LocalDirectoryBackupStore, age_decrypt, age_encrypt
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.ingestion import native_preparation_recovery as m
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.ingestion.native_preparation_recovery import BrainstormNativePreparationRecovery
from zacai.intelligence.contextual_generation import encode_native_contextual_request
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.private_web import BoundaryScope, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.interfaces.sqlite_sessions import SqliteSessionStore
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import BoundedStateBuffer, DisposableStateRestoreVerifier
from zacai.state import (
    ArtifactBackupRun,
    ArtifactBackupRunStatus,
    EvidenceStance,
    MeetingProjectAssociation,
)
from zacai.state_repository import (
    EvidenceInput,
    create_project,
    elevate_source_classification,
    get_project,
    retract_meeting,
)


@pytest.mark.parametrize("project", [False, True])
@pytest.mark.parametrize(
    "fault", [None, "denied_owner", "own_acl", "dependency_acl", "journal", "meeting", "project"]
)
def test_actual_native_pair_cold_protection_and_read_existing(
    test_session_factory, private_store, tmp_path, monkeypatch, project, fault
):
    if fault == "project" and not project:
        pytest.skip("Project-version mutation requires the genuine project selection")
    factory = test_session_factory
    engine = factory.kw["bind"]
    assert_safe_test_database_url(str(engine.url))
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT current_database()")) == "zacai_test"
    preparation, pair, retained_at, _ = prepare(factory, private_store, project)
    expected = dict(preparation.hashes) | {
        pair.body_reference.source_id: pair.body_reference.content_hash,
        pair.dependency_reference.source_id: pair.dependency_reference.content_hash,
    }
    assert len(expected) == (15 if project else 14)
    identity_path = tmp_path / "throwaway.agekey"
    recipient = keypair(identity_path)
    objects = LocalDirectoryBackupStore(tmp_path / "objects")
    reader = LocalDirectoryBackupStore(tmp_path / "objects")
    restoration = DisposableStateRestoreVerifier()
    # Genuine existing State/key mechanics, without a mocked restore verdict.
    with BoundedStateBuffer() as buffer:
        backup.export_boundary_stream(engine, B.BRAINSTORM, buffer)
        snapshot = buffer.getvalue()
    restoration.verify(snapshot, expected, current_selected_sources=engine)
    ciphertext = age_encrypt(snapshot, recipient)
    digest = content_hash_of(ciphertext)
    proof_key = f"BRAINSTORM/state/{uuid4()}/{digest}.age"
    objects.put_object(proof_key, ciphertext)
    assert age_decrypt(reader.get_object(proof_key), identity_path) == snapshot
    proof = canonical_bytes(
        {
            "format": "zac-existing-state-recovery-v1",
            "boundary": "BRAINSTORM",
            "full_row_field_comparison": "passed",
            "target_cleaned": True,
            # Invented escrow/off-device assertions, not production evidence.
            "off_device_retrieval": True,
            "recovered_identity_from_password_manager": True,
            "temporary_recovered_key_removed": True,
            "state_object": proof_key,
            "ciphertext_hash": digest,
            "plaintext_hash": content_hash_of(snapshot),
        }
    )
    proof_path = tmp_path / "invented-independent-proof.json"
    proof_path.write_bytes(proof)
    proof_path.chmod(0o600)
    protector = BrainstormContextualProtector(
        factory=factory,
        engine=engine,
        artifacts=private_store,
        objects=objects,
        verification_objects=reader,
        recipient=recipient,
        identity_path=identity_path,
        manifest_cache=tmp_path / "manifest.json",
        restoration=restoration,
    )
    # An actual invented session is current read access, never processing consent.
    clock = HostObservedClock(lambda: datetime.now(UTC))
    assert clock() >= retained_at  # No manufactured current observation/backdating.
    sessions = SqliteSessionStore(tmp_path / "sessions", key=b"x" * 32)
    owner = OwnerGrant(
        Identity("https://accounts.google.com", "invented-native-owner"),
        (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),),
    )
    cookie = sessions.start_user(owner.identity, clock())
    continuity = NamedSessionContinuity(
        sessions=sessions,
        owner=lambda: owner,
        clock=clock,
        key=b"x" * 32,
        origin="https://caz.example",
        client_id="invented-native",
    )
    adapter = BrainstormNativePreparationRecovery(
        protector=protector,
        operation=continuity.for_cookie(cookie),
        clock=clock,
        recovered_key_receipt=proof_path,
        key_proof_digest=content_hash_of(proof),
    )
    if fault == "denied_owner":
        owner = OwnerGrant(
            owner.identity, (BoundaryScope(B.PERSONAL, frozenset({C.CONFIDENTIAL})),)
        )
        key_calls, private_reads = [], []
        actual_key, actual_get = m.verify_brainstorm_recovered_identity, reader.get_object

        def key(**kwargs):
            key_calls.append(True)
            return actual_key(**kwargs)

        def get(name):
            private_reads.append(name)
            return actual_get(name)

        monkeypatch.setattr(m, "verify_brainstorm_recovered_identity", key)
        monkeypatch.setattr(reader, "get_object", get)
        with pytest.raises(m.NativePreparationRecoveryError):
            adapter.protect(pair)
        assert key_calls == [] and private_reads == []
        return
    receipt = adapter.protect(pair)
    assert receipt.captured_at == retained_at
    assert receipt.original_observed_at == preparation.request.context.task.event.observed_at
    assert receipt.request_digest == content_hash_of(
        encode_native_contextual_request(preparation.request)
    )
    assert not receipt.processing_authorized and not receipt.access_authorized
    # Exact reopened concrete graph; neither loading nor recheck can put/repair.
    reopened = BrainstormNativePreparationRecovery(
        protector=protector,
        operation=continuity.for_cookie(cookie),
        clock=clock,
        recovered_key_receipt=proof_path,
        key_proof_digest=content_hash_of(proof),
    )
    original_put = objects.put_object

    def no_put(*_, **__):
        raise AssertionError("Read-existing recovery cannot put or remint")

    objects.put_object = no_put
    try:
        assert reopened.load_retained(pair) == receipt
        reopened.recheck(pair, receipt)
    finally:
        objects.put_object = original_put

    if fault is None:
        return
    actual_key = m.verify_brainstorm_recovered_identity
    callbacks = []

    def key_then_committed_mutation(**kwargs):
        actual_key(**kwargs)
        callbacks.append(True)
        if len(callbacks) != 2:
            return
        # Separate genuine writer commits AFTER final actual key proof, before
        # final current-cookie check and callback-free canonical read.
        with factory() as writer:
            assert writer.scalar(text("SELECT current_database()")) == "zacai_test"
            writer.execute(text("SET LOCAL lock_timeout='2s'"))
            if fault in {"own_acl", "dependency_acl"}:
                source_id = (
                    pair.body_reference.source_id
                    if fault == "own_acl"
                    else preparation.selection.native[0].source_id
                )
                elevate_source_classification(
                    writer,
                    source_id=source_id,
                    trust_boundary=B.BRAINSTORM,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="Invented final key callback restriction",
                    elevated_by="invented-owner",
                )
            elif fault == "journal":
                writer.get(
                    ArtifactBackupRun, receipt.artifact_backup_run_id
                ).status = ArtifactBackupRunStatus.FAILED
            elif fault == "meeting":
                retract_meeting(
                    writer,
                    meeting_id=preparation.selection.selected.meeting_id,
                    requestor_boundaries=frozenset({B.BRAINSTORM}),
                    source_id=preparation.selection.intake_instruction_reference.source_id,
                    reason="Invented final key callback withdrawal",
                )
            else:
                project_id = writer.get(
                    MeetingProjectAssociation, preparation.selection.projects[0].association_id
                ).project_id
                current = get_project(
                    writer, entity_id=project_id, requestor_boundaries=frozenset({B.BRAINSTORM})
                )
                assert current is not None
                advanced = create_project(
                    writer,
                    entity_id=project_id,
                    trust_boundary=current.trust_boundary,
                    data_classification=current.data_classification,
                    name="Invented final callback project version",
                    company_id=current.company_id,
                    status=current.status,
                    evidence=[
                        EvidenceInput(
                            source_id=preparation.selection.projects[0].source_id,
                            stance=EvidenceStance.SUPPORTS,
                            confidence=1.0,
                        )
                    ],
                )
                assert advanced.version == current.version + 1
            writer.commit()

    monkeypatch.setattr(m, "verify_brainstorm_recovered_identity", key_then_committed_mutation)
    objects.put_object = no_put
    try:
        with pytest.raises(m.NativePreparationRecoveryError) as error:
            reopened.load_retained(pair)
        assert error.value.__context__ is None and len(callbacks) == 2
    finally:
        objects.put_object = original_put
