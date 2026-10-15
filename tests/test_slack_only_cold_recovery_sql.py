"""ROOT ONLY: invented providers/owner, actual age/State/journal/PG restoration.

Local object clients are not off-device. Key-evidence escrow assertions are
explicitly fabricated test metadata; referenced State is genuinely encrypted,
decrypted and cold-restored. No model, production consent or private inputs.
"""

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select, text

from tests.conftest import assert_safe_test_database_url
from tests.test_fireflies_protection import keypair
from tests.test_native_source_preparation import NOW, slack_inputs
from tests.test_personal_fragment_protection_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_review_context import capture
from zacai import backup
from zacai.backup_artifacts import LocalDirectoryBackupStore, age_decrypt, age_encrypt
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.host_clock import HostObservedClock
from zacai.ingestion import native_preparation_recovery as m
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.ingestion.native_batch_inventory import (
    load_native_batch_inventory,
    prepare_native_batch_recovery_selection,
)
from zacai.ingestion.native_contextual_preparation_retention import (
    retain_native_contextual_preparation,
)
from zacai.ingestion.native_preparation_recovery import BrainstormNativePreparationRecovery
from zacai.ingestion.native_proposal_retention import (
    load_retained_native_proposal,
    retain_native_proposal,
)
from zacai.ingestion.native_source_capture import (
    SlackCaptureInput,
    prepare_native_batch_proposal,
    record_native_batch,
)
from zacai.intelligence.contextual_generation import encode_native_contextual_request
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.native_contextual_assembly import (
    NativeContextualSelection,
    NativeEvidenceSelection,
    assemble_native_contextual_selection,
)
from zacai.intelligence.review_context import MeetingEvidence
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
    Source,
    SourceSystem,
)
from zacai.state_repository import (
    elevate_source_classification,
    get_effective_source_classification,
    record_source,
)


def prepare_slack_only(factory, store):
    """Commit exact Slack-only originals; discard live ORM/input authority."""
    with factory() as sql:
        data = slack_inputs()
        inputs = (
            SlackCaptureInput(data["selection"], data["account_response"], data["page_response"]),
        )
        bid = uuid4()
        proposal = prepare_native_batch_proposal(
            batch_id=bid, gmail_inputs=(), slack_inputs=inputs, family="slack_only"
        )
        approval_raw = canonical_bytes(
            {
                "format": "invented-slack-owner-decision",
                "proposal_hash": content_hash_of(proposal),
                "authentication": "TEST_ONLY_EXTERNAL_OWNER_NOT_PROVEN",
            }
        )
        digest = content_hash_of(approval_raw)
        source, created = record_source(
            sql,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            system=SourceSystem.USER_INSTRUCTION,
            external_ref="invented-slack-approval/" + str(uuid4()),
            content_hash=digest,
            content_location=store.put(B.BRAINSTORM, digest, approval_raw),
            captured_at=NOW,
        )
        assert created
        approval = EvidenceReference(
            source_id=source.id,
            content_hash=digest,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.CONFIDENTIAL,
        )
        pref = retain_native_proposal(
            sql,
            artifacts=store,
            batch_id=bid,
            proposal_raw=proposal,
            expected_proposal_hash=content_hash_of(proposal),
            gmail_inputs=(),
            slack_inputs=inputs,
            retained_at=NOW,
            family="slack_only",
        )
        batch = record_native_batch(
            sql,
            artifacts=store,
            proposal_raw=proposal,
            approved_proposal_hash=content_hash_of(proposal),
            approval_reference=approval,
            gmail_inputs=(),
            slack_inputs=inputs,
            captured_at=NOW,
            family="slack_only",
        )
        meeting = capture(sql, store, "invented-slack-only-" + uuid4().hex)
        sql.commit()
    # Independent fresh Session loads retained original bytes, not input tuples.
    with factory() as sql:
        raw = load_retained_native_proposal(
            sql,
            artifacts=store,
            proposal_reference=pref,
            batch_id=bid,
            expected_proposal_hash=pref.content_hash,
            as_of=NOW,
        )
        before = list(sql.execute(select(*Source.__table__.columns).order_by(Source.id)))
        inventory = load_native_batch_inventory(
            sql,
            artifacts=store,
            batch_reference=batch.batch_reference,
            approval_reference=batch.approval_reference,
            approved_proposal_raw=raw,
            as_of=NOW,
        )
        selection_proof = prepare_native_batch_recovery_selection(
            sql,
            artifacts=store,
            inventory=inventory,
            proposal_reference=pref,
            approved_proposal_raw=raw,
            as_of=NOW,
        )
        assert len(selection_proof.hashes) == 6
        assert not selection_proof.recovery_verified and not selection_proof.processing_authorized
        assert before == list(sql.execute(select(*Source.__table__.columns).order_by(Source.id)))
        provider = batch.artifact_references[0][-1]
        row = sql.get(Source, provider.source_id)
        assert row.system is SourceSystem.SLACK
        full_text = json.loads(store.get(B.BRAINSTORM, row.content_location))["text"]
        assert all(
            sql.get(Source, r.source_id).system is SourceSystem.SLACK
            for r in batch.artifact_references[0]
        )
    selection = NativeContextualSelection(
        format="zac-native-contextual-selection-v1",
        selected=MeetingEvidence(meeting.meeting_id, meeting.normalized_source_id),
        batch_id=bid,
        batch_reference=batch.batch_reference,
        intake_instruction_reference=batch.approval_reference,
        proposal_reference=pref,
        approved_proposal_hash=pref.content_hash,
        native=(
            NativeEvidenceSelection(
                source_id=provider.source_id,
                content_hash=provider.content_hash,
                field="text",
                field_text_hash=content_hash_of(full_text.encode()),
                spans=({"start": 0, "end": len(full_text)},),
                relevance_reason="Invented Slack selected evidence; no current-fact promotion",
            ),
        ),
    )
    preparation = assemble_native_contextual_selection(
        factory,
        artifacts=store,
        selection=selection,
        authorized_boundaries=frozenset({B.BRAINSTORM}),
        allowed_classifications=frozenset({C.CONFIDENTIAL}),
        observed_at=NOW,
    )
    assert len(preparation.hashes) == 9
    retained_at = NOW + timedelta(seconds=1)
    with factory() as sql:
        pair = retain_native_contextual_preparation(
            sql, factory=factory, artifacts=store, preparation=preparation, retained_at=retained_at
        )
        sql.commit()
    return preparation, pair, retained_at


@pytest.mark.parametrize(
    "fault",
    [None, "denied_owner", "own_acl", "dependency_acl", "unselected_dependency_acl", "journal"],
)
def test_actual_slack_only_commit_close_protected_reopen(
    clean_factory, tmp_path, monkeypatch, fault
):
    private_store = LocalFilesystemArtifactStore(tmp_path / "private-artifacts")
    factory = clean_factory
    engine = factory.kw["bind"]
    assert_safe_test_database_url(str(engine.url))
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT current_database()")) == "zacai_test"
    preparation, pair, retained_at = prepare_slack_only(factory, private_store)
    unselected_dependency_id = None
    if fault == "unselected_dependency_acl":
        selected_ids = {item.source_id for item in preparation.selection.native}
        with factory() as sql:
            account_ids = list(
                sql.scalars(
                    select(Source.id).where(
                        Source.id.in_(tuple(dict(preparation.hashes))),
                        Source.system == SourceSystem.SLACK,
                        Source.external_ref.startswith("slack/account/"),
                    )
                )
            )
        assert len(account_ids) == 1
        unselected_dependency_id = account_ids[0]
        assert unselected_dependency_id in dict(preparation.hashes)
        assert unselected_dependency_id not in selected_ids
    expected = dict(preparation.hashes) | {
        pair.body_reference.source_id: pair.body_reference.content_hash,
        pair.dependency_reference.source_id: pair.dependency_reference.content_hash,
    }
    assert len(expected) == 11
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
    committed_mutations = []

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
            if fault in {"own_acl", "dependency_acl", "unselected_dependency_acl"}:
                source_id = (
                    pair.body_reference.source_id
                    if fault == "own_acl"
                    else preparation.selection.native[0].source_id
                )
                if fault == "unselected_dependency_acl":
                    assert unselected_dependency_id is not None
                    source_id = unselected_dependency_id
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
            else:
                raise AssertionError("unknown invented mutation")
            writer.commit()
            committed_mutations.append(fault)

    monkeypatch.setattr(m, "verify_brainstorm_recovered_identity", key_then_committed_mutation)
    objects.put_object = no_put
    try:
        with pytest.raises(m.NativePreparationRecoveryError) as error:
            reopened.load_retained(pair)
        assert error.value.__context__ is None and len(callbacks) == 2
        assert committed_mutations == [fault]
        with factory() as verify:
            if fault in {"own_acl", "dependency_acl", "unselected_dependency_acl"}:
                target = (
                    pair.body_reference.source_id
                    if fault == "own_acl"
                    else unselected_dependency_id
                    if fault == "unselected_dependency_acl"
                    else preparation.selection.native[0].source_id
                )
                assert target is not None
                assert (
                    get_effective_source_classification(verify, source_id=target)
                    is C.HIGHLY_RESTRICTED
                )
            else:
                assert (
                    verify.get(ArtifactBackupRun, receipt.artifact_backup_run_id).status
                    is ArtifactBackupRunStatus.FAILED
                )
    finally:
        objects.put_object = original_put
