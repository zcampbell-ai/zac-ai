"""Real controlled test SQL + age + local clients, never B2 or live state.

The shared zacai_test inventory accumulates other tests' synthetic Sources with
unavailable ephemeral artifacts. Only raw-artifact inventory/coverage functions
are narrowed to this fixture's new Sources, as existing protector tests do.
The actual complete SQL snapshot/restore/journal/selected-row comparisons and
_hashes/_protect_state/admin/operator/reentrant leases are never replaced.
This is selected-fixture recovery evidence, not whole accumulated test-artifact
coverage, production readiness or off-device recovery.
"""

import csv
import io
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select, text

from tests.test_contextual_storage import stored
from tests.test_fireflies_protection import keypair
from tests.test_work_proposals import plan
from zacai import backup, backup_artifacts, contextual_protection
from zacai.backup_artifacts import LocalDirectoryBackupStore, age_decrypt, age_encrypt
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.contextual_evaluation import decode_contextual_packet
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.work_proposals import WorkChoice, WorkPreference, proposal_fingerprint
from zacai.interfaces.oidc_identity import GOOGLE_ISSUER
from zacai.interfaces.work_choice_capture import (
    CapturedWorkChoice,
    ChoiceCheckpointScope,
    WorkChoiceRecoveryReceipt,
    _encode,
)
from zacai.interfaces.work_choice_protection import BrainstormWorkChoiceProtection
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source


def test_actual_choice_protect_recheck_and_immutable_receipt_with_real_sql(
    test_session_factory, tmp_path, monkeypatch
):
    factory, artifacts, packet_bytes, packet_id, _, baseline = stored.__wrapped__(
        test_session_factory, tmp_path
    )
    packet = decode_contextual_packet(packet_bytes)
    proposal = plan(packet)
    captured = datetime.now(UTC)
    request_id = uuid4()
    envelope = CapturedWorkChoice(
        request_id=request_id,
        issuer=GOOGLE_ISSUER,
        subject="invented-sql-owner",
        packet_reference=EvidenceReference(
            source_id=packet_id,
            content_hash=content_hash_of(packet_bytes),
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.CONFIDENTIAL,
        ),
        proposal=proposal,
        preference=WorkPreference(
            proposal_digest=proposal_fingerprint(proposal), choice=WorkChoice.AS_PROPOSED
        ),
        packet_receipt_digest="a" * 64,
        recorded_at=captured,
    )
    choice_bytes = _encode(envelope)
    digest = content_hash_of(choice_bytes)
    location = artifacts.put(B.BRAINSTORM, digest, choice_bytes)
    with factory() as session:
        source, _ = record_source(
            session,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            system=SourceSystem.USER_INSTRUCTION,
            external_ref=f"work-choice/{request_id}",
            content_hash=digest,
            content_location=location,
            captured_at=captured,
        )
        source_id = source.id
        session.commit()

    def rows(session, *, trust_boundary):
        found = session.execute(
            select(Source.id, Source.content_hash, Source.content_location).where(
                Source.trust_boundary == trust_boundary
            )
        ).all()
        return [(h, loc) for sid, h, loc in found if sid not in baseline]

    def scoped_hashes(conn):
        found = conn.execute(
            select(Source.id, Source.content_hash).where(Source.trust_boundary == B.BRAINSTORM)
        ).all()
        return {h for sid, h in found if sid not in baseline and h is not None}

    monkeypatch.setattr(backup_artifacts, "_source_rows_for_boundary", rows)
    monkeypatch.setattr(contextual_protection, "_snapshot_artifact_hashes", scoped_hashes)
    identity = tmp_path / "throwaway-choice.agekey"
    recipient = keypair(identity)
    writer = LocalDirectoryBackupStore(tmp_path / "objects")
    reader = LocalDirectoryBackupStore(tmp_path / "objects")
    protector = BrainstormContextualProtector(
        factory=factory,
        engine=factory.kw["bind"],
        artifacts=artifacts,
        objects=writer,
        verification_objects=reader,
        recipient=recipient,
        identity_path=identity,
        manifest_cache=tmp_path / "manifest",
        restoration=DisposableStateRestoreVerifier(),
    )
    gate = BrainstormWorkChoiceProtection(protector=protector, clock=lambda: datetime.now(UTC))
    scope = ChoiceCheckpointScope(source_id, digest, captured)
    receipt = gate.protect(scope)
    original_receipt = reader.get_object(receipt.receipt_object)
    assert (
        WorkChoiceRecoveryReceipt.model_validate_json(age_decrypt(original_receipt, identity))
        == receipt
    )
    gate.recheck(scope, receipt)
    assert gate.protect(scope) == receipt
    # Real randomized backup repair cannot invalidate exact plaintext recovery.
    writer.put_object(receipt.artifact_object, age_encrypt(choice_bytes, recipient))
    assert (
        content_hash_of(reader.get_object(receipt.artifact_object))
        != receipt.artifact_ciphertext_hash
    )
    gate.recheck(scope, receipt)
    assert reader.get_object(receipt.receipt_object) == original_receipt
    assert protector._lease_guard is None
    with backup._admin_connection() as admin:
        assert (
            admin.scalar(
                text("SELECT count(*) FROM pg_database WHERE datname='zacai_restore_test'")
            )
            == 0
        )
    assert not list(tmp_path.rglob("*.csv"))
    # Actual PostgreSQL COPY time representation, not Python fixture isoformat.
    journal = age_decrypt(reader.get_object(receipt.journal_object), identity)
    run = next(
        row
        for row in csv.DictReader(io.StringIO(journal.decode()))
        if row["id"] == str(receipt.artifact_backup_run_id)
    )
    assert " " in run["started_at"]
    started, finished = (
        datetime.fromisoformat(run["started_at"]),
        datetime.fromisoformat(run["finished_at"]),
    )
    assert captured <= started <= finished <= receipt.verified_at

    # Exercise PostgreSQL's short UTC offset form (+00) independently of the
    # server's local timezone, preserving the same actual run timestamps.
    with factory.kw["bind"].connect() as conn:
        conn.execute(text("SET TRANSACTION READ ONLY"))
        conn.execute(text("SET LOCAL TIME ZONE 'UTC'"))
        raw = backup._raw_connection(conn)
        with (
            raw.cursor() as cur,
            cur.copy(
                "COPY (SELECT started_at, finished_at FROM artifact_backup_run WHERE id = %s) "
                "TO STDOUT WITH (FORMAT csv, HEADER true)",
                (receipt.artifact_backup_run_id,),
            ) as copied,
        ):
            utc_csv = b"".join(bytes(chunk) for chunk in copied)
    utc_row = next(csv.DictReader(io.StringIO(utc_csv.decode())))
    assert utc_row["started_at"].endswith("+00")
    assert datetime.fromisoformat(utc_row["started_at"]) == started
    assert datetime.fromisoformat(utc_row["finished_at"]) == finished
