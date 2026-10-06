"""Root-only actual PostgreSQL/native writer, invented Gmail/Slack bytes.

Caller-owned synthetic human instruction proves storage integrity only, not
actual authentication/access approval. No provider/model/backup calls or facts.
Root must overlay the frozen writer and envelope at canonical module paths.
"""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select

from tests.test_native_source_preparation import gmail_inputs, slack_inputs
from zacai.ingestion import native_source_capture as m
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Base, Source, SourceSystem
from zacai.state_repository import (
    elevate_source_classification,
    get_current_source_revision,
    record_source,
)

NOW = datetime(2026, 10, 6, tzinfo=UTC)


class ObservedStore(LocalFilesystemArtifactStore):
    """Actual filesystem store with an explicitly injected late-write failure."""

    def __init__(self, root):
        super().__init__(root)
        self.writes = []
        self.fail_metadata = False

    def put(self, boundary, digest, raw):
        self.writes.append((boundary, digest))
        if self.fail_metadata and b'"format":"zac-native-selected-batch-evidence-v1"' in raw:
            raise RuntimeError("invented metadata write fault")
        return super().put(boundary, digest, raw)


def capture_args(sql, store, *, mail=None, slack=None, when=NOW):
    g, _ = gmail_inputs()
    s = slack_inputs()
    gm = mail or (
        m.GmailCaptureInput(
            g["scope"], g["profile_response"], g["message_response"], g["expected_message_id"]
        ),
    )
    sl = slack or (m.SlackCaptureInput(s["selection"], s["account_response"], s["page_response"]),)
    proposal = m.prepare_native_batch_proposal(batch_id=uuid4(), gmail_inputs=gm, slack_inputs=sl)
    approved = content_hash_of(proposal)
    raw = canonical_bytes(
        {
            "format": "invented-human-instruction-test-only",
            "proposal_hash": approved,
            "authentication": "EXTERNAL_TEST_CALLER_NOT_REAL_OWNER",
        }
    )
    digest = content_hash_of(raw)
    source, new = record_source(
        sql,
        trust_boundary=B.BRAINSTORM,
        data_classification=C.CONFIDENTIAL,
        system=SourceSystem.USER_INSTRUCTION,
        external_ref=f"invented-native-approval/{uuid4()}",
        content_hash=digest,
        content_location=store.put(B.BRAINSTORM, digest, raw),
        captured_at=when,
    )
    assert new
    return {
        "artifacts": store,
        "proposal_raw": proposal,
        "approved_proposal_hash": approved,
        "approval_reference": EvidenceReference(
            source_id=source.id,
            content_hash=digest,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.CONFIDENTIAL,
        ),
        "gmail_inputs": gm,
        "slack_inputs": sl,
        "captured_at": when,
    }


def envelope(sql, store, receipt):
    source = sql.get(Source, receipt.batch_reference.source_id)
    raw = store.get(B.BRAINSTORM, source.content_location)
    assert content_hash_of(raw) == source.content_hash == receipt.batch_reference.content_hash
    return raw, json.loads(raw)


def non_source_counts(sql):
    return {
        name: sql.scalar(select(func.count()).select_from(table))
        for name, table in Base.metadata.tables.items()
        if table is not Source.__table__
    }


def test_actual_both_origins_inventory_and_same_batch_replay(db_session, tmp_path):
    store = ObservedStore(tmp_path / "artifacts")
    args = capture_args(db_session, store)
    counts = non_source_counts(db_session)
    first = m.record_native_batch(db_session, **args)
    raw, value = envelope(db_session, store, first)
    assert {x["provider"] for x in value["selections"]} == {"gmail", "slack"}
    refs = (
        first.approval_reference,
        first.batch_reference,
        *(r for group in first.artifact_references for r in group),
    )
    inventory = {r.source_id: r.content_hash for r in refs}
    assert len(inventory) == 8 and len(first.new_source_ids) == 7
    for selection in value["selections"]:
        for artifact in selection["artifacts"]:
            row = db_session.get(Source, UUID(artifact["reference"]["source_id"]))
            assert row.content_hash == content_hash_of(
                store.get(B.BRAINSTORM, row.content_location)
            )
            assert row.captured_at == NOW
            origin = artifact["derives_from_wire"]
            if origin is not None:
                assert UUID(origin["source_id"]) in inventory
                assert inventory[UUID(origin["source_id"])] == origin["content_hash"]
        assert (
            selection["artifacts"][-1]["derives_from_wire"]
            == selection["artifacts"][1]["reference"]
        )
    before = [
        (s.id, s.captured_at, s.content_hash, s.supersedes_source_id)
        for s in db_session.scalars(select(Source))
    ]
    second = m.record_native_batch(
        db_session, **{**args, "captured_at": NOW + timedelta(minutes=1)}
    )
    assert second.batch_reference == first.batch_reference and not second.new_source_ids
    assert second.original_observed_at == NOW and envelope(db_session, store, second)[0] == raw
    assert before == [
        (s.id, s.captured_at, s.content_hash, s.supersedes_source_id)
        for s in db_session.scalars(select(Source))
    ]
    assert non_source_counts(db_session) == counts
    assert not first.committed and not first.recovery_verified and not first.permission_granted
    assert not any(
        value[k]
        for k in (
            "facts_confirmed",
            "permission_granted",
            "recovery_verified",
            "complete_history_verified",
        )
    )


def test_actual_provider_wire_revision_and_old_replay_do_not_promote_tip(db_session, tmp_path):
    store = ObservedStore(tmp_path / "artifacts")
    args = capture_args(db_session, store)
    old = m.record_native_batch(db_session, **args)
    mail = args["gmail_inputs"][0]
    wire = json.loads(mail.message_response)
    wire["labelIds"] = ["INBOX"]
    gm = (replace(mail, message_response=json.dumps(wire).encode()),)
    revised_args = capture_args(db_session, store, mail=gm, when=NOW + timedelta(minutes=1))
    new = m.record_native_batch(db_session, **revised_args)
    old_wire, new_wire = old.artifact_references[0][1], new.artifact_references[0][1]
    row = db_session.get(Source, new_wire.source_id)
    assert row.supersedes_source_id == old_wire.source_id
    assert new.artifact_references[0][2] == old.artifact_references[0][2]
    replay = m.record_native_batch(
        db_session, **{**args, "captured_at": NOW + timedelta(minutes=2)}
    )
    assert replay.artifact_references == old.artifact_references and not replay.new_source_ids
    assert (
        get_current_source_revision(
            db_session,
            system=SourceSystem.EMAIL,
            external_ref=row.external_ref,
            trust_boundary=B.BRAINSTORM,
        ).id
        == row.id
    )


@pytest.mark.parametrize("target", ["approval", "provider"])
def test_actual_effective_elevation_holds_before_first_artifact_write(db_session, tmp_path, target):
    store = ObservedStore(tmp_path / "artifacts")
    args = capture_args(db_session, store)
    first = m.record_native_batch(db_session, **args)
    ref = args["approval_reference"] if target == "approval" else first.artifact_references[-1][-1]
    elevate_source_classification(
        db_session,
        source_id=ref.source_id,
        trust_boundary=B.BRAINSTORM,
        new_classification=C.HIGHLY_RESTRICTED,
        reason="Invented test classification correction",
        elevated_by="synthetic-owner",
    )
    before = db_session.scalar(select(func.count()).select_from(Source))
    store.writes.clear()
    with pytest.raises(m.NativeBatchCaptureError, match="^native batch capture held$"):
        m.record_native_batch(db_session, **args)
    assert store.writes == []
    assert db_session.scalar(select(func.count()).select_from(Source)) == before


def test_actual_late_savepoint_failure_leaves_orphans_not_canonical_sources(db_session, tmp_path):
    store = ObservedStore(tmp_path / "artifacts")
    args = capture_args(db_session, store)
    before = db_session.scalar(select(func.count()).select_from(Source))
    store.writes.clear()
    store.fail_metadata = True
    with pytest.raises(m.NativeBatchCaptureError, match="^native batch capture held$"):
        m.record_native_batch(db_session, **args)
    assert db_session.scalar(select(func.count()).select_from(Source)) == before
    assert (
        list(
            db_session.scalars(select(Source).where(Source.system != SourceSystem.USER_INSTRUCTION))
        )
        == []
    )
    assert len(store.writes) >= 7
    for boundary, digest in store.writes[:-1]:
        assert content_hash_of(store.get(boundary, store.location_for(digest))) == digest
    # Observed ordinary savepoint rollback permits reuse here; this is not a
    # host contract guarantee. Hosts must roll back their outer transaction on hold.
    unrelated = capture_args(db_session, store)
    assert db_session.get(Source, unrelated["approval_reference"].source_id) is not None


@pytest.mark.parametrize(
    "fault", ["proposal_hash", "approval_hash", "approval_class", "approval_kind"]
)
def test_actual_instruction_integrity_holds_before_writes(db_session, tmp_path, fault):
    store = ObservedStore(tmp_path / "artifacts")
    args = capture_args(db_session, store)
    if fault == "proposal_hash":
        args["approved_proposal_hash"] = "f" * 64
    elif fault == "approval_hash":
        args["approval_reference"] = args["approval_reference"].model_copy(
            update={"content_hash": "f" * 64}
        )
    elif fault == "approval_class":
        args["approval_reference"] = args["approval_reference"].model_copy(
            update={"effective_classification": C.HIGHLY_RESTRICTED}
        )
    else:
        raw = b"Invented MANUAL source is not an instruction"
        digest = content_hash_of(raw)
        source, _ = record_source(
            db_session,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            system=SourceSystem.MANUAL,
            external_ref=f"invented-wrong-kind/{uuid4()}",
            content_hash=digest,
            content_location=store.put(B.BRAINSTORM, digest, raw),
            captured_at=NOW,
        )
        args["approval_reference"] = EvidenceReference(
            source_id=source.id,
            content_hash=digest,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.CONFIDENTIAL,
        )
    before = db_session.scalar(select(func.count()).select_from(Source))
    store.writes.clear()
    with pytest.raises(m.NativeBatchCaptureError, match="^native batch capture held$"):
        m.record_native_batch(db_session, **args)
    assert (
        store.writes == [] and db_session.scalar(select(func.count()).select_from(Source)) == before
    )


@pytest.mark.parametrize("corrupt", [False, True])
def test_actual_final_callback_cached_row_corruption_defense(db_session, tmp_path, corrupt):
    """Admin-corruption defense only; ordinary Source mutation remains forbidden.

    Scoped to one invented provider UUID in D027 disposable DB. Re-enable the
    exact trigger BEFORE the writer resumes. No operational permission change.
    """
    from sqlalchemy import text

    from tests.conftest import assert_connected_to_safe_test_database

    class FinalReadStore(ObservedStore):
        fired = False
        checkpoints = ()

        def get(self, boundary, location):
            raw = super().get(boundary, location)
            if not self.fired and b'"format":"zac-native-selected-batch-evidence-v1"' in raw:
                self.fired = True
                self.checkpoints = ["metadata callback entered"]
                if corrupt:
                    assert_connected_to_safe_test_database(
                        db_session.scalar(text("SELECT current_database()"))
                    )
                    row = db_session.scalars(
                        select(Source).where(Source.system == SourceSystem.EMAIL)
                    ).first()
                    assert row is not None and row.external_ref.startswith("gmail/")
                    self.retained_row = (
                        row  # Caller retains a genuine ORM instance through final writer reads.
                    )
                    self.checkpoints.append("invented row selected")
                    original_hash = row.content_hash
                    # Test-only: discharge deferred FK events before disposable
                    # admin DDL. No production constraint or Source policy changes.
                    db_session.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
                    self.checkpoints.append("deferred constraints checked")
                    db_session.execute(
                        text("ALTER TABLE source DISABLE TRIGGER source_forbid_mutation")
                    )
                    try:
                        changed = db_session.execute(
                            Source.__table__.update()
                            .where(Source.id == row.id)
                            .values(content_hash="f" * 64)
                        )
                        assert changed.rowcount == 1
                        self.checkpoints.append("update rowcount one")
                    finally:
                        db_session.execute(
                            text("ALTER TABLE source ENABLE TRIGGER source_forbid_mutation")
                        )
                        db_session.execute(text("SET CONSTRAINTS ALL DEFERRED"))
                    self.checkpoints.append("trigger reenabled")
                    assert (
                        db_session.scalar(
                            text(
                                "SELECT tgenabled FROM pg_trigger WHERE tgname='source_forbid_mutation'"
                            )
                        )
                        == "O"
                    )
                    assert (
                        db_session.scalar(select(Source.content_hash).where(Source.id == row.id))
                        == "f" * 64
                    )
                    self.checkpoints.append("fresh scalar changed")
                    assert (
                        row.content_hash == original_hash
                    )  # Real identity-map stale attrs, not a mocked Source.
                    self.checkpoints.append("retained ORM unchanged")
            return raw

    store = FinalReadStore(tmp_path / "artifacts")
    args = capture_args(db_session, store)
    before = db_session.scalar(select(func.count()).select_from(Source))
    if corrupt:
        try:
            with pytest.raises(m.NativeBatchCaptureError, match="^native batch capture held$"):
                m.record_native_batch(db_session, **args)
        finally:
            # Also discriminate setup completion if OLD writer returns success.
            assert store.checkpoints == [
                "metadata callback entered",
                "invented row selected",
                "deferred constraints checked",
                "update rowcount one",
                "trigger reenabled",
                "fresh scalar changed",
                "retained ORM unchanged",
            ]
        assert db_session.scalar(select(func.count()).select_from(Source)) == before
    else:
        result = m.record_native_batch(db_session, **args)
        assert result.batch_reference.source_id is not None and len(result.new_source_ids) == 7
    assert store.fired
    if corrupt:
        assert store.checkpoints == [
            "metadata callback entered",
            "invented row selected",
            "deferred constraints checked",
            "update rowcount one",
            "trigger reenabled",
            "fresh scalar changed",
            "retained ORM unchanged",
        ]


def test_actual_all_source_columns_and_source_driven_backup_inventory(db_session, tmp_path):
    """Current source-driven inventory only; no encryption/upload/restore proof."""
    from zacai.backup_artifacts import source_hashes_for_boundary

    store = ObservedStore(tmp_path / "artifacts")
    args = capture_args(db_session, store)
    approval = args["approval_reference"]
    human_before = db_session.execute(
        select(*Source.__table__.columns).where(Source.id == approval.source_id)
    ).one()
    human_raw = store.get(B.BRAINSTORM, human_before.content_location)
    first = m.record_native_batch(db_session, **args)
    expected_refs = (
        approval,
        first.batch_reference,
        *(r for group in first.artifact_references for r in group),
    )
    ids = {r.source_id for r in expected_refs}
    hashes = {r.source_id: r.content_hash for r in expected_refs}
    rows = db_session.execute(select(*Source.__table__.columns).where(Source.id.in_(ids))).all()
    assert len(rows) == len(ids) == 8
    before = {row.id: tuple(row) for row in rows}
    assert len(before[approval.source_id]) == len(Source.__table__.columns)
    assert before[approval.source_id] == tuple(human_before)
    for row in rows:
        assert row.trust_boundary is B.BRAINSTORM and row.data_classification is C.CONFIDENTIAL
        assert row.captured_at == NOW and row.excerpt is None and row.supersedes_source_id is None
        assert row.external_ref and row.content_location
        assert (
            row.content_hash
            == hashes[row.id]
            == content_hash_of(store.get(B.BRAINSTORM, row.content_location))
        )
    assert store.get(B.BRAINSTORM, human_before.content_location) == human_raw
    orphan_raw = b"Invented unreferenced original must not count as retained context"
    orphan_hash = content_hash_of(orphan_raw)
    store.put(B.BRAINSTORM, orphan_hash, orphan_raw)
    actual = source_hashes_for_boundary(db_session, trust_boundary=B.BRAINSTORM)
    assert actual == set(hashes.values()) and orphan_hash not in actual
    assert store.get(B.BRAINSTORM, store.location_for(orphan_hash)) == orphan_raw
    replay = m.record_native_batch(
        db_session, **{**args, "captured_at": NOW + timedelta(minutes=1)}
    )
    after = {
        row.id: tuple(row)
        for row in db_session.execute(select(*Source.__table__.columns).where(Source.id.in_(ids)))
    }
    assert before == after and not replay.new_source_ids
    assert replay.original_observed_at == NOW
    assert source_hashes_for_boundary(db_session, trust_boundary=B.BRAINSTORM) == actual
    assert not replay.recovery_verified and not replay.committed and not replay.permission_granted


@pytest.mark.parametrize("dirty_callback", [False, True])
def test_actual_final_callback_dirty_approval_cannot_ack_failed_savepoint(
    db_session, tmp_path, dirty_callback
):
    """Ordinary ORM dirty callback meets real append-only trigger, no admin DDL.

    The writer cannot acknowledge until its own savepoint exit succeeds. Source
    artifact bytes remain original; callback is an explicitly invented fault.
    """

    class DirtyApprovalStore(ObservedStore):
        watched_location = None
        approval_id = None
        milestones = ()

        def get(self, boundary, location):
            raw = super().get(boundary, location)
            if location == self.watched_location and not self.milestones:
                with db_session.no_autoflush:
                    batch_id = db_session.scalar(
                        select(Source.id).where(
                            Source.system == SourceSystem.MANUAL,
                            Source.external_ref.startswith("native-source-batch/"),
                        )
                    )
                if batch_id is not None:
                    self.milestones = ["final approval callback entered"]
                    if dirty_callback:
                        row = db_session.get(Source, self.approval_id)
                        assert row is not None and row.content_location == location
                        self.retained_approval = row
                        row.content_location = self.location_for("f" * 64)
                        assert row in db_session.dirty
                        self.milestones.append("genuine approval ORM dirtied")
                        with db_session.no_autoflush:
                            assert (
                                db_session.scalar(
                                    select(Source.content_location).where(Source.id == row.id)
                                )
                                == location
                            )
                        self.milestones.append("stored approval still original before exit")
            return raw

    store = DirtyApprovalStore(tmp_path / "artifacts")
    args = capture_args(db_session, store)
    approval = db_session.get(Source, args["approval_reference"].source_id)
    original_location = approval.content_location
    original_bytes = store.get(B.BRAINSTORM, original_location)
    store.watched_location = original_location
    store.approval_id = approval.id
    before = db_session.scalar(select(func.count()).select_from(Source))
    nested_before = db_session.get_nested_transaction()
    if dirty_callback:
        try:
            with pytest.raises(m.NativeBatchCaptureError, match="^native batch capture held$"):
                m.record_native_batch(db_session, **args)
        finally:
            assert store.milestones == [
                "final approval callback entered",
                "genuine approval ORM dirtied",
                "stored approval still original before exit",
            ]
            # Both OLD false-success and corrected hold must demonstrate the
            # failed/aborted nested write actually left no canonical batch.
            assert db_session.is_active and not db_session.dirty
            assert db_session.get_nested_transaction() is nested_before
            assert db_session.scalar(select(func.count()).select_from(Source)) == before
            assert (
                db_session.scalar(
                    select(Source.content_location).where(Source.id == store.approval_id)
                )
                == original_location
            )
        assert db_session.scalar(select(func.count()).select_from(Source)) == before
        assert (
            db_session.scalar(select(Source.content_location).where(Source.id == store.approval_id))
            == original_location
        )
        assert not db_session.dirty and db_session.is_active
        assert db_session.get_nested_transaction() is nested_before
        assert store.get(B.BRAINSTORM, original_location) == original_bytes
        assert (
            db_session.scalar(
                select(Source.id).where(Source.external_ref.startswith("native-source-batch/"))
            )
            is None
        )
    else:
        result = m.record_native_batch(db_session, **args)
        assert len(result.new_source_ids) == 7
        assert store.milestones == ["final approval callback entered"]
        assert not db_session.dirty and db_session.is_active
        assert db_session.get_nested_transaction() is nested_before


def test_actual_new_content_observation_before_tip_holds_without_artifact_write(
    db_session, tmp_path
):
    """Different new bytes cannot make an older observation the current tip.

    Actual host clock/auth is external; all timestamps and approval evidence in
    this intentionally out-of-order storage scenario are invented fixtures.
    """
    store = ObservedStore(tmp_path / "artifacts")
    first_args = capture_args(db_session, store)
    first = m.record_native_batch(db_session, **first_args)
    mail = first_args["gmail_inputs"][0]
    newer_wire = json.loads(mail.message_response)
    newer_wire["labelIds"] = ["INBOX"]
    newer_args = capture_args(
        db_session,
        store,
        mail=(replace(mail, message_response=canonical_bytes(newer_wire)),),
        when=NOW + timedelta(minutes=2),
    )
    newer = m.record_native_batch(db_session, **newer_args)
    wire_row = db_session.get(Source, newer.artifact_references[0][1].source_id)
    assert wire_row.supersedes_source_id == first.artifact_references[0][1].source_id
    assert wire_row.captured_at == NOW + timedelta(minutes=2)
    older_wire = json.loads(mail.message_response)
    older_wire["labelIds"] = ["STARRED"]
    older_args = capture_args(
        db_session,
        store,
        mail=(replace(mail, message_response=canonical_bytes(older_wire)),),
        when=NOW + timedelta(minutes=1),
    )
    assert content_hash_of(older_args["gmail_inputs"][0].message_response) not in {
        first.artifact_references[0][1].content_hash,
        newer.artifact_references[0][1].content_hash,
    }
    approval = db_session.get(Source, older_args["approval_reference"].source_id)
    assert approval.captured_at == older_args["captured_at"] < wire_row.captured_at
    before = {
        row.id: tuple(row)
        for row in db_session.execute(select(*Source.__table__.columns))
    }
    business_before = non_source_counts(db_session)
    writes_before = len(store.writes)
    nested_before = db_session.get_nested_transaction()
    with pytest.raises(m.NativeBatchCaptureError, match="^native batch capture held$"):
        m.record_native_batch(db_session, **older_args)
    assert len(store.writes) == writes_before
    assert before == {
        row.id: tuple(row)
        for row in db_session.execute(select(*Source.__table__.columns))
    }
    assert non_source_counts(db_session) == business_before
    assert db_session.is_active and db_session.get_nested_transaction() is nested_before
    assert get_current_source_revision(
        db_session,
        system=SourceSystem.EMAIL,
        external_ref=wire_row.external_ref,
        trust_boundary=B.BRAINSTORM,
    ).id == wire_row.id


def test_actual_1100_linked_profile_revisions_allow_exact_old_replay_and_new_batch(
    db_session, tmp_path
):
    """Real Source chain/artifacts, one bulk flush, no1100 selected batch jobs.

    Direct fixture inserts retain the exact record_source supersedes structure;
    actual writer uses record_source for initial capture and later replay. All
    profile wire bytes, identities, approval and times are synthetic. No backup
    or live permission is implied by this Source storage acceptance.
    """
    from zacai.connectors.gmail_wire import inspect_profile

    store = ObservedStore(tmp_path / "artifacts")
    initial_args = capture_args(db_session, store)
    first = m.record_native_batch(db_session, **initial_args)
    original_raw, original_envelope = envelope(db_session, store, first)
    original_profile = db_session.get(Source, first.artifact_references[0][0].source_id)
    mail = initial_args["gmail_inputs"][0]
    profile_value = json.loads(mail.profile_response)
    previous_id = original_profile.id
    history_rows = []
    history_bytes = {}
    for index in range(1100):
        value = {
            **profile_value,
            "historyId": str(int(profile_value["historyId"]) + index + 1),
            "messagesTotal": profile_value["messagesTotal"] + index + 1,
        }
        raw = canonical_bytes(value)
        inspected = inspect_profile(raw, mail.scope)
        assert inspected.value.email_address.casefold() == mail.scope.expected_email.casefold()
        digest = content_hash_of(raw)
        location = store.put(B.BRAINSTORM, digest, raw)
        assert store.get(B.BRAINSTORM, location) == raw
        source = Source(
            id=uuid4(),
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            system=SourceSystem.EMAIL,
            external_ref=original_profile.external_ref,
            content_hash=digest,
            content_location=location,
            captured_at=NOW + timedelta(microseconds=index + 1),
            supersedes_source_id=previous_id,
        )
        history_rows.append(source)
        history_bytes[source.id] = raw
        previous_id = source.id
    db_session.add_all(history_rows)
    db_session.flush()  # actual deferrable Source FK permits this legitimate chain
    assert not db_session.new and not db_session.dirty and not db_session.deleted
    assert db_session.scalar(
        select(func.count()).select_from(Source).where(
            Source.system == SourceSystem.EMAIL,
            Source.external_ref == original_profile.external_ref,
            Source.trust_boundary == B.BRAINSTORM,
        )
    ) == 1101
    latest = get_current_source_revision(
        db_session,
        system=SourceSystem.EMAIL,
        external_ref=original_profile.external_ref,
        trust_boundary=B.BRAINSTORM,
    )
    assert latest.id == history_rows[-1].id
    assert latest.supersedes_source_id == history_rows[-2].id
    assert store.get(B.BRAINSTORM, latest.content_location) == history_bytes[latest.id]
    assert latest.content_hash == content_hash_of(history_bytes[latest.id])
    # Every old row retains its original genuine hash/location/time/chain.
    before = {
        row.id: tuple(row)
        for row in db_session.execute(select(*Source.__table__.columns))
    }
    business_before = non_source_counts(db_session)
    replay = m.record_native_batch(
        db_session, **{**initial_args, "captured_at": NOW + timedelta(seconds=1)}
    )
    assert replay.batch_reference == first.batch_reference
    assert replay.artifact_references == first.artifact_references
    assert replay.original_observed_at == NOW and not replay.new_source_ids
    assert envelope(db_session, store, replay) == (original_raw, original_envelope)
    assert before == {
        row.id: tuple(row)
        for row in db_session.execute(select(*Source.__table__.columns))
    }
    assert get_current_source_revision(
        db_session,
        system=SourceSystem.EMAIL,
        external_ref=original_profile.external_ref,
        trust_boundary=B.BRAINSTORM,
    ).id == latest.id
    # A separate exact approved snapshot can cite old profile bytes as another
    # observation without replacing/promoting the newer profile tip as fact.
    separate_args = capture_args(db_session, store, when=NOW + timedelta(seconds=2))
    before_second = {
        row.id: tuple(row)
        for row in db_session.execute(select(*Source.__table__.columns))
    }
    separate = m.record_native_batch(db_session, **separate_args)
    assert separate.artifact_references == first.artifact_references
    assert separate.original_observed_at == NOW + timedelta(seconds=2)
    assert len(separate.new_source_ids) == 1  # only its new MANUAL batch envelope
    after = {
        row.id: tuple(row)
        for row in db_session.execute(select(*Source.__table__.columns))
    }
    assert all(after[sid] == fields for sid, fields in before_second.items())
    assert set(after) == set(before_second) | separate.new_source_ids
    assert get_current_source_revision(
        db_session,
        system=SourceSystem.EMAIL,
        external_ref=original_profile.external_ref,
        trust_boundary=B.BRAINSTORM,
    ).id == latest.id
    assert non_source_counts(db_session) == business_before
    assert not separate.committed and not separate.permission_granted and not separate.recovery_verified

@pytest.mark.parametrize("release_fault", [False, True])
def test_actual_python_release_savepoint_event_never_acknowledges_failed_exit(
    db_session, tmp_path, release_fault
):
    """Python connection-event fault on real PG, not a server failure.

    The caller explicitly rolls its outer transaction back on hold; a failed
    RELEASE can leave a connection transaction invalid until that rollback.
    The event sees a clean UoW, so this discriminates result placement even
    with the writer's dirty-state defense retained.
    """
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    engine = db_session.get_bind().engine
    connection = engine.connect()
    outer = connection.begin()
    sql = Session(bind=connection)
    milestones = []
    releases_sent = []
    baseline = connection.scalar(select(func.count()).select_from(Source))
    store = ObservedStore(tmp_path / "release-artifacts")
    args = capture_args(sql, store)
    before = sql.scalar(select(func.count()).select_from(Source))
    assert before == baseline + 1

    def before_release(conn, name, context):
        assert conn is connection and not sql.new and not sql.dirty and not sql.deleted
        assert conn.scalar(select(func.count()).select_from(Source)) == before + 7
        milestones.append("clean seven-row savepoint reached RELEASE event")
        if release_fault:
            milestones.append("Python event raises before RELEASE SQL")
            raise RuntimeError("invented Python release event fault")

    def before_cursor(conn, cursor, statement, parameters, context, executemany):
        if statement.upper().startswith("RELEASE SAVEPOINT"):
            releases_sent.append(statement)

    event.listen(connection, "release_savepoint", before_release)
    event.listen(connection, "before_cursor_execute", before_cursor)
    try:
        if release_fault:
            with pytest.raises(m.NativeBatchCaptureError, match="^native batch capture held$"):
                m.record_native_batch(sql, **args)
        else:
            receipt = m.record_native_batch(sql, **args)
            assert len(receipt.new_source_ids) == 7 and not receipt.committed
    finally:
        event.remove(connection, "release_savepoint", before_release)
        event.remove(connection, "before_cursor_execute", before_cursor)
        sql.close()
        outer.rollback()
        milestones.append("caller outer transaction rolled back")
        try:
            assert connection.scalar(select(func.count()).select_from(Source)) == baseline
            assert connection.scalar(select(Source.id).where(
                Source.external_ref == "native-source-batch/" + json.loads(args["proposal_raw"])["batch_id"]
            )) is None
            assert connection.scalar(select(1)) == 1
            milestones.append("canonical count restored and connection usable")
        finally:
            connection.rollback()
            connection.close()
        assert milestones == ([
            "clean seven-row savepoint reached RELEASE event",
            "Python event raises before RELEASE SQL",
        ] if release_fault else ["clean seven-row savepoint reached RELEASE event"]) + [
            "caller outer transaction rolled back",
            "canonical count restored and connection usable",
        ]
        assert len(releases_sent) == (0 if release_fault else 1)


def test_actual_clean_effective_elevation_is_not_only_dirty_state_hold(db_session, tmp_path):
    from zacai.state_repository import get_effective_source_classification

    store = ObservedStore(tmp_path / "clean-elevation-artifacts")
    args = capture_args(db_session, store)
    first = m.record_native_batch(db_session, **args)
    ref = first.artifact_references[-1][-1]
    elevate_source_classification(
        db_session, source_id=ref.source_id, trust_boundary=B.BRAINSTORM,
        new_classification=C.HIGHLY_RESTRICTED,
        reason="Invented clean effective ACL correction", elevated_by="synthetic-owner",
    )
    db_session.flush()
    assert not db_session.new and not db_session.dirty and not db_session.deleted
    assert get_effective_source_classification(db_session, source_id=ref.source_id) == C.HIGHLY_RESTRICTED
    assert db_session.scalar(select(Source.data_classification).where(Source.id == ref.source_id)) == C.CONFIDENTIAL
    before = db_session.scalar(select(func.count()).select_from(Source))
    store.writes.clear()
    with pytest.raises(m.NativeBatchCaptureError, match="^native batch capture held$"):
        m.record_native_batch(db_session, **args)
    assert store.writes == []
    assert db_session.scalar(select(func.count()).select_from(Source)) == before


def test_actual_shared_gmail_profile_divergence_holds_before_proposal(db_session, tmp_path):
    store = ObservedStore(tmp_path / "profile-divergence")
    args = capture_args(db_session, store)
    mail = args["gmail_inputs"][0]
    message = json.loads(mail.message_response)
    message["id"] = "m2"
    profile = json.loads(mail.profile_response)
    profile["historyId"] = "999"
    second = replace(
        mail, expected_message_id="m2", message_response=json.dumps(message).encode(),
        profile_response=json.dumps(profile).encode(),
    )
    # Both actual preparers accept the genuine provider fields independently.
    for item in (mail, second):
        prepared = m.prepare_gmail_source(
            scope=item.scope, profile_response=item.profile_response,
            message_response=item.message_response, expected_message_id=item.expected_message_id,
            captured_at=NOW,
        )
        assert prepared.artifacts[0].system is SourceSystem.EMAIL
    store.writes.clear()
    before = db_session.scalar(select(func.count()).select_from(Source))
    with pytest.raises(m.NativeBatchCaptureError, match="^native batch proposal held$"):
        m.prepare_native_batch_proposal(
            batch_id=uuid4(), gmail_inputs=(mail, second), slack_inputs=args["slack_inputs"],
        )
    assert store.writes == []
    assert db_session.scalar(select(func.count()).select_from(Source)) == before


def test_actual_future_exact_replay_holds_before_put_without_row_corruption(db_session, tmp_path):
    store = ObservedStore(tmp_path / "future-replay")
    future = capture_args(db_session, store, when=NOW + timedelta(minutes=1))
    receipt = m.record_native_batch(db_session, **future)
    args = capture_args(db_session, store, when=NOW)
    assert args["gmail_inputs"] == future["gmail_inputs"]
    assert args["slack_inputs"] == future["slack_inputs"]
    retained = db_session.get(Source, receipt.artifact_references[0][0].source_id)
    assert retained.captured_at > args["captured_at"]
    before = {row.id: tuple(row) for row in db_session.execute(select(*Source.__table__.columns))}
    store.writes.clear()
    with pytest.raises(m.NativeBatchCaptureError, match="^native batch capture held$"):
        m.record_native_batch(db_session, **args)
    assert store.writes == []
    after = {row.id: tuple(row) for row in db_session.execute(select(*Source.__table__.columns))}
    assert after == before


def test_actual_overlapping_slack_message_views_hold_before_put(db_session, tmp_path):
    store = ObservedStore(tmp_path / "overlapping-slack")
    args = capture_args(db_session, store)
    first = args["slack_inputs"][0]
    page = json.loads(first.page_response)
    page["messages"][0]["text"] = "Different invented same-ts observation"
    second = replace(
        first, selection=first.selection.model_copy(update={"latest": "201.999999"}),
        page_response=json.dumps(page).encode(),
    )
    prepared = tuple(m.prepare_slack_sources(
        selection=item.selection, account_response=item.account_response,
        page_response=item.page_response, captured_at=NOW, boundary=B.BRAINSTORM,
        classification=C.CONFIDENTIAL, requestor_boundaries=frozenset({B.BRAINSTORM}),
        allowed_classifications=frozenset({C.CONFIDENTIAL}),
    ) for item in (first, second))
    left, right = prepared[0].artifacts[2], prepared[1].artifacts[2]
    assert left.external_ref == right.external_ref and left.content_hash != right.content_hash
    sl = (first, second)
    proposal = m.prepare_native_batch_proposal(
        batch_id=uuid4(), gmail_inputs=args["gmail_inputs"], slack_inputs=sl,
    )
    before = {row.id: tuple(row) for row in db_session.execute(select(*Source.__table__.columns))}
    store.writes.clear()
    with pytest.raises(m.NativeBatchCaptureError, match="^native batch capture held$"):
        m.record_native_batch(db_session, **{
            **args, "slack_inputs": sl, "proposal_raw": proposal,
            "approved_proposal_hash": content_hash_of(proposal),
        })
    assert store.writes == []
    assert {row.id: tuple(row) for row in db_session.execute(select(*Source.__table__.columns))} == before


def test_actual_same_time_new_revision_is_permitted(db_session, tmp_path):
    store = ObservedStore(tmp_path / "same-time")
    original = capture_args(db_session, store, when=NOW)
    first = m.record_native_batch(db_session, **original)
    mail = original["gmail_inputs"][0]
    value = json.loads(mail.message_response)
    value["labelIds"] = ["STARRED"]
    changed = replace(mail, message_response=canonical_bytes(value))
    second_args = capture_args(db_session, store, mail=(changed,), when=NOW)
    second = m.record_native_batch(db_session, **second_args)
    old_ref = first.artifact_references[0][1]
    new_ref = second.artifact_references[0][1]
    assert old_ref.source_id != new_ref.source_id
    old_row = db_session.get(Source, old_ref.source_id)
    new_row = db_session.get(Source, new_ref.source_id)
    assert new_row.captured_at == old_row.captured_at == NOW
    assert new_row.supersedes_source_id == old_row.id
    assert get_current_source_revision(db_session, system=SourceSystem.EMAIL,
        external_ref=old_row.external_ref, trust_boundary=B.BRAINSTORM).id == new_row.id


def test_actual_two_gmail_messages_share_exact_profile_source(db_session, tmp_path):
    store = ObservedStore(tmp_path / "same-profile")
    initial = capture_args(db_session, store)
    mail = initial["gmail_inputs"][0]
    value = json.loads(mail.message_response)
    value["id"] = "m2"
    second = replace(mail, expected_message_id="m2", message_response=canonical_bytes(value))
    args = capture_args(db_session, store, mail=(mail, second))
    assert mail.profile_response == second.profile_response
    result = m.record_native_batch(db_session, **args)
    assert len(result.artifact_references) == 3
    assert result.artifact_references[0][0] == result.artifact_references[1][0]
    assert result.artifact_references[0][1] != result.artifact_references[1][1]
    profile = db_session.get(Source, result.artifact_references[0][0].source_id)
    assert profile.external_ref.startswith("gmail/account/")
    assert db_session.scalar(select(func.count()).select_from(Source).where(
        Source.system == SourceSystem.EMAIL, Source.external_ref == profile.external_ref)) == 1
