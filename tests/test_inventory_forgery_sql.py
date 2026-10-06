"""Actual PostgreSQL retained inventory role binding, invented wire records."""

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_native_batch_writer_sql import NOW, ObservedStore, capture_args
from zacai.ingestion import native_batch_inventory as m
from zacai.ingestion import native_source_capture as writer


@pytest.mark.parametrize(
    "fault", ["batch_id", "swap_controls", "observed_later", "proposal_digest", "drop_group"]
)
def test_actual_retained_inventory_rejects_forged_metadata(db_session, tmp_path, fault):
    store = ObservedStore(tmp_path / "artifacts")
    args = capture_args(db_session, store)
    receipt = writer.record_native_batch(db_session, **args)
    good = m.load_native_batch_inventory(
        db_session,
        artifacts=store,
        batch_reference=receipt.batch_reference,
        approval_reference=receipt.approval_reference,
        approved_proposal_raw=args["proposal_raw"],
        as_of=NOW + timedelta(hours=2),
    )
    m.verify_native_batch_inventory_rows(
        db_session, artifacts=store, inventory=good, as_of=NOW + timedelta(hours=2)
    )
    if fault == "batch_id":
        bad = replace(good, batch_id=uuid4())
    elif fault == "swap_controls":
        bad = replace(
            good, batch_reference=good.approval_reference, approval_reference=good.batch_reference
        )
    elif fault == "observed_later":
        bad = replace(good, original_observed_at=NOW + timedelta(hours=1))
    elif fault == "proposal_digest":
        bad = replace(good, proposal_digest="0" * 64)
    else:
        dropped = {ref.source_id for ref in good.artifact_references[0]}
        kept = {ref.source_id for group in good.artifact_references[1:] for ref in group}
        removed = dropped - kept
        rows = list(
            db_session.execute(
                __import__("sqlalchemy").select(m.Source.id, m.Source.external_ref, m.Source.system)
            )
        )
        removed_provenance = {(r.external_ref, r.system) for r in rows if r.id in removed}
        bad = replace(
            good,
            artifact_references=good.artifact_references[1:],
            hashes=tuple(v for v in good.hashes if v[0] not in removed),
            source_fingerprints=tuple(v for v in good.source_fingerprints if v[0] not in removed),
            provenance=tuple(v for v in good.provenance if v not in removed_provenance),
        )
        assert len(bad.hashes) < len(good.hashes)
    assert bad != good
    with pytest.raises(m.NativeBatchInventoryError):
        m.verify_native_batch_inventory_rows(
            db_session, artifacts=store, inventory=bad, as_of=NOW + timedelta(hours=2)
        )


@pytest.mark.parametrize("field", ["external_ref", "system", "slack_to_email", "email_to_slack"])
def test_actual_admin_role_corruption_recomputed_metadata_still_holds(db_session, tmp_path, field):
    """Deliberate local zacai_test admin fault, not normal Source mutation."""
    from sqlalchemy import select, text, update
    from sqlalchemy.exc import DBAPIError

    from zacai.state import Source, SourceSystem

    store = ObservedStore(tmp_path / "role-artifacts")
    args = capture_args(db_session, store)
    receipt = writer.record_native_batch(db_session, **args)
    at = NOW + timedelta(hours=2)
    good = m.load_native_batch_inventory(
        db_session,
        artifacts=store,
        batch_reference=receipt.batch_reference,
        approval_reference=receipt.approval_reference,
        approved_proposal_raw=args["proposal_raw"],
        as_of=at,
    )
    m.verify_native_batch_inventory_rows(db_session, artifacts=store, inventory=good, as_of=at)
    target = (
        receipt.artifact_references[0][-1]
        if field == "email_to_slack"
        else receipt.artifact_references[-1][-1]
    ).source_id
    original = db_session.execute(
        select(Source.system, Source.external_ref, Source.content_hash).where(Source.id == target)
    ).one()
    expected_kind = SourceSystem.EMAIL if field == "email_to_slack" else SourceSystem.SLACK
    assert original.system is expected_kind
    assert original.external_ref.startswith(
        "gmail/" if expected_kind is SourceSystem.EMAIL else "slack/"
    )
    value = {
        "external_ref": "invented-native-admin-role-remap",
        "system": SourceSystem.MANUAL,
        "slack_to_email": SourceSystem.EMAIL,
        "email_to_slack": SourceSystem.SLACK,
    }[field]
    column = "external_ref" if field == "external_ref" else "system"
    milestones = ["genuine writer loader verifier positive"]
    # First prove actual append-only policy denies the exact ordinary operation.
    with pytest.raises(DBAPIError), db_session.begin_nested():
        db_session.execute(update(Source).where(Source.id == target).values(**{column: value}))
        db_session.flush()
    assert db_session.scalar(select(getattr(Source, column)).where(Source.id == target)) == getattr(
        original, column
    )
    assert not db_session.new and not db_session.dirty and not db_session.deleted
    milestones.append("ordinary mutation denied and rolled back")
    try:
        # Exact local test DB/role guard before any trigger DDL. This fixture
        # intentionally requires the reviewed local owner role, no generic admin.
        assert db_session.scalar(text("SELECT current_database()")) == "zacai_test"
        assert db_session.scalar(text("SELECT current_user")) == "brainstormzac"
        assert db_session.scalar(text("SELECT session_user")) == "brainstormzac"
        assert (
            db_session.scalar(
                text(
                    "SELECT tableowner FROM pg_tables WHERE schemaname=current_schema() AND tablename='source'"
                )
            )
            == "brainstormzac"
        )
        db_session.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
        assert (
            db_session.scalar(
                text(
                    "SELECT tgenabled FROM pg_trigger WHERE tgrelid='source'::regclass AND tgname='source_forbid_mutation'"
                )
            )
            == "O"
        )
        db_session.execute(text("ALTER TABLE source DISABLE TRIGGER source_forbid_mutation"))
        try:
            changed = db_session.execute(
                update(Source)
                .where(Source.id == target)
                .values(**{column: value})
                .execution_options(synchronize_session=False)
            )
            assert changed.rowcount == 1
            milestones.append("exact invented row corrupted")
        finally:
            db_session.execute(text("ALTER TABLE source ENABLE TRIGGER source_forbid_mutation"))
            db_session.execute(text("SET CONSTRAINTS ALL DEFERRED"))
        assert (
            db_session.scalar(
                text(
                    "SELECT tgenabled FROM pg_trigger WHERE tgrelid='source'::regclass AND tgname='source_forbid_mutation'"
                )
            )
            == "O"
        )
        assert (
            db_session.scalar(select(getattr(Source, column)).where(Source.id == target)) == value
        )
        milestones.append("trigger restored and corruption observed")
        rows = [
            dict(row)
            for row in db_session.execute(
                select(*Source.__table__.columns, m._effective()).where(
                    Source.id.in_(dict(good.hashes))
                )
            ).mappings()
        ]
        bad = replace(
            good,
            source_fingerprints=tuple(
                sorted(((r["id"], m._fingerprint(r)) for r in rows), key=lambda p: str(p[0]))
            ),
            provenance=tuple(sorted({r["external_ref"]: r["system"] for r in rows}.items())),
        )
        assert bad != good and bad.hashes == good.hashes
        milestones.append("adversarial current metadata recomputed")
        with pytest.raises(m.NativeBatchInventoryError):
            m.verify_native_batch_inventory_rows(
                db_session, artifacts=store, inventory=bad, as_of=at
            )
        assert milestones == [
            "genuine writer loader verifier positive",
            "ordinary mutation denied and rolled back",
            "exact invented row corrupted",
            "trigger restored and corruption observed",
            "adversarial current metadata recomputed",
        ]
    finally:
        # Caller rollback restores test-only admin transaction including all
        # invented Sources, never leaves a policy change or mutated row behind.
        db_session.rollback()
        assert (
            db_session.scalar(
                text(
                    "SELECT tgenabled FROM pg_trigger WHERE tgrelid='source'::regclass AND tgname='source_forbid_mutation'"
                )
            )
            == "O"
        )
        assert db_session.scalar(select(Source.id).where(Source.id == target)) is None
        assert db_session.scalar(select(1)) == 1
