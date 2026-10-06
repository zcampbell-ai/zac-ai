"""Root-only guarded zacai_test, actual committed/reopened native evidence.

Invented Gmail/Slack/instruction bytes. No account, model, encrypted recovery or
human authentication claim. One explicit admin-corruption fixture only touches
its own committed Source; normal application mutation is denied by the trigger.
"""

import json
from datetime import timedelta
from uuid import UUID

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.exc import DBAPIError

from tests.test_native_batch_writer_sql import NOW, ObservedStore, capture_args
from zacai.ingestion import native_batch_inventory as inventory
from zacai.ingestion import native_proposal_retention as proposal
from zacai.ingestion import native_source_capture as writer
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source
from zacai.state_repository import elevate_source_classification


@pytest.fixture(scope="session")
def committed_store(tmp_path_factory):
    # Same lifetime as independently committed shared Source rows.
    return ObservedStore(tmp_path_factory.mktemp("native-proposal-private-artifacts"))


def committed(factory, store):
    with factory() as sql:
        args = capture_args(sql, store)
        bid = UUID(json.loads(args["proposal_raw"])["batch_id"])
        pref = proposal.retain_native_proposal(
            sql,
            artifacts=store,
            batch_id=bid,
            proposal_raw=args["proposal_raw"],
            expected_proposal_hash=args["approved_proposal_hash"],
            gmail_inputs=args["gmail_inputs"],
            slack_inputs=args["slack_inputs"],
            retained_at=NOW,
        )
        batch = writer.record_native_batch(sql, **args)
        sql.commit()
        ids = {pref.source_id, batch.batch_reference.source_id, batch.approval_reference.source_id}
        ids.update(ref.source_id for group in batch.artifact_references for ref in group)
        original = list(
            sql.execute(
                select(*Source.__table__.columns).where(Source.id.in_(ids)).order_by(Source.id)
            )
        )
        assert len(original) == 9
    # All independently held raw proposal/provider tuples are discarded here.
    return store, bid, pref, batch.batch_reference, batch.approval_reference, original


def read(sql, store, bid, pref):
    return proposal.load_retained_native_proposal(
        sql,
        artifacts=store,
        proposal_reference=pref,
        batch_id=bid,
        expected_proposal_hash=pref.content_hash,
        as_of=NOW + timedelta(minutes=5),
    )


def test_actual_commit_close_reopen_read_then_loader_and_original_replay(
    test_session_factory, committed_store
):
    store, bid, pref, batch_ref, approval_ref, original = committed(
        test_session_factory, committed_store
    )
    with test_session_factory() as sql:
        raw = read(sql, store, bid, pref)
        selected = inventory.load_native_batch_inventory(
            sql,
            artifacts=store,
            batch_reference=batch_ref,
            approval_reference=approval_ref,
            approved_proposal_raw=raw,
            as_of=NOW + timedelta(minutes=5),
        )
        assert len(selected.hashes) == 8 and pref.source_id not in dict(selected.hashes)
        assert selected.original_observed_at == NOW and not selected.recovery_verified
        assert not selected.processing_authorized
        # Inventory publicly reconstructs input evidence; test regenerates only
        # the known invented fixture tuples AFTER successful restart read.
        from tests.test_native_source_preparation import gmail_inputs, slack_inputs

        g, _ = gmail_inputs()
        s = slack_inputs()
        replay = proposal.retain_native_proposal(
            sql,
            artifacts=store,
            batch_id=bid,
            proposal_raw=raw,
            expected_proposal_hash=pref.content_hash,
            gmail_inputs=(
                writer.GmailCaptureInput(
                    g["scope"],
                    g["profile_response"],
                    g["message_response"],
                    g["expected_message_id"],
                ),
            ),
            slack_inputs=(
                writer.SlackCaptureInput(s["selection"], s["account_response"], s["page_response"]),
            ),
            retained_at=NOW + timedelta(minutes=4),
        )
        assert replay == pref
        ids = [row.id for row in original]
        assert original == list(
            sql.execute(
                select(*Source.__table__.columns).where(Source.id.in_(ids)).order_by(Source.id)
            )
        )
        assert sql.get(Source, pref.source_id).captured_at == NOW


def test_actual_effective_elevation_before_private_body_denial(
    test_session_factory, committed_store
):
    store, bid, pref, _, _, _ = committed(test_session_factory, committed_store)
    with test_session_factory() as sql:
        assert read(sql, store, bid, pref)
        elevate_source_classification(
            sql,
            source_id=pref.source_id,
            trust_boundary=B.BRAINSTORM,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="Invented owner restriction",
            elevated_by="invented-owner",
        )
        sql.commit()
    calls = []

    class NoPrivateRead:
        def get(self, *args):
            calls.append(True)
            return store.get(*args)

    with test_session_factory() as sql, pytest.raises(proposal.NativeProposalRetentionError):
        read(sql, NoPrivateRead(), bid, pref)
    assert calls == []


@pytest.mark.parametrize("fault", ["column", "effective"])
def test_actual_last_read_mutation_holds_with_positive_and_fired_controls(
    test_session_factory, committed_store, fault, monkeypatch
):
    store, bid, pref, _, _, _ = committed(test_session_factory, committed_store)
    milestones = []
    finals = []
    original_final = proposal._final

    def final(*args, **kwargs):
        finals.append("entered")
        actual = proposal._rows(args[0], args[1])
        assert len(actual) == 1
        changed = {key for key, value in args[2].items() if actual[0][key] != value}
        assert changed == ({"excerpt"} if fault == "column" else {"effective"})
        try:
            return original_final(*args, **kwargs)
        except ValueError as error:
            assert error.args == ("final source observation changed",)
            finals.append("held")
            raise

    with test_session_factory() as sql:
        assert read(sql, store, bid, pref)
        original = sql.get(Source, pref.source_id)
        assert original.external_ref == "native-source-proposal/" + str(bid)
        original_excerpt = original.excerpt
        sql.rollback()
        monkeypatch.setattr(proposal, "_final", final)
        if fault == "column":
            # Ordinary ORM/SQL mutation really is refused before admin test.
            with pytest.raises(DBAPIError):
                sql.execute(
                    update(Source)
                    .where(Source.id == pref.source_id)
                    .values(excerpt="Invented ordinary mutation")
                )
                sql.flush()
            sql.rollback()

        class LastRead:
            def get(self, boundary, location):
                raw = store.get(boundary, location)
                milestones.append("read-original")
                if fault == "effective":
                    elevate_source_classification(
                        sql,
                        source_id=pref.source_id,
                        trust_boundary=B.BRAINSTORM,
                        new_classification=C.HIGHLY_RESTRICTED,
                        reason="Invented final access change",
                        elevated_by="invented-owner",
                    )
                    assert not sql.new and not sql.dirty and not sql.deleted
                    milestones.append("elevation-applied")
                else:
                    assert sql.scalar(text("SELECT current_database()")) == "zacai_test"
                    selected = sql.get(Source, pref.source_id)
                    assert (
                        selected.id == pref.source_id
                        and selected.external_ref == "native-source-proposal/" + str(bid)
                    )
                    sql.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
                    sql.execute(text("ALTER TABLE source DISABLE TRIGGER source_forbid_mutation"))
                    try:
                        sql.execute(
                            update(Source)
                            .where(Source.id == pref.source_id)
                            .values(excerpt="Invented admin-corruption observation")
                            .execution_options(synchronize_session=False)
                        )
                        milestones.append("column-applied")
                    finally:
                        sql.execute(
                            text("ALTER TABLE source ENABLE TRIGGER source_forbid_mutation")
                        )
                    assert (
                        sql.scalar(
                            text(
                                "SELECT tgenabled FROM pg_trigger WHERE tgrelid='source'::regclass AND tgname='source_forbid_mutation'"
                            )
                        )
                        == "O"
                    )
                    milestones.append("trigger-restored")
                return raw

        try:
            with pytest.raises(proposal.NativeProposalRetentionError):
                read(sql, LastRead(), bid, pref)
            # Assert callbacks reached the genuine mutation, outside catches.
            expected = (
                ["read-original", "elevation-applied"]
                if fault == "effective"
                else ["read-original", "column-applied", "trigger-restored"]
            )
            assert milestones == expected
            assert finals == ["entered", "held"]
            if fault == "column":
                assert (
                    sql.scalar(select(Source.excerpt).where(Source.id == pref.source_id))
                    == "Invented admin-corruption observation"
                )
        finally:
            sql.rollback()  # Restores only this invented row/elevation transaction.
        assert (
            sql.scalar(select(Source.excerpt).where(Source.id == pref.source_id))
            == original_excerpt
        )
