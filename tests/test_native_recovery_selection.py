"""Real filesystem/parser + invented SQLite rows; no crypto/PG/authority proof."""

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select, update

from tests.test_native_batch_inventory import NOW, put_source, ref
from tests.test_native_batch_inventory import (
    saved as saved,  # noqa: PLC0414 - pytest fixture re-export
)
from zacai.ingestion import native_batch_inventory as m
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceClassificationElevation, SourceSystem


@pytest.fixture
def complete(saved):
    sql, args, _, _, _ = saved
    native = m.load_native_batch_inventory(sql, **args)
    proposal = put_source(
        sql,
        args["artifacts"],
        SourceSystem.MANUAL,
        f"native-source-proposal/{native.batch_id}",
        args["approved_proposal_raw"],
        at=NOW + timedelta(milliseconds=500),
    )
    sql.commit()
    options = {
        "artifacts": args["artifacts"],
        "inventory": native,
        "proposal_reference": ref(proposal),
        "approved_proposal_raw": args["approved_proposal_raw"],
        "as_of": args["as_of"],
    }
    yield sql, options, proposal


def test_complete_selection_preserves_original_and_later_proposal_date(complete):
    sql, args, proposal = complete
    before = list(sql.execute(select(*Source.__table__.columns)))
    selection = m.prepare_native_batch_recovery_selection(sql, **args)
    assert len(selection.hashes) == 9 and len(selection.source_fingerprints) == 9
    assert dict(selection.hashes) == dict(args["inventory"].hashes) | {
        proposal.id: proposal.content_hash
    }
    assert selection.inventory is args["inventory"]
    assert selection.inventory.original_observed_at == NOW
    assert selection.proposal_reference == ref(proposal)
    assert not any(
        (
            selection.recovery_verified,
            selection.processing_authorized,
            selection.facts_confirmed,
            selection.complete_history_verified,
        )
    )
    assert list(sql.execute(select(*Source.__table__.columns))) == before
    assert "Invented" not in repr(selection)


@pytest.mark.parametrize(
    "fault", ["wrong_hash", "wrong_batch", "same_control", "wrong_bytes", "omitted_inventory"]
)
def test_binding_denials_after_positive(complete, fault):
    sql, args, _proposal = complete
    m.prepare_native_batch_recovery_selection(sql, **args)
    if fault == "wrong_hash":
        args["proposal_reference"] = args["proposal_reference"].model_copy(
            update={"content_hash": "0" * 64}
        )
    elif fault == "wrong_batch":
        args["inventory"] = replace(args["inventory"], batch_id=uuid4())
    elif fault == "same_control":
        args["proposal_reference"] = args["inventory"].batch_reference
    elif fault == "wrong_bytes":
        args["approved_proposal_raw"] = b"other invented original"
    else:
        args["inventory"] = replace(args["inventory"], hashes=args["inventory"].hashes[:-1])
    with pytest.raises(m.NativeBatchInventoryError):
        m.prepare_native_batch_recovery_selection(sql, **args)


def test_proposal_effective_denial_before_private_store_get(complete):
    sql, args, proposal = complete
    m.prepare_native_batch_recovery_selection(sql, **args)
    sql.add(
        SourceClassificationElevation(
            id=uuid4(),
            source_id=proposal.id,
            trust_boundary=B.BRAINSTORM,
            previous_classification=C.CONFIDENTIAL,
            reason="Invented restriction",
            elevated_by="invented",
            new_classification=C.HIGHLY_RESTRICTED,
            elevated_at=NOW,
        )
    )
    sql.commit()
    original = args["artifacts"].get
    calls = []

    def spy(*a):
        calls.append(a)
        return original(*a)

    args["artifacts"].get = spy
    with pytest.raises(m.NativeBatchInventoryError):
        m.prepare_native_batch_recovery_selection(sql, **args)
    assert calls == []


@pytest.mark.parametrize("fault", ["proposal_excerpt", "provider_excerpt", "proposal_effective"])
def test_last_native_read_mutation_caught_by_complete_final_snapshot(complete, fault):
    sql, args, proposal = complete
    m.prepare_native_batch_recovery_selection(sql, **args)
    original = args["artifacts"].get
    batch = sql.get(Source, args["inventory"].batch_reference.source_id)
    provider = args["inventory"].artifact_references[0][0].source_id
    fired = []

    def change(boundary, location):
        raw = original(boundary, location)
        if location == batch.content_location and not fired:
            if fault == "proposal_effective":
                sql.add(
                    SourceClassificationElevation(
                        id=uuid4(),
                        source_id=proposal.id,
                        trust_boundary=B.BRAINSTORM,
                        previous_classification=C.CONFIDENTIAL,
                        reason="Invented restriction",
                        elevated_by="invented",
                        new_classification=C.HIGHLY_RESTRICTED,
                        elevated_at=NOW,
                    )
                )
                sql.flush()
            else:
                sid = proposal.id if fault == "proposal_excerpt" else provider
                sql.execute(
                    update(Source).where(Source.id == sid).values(excerpt="invented corruption"),
                    execution_options={"synchronize_session": False},
                )
            fired.append(True)
        return raw

    args["artifacts"].get = change
    with pytest.raises(m.NativeBatchInventoryError):
        m.prepare_native_batch_recovery_selection(sql, **args)
    assert fired == [True]


@pytest.mark.parametrize("fault", ["future", "wrong_domain", "ambiguous"])
def test_exact_proposal_source_identity_controls(complete, fault):
    sql, args, proposal = complete
    m.prepare_native_batch_recovery_selection(sql, **args)
    if fault == "future":
        sql.execute(
            update(Source)
            .where(Source.id == proposal.id)
            .values(captured_at=args["as_of"] + timedelta(seconds=1))
        )
    elif fault == "wrong_domain":
        sql.execute(
            update(Source)
            .where(Source.id == proposal.id)
            .values(external_ref="different-proposal/" + str(uuid4()))
        )
    else:
        put_source(
            sql,
            args["artifacts"],
            SourceSystem.MANUAL,
            proposal.external_ref,
            b"other invented proposal revision",
        )
    sql.commit()
    with pytest.raises(m.NativeBatchInventoryError):
        m.prepare_native_batch_recovery_selection(sql, **args)


def test_private_store_interruption_propagates_no_ack(complete):
    sql, args, _proposal = complete
    m.prepare_native_batch_recovery_selection(sql, **args)
    fired = []

    def interrupt(*_args):
        fired.append(True)
        raise KeyboardInterrupt

    args["artifacts"].get = interrupt
    with pytest.raises(KeyboardInterrupt):
        m.prepare_native_batch_recovery_selection(sql, **args)
    assert fired == [True]
