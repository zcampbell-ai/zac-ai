"""Invented canonical rows; statement shape observed, no PostgreSQL execution."""

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

from zacai.intelligence.contracts import EvidenceReference
from zacai.interfaces import reply_final_snapshot as m
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem


@pytest.fixture
def fixture(monkeypatch):
    rows = [
        Source(
            id=uuid4(),
            system=SourceSystem.MANUAL,
            external_ref=f"invented/{i}",
            content_hash=str(i) * 64,
            content_location=f"invented/{i}",
            captured_at=datetime(2026, 10, 5, tzinfo=UTC),
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
        )
        for i in range(3)
    ]
    refs = tuple(
        EvidenceReference(
            source_id=r.id,
            content_hash=r.content_hash,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.CONFIDENTIAL,
        )
        for r in rows
    )
    state = SimpleNamespace(rows=rows, refs=refs, before_query=None, queries=0)
    monkeypatch.setattr(m, "_assert_ledger_isolation", lambda session: None)

    class Session:
        def get(self, model, source_id):
            return next((r for r in rows if r.id == source_id), None)

        def execute(self, statement):
            state.queries += 1
            sql = str(statement)
            assert "coalesce" in sql and "source_classification_elevation" in sql
            assert "elevated_at DESC" in sql
            if state.before_query:
                state.before_query()
            return SimpleNamespace(
                all=lambda: [
                    (
                        r.id,
                        r.system,
                        r.external_ref,
                        r.content_hash,
                        r.content_location,
                        r.captured_at,
                        r.trust_boundary,
                        r.data_classification,
                        getattr(r, "effective", r.data_classification),
                    )
                    for r in rows
                ]
            )

    state.session = Session()
    state.check = lambda active: m.verify_reply_final_snapshot(
        state.session, references=refs, consent_source_id=rows[0].id, active=active
    )
    return state


def test_current_reply_inventory_checked_in_one_combined_query(fixture):
    assert fixture.check(True) is False
    assert fixture.queries == 1


@pytest.mark.parametrize("mutation", ["elevation", "missing", "hash", "boundary", "rawclass"])
def test_mutation_after_prior_row_reads_holds_final_release(fixture, mutation):
    s = fixture

    def mutate():
        row = s.rows[-1]
        if mutation == "elevation":
            row.effective = C.HIGHLY_RESTRICTED
        elif mutation == "missing":
            s.rows.pop()
        elif mutation == "hash":
            row.content_hash = "f" * 64
        elif mutation == "boundary":
            row.trust_boundary = B.PERSONAL
        else:
            row.data_classification = C.HIGHLY_RESTRICTED

    s.before_query = mutate
    with pytest.raises(ValueError):
        s.check(True)
    assert s.queries == 1


@pytest.mark.parametrize("active", [False, True])
def test_same_snapshot_cancellation_labels_history_and_holds_active(fixture, active):
    s = fixture

    def cancel():
        r = s.rows[0]
        s.rows.append(
            Source(
                id=uuid4(),
                system=SourceSystem.USER_INSTRUCTION,
                external_ref=f"packet-followup-revocation/{r.id}",
                content_hash="a" * 64,
                content_location="invented/cancel",
                captured_at=r.captured_at,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.CONFIDENTIAL,
            )
        )

    s.before_query = cancel
    if active:
        with pytest.raises(ValueError):
            s.check(True)
    else:
        assert s.check(False) is True
    assert s.queries == 1


def test_conflicting_reference_hash_cannot_be_hidden(fixture):
    s = fixture
    with pytest.raises(ValueError):
        m.verify_reply_final_snapshot(
            s.session,
            references=(*s.refs, s.refs[0].model_copy(update={"content_hash": "f" * 64})),
            consent_source_id=s.rows[0].id,
            active=True,
        )
    assert s.queries == 0
