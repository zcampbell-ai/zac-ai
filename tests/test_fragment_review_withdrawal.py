"""Actual codecs/files, simulated canonical SQL snapshots; no cancellation intent."""

from uuid import uuid4

import pytest

from tests.test_fragment_review_retention import (
    authority as authority,  # noqa: PLC0414
)
from tests.test_fragment_review_retention import (
    case as case,  # noqa: PLC0414
)
from tests.test_fragment_review_retention import (
    consent_case as consent_case,  # noqa: PLC0414
)
from tests.test_fragment_review_retention import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_fragment_review_retention import (
    packet_case as packet_case,  # noqa: PLC0414
)
from tests.test_fragment_review_retention import (
    retained as retained,  # noqa: PLC0414
)
from zacai.intelligence import fragment_review_retention as retention
from zacai.intelligence import fragment_review_withdrawal as m
from zacai.policy import DataClassification as C


@pytest.fixture
def historical(retained, monkeypatch):
    f = retained
    seen = []

    def rows(session, refs, *scope):
        seen.append(refs)
        result = []
        for ref in refs:
            selected = [row for row in f.current["rows"] if row["id"] == ref.source_id]
            if not selected or any(row["content_hash"] != ref.content_hash for row in selected):
                raise ValueError("missing current selected Source")
            if any(
                row.get("effective", C.HIGHLY_RESTRICTED) != ref.effective_classification
                for row in selected
            ):
                raise ValueError("current label differs")
            result.extend(selected)
        return tuple(tuple(row.items()) for row in result)

    monkeypatch.setattr(m, "_fragment_rows", rows)
    monkeypatch.setattr(m, "_physical", retention._physical)
    f.seen = seen
    return f


def load(f, **kw):
    args = {"artifacts": f.store, "reference": f.own, "expected_declaration": f.declaration}
    args.update(kw)
    return m.load_historical_fragment_declaration_target(f.session, **args)


def test_stale_inputs_hold_current_loader_but_historical_target_remains_exact(historical):
    f = historical
    f.current["rows"] = f.current["rows"][-1:]
    with pytest.raises(retention.FragmentDeclarationRetentionError):
        retention.load_fragment_review_declaration(
            f.session, artifacts=f.store, reference=f.own, expected_declaration=f.declaration
        )
    assert not f.events
    got = load(f)
    assert got.reference == f.own and got.generation == f.g and got.request == f.q
    assert got.declaration == f.declaration and got.captured_at == f.g.approved_at
    assert got.declaration.expires_at == f.g.expires_at
    assert got.cancel_authorized is got.processing_authorized is got.owner_authenticated is False
    assert f.seen == [(f.own,), (f.own,)]
    assert f.events == ["body"]
    assert not hasattr(got, "human_action") and "invented-owner" not in repr(got)


@pytest.mark.parametrize("fault", ["hash", "effective", "namespace", "system", "prefix", "date"])
def test_own_source_faults_hold_before_body(historical, fault):
    f = historical
    row = f.current["rows"][-1]
    if fault == "hash":
        row["content_hash"] = "0" * 64
    elif fault == "effective":
        row["effective"] = C.CONFIDENTIAL
    elif fault == "namespace":
        row["external_ref"] += "/wrong"
    elif fault == "system":
        row["system"] = None
    elif fault == "prefix":
        f.current["ids"] = (f.own.source_id, uuid4())
    else:
        row["captured_at"] = f.g.expires_at
    with pytest.raises(m.FragmentWithdrawalTargetError) as error:
        load(f)
    assert error.value.__cause__ is error.value.__context__ is None
    assert not f.events


@pytest.mark.parametrize("fault", ["bytes", "metadata", "effective", "prefix", "transaction"])
def test_callback_drift_holds_after_real_bounded_read(historical, monkeypatch, fault):
    f = historical
    get = f.store.get_bounded
    milestone = []

    def callback(*a, **kw):
        raw = get(*a, **kw)
        milestone.append(True)
        if fault == "bytes":
            return raw + b" "
        if fault == "metadata":
            f.current["rows"][-1]["captured_at"] = f.g.expires_at
        elif fault == "effective":
            f.current["rows"][-1]["effective"] = C.CONFIDENTIAL
        elif fault == "prefix":
            f.current["ids"] = (f.own.source_id, uuid4())
        else:
            f.session.rollback()
            f.session.begin()
        return raw

    monkeypatch.setattr(f.store, "get_bounded", callback)
    with pytest.raises(m.FragmentWithdrawalTargetError):
        load(f)
    assert milestone == [True] and f.events == ["body"]


@pytest.mark.parametrize("fault", ["lineage", "reference-type"])
def test_exact_own_lineage_and_reference_type_hold_before_body(historical, fault):
    f = historical
    kw = {}
    if fault == "lineage":
        f.current["rows"][-1]["lineage_id"] = uuid4()
    else:
        kw["reference"] = f.own.model_dump(mode="json")
    with pytest.raises(m.FragmentWithdrawalTargetError):
        load(f, **kw)
    assert not f.events
