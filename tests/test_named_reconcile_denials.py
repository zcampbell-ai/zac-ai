"""Canonical codecs and real bounded selector; invented row/session/recovery seams.

These branch regressions prove no retry on incomplete/ambiguous canonical history,
not actual SQL isolation, independent recovery or a usable live owner session.
"""

from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_named_reconcile import fixture as reconcile_fixture
from zacai.interfaces import named_question_pipeline as m
from zacai.interfaces.named_decision_capture import _find_named
from zacai.interfaces.private_web import OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.interfaces.text_reply_capture import SavedHistoricalTextReply
from zacai.interfaces.text_reply_protection import BrainstormTextReplyProtection
from zacai.policy import TrustBoundary


@pytest.fixture
def fixture(monkeypatch):
    s = reconcile_fixture.__wrapped__(monkeypatch)
    s.named_queries = []
    s.forbidden_calls = []

    def forbidden(*args, **kwargs):
        s.forbidden_calls.append((args, kwargs))
        raise AssertionError("no generation/admission/claim/renewal in reconcile")

    s.pipeline._build = s.pipeline._active = s.pipeline._build_history = forbidden
    s.authority.record = s.authority.claim = forbidden

    def scalars(session, statement):
        # Execute the real loader's equality/limit contract over canonical memory
        # rows. Keys are independent of external_ref, permitting true ambiguity.
        sql = str(statement)
        assert "source.external_ref =" in sql and "LIMIT" in sql
        params = statement.compile().params
        reference = next(value for value in params.values() if type(value) is str)
        limit = next(value for value in params.values() if type(value) is int)
        assert limit == 2
        s.named_queries.append(reference)
        return iter(
            [r for r in s.sources.values() if r.external_ref == reference][:limit]
        )

    monkeypatch.setattr(s.client._factory, "scalars", scalars, raising=False)
    monkeypatch.setattr(m, "_find_named", _find_named)
    yield s
    assert s.forbidden_calls == []


def reconcile(s):
    return s.pipeline.reconcile(
        operation=s.operation, decision_reference=s.consent.decision_reference
    )


def selected_row(s, prefix):
    return next(
        row for row in s.sources.values() if row.external_ref.startswith(prefix)
    )


def test_actual_bounded_selector_positive_control(fixture):
    s = fixture
    result = reconcile(s)
    assert type(result) is SavedHistoricalTextReply and result.saved == s.saved_reply
    assert len(s.named_queries) == 3
    assert [key.split("/")[0] for key in s.named_queries] == [
        "packet-followup-consent",
        "packet-followup-claim",
        "text-reply",
    ]


@pytest.mark.parametrize(
    "prefix", ["packet-followup-consent/", "packet-followup-claim/", "text-reply/"]
)
def test_missing_canonical_attempt_component_holds_without_retry(fixture, prefix):
    s = fixture
    assert type(reconcile(s)) is SavedHistoricalTextReply
    row = selected_row(s, prefix)
    s.sources = {key: value for key, value in s.sources.items() if value.id != row.id}
    with pytest.raises(m.NamedQuestionPipelineError, match="no retry issued"):
        reconcile(s)
    assert row.external_ref in s.named_queries


@pytest.mark.parametrize(
    "prefix", ["packet-followup-consent/", "packet-followup-claim/", "text-reply/"]
)
def test_actual_selector_rejects_duplicate_external_ref_under_distinct_storage_keys(
    fixture, prefix
):
    s = fixture
    assert type(reconcile(s)) is SavedHistoricalTextReply
    row = selected_row(s, prefix)
    duplicate = SimpleNamespace(**vars(row))
    duplicate.id = uuid4()
    s.sources[f"invented-second-row/{duplicate.id}"] = duplicate
    assert (
        len([r for r in s.sources.values() if r.external_ref == row.external_ref]) == 2
    )
    with pytest.raises(m.NamedQuestionPipelineError, match="no retry issued"):
        reconcile(s)
    assert row.external_ref == s.named_queries[-1]


@pytest.mark.parametrize("response", [None, 1, "unknown", {}])
def test_unknown_receipt_visibility_holds_instead_of_becoming_missing_receipt_status(
    fixture, response
):
    s = fixture
    assert type(reconcile(s)) is SavedHistoricalTextReply
    s.receipt_present = response
    with pytest.raises(m.NamedQuestionPipelineError, match="no retry issued"):
        reconcile(s)


def test_owner_change_after_receipt_lookup_holds_final_historical_release(
    fixture, monkeypatch
):
    s = fixture
    assert type(reconcile(s)) is SavedHistoricalTextReply
    original = BrainstormTextReplyProtection._load_receipt
    reads = []

    def changed_owner(protection, key):
        receipt = original(protection, key)
        reads.append(key)
        s.owner = OwnerGrant(
            Identity(s.owner.identity.issuer, "invented-replacement-owner"),
            s.owner.scopes,
        )
        return receipt

    monkeypatch.setattr(BrainstormTextReplyProtection, "_load_receipt", changed_owner)
    with pytest.raises(m.NamedQuestionPipelineError, match="no retry issued"):
        reconcile(s)
    assert len(reads) == 1


def test_changed_question_boundary_denied_before_proof_callbacks(fixture, monkeypatch):
    s = fixture
    assert type(reconcile(s)) is SavedHistoricalTextReply
    original_inventory = m.load_named_consent_inventory
    original_inputs = s.pipeline._question_inputs
    callbacks = []

    def inventory(*args, **kwargs):
        result = original_inventory(*args, **kwargs)
        question = next(
            r
            for r in s.sources.values()
            if r.id == result.decision.question_reference.source_id
        )
        question.trust_boundary = TrustBoundary.PERSONAL
        return result

    def inputs(record):
        callbacks.append(record)
        return original_inputs(record)

    monkeypatch.setattr(m, "load_named_consent_inventory", inventory)
    s.pipeline._question_inputs = inputs
    with pytest.raises(m.NamedQuestionPipelineError):
        reconcile(s)
    assert callbacks == []
