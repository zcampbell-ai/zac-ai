"""Invented Source/SQL seams; real canonical decoders, no recovery/auth claim."""
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_named_followup_decision import fixture as declared_fixture
from zacai import review_authorization
from zacai.ingestion.artifact_store import content_hash_of
from zacai.interfaces import named_decision_inventory as module
from zacai.interfaces.named_followup_decision import encode_named_decision
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem


@pytest.fixture
def fixture(monkeypatch):
    s = declared_fixture.__wrapped__(monkeypatch)
    raw = encode_named_decision(s.decision)
    ref = s.decision.question_reference.model_copy(update={
        "source_id": uuid4(), "content_hash": content_hash_of(raw),
    })
    row = Source(
        id=ref.source_id, system=SourceSystem.USER_INSTRUCTION,
        trust_boundary=B.BRAINSTORM, data_classification=C.CONFIDENTIAL,
        content_hash=ref.content_hash, content_location=ref.content_hash,
        external_ref=f"packet-followup-named-decision/{s.manifest.request_id}",
        captured_at=s.decision.admitted_at,
    )
    s.sources[row.external_ref], s.raw[ref.content_hash] = row, raw
    s.ref, s.row = ref, row
    s.labels = {}

    def label(session, *, source_id):
        return s.labels.get(source_id, session.get(Source, source_id).data_classification)

    monkeypatch.setattr(module, "get_effective_source_classification", label)
    monkeypatch.setattr(review_authorization, "get_effective_source_classification", label)
    return s


def load(s, **changes):
    with s.client._factory() as session:
        return module.load_named_decision_inventory(
            session, artifacts=s.client._artifacts,
            reference=changes.get("reference", s.ref),
            as_of=changes.get("as_of", s.decision.bound_at),
        )


def test_actual_envelopes_and_exact_direct_inventory_without_permission(fixture):
    s = fixture
    found = load(s)
    assert found.decision == s.decision
    assert dict(found.hashes) == {
        ref.source_id: ref.content_hash for ref in (
            s.ref, s.decision.question_reference, *s.decision.run_scope.parent_references,
            s.manifest.packet_reference, *s.manifest.evidence_references,
        )
    }
    assert not found.decision.processing_authorized
    assert not found.decision.execution_authorized
    assert s.turn.original_text not in repr(found)


@pytest.mark.parametrize("field,value", [
    ("system", SourceSystem.MANUAL), ("external_ref", "text-turn/forged"),
    ("trust_boundary", B.PERSONAL), ("data_classification", C.PUBLIC),
    ("content_hash", "f" * 64),
])
def test_decision_source_substitution_denied(fixture, field, value):
    setattr(fixture.row, field, value)
    with pytest.raises(module.NamedDecisionInventoryError, match="canonical named decision"):
        load(fixture)


def test_canonical_artifact_corruption_and_acl_denied(fixture):
    s = fixture
    original = s.raw[s.ref.content_hash]
    s.raw[s.ref.content_hash] = original + b" "
    with pytest.raises(module.NamedDecisionInventoryError):
        load(s)
    s.raw[s.ref.content_hash] = original
    s.labels[s.ref.source_id] = C.HIGHLY_RESTRICTED
    with pytest.raises(module.NamedDecisionInventoryError):
        load(s)


@pytest.mark.parametrize("which", ["question", "packet", "evidence"])
def test_missing_or_changed_actual_dependency_denied(fixture, which):
    s = fixture
    ref = {"question": s.decision.question_reference, "packet": s.manifest.packet_reference,
           "evidence": s.manifest.evidence_references[0]}[which]
    row = next(row for row in s.sources.values() if row.id == ref.source_id)
    s.labels[row.id] = C.HIGHLY_RESTRICTED
    with pytest.raises(module.NamedDecisionInventoryError):
        load(s)
    s.labels.clear()
    del s.sources[row.external_ref]
    with pytest.raises(module.NamedDecisionInventoryError):
        load(s)


def test_observation_and_admission_provenance_hold_but_expired_history_can_inventory(fixture):
    s = fixture
    with pytest.raises(module.NamedDecisionInventoryError):
        load(s, as_of=s.decision.bound_at - timedelta(microseconds=1))
    assert load(s, as_of=s.decision.processing_expires_at + timedelta(days=1)).decision == s.decision
    s.row.captured_at += timedelta(microseconds=1)
    with pytest.raises(module.NamedDecisionInventoryError):
        load(s)


def test_question_kind_and_original_bytes_cannot_impersonate_named_action(fixture):
    s = fixture
    row = next(row for row in s.sources.values() if row.id == s.decision.question_reference.source_id)
    row.system = SourceSystem.MANUAL
    with pytest.raises(module.NamedDecisionInventoryError):
        load(s)
    with pytest.raises(module.NamedDecisionInventoryError):
        load(s, reference=s.decision.question_reference)
