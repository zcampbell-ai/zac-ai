"""Invented branch evidence only; signed owner real, SQL/recovery/HTTP simulated."""
# ruff: noqa: F401,F811
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from tests.test_history_publication_review import (
    RUBRIC,
    TEMPLATE,
    action_case,
    base_factory_case,
    canonical_case,
    case,
    declaration_case,
    dispatch_case,
    factory_case,
    host,
    installed,
    loader_case,
    observed_case,
    post_case,
    producer_case,
    released_case,
    review_case,
    review_inputs,
    setup,
)
from zacai.contextual_protection import PersonalFragmentCleanupUncertain
from zacai.intelligence import history_publication_review as review
from zacai.intelligence import history_review_runtime as runtime
from zacai.intelligence.review_evaluation import ReviewJudgment
from zacai.state import SourceSystem

PRIVATE = "invented-private-path-and-history-sentinel"


def fault(kind):
    return {"ordinary": ValueError(PRIVATE), "cleanup": PersonalFragmentCleanupUncertain(PRIVATE),
            "interrupt": KeyboardInterrupt(PRIVATE), "exit": SystemExit(PRIVATE)}[kind]


def expected(kind):
    return {"ordinary": review.HistoryPublicationReviewError,
            "cleanup": PersonalFragmentCleanupUncertain,
            "interrupt": KeyboardInterrupt, "exit": SystemExit}[kind]


@pytest.mark.parametrize("kind", ["ordinary", "cleanup", "interrupt", "exit"])
def test_constructor_configuration_errors_are_safe_and_parent_stays_consumed(review_inputs, monkeypatch, kind):
    c = review_inputs
    calls = []
    def broken():
        calls.append(True)
        raise fault(kind)
    monkeypatch.setattr(c.runtime, "configuration", broken)
    # Inspect state of the actual constructor on the exact real class, not an issuer substitute.
    gate = review.CanonicalPersonalHistoryReviewAuthorization.__new__(review.CanonicalPersonalHistoryReviewAuthorization)
    with pytest.raises(expected(kind)) as caught:
        gate.__init__(generation_authorization=c.p.gate, output=c.output, runtime=c.runtime,
                      rubric_utf8=RUBRIC, template_utf8=TEMPLATE)
    assert calls == [True]
    assert gate._phase == "HELD" and c.p.gate._phase == "REVIEW_ENTERED"
    assert PRIVATE not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert c.state.posts == [] and len(c.p.state.commits) == 3


@pytest.mark.parametrize("kind", ["ordinary", "cleanup", "interrupt", "exit"])
def test_invocation_fault_is_safe_permanently_used_and_withheld(review_case, monkeypatch, kind):
    c = review_case
    calls = []
    def broken(gate):
        assert gate is c.gate
        calls.append(True)
        raise fault(kind)
    monkeypatch.setattr(c.runtime, "invoke", broken)
    with pytest.raises(expected(kind)) as caught:
        c.gate.invoke()
    assert calls == [True] and c.gate._invoked and c.gate._phase == "HELD"
    assert PRIVATE not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    with pytest.raises(review.HistoryPublicationReviewError):
        c.gate.invoke()
    assert calls == [True] and c.state.posts == []


@pytest.mark.parametrize("name", ["fragment_review_runtime.py", "review_evaluation.py", "artifact_store.py"])
def test_actual_dependency_byte_drift_holds_before_post(review_case, monkeypatch, name):
    c = review_case
    read = Path.read_bytes
    hits = []
    def changed(path):
        raw = read(path)
        if path.name == name:
            hits.append(str(path))
            return raw + b"\n# invented dependency drift\n"
        return raw
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(review.HistoryPublicationReviewError):
        c.gate.invoke()
    assert hits and c.state.posts == [] and c.gate._phase == "HELD"
    assert len(c.p.state.commits) == 3


@pytest.mark.parametrize("kind", ["owner", "wall", "cancellation", "native", "inventory"])
def test_retained_pass_final_current_release_withholds_on_drift(review_case, monkeypatch, kind):
    c = review_case
    c.state.judgment = ReviewJudgment.PASS
    observed = c.gate.invoke()
    retained = review.capture_history_publication_assessment(c.gate, observed=observed)
    assert retained.ready_to_deliver and c.gate._phase == "ASSESSMENT_RETAINED"
    assert len(c.state.posts) == 1 and len(c.p.state.commits) == 5
    if kind == "owner":
        c.p.f.s.inputs.owners.revoke()
    elif kind == "wall":
        monkeypatch.setattr(c.p.f.s.inputs.clock, "_read", lambda: c.p.s.g.expires_at)
    elif kind == "cancellation":
        c.p.s.c.cancelled = True
    elif kind == "native":
        monkeypatch.setattr(review, "_NATIVE_MONOTONIC", lambda: c.gate._deadline)
    else:
        rows = c.p.s.c.a.s.rows
        sid = uuid4()
        row = dict(next(iter(rows.values())))
        row.update(id=sid, lineage_id=sid, supersedes_source_id=None,
                   external_ref="unrelated-invented-personal-append", system=SourceSystem.MANUAL)
        rows[sid] = row
        assert str(sid).encode() in c.p.s.p._plan().rows
    with pytest.raises(review.HistoryPublicationReviewError):
        review.release_history_reviewed_text(c.gate, expected=retained)
    assert c.gate._phase == "HELD" and len(c.state.posts) == 1
    assert len(c.p.state.commits) == 5


@pytest.mark.parametrize("kind", ["child", "assessment"])
def test_preexisting_child_or_assessment_refuses_before_burn_and_post(review_case, kind):
    c = review_case
    rows = c.p.s.c.a.s.rows
    sid = uuid4()
    row = dict(next(iter(rows.values())))
    prefix = review._review_prefix(c.p.s.g.id) if kind == "child" else review._assessment_prefix(c.p.s.g.id)
    row.update(id=sid, lineage_id=sid, supersedes_source_id=None,
               external_ref=prefix + "invented-conflict", system=SourceSystem.MANUAL)
    rows[sid] = row
    assert sid in review.generation._ids(c.p.s.c.a.s.session, prefix)
    before = len(c.p.state.commits)
    with pytest.raises(review.HistoryPublicationReviewError):
        c.gate.invoke()
    assert c.state.posts == [] and c.gate._phase == "HELD"
    assert len(c.p.state.commits) == before


def test_metadata_expiry_consumes_inprocess_attempt_without_post_or_claim(review_case, monkeypatch):
    c = review_case
    original = c.runtime._transport
    milestones = []
    before_commit_calls = c.p.s.c.events.count("commit")
    def transport(method, path, body, remaining):
        raw = original(method, path, body, remaining)
        if path == "/api/show":
            milestones.append(path)
            monkeypatch.setattr(runtime, "_NATIVE_MONOTONIC", lambda: c.gate._deadline)
            monkeypatch.setattr(review, "_NATIVE_MONOTONIC", lambda: c.gate._deadline)
        return raw
    c.runtime._transport = c.runtime._original_transport = transport
    with pytest.raises(review.HistoryPublicationReviewError):
        c.gate.invoke()
    assert milestones == ["/api/show"] and c.runtime._entered and c.gate._invoked
    assert c.state.posts == [] and c.gate._phase == "HELD"
    # This legacy mock appends to a misnamed `commits` list at record_source,
    # before the real commit seam. It does not simulate SQL rollback.
    assert len(c.p.state.commits) == 4
    assert c.p.s.c.events.count("commit") == before_commit_calls
    with pytest.raises(review.HistoryPublicationReviewError):
        c.gate.invoke()
    assert milestones == ["/api/show"]


def test_visible_text_comes_from_reviewed_raw_even_if_mutable_output_view_changed(review_case):
    c = review_case
    c.state.judgment = ReviewJudgment.PASS
    observed = c.gate.invoke()
    retained = review.capture_history_publication_assessment(c.gate, observed=observed)
    from zacai.intelligence.history_contextual_codec import (
        decode_history_contextual_packet,
        render_history_packet_preview,
    )
    original_text = render_history_packet_preview(decode_history_contextual_packet(c.gate._packet_raw).review, c.p.s.q)
    packet = c.output.packet
    assert packet.review.overview
    # Deliberately alter only the in-memory proposed presentation object, never canonical bytes.
    object.__setattr__(packet.review, "overview", ())
    text = review.release_history_reviewed_text(c.gate, expected=retained)
    assert text == original_text and c.gate._phase == "DELIVERY_RELEASED"
    assert c.gate._packet_raw and len(c.state.posts) == 1


def test_short_original_wall_interval_caps_delayed_final_scalar_query(review_case, monkeypatch):
    from datetime import timedelta

    c = review_case
    c.state.judgment = ReviewJudgment.PASS
    retained = review.capture_history_publication_assessment(c.gate, observed=c.gate.invoke())
    assert retained.ready_to_deliver and len(c.state.posts) == 1
    original_owner = c.p.gate._owner
    original_current = c.p.gate._receipt_current
    owner_marks, query_marks = [], []
    def owner():
        monkeypatch.setattr(c.p.f.s.inputs.clock, "_read", lambda: c.p.s.g.expires_at - timedelta(milliseconds=500))
        at = original_owner()
        owner_marks.append(at)
        return at
    def delayed(session, receipt):
        original_current(session, receipt)
        if owner_marks:
            query_marks.append(True)
            # Explicitly simulated forward builtin observation after the real
            # scalar-plan helper, still BEFORE the original reviewer deadline.
            monkeypatch.setattr(review, "_NATIVE_MONOTONIC", lambda: c.gate._deadline - 0.01)
    monkeypatch.setattr(c.p.gate, "_owner", owner)
    monkeypatch.setattr(c.p.gate, "_receipt_current", delayed)
    with pytest.raises(review.HistoryPublicationReviewError):
        review.release_history_reviewed_text(c.gate, expected=retained)
    assert len(owner_marks) == 1 and query_marks == [True]
    assert review._NATIVE_MONOTONIC() < c.gate._deadline
    assert c.gate._phase == "HELD" and len(c.state.posts) == 1
    assert len(c.p.state.commits) == 5
