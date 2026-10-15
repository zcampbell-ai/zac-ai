"""Actual invented local SQLite owner sessions and real selector/codec.

Canonical reader and declaration preparation are explicit spies. No PostgreSQL,
backup crypto, model calls, private history or live owner acceptance is tested.
"""
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from tests.test_claude_large_original_message import AT, MID, prepared
from tests.test_claude_task_selection import OTHER, sibling
from tests.test_local_contextual_runtime import route
from tests.test_review_generation import synthetic_context
from zacai import personal_history_task_selection as m
from zacai.claude_original_capture import ClaudeArtifactRootIdentity
from zacai.host_clock import HostObservedClock
from zacai.intelligence.contracts import IntelligenceTask
from zacai.intelligence.history_generation_review_declaration import (
    PURPOSE,
    HistoryReviewPurposeProfileV1,
)
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.personal_history_factory import PersonalHistoryTaskConfiguration
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.interfaces.private_web import BoundaryScope, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.interfaces.sqlite_sessions import SqliteSessionStore
from zacai.personal_history_task_selection import PersonalTaskSelectionError
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


@pytest.fixture
def case(tmp_path, monkeypatch):
    s = SimpleNamespace(now=AT, loads=[], preparations=[], opened=0, root_reads=0)
    s.clock = HostObservedClock(lambda: s.now)
    s.owner = OwnerGrant(
        Identity("https://accounts.google.com", "invented-owner"),
        (BoundaryScope(B.PERSONAL, frozenset({C.HIGHLY_RESTRICTED})),),
    )
    s.sessions = SqliteSessionStore(tmp_path / "sessions", key=b"x" * 32)
    s.cookie = s.sessions.start_user(s.owner.identity, s.now)
    owner = lambda: s.owner
    s.inputs = NamedOwnerHostInputs(
        "https://caz.example", "invented-client", b"x" * 32, tmp_path,
        None, owner, s.sessions, s.clock,
    )
    s.continuity = NamedSessionContinuity(
        sessions=s.sessions, owner=owner, clock=s.clock, key=b"x" * 32,
        origin=s.inputs.origin, client_id=s.inputs.client_id,
    )
    s.operation = s.continuity.for_cookie(s.cookie)
    s.raw_read = prepared(
        text="Sales Audit scope was proposed.",
        siblings=(sibling(text="Icon Park budget was proposed."),),
        selected_ids=(MID, OTHER),
    )
    def current_read(raw):
        return replace(raw,
            original_reference=raw.original_reference.model_copy(update={
                "effective_classification": C.HIGHLY_RESTRICTED}),
            companion_reference=raw.companion_reference.model_copy(update={
                "effective_classification": C.HIGHLY_RESTRICTED}),
            joint_output_classification=C.HIGHLY_RESTRICTED,
        )
    s.read = current_read(s.raw_read)
    s.current_read = current_read
    s.root = ClaudeArtifactRootIdentity("/invented", 1, 2, 3)
    context = synthetic_context(boundary=B.PERSONAL, classification=C.HIGHLY_RESTRICTED)
    context = ReviewContext(IntelligenceTask.model_validate({
        **context.task.model_dump(), "required_capabilities": frozenset({"contextual_meeting_review"}),
    }), context.meeting_source_id, context.related_source_ids)
    s.engine = create_engine("sqlite+pysqlite:///:memory:")
    s.factory = sessionmaker(bind=s.engine)
    selected_route = route().model_copy(update={"max_input_characters": 64000})
    profile = HistoryReviewPurposeProfileV1(
        reviewer_id=uuid4(), run_id=uuid4(),
        route=selected_route.model_copy(update={"capabilities": frozenset({PURPOSE}),
            "max_output_tokens": 32000, "estimated_latency_ms": 1000, "estimated_cost_usd": 0.0}),
        model_digest="1" * 64, tokenizer_digest="2" * 64, runtime_digest="3" * 64,
        template_digest="4" * 64, renderer_digest="5" * 64, rubric_digest="6" * 64,
        reviewer_wire_digest="7" * 64, body_derivation_digest="8" * 64,
        context_window_tokens=16384, max_output_tokens=512, max_latency_ms=1000,
        max_estimated_cost_usd=0.0,
    )
    s.configuration = PersonalHistoryTaskConfiguration(
        factory=s.factory,
        engine=s.engine, artifacts=object(), expected_root=s.root,
        original_reference=s.read.original_reference,
        companion_reference=s.read.companion_reference,
        expected_account_ref=s.read.proposal.account_ref,
        expected_exported_at=s.read.proposal.exported_at,
        selections=(), original_context=context, route=selected_route,
        generation_id=uuid4(), builder_id=uuid4(), expires_at=s.now + timedelta(minutes=10),
        generation_counter=object.__new__(OllamaQwenContextualTokenCounter), generation_runtime_digest="1" * 64,
        review_profile=profile, cold_artifacts=None, objects=None, verification_objects=None,
        recipient="invented", identity_path=tmp_path / "invented", manifest_cache=tmp_path / "cache",
        restoration=None,
    )
    monkeypatch.setattr(m, "assert_local_review_state_engine", lambda engine: None)
    def observe(artifacts):
        s.root_reads += 1
        return s.root
    monkeypatch.setattr(m, "observe_claude_artifact_root", observe)
    original_call = sessionmaker.__call__
    def open_session(factory, **kw):
        s.opened += 1
        return original_call(factory, **kw)
    monkeypatch.setattr(sessionmaker, "__call__", open_session)
    monkeypatch.setattr(m, "_physical", lambda session: session)
    monkeypatch.setattr(m, "_same", lambda session, entry: None)
    def load(session, **kw):
        s.loads.append(kw)
        if getattr(s, "revoke_during_read", False):
            s.sessions.revoke(s.cookie)
        return s.read
    monkeypatch.setattr(m, "load_claude_original", load)
    def prepare(configuration, **kw):
        s.preparations.append((configuration, kw))
        return SimpleNamespace(processing_authorized=False)
    monkeypatch.setattr(m, "prepare_personal_history_task", prepare)
    s.make = lambda: m.PersonalHistoryTaskPreparation(
        configuration=s.configuration, inputs=s.inputs, approved_message_ids=(MID, OTHER),
    )
    yield s
    s.engine.dispose()


def prepare(s, app, instruction, **changes):
    return app.prepare(**{
        "operation": s.operation, "instruction": instruction,
        "approved_message_ids": (MID, OTHER), **changes,
    })


def test_task_wording_selects_distinct_context_then_passes_exact_spans(case):
    s = case
    first = s.make()
    proposal = first.propose(operation=s.operation, instruction="Summarize Sales Audit")
    assert proposal.selection.outcome == "CLARIFICATION"
    assert proposal.selection.question.count("?") == 1
    assert not proposal.processing_authorized and not s.preparations
    option = next(i for i, v in enumerate(proposal.selection.options, 1)
                  if v.selected_message_ids == (MID,))
    prepare(s, first, "Summarize Sales Audit", option_number=option)
    assert tuple(v.message_id for v in s.preparations[-1][0].selections) == (MID,)
    second = s.make()
    second.propose(operation=s.operation, instruction="Summarize Icon Park")
    result = prepare(s, second, "Summarize Icon Park")
    assert tuple(v.message_id for v in s.preparations[-1][0].selections) == (OTHER,)
    assert s.preparations[-1][1]["instruction"] == "Summarize Icon Park"
    assert not result.processing_authorized


@pytest.mark.parametrize("fault", ["task", "cohort", "new-session", "revoked", "deadline", "route"])
def test_original_answer_binding_holds_changed_inputs_before_preparation(case, fault):
    s, instruction = case, "Summarize Sales Audit"
    app = s.make()
    proposal = app.propose(operation=s.operation, instruction=instruction)
    kw = {"option_number": 1}
    if fault == "task":
        instruction = "Summarize Icon Park"
    elif fault == "cohort":
        kw["approved_message_ids"] = (MID,)
    elif fault == "new-session":
        cookie = s.sessions.start_user(s.owner.identity, s.now)
        kw["operation"] = s.continuity.for_cookie(cookie)
    elif fault == "revoked":
        s.sessions.revoke(s.cookie)
    elif fault == "deadline":
        s.now = s.configuration.expires_at
    elif fault == "route":
        object.__setattr__(s.configuration.route, "capabilities", frozenset({"changed"}))
    with pytest.raises(PersonalTaskSelectionError):
        prepare(s, app, instruction, **kw)
    assert not s.preparations
    assert proposal.selection.processing_authorized is False


def test_changed_retained_pair_rejected_and_no_retry(case):
    s = case
    app = s.make()
    app.propose(operation=s.operation, instruction="Summarize Sales Audit")
    original = s.read
    s.read = s.current_read(prepared(text="Changed Sales Audit scope", selected_ids=(MID,)))
    with pytest.raises(PersonalTaskSelectionError):
        prepare(s, app, "Summarize Sales Audit", option_number=1)
    s.read = original
    with pytest.raises(PersonalTaskSelectionError):
        prepare(s, app, "Summarize Sales Audit", option_number=1)
    assert not s.preparations


def test_revocation_during_fresh_read_denies_answer(case):
    s = case
    app = s.make()
    app.propose(operation=s.operation, instruction="Summarize Sales Audit")
    s.revoke_during_read = True
    with pytest.raises(PersonalTaskSelectionError):
        prepare(s, app, "Summarize Sales Audit", option_number=1)
    assert not s.preparations


def test_missing_context_is_structured_without_preparation_or_processing(case):
    s = case
    app = s.make()
    result = app.propose(operation=s.operation, instruction="Summarize merchant reconciliation")
    assert result.selection.outcome == "MISSING_CONTEXT"
    assert result.selection.non_choice_reason
    assert result.selection.question is None
    assert not result.processing_authorized and not s.preparations
    with pytest.raises(PersonalTaskSelectionError):
        prepare(s, app, "Summarize merchant reconciliation")


def test_correction_ancestry_passes_as_whole_spans_not_keyword_excerpt(case):
    s = case
    raw = prepared(
        text="Sales Audit originally proposed 30 hours.",
        siblings=(sibling(parent=MID, text="Actually use 45 hours instead."),),
        selected_ids=(MID, OTHER),
    )
    s.read = s.current_read(raw)
    s.configuration = replace(s.configuration,
        original_reference=s.read.original_reference,
        companion_reference=s.read.companion_reference,
    )
    app = s.make()
    result = app.propose(operation=s.operation, instruction="Summarize Sales Audit")
    assert result.selection.outcome == "PROPOSED", result.selection.non_choice_reason
    prepare(s, app, "Summarize Sales Audit")
    spans = s.preparations[-1][0].selections
    assert tuple(v.message_id for v in spans) == (MID, OTHER)
    assert spans[1].character_start == 0
    assert spans[1].character_end == len("Actually use 45 hours instead.")


@pytest.mark.parametrize("fault", ["bind", "binds"])
def test_wrong_database_configuration_denied_before_any_source_io(case, fault):
    s = case
    app = s.make()
    other = create_engine("sqlite+pysqlite:///:memory:")
    try:
        if fault == "bind":
            s.factory.configure(bind=other)
        else:
            s.factory.configure(binds={m.IntelligenceTask: other})
        with pytest.raises(PersonalTaskSelectionError):
            app.propose(operation=s.operation, instruction="Summarize Sales Audit")
        assert not s.opened and not s.root_reads and not s.loads and not s.preparations
        with pytest.raises(PersonalTaskSelectionError):
            app.propose(operation=s.operation, instruction="Summarize Sales Audit")
    finally:
        other.dispose()


def test_wrong_constructor_configuration_has_fixed_cause_free_diagnostic(case):
    s = case
    bad = replace(s.configuration, original_reference="PRIVATE-invalid-reference")
    with pytest.raises(PersonalTaskSelectionError) as caught:
        m.PersonalHistoryTaskPreparation(
            configuration=bad, inputs=s.inputs, approved_message_ids=(MID, OTHER),
        )
    assert str(caught.value) == "task context preparation unavailable"
    assert caught.value.__context__ is None
    assert not s.opened and not s.root_reads and not s.loads


def test_interrupted_custody_read_is_private_safe_and_terminal(case, monkeypatch):
    s = case
    app = s.make()
    def interrupted(*args, **kw):
        raise KeyboardInterrupt("PRIVATE-source-marker")
    monkeypatch.setattr(m, "load_claude_original", interrupted)
    with pytest.raises(PersonalTaskSelectionError) as caught:
        app.propose(operation=s.operation, instruction="Summarize Sales Audit")
    assert caught.value.__context__ is None
    assert "PRIVATE" not in str(caught.value)
    before = s.opened
    with pytest.raises(PersonalTaskSelectionError):
        app.propose(operation=s.operation, instruction="Summarize Sales Audit")
    assert s.opened == before and not s.preparations


def test_resolve_choice_discloses_before_preparation_then_confirms_same_option(case):
    s = case
    app = s.make()
    first = app.propose(operation=s.operation, instruction="Summarize Sales Audit")
    option = next(i for i, v in enumerate(first.selection.options, 1)
                  if v.selected_message_ids == (MID,))
    resolved = app.resolve_choice(
        operation=s.operation, instruction="Summarize Sales Audit",
        approved_message_ids=(MID, OTHER), option_number=option,
    )
    assert resolved.selection.outcome == "PROPOSED" and app._phase == "RESOLVED"
    assert tuple(e.message_id for e in resolved.selection.preview.sidecar.entries) == (MID,)
    assert not s.preparations and not resolved.processing_authorized
    assert app._selection is first.selection  # Original comparison binding is retained.
    prepare(s, app, "Summarize Sales Audit")
    assert tuple(span.message_id for span in s.preparations[-1][0].selections) == (MID,)


@pytest.mark.parametrize("fault", ["task", "cohort", "new-session", "revoked", "deadline", "pair", "different-choice"])
def test_resolved_confirmation_rejects_changed_original_context_or_answer(case, fault):
    s = case
    app = s.make()
    app.propose(operation=s.operation, instruction="Summarize Sales Audit")
    app.resolve_choice(operation=s.operation, instruction="Summarize Sales Audit",
        approved_message_ids=(MID, OTHER), option_number=1)
    instruction, kwargs = "Summarize Sales Audit", {}
    if fault == "task":
        instruction = "Summarize Icon Park"
    elif fault == "cohort":
        kwargs["approved_message_ids"] = (MID,)
    elif fault == "new-session":
        cookie = s.sessions.start_user(s.owner.identity, s.now)
        kwargs["operation"] = s.continuity.for_cookie(cookie)
    elif fault == "revoked":
        s.sessions.revoke(s.cookie)
    elif fault == "deadline":
        s.now = s.configuration.expires_at
    elif fault == "pair":
        s.read = s.current_read(prepared(text="Changed Sales Audit scope", selected_ids=(MID,)))
    elif fault == "different-choice":
        kwargs["option_number"] = 2
    with pytest.raises(PersonalTaskSelectionError):
        prepare(s, app, instruction, **kwargs)
    assert not s.preparations


def test_resolve_choice_is_one_shot_and_cannot_silently_change_option(case):
    s = case
    app = s.make()
    app.propose(operation=s.operation, instruction="Summarize Sales Audit")
    app.resolve_choice(operation=s.operation, instruction="Summarize Sales Audit",
        approved_message_ids=(MID, OTHER), option_number=1)
    with pytest.raises(PersonalTaskSelectionError):
        app.resolve_choice(operation=s.operation, instruction="Summarize Sales Audit",
            approved_message_ids=(MID, OTHER), option_number=2)
    with pytest.raises(PersonalTaskSelectionError):
        prepare(s, app, "Summarize Sales Audit")
    assert not s.preparations


@pytest.mark.parametrize("fault", ["span", "selected-hash"])
def test_initial_proposal_refuses_changed_selected_entries_with_same_comparison_binding(
    case, monkeypatch, fault,
):
    from zacai.intelligence.history_context_metadata import (
        HistoryMessageSpan,
        prepare_claude_history_context_preview,
    )
    from zacai.intelligence.history_contextual_codec import prepare_history_contextual_request

    s = case
    app = s.make()
    shown = app.propose(operation=s.operation, instruction="Summarize Icon Park")
    assert shown.selection.outcome == "PROPOSED"
    actual_selector = m.propose_claude_task_context

    def changed_selection(original, read, **kwargs):
        fresh = actual_selector(original, read, **kwargs)
        assert fresh.selection_binding_digest == shown.selection.selection_binding_digest
        if fault == "span":
            prior = fresh.preview.sidecar.entries[0]
            changed = prepare_claude_history_context_preview(
                original, read,
                selections=(HistoryMessageSpan(message_id=prior.message_id,
                    character_start=1, character_end=prior.character_end),),
                observed_at=kwargs["observed_at"], route=kwargs["route"],
            )
            request = prepare_history_contextual_request(
                changed, original_context=original, route=kwargs["route"],
            )
            return replace(fresh, preview=changed, request=request)
        entry = fresh.preview.sidecar.entries[0].model_copy(update={"selected_text_hash": "0" * 64})
        sidecar = fresh.preview.sidecar.model_copy(update={"entries": (entry,)})
        return replace(fresh, preview=replace(fresh.preview, sidecar=sidecar))

    monkeypatch.setattr(m, "propose_claude_task_context", changed_selection)
    with pytest.raises(PersonalTaskSelectionError):
        prepare(s, app, "Summarize Icon Park")
    assert not s.preparations and app._phase == "HELD"
