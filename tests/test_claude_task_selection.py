"""Invented original files and real codecs/profiles; supplied observations, no SQL authority."""

from dataclasses import replace
from uuid import UUID

import pytest

from tests.test_claude_large_original_message import AT, MID, ZERO, prepared
from tests.test_history_context_metadata import base
from tests.test_local_contextual_runtime import route
from zacai.intelligence.claude_task_selection import (
    ClaudeTaskSelectionError,
    propose_claude_task_context,
)
from zacai.intelligence.contracts import IntelligenceTask
from zacai.intelligence.history_contextual_codec import (
    decode_history_contextual_request,
    encode_history_contextual_request,
)
from zacai.intelligence.meeting_review import ReviewContext

OTHER = UUID("33333333-3333-4333-8333-333333333333")


def choose(read, instruction="Summarize Sales Audit", ids=(MID,), **changes):
    original = base()
    task = IntelligenceTask.model_validate(
        {**original.task.model_dump(), "instruction": instruction}
    )
    context = ReviewContext(task, original.meeting_source_id, original.related_source_ids)
    kw = {
        "approved_message_ids": ids,
        "expected_original": read.original_reference,
        "expected_companion": read.companion_reference,
        "observed_at": AT,
        "route": route(),
    }
    kw.update(changes)
    return propose_claude_task_context(context, read, **kw)


def sibling(role="human", parent=ZERO, text="Icon Park Sales discussion"):
    return {
        "uuid": str(OTHER),
        "sender": role,
        "text": text,
        "content": [],
        "created_at": "2026-10-06T12:30:00Z",
        "updated_at": "2026-10-06T12:30:00Z",
        "parent_message_uuid": str(parent),
    }


def test_actual_files_pair_full_user_preview_and_exact_wording(tmp_path):
    read = prepared(text="Sales Audit historically requested reconciliation.")
    for name, raw in [
        ("original", read.original_raw),
        ("companion", read.companion_raw),
        ("envelope", read.envelope_raw),
    ]:
        (tmp_path / name).write_bytes(raw)
    read = replace(
        read,
        original_raw=(tmp_path / "original").read_bytes(),
        companion_raw=(tmp_path / "companion").read_bytes(),
        envelope_raw=(tmp_path / "envelope").read_bytes(),
    )
    words = "Summarize Sales Audit\r\nPreserve dated uncertainty"
    result = choose(read, words)
    assert result.outcome == "PROPOSED" and result.question is None
    preview = result.preview
    assert preview is not None
    assert (
        result.instruction
        == preview.original_task.instruction
        == preview.context.task.instruction
        == words
    )
    assert result.request is not None
    assert result.request.original_task.instruction == result.request.task.instruction == words
    assert (
        decode_history_contextual_request(encode_history_contextual_request(result.request))
        == result.request
    )
    meta = preview.sidecar.entries[0]
    assert meta.current_original_reference == read.original_reference
    assert meta.current_companion_reference == read.companion_reference
    assert meta.historical_role == "USER" and meta.character_start == 0
    assert meta.character_end == meta.full_decoded_characters
    assert meta.omitted_prefix_characters == meta.omitted_suffix_characters == 0
    assert not result.relevance_verified and not result.processing_authorized
    assert not meta.current_fact and not meta.sender_authenticated


@pytest.mark.parametrize("role,parent", [("assistant", ZERO), ("human", UUID(int=99))])
def test_assistant_or_incomplete_candidate_cannot_enter_preview(role, parent):
    read = prepared(
        text="Unrelated historical weather", siblings=(sibling(role, parent),), selected_ids=(MID,)
    )
    result = choose(read, ids=(OTHER,))
    assert result.outcome == "MISSING_CONTEXT"
    assert all(c.profile_hash is c.full_text_hash is None for c in result.candidates)
    assert result.preview is None and result.question is None


def test_same_account_distinct_discussions_one_dated_question_no_project_merge():
    read = prepared(
        text="Sales Audit scope was proposed.", siblings=(sibling(),), selected_ids=(MID, OTHER)
    )
    result = choose(read, ids=(MID, OTHER))
    assert result.outcome == "CLARIFICATION" and result.preview is None and result.request is None
    assert result.question is not None and result.question.count("?") == 1
    assert "reported 2026-10-06" in result.question
    assert str(MID) not in result.question and str(OTHER) not in result.question
    assert {c.message_id for c in result.candidates} == {MID, OTHER}
    assert len(result.candidates) == 2 and not result.relevance_verified


@pytest.mark.parametrize("fault", ["bytes", "companion", "reference", "missing-cohort"])
def test_stale_or_foreign_pair_cohort_holds(fault):
    read = prepared(text="Sales Audit dated context")
    changes = {}
    if fault == "bytes":
        read = replace(read, original_raw=read.original_raw + b" ")
    elif fault == "companion":
        read = replace(read, companion_raw=read.companion_raw + b" ")
    elif fault == "reference":
        changes["expected_original"] = read.original_reference.model_copy(
            update={"content_hash": "a" * 64}
        )
    else:
        changes["approved_message_ids"] = (OTHER,)
    with pytest.raises(ClaudeTaskSelectionError) as held:
        choose(read, **changes)
    assert str(held.value) == "task context selection unavailable"
    assert held.value.__cause__ is held.value.__context__ is None


def test_unmatched_and_oversized_full_message_are_missing_not_excerpted():
    assert choose(prepared(text="Only unrelated weather")).outcome == "MISSING_CONTEXT"
    result = choose(prepared(text="Sales Audit " + "x" * 8000))
    assert result.outcome == "MISSING_CONTEXT" and result.preview is None


def test_approved_later_correction_without_keywords_is_preserved():
    correction = "Actually, replace that amount with 45 hours and mark it proposed."
    read = prepared(
        text="Sales Audit originally proposed 30 hours.",
        siblings=(sibling(parent=MID, text=correction),),
        selected_ids=(MID, OTHER),
    )
    result = choose(
        read, ids=(MID, OTHER), route=route().model_copy(update={"max_input_characters": 64000})
    )
    assert result.outcome == "PROPOSED" and result.request is not None
    assert tuple(e.message_id for e in result.request.sidecar.entries) == (MID, OTHER)
    assert correction in result.preview.context.task.context[-1].untrusted_text
    assert not result.current_facts_verified and not result.relevance_verified


def test_unlinked_later_user_cannot_be_silently_omitted():
    read = prepared(
        text="Sales Audit originally proposed 30 hours.",
        siblings=(sibling(text="Actually use 45 hours instead."),),
        selected_ids=(MID, OTHER),
    )
    result = choose(read, ids=(MID, OTHER))
    assert result.outcome == "CLARIFICATION" and result.request is None
    assert len(result.options) == 2  # The actual unlinked roots are whole choices.
    assert "Actually use 45 hours instead." in result.question


def test_correction_aggregate_overflow_asks_without_clipping():
    read = prepared(
        text="Sales Audit " + ("a" * 1000 + "\n") * 4 + "a" * 100,
        siblings=(sibling(parent=MID, text="Correction " + ("b" * 1000 + "\n") * 4 + "b" * 100),),
        selected_ids=(MID, OTHER),
    )
    result = choose(
        read, ids=(MID, OTHER), route=route().model_copy(update={"max_input_characters": 64000})
    )
    assert result.outcome == "MISSING_CONTEXT" and result.preview is result.request is None
    assert result.question is None and "bounds" in result.non_choice_reason
    assert len(result.candidates) == 2


def test_numbered_quote_choices_have_dates_but_no_visible_binding_ids():
    first = "Sales Audit client requirement <script>invented</script>"
    second = "Icon Park Sales signage requirement"
    read = prepared(text=first, siblings=(sibling(text=second),), selected_ids=(MID, OTHER))
    result = choose(read, ids=(MID, OTHER))
    assert result.outcome == "CLARIFICATION"
    assert len(result.options) == 2
    for number, option in enumerate(result.options, 1):
        assert result.question.splitlines()[number] == f"{number}. {option.display_label}"
        assert "reported 2026-10-06T" in option.display_label
    assert first in result.question and second in result.question
    assert str(MID) not in result.question and str(OTHER) not in result.question
    assert all(c.quote_preview in (first, second) for c in result.candidates)


def test_joined_utf8_separator_overflow_requires_declared_clarification(monkeypatch):
    from zacai.intelligence import claude_task_selection as selector

    first = "Sales Audit " + "é" * 998 + "\n" + "é" * 998 + "\n" + "é" * 997
    second = "Correction " + "é" * 750 + "\n" + "é" * 750 + "\n" + "é" * 750 + "\n" + "é" * 743
    assert len(first.encode()) == len(second.encode()) == 6000
    read = prepared(
        text=first, siblings=(sibling(parent=MID, text=second),), selected_ids=(MID, OTHER)
    )
    milestones = []
    real = selector.prepare_claude_history_context_preview

    def observe(*args, **kwargs):
        assert tuple(s.message_id for s in kwargs["selections"]) == (MID, OTHER)
        milestones.append(len(first.encode()) + len(second.encode()) + 1)
        return real(*args, **kwargs)

    monkeypatch.setattr(selector, "prepare_claude_history_context_preview", observe)
    result = None
    error = None
    try:
        result = choose(
            read, ids=(MID, OTHER), route=route().model_copy(update={"max_input_characters": 64000})
        )
    except ClaudeTaskSelectionError as held:
        error = held
    assert error is None, "separator overflow must ask rather than raise a generic hold"
    assert milestones == [], "over-capacity context must hold before preview construction"
    assert result.outcome == "MISSING_CONTEXT" and result.request is None
    assert result.question is None and "bounds" in result.non_choice_reason


def test_keyword_repeating_correction_is_one_linear_cohort():
    read = prepared(
        text="Sales Audit is 30 hours",
        siblings=(sibling(parent=MID, text="Correction: Sales Audit is 45 hours"),),
        selected_ids=(MID, OTHER),
    )
    result = choose(
        read, ids=(MID, OTHER), route=route().model_copy(update={"max_input_characters": 64000})
    )
    assert result.outcome == "PROPOSED" and result.request is not None
    assert tuple(e.message_id for e in result.request.sidecar.entries) == (MID, OTHER)


def test_unrelated_unavailable_record_does_not_run_full_prepare(monkeypatch):
    from zacai.intelligence import claude_task_selection as m

    read = prepared(
        text="Sales Audit approved draft",
        siblings=(sibling(text="weather\n"),),
        selected_ids=(MID, OTHER),
    )
    calls = []
    real = m.prepare_claude_large_original_message

    def observe(*a, **kw):
        calls.append(kw["message_id"])
        return real(*a, **kw)

    monkeypatch.setattr(m, "prepare_claude_large_original_message", observe)
    result = choose(read, ids=(MID, OTHER))
    # Unlinked later USER is a conservative clarification, but no full-file
    # preparation of irrelevant or ineligible candidates is performed.
    assert result.outcome == "MISSING_CONTEXT" and result.question is None and calls == []
    assert "unavailable" in result.non_choice_reason
    # Different earlier unrelated root is harmless and does not hold a proposal.
    bad = sibling(text="weather\n")
    bad["created_at"] = bad["updated_at"] = "2026-10-06T11:30:00Z"
    result = choose(
        prepared(text="Sales Audit approved draft", prefixes=(bad,), selected_ids=(MID, OTHER)),
        ids=(MID, OTHER),
    )
    assert result.outcome == "PROPOSED" and calls == [MID]


def test_unavailable_matching_earlier_context_does_not_disappear():
    ancestor = sibling(text="Sales Audit " + "x" * 2000)
    ancestor["created_at"] = ancestor["updated_at"] = "2026-10-06T11:30:00Z"
    read = prepared(
        text="Sales Audit 45 hours", parent=OTHER, prefixes=(ancestor,), selected_ids=(MID, OTHER)
    )
    result = choose(read, ids=(MID, OTHER))
    assert (
        result.outcome == "MISSING_CONTEXT" and result.request is None and result.question is None
    )
    assert "unavailable" in result.non_choice_reason
    item = next(c for c in result.candidates if c.message_id == OTHER)
    assert item.profile_hash is item.full_text_hash is None
    assert item.unavailable_reason is not None


def test_branch_divergent_corrections_are_not_sorted_as_linear():
    third = UUID(int=444)
    row = sibling(parent=MID, text="Use 50 hours instead")
    row["uuid"] = str(third)
    read = prepared(
        text="Sales Audit 30 hours",
        siblings=(sibling(parent=MID, text="Use 45 hours instead"), row),
        selected_ids=(MID, OTHER, third),
    )
    result = choose(
        read,
        ids=(MID, OTHER, third),
        route=route().model_copy(update={"max_input_characters": 64000}),
    )
    assert result.outcome == "CLARIFICATION" and result.request is None
    assert len(result.options) == 2
    assert all(len(option.selected_message_ids) == 2 for option in result.options)
    assert "45 hours" in result.question and "50 hours" in result.question


def test_metadata_excluded_correction_requires_approval_without_text_read():
    read = prepared(
        text="Sales Audit 30 hours",
        siblings=(sibling(parent=MID, text="SENSITIVE UNAPPROVED CORRECTION"),),
        selected_ids=(MID, OTHER),
    )
    result = choose(read, ids=(MID,))
    assert (
        result.outcome == "MISSING_CONTEXT" and result.request is None and result.question is None
    )
    assert "excluded USER context" in result.non_choice_reason
    assert all("SENSITIVE UNAPPROVED" not in c.quote_preview for c in result.candidates)
    assert {c.message_id for c in result.candidates} == {MID}


def test_preview_capacity_failure_is_one_context_question():
    read = prepared(
        text="Sales Audit 30 hours",
        siblings=(sibling(parent=MID, text="Use 45 hours instead"),),
        selected_ids=(MID, OTHER),
    )
    result = choose(
        read, ids=(MID, OTHER), route=route().model_copy(update={"max_input_characters": 100})
    )
    assert result.outcome == "MISSING_CONTEXT" and result.preview is result.request is None
    assert result.question is None and "preview" in result.non_choice_reason
    assert "preview cannot fit" in result.non_choice_reason


def test_more_than_four_choices_and_question_punctuation_are_explicit():
    ids = [MID, OTHER, UUID(int=444), UUID(int=555), UUID(int=666)]
    rows = []
    for n, ident in enumerate(ids[1:]):
        row = sibling(text=f'Sales Audit choice {n}?\n"Dated report"')
        row["uuid"] = str(ident)
        rows.append(row)
    read = prepared(text="Sales Audit first?", siblings=tuple(rows), selected_ids=tuple(ids))
    result = choose(read, ids=tuple(ids))
    assert result.outcome == "CLARIFICATION" and len(result.candidates) == 5
    assert result.question.count("?") == 1
    assert len(result.options) == 5 and len(result.question.splitlines()) == 6
    for number, option in enumerate(result.options, 1):
        assert result.question.splitlines()[number] == f"{number}. {option.display_label}"
    assert "\\u003f" not in result.question and "\\n" not in result.question
    assert result.candidates[0].quote_preview == "Sales Audit first?"


@pytest.mark.parametrize(
    "words,text",
    [
        ("Summarize Sales Audit", "Icon Park Sales discussion"),
        ("Draft notes from that meeting", "from that unrelated weather"),
    ],
)
def test_common_or_partial_overlap_cannot_be_proposed(words, text):
    result = choose(prepared(text=text), instruction=words)
    assert result.outcome != "PROPOSED" and result.request is None


def test_matching_not_retained_in_custody_is_unavailable_not_generic_error():
    read = prepared(
        text="Sales Audit 30 hours",
        siblings=(sibling(parent=MID, text="Sales Audit 45 hours"),),
        selected_ids=(MID,),
    )
    result = choose(read, ids=(MID, OTHER))
    assert (
        result.outcome == "MISSING_CONTEXT" and result.request is None and result.question is None
    )
    assert "retained custody" in result.non_choice_reason
    item = next(c for c in result.candidates if c.message_id == OTHER)
    assert item.profile_hash is item.full_text_hash is None
