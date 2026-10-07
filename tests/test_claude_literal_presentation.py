"""Invented parser/preparer inputs only; no owner, SQL or recovery proof."""

from dataclasses import replace
from html import escape
from uuid import uuid4

import pytest

from tests.test_claude_historical_fragment import prepare
from tests.test_claude_large_original_message import prepared
from zacai.claude_literal_presentation import (
    HistoricalLiteralOutputError,
    render_historical_literal,
)


def literal(text="Invented dated human message"):
    return prepare(prepared(parent=uuid4(), text=text), end=len(text))


def test_actual_preparation_escaped_literal_and_single_question():
    text = '<script>alert("x")</script> & dated preference'
    result = literal(text)
    output = render_historical_literal(result, owner_question="Does this still apply?")
    assert escape(text) in output
    assert "<script>" not in output
    assert "Reported USER role, unverified author" in output
    assert "2026-10-06T12:00:00+00:00" in output
    assert "Missing ancestry" in output
    assert "Current facts and owner preferences are unconfirmed" in output
    assert output.count('class="owner-question"') == 1
    assert result.owner_authenticated is result.recovery_verified is False


def test_no_question_by_default():
    assert 'class="owner-question"' not in render_historical_literal(literal())


@pytest.mark.parametrize(
    "field,value",
    [
        ("historical_role", "ASSISTANT"),
        ("selected_text", "Changed"),
        ("parent_id", uuid4()),
        ("selected_decoded_utf8_end", 9000),
        ("omitted_prefix_characters", 2),
    ],
)
def test_mutated_literal_holds_without_private_context(field, value):
    result = literal()
    altered = replace(result, fragment=replace(result.fragment, **{field: value}))
    with pytest.raises(HistoricalLiteralOutputError) as caught:
        render_historical_literal(altered)
    assert str(caught.value) == "Historical literal output held"
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_profile_digest_hold():
    with pytest.raises(HistoricalLiteralOutputError):
        render_historical_literal(replace(literal(), profile_hash="0" * 64))


def test_unicode_selected_after_multibyte_prefix_exact_offsets():
    source = "🙂 prefix é<literal>"
    result = prepare(prepared(parent=uuid4(), text=source), start=9, end=len(source))
    assert result.fragment.selected_decoded_utf8_start == len(source[:9].encode())
    assert escape(source[9:]) in render_historical_literal(result)


@pytest.mark.parametrize("question", ["x" * 301, "One?\nTwo?", " padded "])
def test_bounded_single_host_question(question):
    with pytest.raises(HistoricalLiteralOutputError):
        render_historical_literal(literal(), owner_question=question)


def test_foreign_object_no_property_access():
    class Foreign:
        @property
        def profile(self):
            pytest.fail("foreign private property accessed")

    with pytest.raises(HistoricalLiteralOutputError):
        render_historical_literal(Foreign())


def test_assistant_suggestion_reported_not_owner_preference():
    aid = uuid4()
    earlier = {
        "uuid": str(aid),
        "sender": "assistant",
        "text": "Invented suggestion: use Friday",
        "content": [],
        "created_at": "2026-10-06T11:00:00Z",
        "updated_at": "2026-10-06T11:30:00Z",
        "parent_message_uuid": str(uuid4()),
    }
    result = prepare(
        prepared(prefixes=(earlier,), selected_ids=(aid,)),
        message_id=aid,
        end=len(earlier["text"]),
    )
    output = render_historical_literal(result)
    assert "Reported ASSISTANT role, unverified author" in output
    assert "updated 2026-10-06T11:30:00+00:00" in output
    assert "Current facts and owner preferences are unconfirmed" in output


def test_superseded_dated_report_remains_literal_not_current_fact():
    read = replace(prepared(parent=uuid4()), original_tip_id=uuid4(), superseded_at_read=True)
    output = render_historical_literal(prepare(read, end=8))
    assert "The original had a later revision at the read observation" in output
    assert "Invented" in output
    assert "Current facts and owner preferences are unconfirmed" in output


def test_native_closed_details_with_concise_top_and_no_source_links():
    result = literal()
    output = render_historical_literal(result, owner_question="Does this still apply?")
    top, details = output.split("<details>", 1)
    assert "Dated historical excerpt" in top
    assert "Thread context is incomplete" in top
    assert 'class="owner-question"' in top
    assert "Omitted:" not in top
    assert "Current pair sensitivity:" not in top
    assert str(result.profile.current_original_reference.source_id) not in top
    assert details.startswith("<summary>Evidence details and limits</summary>")
    assert "<details open" not in output
    assert output.count("<details>") == output.count("</details>") == 1
    assert "href=" not in output
    assert "<script" not in output
    assert "Omitted:" in details and "Current pair sensitivity:" in details


def test_exact_capture_and_current_source_identities_inside_details():
    result = literal()
    details = render_historical_literal(result).split("<details>", 1)[1]
    for label, ref in (
        ("Original capture binding", result.profile.original_binding_reference),
        ("Companion capture binding", result.profile.companion_binding_reference),
        ("Current original observation", result.profile.current_original_reference),
        ("Current companion observation", result.profile.current_companion_reference),
    ):
        expected = (
            f"<dt>{label}</dt><dd>Source <code>{ref.source_id}</code>; "
            f"{ref.trust_boundary.value}; {ref.effective_classification.value}.</dd>"
        )
        assert expected in details


def test_historical_punctuation_and_whitespace_preserved_verbatim():
    text = 'Invented quote — keep  this punctuation.\n"Second line" & <literal>'
    output = render_historical_literal(literal(text))
    assert f"<blockquote><pre>{escape(text)}</pre></blockquote>" in output
    assert "—" in output  # Historical quotes are not rewritten to match owner prose.
    generated = output.replace(f"<blockquote><pre>{escape(text)}</pre></blockquote>", "")
    assert "—" not in generated


class InjectingInt(int):
    def __format__(self, spec):
        return '<img src=x onerror="invented">'


@pytest.mark.parametrize(
    "field",
    [
        "omitted_prefix_characters",
        "omitted_suffix_characters",
        "full_decoded_characters",
        "selected_character_start",
        "selected_character_end",
        "selected_decoded_utf8_start",
        "selected_decoded_utf8_end",
    ],
)
def test_integer_subclass_metadata_is_denied_before_format(field):
    result = literal()
    bad = replace(
        result,
        fragment=replace(result.fragment, **{field: InjectingInt(getattr(result.fragment, field))}),
    )
    with pytest.raises(HistoricalLiteralOutputError) as caught:
        render_historical_literal(bad)
    assert caught.value.__context__ is None


@pytest.mark.parametrize("field", ["reported_created_at", "reported_updated_at"])
def test_none_dates_hold_existing_required_fragment_contract(field):
    result = literal()
    bad = replace(result, fragment=replace(result.fragment, **{field: None}))
    with pytest.raises(HistoricalLiteralOutputError):
        render_historical_literal(bad)


def test_profile_does_not_admit_missing_updated_date():
    result = literal()
    with pytest.raises(ValueError):
        type(result.profile).model_validate(
            result.profile.model_copy(update={"reported_updated_at": None})
        )
