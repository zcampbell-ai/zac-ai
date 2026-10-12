"""Invented real custody/codecs; branch comparison remains unauthenticated."""
import json
from uuid import UUID

import pytest

from tests.test_claude_task_selection import MID, OTHER, choose, prepared, route, sibling
from tests.test_selector_resolution import answer, same_original_task  # noqa: F401
from zacai.claude_history_index import index_claude_member_history
from zacai.claude_original_capture import _envelope, prepare_claude_custody_proposal
from zacai.claude_original_read import ReadClaudeCustody
from zacai.history_manifest import MAX_EXPORT_BYTES, HistorySelection
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import claude_task_selection as selector

A1, R2, A2, H2 = (UUID(int=v) for v in (44, 55, 66, 77))


def branch_read(shape, prefix=""):
    assistant = sibling(role="assistant", parent=MID, text="Invented assistant response")
    assistant["uuid"] = str(A1)
    hit = sibling(parent=A1, text=prefix + "Sales Audit proposed45hours")
    hit["created_at"] = hit["updated_at"] = "2026-10-06T12:31:00Z"
    template = prepared(text="Initial client requirements", siblings=(assistant, hit), selected_ids=(MID, OTHER))
    conversations = json.loads(template.original_raw)
    if shape == "edit":
        other = dict(hit, uuid=str(H2), text=prefix + "Sales Audit proposed50hours")
        conversations[0]["chat_messages"].append(other)
        approved = (MID, OTHER, H2)
    else:
        second = json.loads(template.original_raw)[0]
        second["uuid"] = str(UUID(int=999))
        roots = second["chat_messages"]
        roots[0]["uuid"] = str(R2)
        roots[0]["text"] = "Separate client requirements"
        roots[1]["uuid"], roots[1]["parent_message_uuid"] = str(A2), str(R2)
        roots[2]["uuid"], roots[2]["parent_message_uuid"] = str(H2), str(A2)
        roots[2]["text"] = prefix + "Sales Audit proposed50hours"
        conversations.append(second)
        approved = (MID, OTHER, R2, H2)
    raw = canonical_bytes(conversations)
    messages = [m for c in index_claude_member_history(raw, expected_file_hash=content_hash_of(raw)).conversations for m in c.messages]
    selections = tuple(HistorySelection(original_id=str(m.original_id), start=m.record.start,
                       end=m.record.end, content_hash=content_hash_of(raw[m.record.start:m.record.end]),
                       reported_at=m.reported_created_at, role=m.historical_role)
                       for m in messages if m.original_id in approved)
    proposal_raw = prepare_claude_custody_proposal(custody_id=template.proposal.custody_id,
        original_raw=raw, account_ref=template.proposal.account_ref,
        exported_at=template.proposal.exported_at, acquired_at=template.proposal.acquired_at,
        captured_at=template.proposal.captured_at, boundary=template.proposal.boundary,
        classification=template.proposal.classification, selections=selections)
    proposal = type(template.proposal).model_validate_json(proposal_raw)
    original = template.original_reference.model_copy(update={"content_hash": content_hash_of(raw)})
    envelope = _envelope(proposal, str(original.source_id))
    companion = template.companion_reference.model_copy(update={"content_hash": content_hash_of(envelope)})
    read = ReadClaudeCustody(original, companion, content_hash_of(proposal_raw), proposal, raw,
        canonical_bytes(json.loads(envelope)["companion"]), template.captured_at,
        original, companion, envelope, template.joint_output_classification, original.source_id,
        False, len(raw) <= MAX_EXPORT_BYTES, False)
    return read, approved


@pytest.mark.parametrize("shape", ["two", "edit"])
def test_non_hit_root_plus_hit_is_an_answerable_branch(shape):
    read, approved = branch_read(shape)
    params = {"ids": approved, "route": route().model_copy(update={"max_input_characters": 64000})}
    first = choose(read, **params)
    assert first.outcome == "CLARIFICATION" and first.request is None
    resolution = answer(first, (MID, OTHER), tuple(v for v in approved if v not in (MID, OTHER)))
    result = None
    failure = None
    try:
        result = choose(read, **params, resolution=resolution)
    except selector.ClaudeTaskSelectionError as error:
        failure = error
    assert failure is None, "coherent retained root+hit must be offered and resolvable"
    assert result.outcome == "PROPOSED" and result.request is not None
    assert {c.message_id for c in first.candidates} == set(approved)
    assert tuple(e.message_id for e in result.request.sidecar.entries) == (MID, OTHER)
    assert not result.processing_authorized and not result.relevance_verified
    assert not resolution.owner_answer_authenticated
    omitted = choose(read, **params, resolution=answer(first, (OTHER,), tuple(v for v in approved if v != OTHER)))
    assert omitted.outcome == "MISSING_CONTEXT" and omitted.request is None
    assert "Required linked" in omitted.non_choice_reason


@pytest.mark.parametrize("shape", ["two", "edit"])
def test_non_hit_required_root_outside_host_cohort_stays_non_choice(shape, monkeypatch):
    read, approved = branch_read(shape)
    admitted = tuple(v for v in approved if v != MID)
    calls = []
    loads = selector.json.loads
    def observe(value, *args, **kwargs):
        if isinstance(value, bytes) and value == b'"Initial client requirements"':
            calls.append(value)
        return loads(value, *args, **kwargs)
    monkeypatch.setattr(selector.json, "loads", observe)
    result = choose(read, ids=admitted, route=route().model_copy(update={"max_input_characters": 64000}))
    assert result.outcome == "MISSING_CONTEXT" and result.request is None and result.question is None
    assert MID not in {c.message_id for c in result.candidates}
    assert calls == [], "outside-cohort root must not reach per-message projection"
