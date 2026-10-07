"""Invented originals and supplied read observations, not canonical/recovery proof."""

from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from zacai import claude_large_original_message as lane
from zacai.claude_history_index import index_claude_member_history
from zacai.claude_message_projection import (
    ClaudeMessageProjectionError,
    extract_claude_selected_message,
)
from zacai.claude_original_capture import (
    ClaudeCustodyProposal,
    _envelope,
    prepare_claude_custody_proposal,
)
from zacai.claude_original_read import ReadClaudeCustody
from zacai.history_manifest import MAX_EXPORT_BYTES, MAX_RECORD_BYTES, HistorySelection
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

AT = datetime(2026, 10, 6, 13, tzinfo=UTC)
MID = UUID("22222222-2222-4222-8222-222222222222")
ZERO = UUID(int=0)


def prepared(
    *,
    padding=0,
    text="Invented dated human message",
    parent=ZERO,
    siblings=(),
    prefixes=(),
    reported_date="2026-10-06T12:00:00Z",
    exported_at=AT,
    selected_ids=(MID,),
):
    import json

    raw = json.dumps(
        [
            {
                "uuid": "11111111-1111-4111-8111-111111111111",
                "account": {"uuid": "invented-account"},
                "created_at": min([reported_date, *(x["created_at"] for x in prefixes + siblings)]),
                "updated_at": max([reported_date, *(x["updated_at"] for x in prefixes + siblings)]),
                "unassessed": "x" * padding,
                "chat_messages": [
                    *prefixes,
                    {
                        "uuid": str(MID),
                        "sender": "human",
                        "text": text,
                        "content": [],
                        "created_at": reported_date,
                        "updated_at": reported_date,
                        "parent_message_uuid": str(parent),
                    },
                    *siblings,
                ],
            }
        ],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    messages = (
        index_claude_member_history(raw, expected_file_hash=content_hash_of(raw))
        .conversations[0]
        .messages
    )
    choices = tuple(
        HistorySelection(
            original_id=str(message.original_id),
            start=message.record.start,
            end=message.record.end,
            content_hash=content_hash_of(raw[message.record.start : message.record.end]),
            reported_at=message.reported_created_at,
            role=message.historical_role,
        )
        for message in messages
        if message.original_id in selected_ids
    )
    proposal_raw = prepare_claude_custody_proposal(
        custody_id=uuid4(),
        original_raw=raw,
        account_ref="invented-account",
        exported_at=exported_at,
        acquired_at=AT,
        captured_at=AT,
        boundary=B.PERSONAL,
        classification=C.CONFIDENTIAL,
        selections=choices,
    )
    proposal = ClaudeCustodyProposal.model_validate_json(proposal_raw)
    original = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(raw),
        trust_boundary=B.PERSONAL,
        effective_classification=C.CONFIDENTIAL,
    )
    envelope = _envelope(proposal, str(original.source_id))
    companion = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(envelope),
        trust_boundary=B.PERSONAL,
        effective_classification=C.CONFIDENTIAL,
    )
    companion_raw = canonical_bytes(__import__("json").loads(envelope)["companion"])
    return ReadClaudeCustody(
        original,
        companion,
        content_hash_of(proposal_raw),
        proposal,
        raw,
        companion_raw,
        AT,
        original,
        companion,
        envelope,
        C.CONFIDENTIAL,
        original.source_id,
        False,
        len(raw) <= MAX_EXPORT_BYTES,
        any(
            m.reported_created_at > proposal.acquired_at
            or m.reported_updated_at > proposal.acquired_at
            for m in messages
            if m.original_id in selected_ids
        ),
    )


def prepare(read, start=0, end=8):
    return lane.prepare_claude_large_original_message(
        read, message_id=MID, character_start=start, character_end=end
    )


@pytest.mark.parametrize("padding", [0, MAX_RECORD_BYTES + 1, MAX_EXPORT_BYTES + 1])
def test_fixed_message_profile_exact_binding_and_unchanged_legacy(padding):
    read = prepared(padding=padding)
    result = prepare(read)
    assert result.capture_binding_projection.selected_text == "Invented"
    assert result.profile.original_binding_reference == read.original_binding_reference
    assert result.profile.current_original_reference == read.original_reference
    assert result.profile.companion_binding_reference == read.companion_binding_reference
    assert result.profile.current_companion_reference == read.companion_reference
    assert result.profile.proposal_hash == read.proposal_hash
    assert result.profile.custody_id == read.proposal.custody_id
    assert result.profile.original_file_bytes == len(read.original_raw)
    assert result.profile.original_file_hash == content_hash_of(read.original_raw)
    assert result.profile.message_capacity_bytes == 128_000
    assert result.profile.original_capacity_bytes == 100_000_000
    assert result.profile.required_protection == "COMPLETE_ORIGINAL_AND_COMPANION"
    assert result.profile_hash == content_hash_of(result.profile_raw)
    assert result.profile_raw == canonical_bytes(result.profile.model_dump(mode="json"))
    assert result.requires_verified_whole_original_and_companion_recovery
    assert not any(
        (
            result.processing_authorized,
            result.recovery_verified,
            result.current_facts_verified,
            result.owner_authenticated,
        )
    )
    if padding:
        with pytest.raises(ClaudeMessageProjectionError):
            extract_claude_selected_message(
                read.companion_raw,
                read.original_raw,
                expected_companion_hash=content_hash_of(read.companion_raw),
                expected_original_reference=read.original_reference,
                expected_account_ref=read.proposal.account_ref,
                expected_exported_at=read.proposal.exported_at,
                character_start=0,
                character_end=8,
            )
    else:
        legacy = extract_claude_selected_message(
            read.companion_raw,
            read.original_raw,
            expected_companion_hash=content_hash_of(read.companion_raw),
            expected_original_reference=read.original_reference,
            expected_account_ref=read.proposal.account_ref,
            expected_exported_at=read.proposal.exported_at,
            character_start=0,
            character_end=8,
        )
        assert legacy == result.capture_binding_projection


@pytest.mark.parametrize("field", ["original", "companion", "proposal", "date", "reference"])
def test_changed_read_observation_holds_with_actual_good_control(field):
    read = prepared()
    assert prepare(read).capture_binding_projection.selected_text == "Invented"
    if field == "original":
        changed = replace(read, original_raw=read.original_raw.replace(b"Invented", b"Changed!"))
    elif field == "companion":
        changed = replace(read, companion_raw=read.companion_raw + b" ")
    elif field == "proposal":
        changed = replace(read, proposal_hash="0" * 64)
    elif field == "date":
        changed = replace(read, captured_at=datetime(2026, 10, 7, 13, tzinfo=UTC))
    else:
        changed = replace(
            read,
            original_reference=read.original_reference.model_copy(update={"source_id": uuid4()}),
        )
    with pytest.raises(lane.ClaudeLargeOriginalMessageError):
        prepare(changed)


def test_unknown_parent_holds_own_lineage():
    read = prepared(parent=uuid4())
    with pytest.raises(lane.ClaudeLargeOriginalMessageError):
        prepare(read)


@pytest.mark.parametrize("start,end", [(True, 8), (0, 8_001), (-1, 8), (0, 999)])
def test_original_text_bounds_remain(start, end):
    read = prepared()
    with pytest.raises(lane.ClaudeLargeOriginalMessageError):
        prepare(read, start, end)


def test_large_profile_changes_with_exact_selected_span():
    read = prepared(text="Unicode café 😀 dated history")
    first = prepare(read, 0, 7)
    second = prepare(read, 8, 12)
    assert first.profile_hash != second.profile_hash
    assert second.capture_binding_projection.selected_text == "café"
    assert second.capture_binding_projection.selected_text_hash == content_hash_of("café".encode())
    assert (
        second.capture_binding_projection.selected_decoded_utf8_end
        - second.capture_binding_projection.selected_decoded_utf8_start
        == 5
    )


def test_oversized_whole_original_holds_before_reparse(monkeypatch):
    read = prepared()
    entered = []

    def forbidden(*args, **kwargs):
        entered.append("reparse")
        raise AssertionError("must not reparse")

    monkeypatch.setattr(lane, "_validated", forbidden)
    with pytest.raises(lane.ClaudeLargeOriginalMessageError):
        prepare(replace(read, original_raw=b" " * (100_000_000 + 1)))
    assert entered == []


def test_fixed_flags_cannot_be_constructor_or_replace_permissions():
    result = prepare(prepared())
    with pytest.raises(ValueError):
        replace(result, processing_authorized=True)
    assert result.profile.selected_character_capacity == 8_000
    assert result.profile.selected_utf8_capacity_bytes == 12_000


@pytest.mark.parametrize(
    "text",
    ["x" * 1501, ("x\n" * 251).rstrip(), "😀" * 1300 + "\n" + "😀" * 1300 + "\n" + "😀" * 1300],
)
def test_distinct_existing_line_and_utf8_limits_hold(text):
    read = prepared(text=text)
    with pytest.raises(lane.ClaudeLargeOriginalMessageError):
        prepare(read, 0, len(text))


def test_future_imported_capacity_drift_holds_before_original_parse(monkeypatch):
    read = prepared()
    entered = []
    monkeypatch.setattr(lane, "MAX_INPUT_BYTES", 200_000_000)
    monkeypatch.setattr(lane, "_validated", lambda *args: entered.append("parse"))
    with pytest.raises(lane.ClaudeLargeOriginalMessageError):
        prepare(read)
    assert entered == []


def test_oversized_message_cannot_obtain_custody_selection_even_for_tiny_text_slice():
    from zacai.claude_original_capture import ClaudeOriginalCaptureError

    # Public custody preparation rejects the full record before a tiny excerpt
    # could be requested. No fabricated read observation bypasses this gate.
    with pytest.raises(ClaudeOriginalCaptureError):
        prepared(text="x" * (MAX_RECORD_BYTES + 1))


def rebound_proposal(read, proposal):
    """Invented supplied observation: rebinding hashes is not Source authority."""
    import json

    raw = canonical_bytes(proposal.model_dump(mode="json"))
    envelope = _envelope(proposal, str(read.original_reference.source_id))
    return replace(
        read,
        proposal=proposal,
        proposal_hash=content_hash_of(raw),
        companion_reference=read.companion_reference.model_copy(
            update={"content_hash": content_hash_of(envelope)}
        ),
        companion_binding_reference=read.companion_binding_reference.model_copy(
            update={"content_hash": content_hash_of(envelope)}
        ),
        envelope_raw=envelope,
        companion_raw=canonical_bytes(json.loads(envelope)["companion"]),
    )


@pytest.mark.parametrize("mutation", ["role", "date", "range"])
def test_hash_consistent_selected_metadata_still_matches_original_record(mutation):
    read = prepared()
    selected = read.proposal.selections[0]
    assert prepare(read).capture_binding_projection.selected_text == "Invented"
    if mutation == "role":
        changed = selected.model_copy(update={"role": "ASSISTANT"})
    elif mutation == "date":
        changed = selected.model_copy(update={"reported_at": AT})
    else:
        changed = selected.model_copy(
            update={
                "end": selected.end - 1,
                "content_hash": content_hash_of(
                    read.original_raw[selected.start : selected.end - 1]
                ),
            }
        )
    forged = rebound_proposal(read, read.proposal.model_copy(update={"selections": (changed,)}))
    # The recomputed envelope and proposal digests match, so denial is actual
    # span/date/role verification, not merely a stale outer digest.
    assert forged.proposal_hash == content_hash_of(
        canonical_bytes(forged.proposal.model_dump(mode="json"))
    )
    assert forged.companion_reference.content_hash == content_hash_of(
        _envelope(forged.proposal, str(forged.original_reference.source_id))
    )
    with pytest.raises(lane.ClaudeLargeOriginalMessageError):
        prepare(forged)


@pytest.mark.parametrize("elevated_field", ["original_reference", "companion_reference"])
def test_permitted_current_label_is_separate_from_immutable_custody(elevated_field):
    read = prepared(padding=MAX_EXPORT_BYTES + 1)
    before = prepare(read)
    changed = replace(
        read,
        **{
            elevated_field: getattr(read, elevated_field).model_copy(
                update={"effective_classification": C.HIGHLY_RESTRICTED}
            )
        },
        joint_output_classification=C.HIGHLY_RESTRICTED,
    )
    after = prepare(changed)
    assert after.capture_binding_projection == before.capture_binding_projection
    assert after.capture_binding_projection.reference == read.original_binding_reference
    assert after.profile.original_binding_reference == read.original_binding_reference
    assert after.profile.companion_binding_reference == read.companion_binding_reference
    assert after.profile.current_original_reference == changed.original_reference
    assert after.profile.current_companion_reference == changed.companion_reference
    assert after.profile.joint_output_classification == C.HIGHLY_RESTRICTED
    assert after.profile_hash != before.profile_hash
    assert after.profile.original_binding_reference.effective_classification == C.CONFIDENTIAL
    assert not after.processing_authorized and not after.recovery_verified


@pytest.mark.parametrize(
    "mutation", ["weaker", "boundary", "hash", "source_id", "joint", "zero", "envelope"]
)
def test_current_observation_mismatches_hold_after_actual_positive(mutation):
    read = prepared()
    assert prepare(read).capture_binding_projection.selected_text == "Invented"
    if mutation == "joint":
        changed = replace(read, joint_output_classification=C.PUBLIC)
    elif mutation == "zero":
        zero = read.companion_reference.model_copy(update={"source_id": ZERO})
        changed = replace(read, companion_reference=zero, companion_binding_reference=zero)
    elif mutation == "envelope":
        changed = replace(read, envelope_raw=read.envelope_raw + b" ")
    else:
        updates = {
            "weaker": {"effective_classification": C.PUBLIC},
            "boundary": {"trust_boundary": B.BRAINSTORM},
            "hash": {"content_hash": "0" * 64},
            "source_id": {"source_id": uuid4()},
        }[mutation]
        changed = replace(
            read, original_reference=read.original_reference.model_copy(update=updates)
        )
    with pytest.raises(lane.ClaudeLargeOriginalMessageError):
        prepare(changed)


def test_unrelated_missing_lineage_is_not_promoted_or_applied_to_selected_root():
    sibling_id, absent = uuid4(), uuid4()
    sibling = {
        "uuid": str(sibling_id),
        "sender": "assistant",
        "text": "Unassessed sibling",
        "content": [],
        "created_at": "2026-10-06T12:00:00Z",
        "updated_at": "2026-10-06T12:00:00Z",
        "parent_message_uuid": str(absent),
    }
    read = prepared(siblings=(sibling,))
    index = index_claude_member_history(
        read.original_raw, expected_file_hash=read.original_reference.content_hash
    )
    target, unresolved = index.conversations[0].messages
    assert target.lineage_complete
    assert not unresolved.lineage_complete and unresolved.parent_status == "UNRESOLVED_MISSING"
    result = prepare(read)
    assert result.profile.parent_status == "EXPLICIT_ZERO_ROOT"
    assert result.profile.coverage == "SELECTED_MESSAGE_ONLY"
    assert not result.profile.other_content_assessed
    assert result.capture_binding_projection.message_id == MID


def test_unknown_export_date_preserves_selected_chronology_conflict_without_promotion():
    past = prepared(reported_date="2026-10-06T12:00:00Z", exported_at=None)
    future = prepared(reported_date="2026-10-07T12:00:00Z", exported_at=None)
    past_result, future_result = prepare(past), prepare(future)
    assert not past_result.profile.selected_dates_after_acquired_at
    assert future_result.profile.selected_dates_after_acquired_at
    assert future_result.profile.custody_selected_dates_after_acquired_at
    assert future_result.profile.declared_exported_at is None
    assert future_result.profile.declared_acquired_at == AT
    assert future_result.profile.declared_captured_at == AT
    assert future_result.profile.date_semantics == "HOST_DECLARED_AND_EXPORT_REPORTED"
    assert future_result.profile_hash != past_result.profile_hash
    assert not future_result.current_facts_verified and not future_result.processing_authorized
    decoded = lane.ClaudeLargeOriginalMessageProfile.model_validate_json(future_result.profile_raw)
    assert decoded == future_result.profile and decoded.selected_dates_after_acquired_at
    assert decoded.projection_reference_semantics == "IMMUTABLE_CAPTURE_BINDING_ONLY"
    with pytest.raises(lane.ClaudeLargeOriginalMessageError):
        prepare(replace(future, reported_dates_after_acquired_at=False))


def test_multiple_retained_messages_are_explicit_v2_selected_message_scope():
    second_id = uuid4()
    second = {
        "uuid": str(second_id),
        "sender": "assistant",
        "text": "Invented second message",
        "content": [],
        "created_at": "2026-10-06T12:00:00Z",
        "updated_at": "2026-10-06T12:00:00Z",
        "parent_message_uuid": str(MID),
    }
    read = prepared(siblings=(second,), selected_ids=(MID, second_id))
    first = prepare(read)
    later = lane.prepare_claude_large_original_message(
        read, message_id=second_id, character_start=0, character_end=8
    )
    assert (
        first.profile.custody_selected_record_count
        == later.profile.custody_selected_record_count
        == 2
    )
    assert first.profile.coverage == later.profile.coverage == "SELECTED_MESSAGE_ONLY"
    assert first.profile.selection.original_id != later.profile.selection.original_id
    assert first.profile_hash != later.profile_hash
    assert first.capture_binding_projection.reference == later.capture_binding_projection.reference
    assert later.capture_binding_projection.historical_role == "ASSISTANT"
    with pytest.raises(ClaudeMessageProjectionError):
        extract_claude_selected_message(
            read.companion_raw,
            read.original_raw,
            expected_companion_hash=content_hash_of(read.companion_raw),
            expected_original_reference=read.original_binding_reference,
            expected_account_ref=read.proposal.account_ref,
            expected_exported_at=read.proposal.exported_at,
            character_start=0,
            character_end=8,
        )


def test_superseded_dated_original_remains_evidence_with_distinct_observation_profile():
    read = prepared()
    first = prepare(read)
    historical = replace(read, original_tip_id=uuid4(), superseded_at_read=True)
    second = prepare(historical)
    assert second.capture_binding_projection == first.capture_binding_projection
    assert second.profile.original_tip_id == historical.original_tip_id
    assert second.profile.superseded_at_read
    assert second.profile_hash != first.profile_hash
    assert not second.current_facts_verified and not second.recovery_verified
    assert not hasattr(second, "projection")
    with pytest.raises(lane.ClaudeLargeOriginalMessageError):
        prepare(replace(read, original_tip_id=uuid4(), superseded_at_read=False))


@pytest.mark.parametrize(
    "field,value",
    [
        ("original_tip_id", "not-uuid"),
        ("superseded_at_read", 1),
        ("reported_dates_after_acquired_at", "False"),
        ("original_within_legacy_byte_limit", 1),
    ],
)
def test_typed_read_metadata_does_not_coerce_to_observation(field, value):
    read = prepared()
    assert prepare(read).profile.date_semantics == "HOST_DECLARED_AND_EXPORT_REPORTED"
    with pytest.raises(lane.ClaudeLargeOriginalMessageError):
        prepare(replace(read, **{field: value}))


@pytest.mark.parametrize(
    "field,value", [("trust_boundary", B.BRAINSTORM), ("effective_classification", C.PUBLIC)]
)
def test_both_base_refs_cannot_drift_from_hash_consistent_proposal(field, value):
    read = prepared()
    assert prepare(read).capture_binding_projection.selected_text == "Invented"
    original = read.original_binding_reference.model_copy(update={field: value})
    companion = read.companion_binding_reference.model_copy(update={field: value})
    forged = replace(
        read,
        original_binding_reference=original,
        original_reference=original,
        companion_binding_reference=companion,
        companion_reference=companion,
        joint_output_classification=original.effective_classification,
    )
    assert original.trust_boundary == companion.trust_boundary
    assert original.effective_classification == companion.effective_classification
    with pytest.raises(lane.ClaudeLargeOriginalMessageError):
        prepare(forged)


def test_current_companion_strongest_label_is_not_original_source_relabeling():
    read = prepared()
    changed = replace(
        read,
        companion_reference=read.companion_reference.model_copy(
            update={"effective_classification": C.HIGHLY_RESTRICTED}
        ),
        joint_output_classification=C.HIGHLY_RESTRICTED,
    )
    result = prepare(changed)
    assert result.profile.current_original_reference.effective_classification == C.CONFIDENTIAL
    assert (
        result.profile.current_companion_reference.effective_classification == C.HIGHLY_RESTRICTED
    )
    assert result.profile.joint_output_classification == C.HIGHLY_RESTRICTED
    with pytest.raises(lane.ClaudeLargeOriginalMessageError):
        prepare(replace(changed, joint_output_classification=C.CONFIDENTIAL))


def test_earlier_ancestor_gap_propagates_to_selected_message():
    parent_id = uuid4()
    parent = {
        "uuid": str(parent_id),
        "sender": "human",
        "text": "Invented ancestor",
        "content": [],
        "created_at": "2026-10-06T12:00:00Z",
        "updated_at": "2026-10-06T12:00:00Z",
        "parent_message_uuid": str(ZERO),
    }
    positive = prepared(parent=parent_id, prefixes=(parent,))
    assert prepare(positive).profile.parent_status == "RESOLVED_EARLIER"
    missing = {**parent, "parent_message_uuid": str(uuid4())}
    broken = prepared(parent=parent_id, prefixes=(missing,))
    with pytest.raises(lane.ClaudeLargeOriginalMessageError):
        prepare(broken)


def test_message_not_in_retained_custody_selection_holds_even_if_present_in_original():
    second_id = uuid4()
    second = {
        "uuid": str(second_id),
        "sender": "human",
        "text": "Invented unselected record",
        "content": [],
        "created_at": "2026-10-06T12:00:00Z",
        "updated_at": "2026-10-06T12:00:00Z",
        "parent_message_uuid": str(MID),
    }
    read = prepared(siblings=(second,))
    assert prepare(read).capture_binding_projection.message_id == MID
    with pytest.raises(lane.ClaudeLargeOriginalMessageError):
        lane.prepare_claude_large_original_message(
            read, message_id=second_id, character_start=0, character_end=8
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_id", str(MID)),
        ("trust_boundary", "PERSONAL"),
        ("effective_classification", "CONFIDENTIAL"),
    ],
)
def test_reference_values_require_actual_reader_types_not_model_copy_coercion(field, value):
    read = prepared()
    assert prepare(read).capture_binding_projection.selected_text == "Invented"
    changed = read.original_reference.model_copy(update={field: value})
    with pytest.raises(lane.ClaudeLargeOriginalMessageError):
        prepare(replace(read, original_reference=changed))


def test_custody_date_conflict_does_not_replace_selected_own_date_observation():
    second_id = uuid4()
    second = {
        "uuid": str(second_id),
        "sender": "human",
        "text": "Invented future reported message",
        "content": [],
        "created_at": "2026-10-07T12:00:00Z",
        "updated_at": "2026-10-07T12:00:00Z",
        "parent_message_uuid": str(MID),
    }
    read = prepared(siblings=(second,), selected_ids=(MID, second_id), exported_at=None)
    past = prepare(read)
    future = lane.prepare_claude_large_original_message(
        read, message_id=second_id, character_start=0, character_end=8
    )
    assert past.profile.custody_selected_dates_after_acquired_at
    assert not past.profile.selected_dates_after_acquired_at
    assert future.profile.custody_selected_dates_after_acquired_at
    assert future.profile.selected_dates_after_acquired_at
    assert past.profile_hash != future.profile_hash
    assert not past.current_facts_verified and not future.current_facts_verified
