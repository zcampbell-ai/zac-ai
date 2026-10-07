"""Invented preparation-only inputs, no committed/read/recovery authority."""

import json
from dataclasses import replace
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from tests.test_claude_large_original_message import AT, MID, ZERO, prepared
from zacai import claude_historical_fragment as f
from zacai import claude_large_original_message as old
from zacai.claude_message_projection import (
    ClaudeMessageProjectionError,
    extract_claude_selected_message,
)
from zacai.claude_original_capture import ClaudeOriginalCaptureError
from zacai.ingestion.artifact_store import content_hash_of
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


def prepare(read, *, message_id=MID, start=0, end=8):
    return f.prepare_claude_historical_fragment(
        read, message_id=message_id, character_start=start, character_end=end
    )


def test_direct_gap_literal_exact_binding_and_legacy_holds():
    missing = uuid4()
    read = prepared(parent=missing)
    result = prepare(read)
    profile, literal = result.profile, result.fragment
    assert profile.coverage == "SELECTED_LITERAL_FRAGMENT_ONLY"
    assert profile.parent_id == literal.parent_id == missing
    assert profile.lineage_gap == literal.lineage_gap == "DIRECT_MISSING_PARENT"
    assert profile.parent_status == literal.parent_status == "UNRESOLVED_MISSING"
    assert profile.thread_context_complete is literal.thread_context_complete is False
    assert profile.lineage_complete is literal.lineage_complete is False
    assert literal.message_id == UUID(profile.selection.original_id) == MID
    assert literal.selected_text == "Invented"
    assert literal.historical_role == profile.selection.role == "USER"
    assert literal.reported_created_at == profile.selection.reported_at
    assert literal.record_hash == content_hash_of(
        read.original_raw[literal.record_bytes.start : literal.record_bytes.end]
    )
    assert profile.proposal_hash == read.proposal_hash
    assert profile.original_file_hash == content_hash_of(read.original_raw)
    assert result.profile_hash == content_hash_of(result.profile_raw)
    assert json.loads(result.profile_raw)["lineage_complete"] is False
    assert not hasattr(result, "capture_binding_projection")
    assert type(result) is not old.ClaudeLargeOriginalMessagePreparation
    with pytest.raises(old.ClaudeLargeOriginalMessageError):
        old.prepare_claude_large_original_message(
            read, message_id=MID, character_start=0, character_end=8
        )
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


def test_inherited_gap_preserves_actual_immediate_parent():
    missing, parent = uuid4(), uuid4()
    earlier = {
        "uuid": str(parent),
        "sender": "assistant",
        "text": "Invented earlier suggestion",
        "content": [],
        "created_at": "2026-10-06T11:00:00Z",
        "updated_at": "2026-10-06T11:00:00Z",
        "parent_message_uuid": str(missing),
    }
    result = prepare(prepared(parent=parent, prefixes=(earlier,)))
    assert result.fragment.parent_id == parent
    assert result.fragment.parent_status == "RESOLVED_EARLIER"
    assert result.profile.lineage_gap == "INHERITED_MISSING_ANCESTOR"
    assert not result.profile.lineage_complete


def test_complete_root_continues_v2_not_fragment():
    read = prepared(parent=ZERO)
    assert (
        old.prepare_claude_large_original_message(
            read, message_id=MID, character_start=0, character_end=8
        ).capture_binding_projection.selected_text
        == "Invented"
    )
    with pytest.raises(f.ClaudeHistoricalFragmentError):
        prepare(read)


def test_exact_unicode_utf8_offsets():
    read = prepared(parent=uuid4(), text="αé🙂 dated literal")
    result = prepare(read, start=1, end=3)
    assert result.fragment.selected_text == "é🙂"
    assert (
        result.fragment.selected_decoded_utf8_start,
        result.fragment.selected_decoded_utf8_end,
    ) == (2, 8)
    assert (
        json.loads(
            read.original_raw[
                result.fragment.text_json_bytes.start : result.fragment.text_json_bytes.end
            ]
        )
        == "αé🙂 dated literal"
    )


def test_large_wholeoriginal_small_fragment_preserves_legacy_flag():
    read = prepared(parent=uuid4(), padding=8_000_001)
    result = prepare(read)
    assert result.profile.original_file_bytes > 8_000_000
    assert not result.profile.original_within_legacy_byte_limit
    assert not result.profile.lineage_complete


@pytest.mark.parametrize(
    "field,value",
    [
        ("original_raw", b"[]"),
        ("companion_raw", b"{}"),
        ("envelope_raw", b"{}"),
        ("proposal_hash", "0" * 64),
        ("joint_output_classification", C.PUBLIC),
        ("reported_dates_after_acquired_at", True),
        ("captured_at", AT.replace(year=2027)),
    ],
)
def test_changed_read_relationship_holds(field, value):
    read = prepared(parent=uuid4())
    with pytest.raises(f.ClaudeHistoricalFragmentError):
        prepare(replace(read, **{field: value}))


@pytest.mark.parametrize("mutation", ["foreign_id", "hash", "boundary", "weaker"])
def test_current_reference_mutation_holds(mutation):
    read = prepared(parent=uuid4())
    update = {
        "foreign_id": {"source_id": uuid4()},
        "hash": {"content_hash": "0" * 64},
        "boundary": {"trust_boundary": B.BRAINSTORM},
        "weaker": {"effective_classification": C.PUBLIC},
    }[mutation]
    changed = read.original_reference.model_copy(update=update)
    with pytest.raises(f.ClaudeHistoricalFragmentError):
        prepare(replace(read, original_reference=changed))


def test_actual_current_sensitivity_tip_and_date_observations_retained():
    read = prepared(parent=uuid4(), exported_at=None, reported_date="2026-10-07T12:00:00Z")
    changed = replace(
        read,
        original_reference=read.original_reference.model_copy(
            update={"effective_classification": C.HIGHLY_RESTRICTED}
        ),
        joint_output_classification=C.HIGHLY_RESTRICTED,
        original_tip_id=uuid4(),
        superseded_at_read=True,
    )
    result = prepare(changed)
    assert result.profile.original_binding_reference.effective_classification == C.CONFIDENTIAL
    assert result.profile.current_original_reference.effective_classification == C.HIGHLY_RESTRICTED
    assert result.profile.joint_output_classification == C.HIGHLY_RESTRICTED
    assert result.profile.superseded_at_read and result.profile.selected_dates_after_acquired_at
    assert result.profile.declared_exported_at is None
    assert result.profile_hash != prepare(read).profile_hash


def test_retained_selection_and_strict_input_holds():
    read = prepared(parent=uuid4())
    for identity, start, end in [(uuid4(), 0, 8), (MID, False, 8), (MID, 0, 8001), (MID, 0, 100)]:
        with pytest.raises(f.ClaudeHistoricalFragmentError):
            prepare(read, message_id=identity, start=start, end=end)


@pytest.mark.parametrize(
    "text,end", [("x" * 1501, 1501), ("é" * 7000, 7000), ("x\n" * 250 + "x", 501), (" x", 2)]
)
def test_original_text_budgets_still_hold(text, end):
    with pytest.raises(f.ClaudeHistoricalFragmentError):
        prepare(prepared(parent=uuid4(), text=text), end=end)


def test_oversize_retained_message_not_enrollable():
    with pytest.raises(ClaudeOriginalCaptureError):
        prepared(parent=uuid4(), text="x" * 128_001)


def test_false_flags_and_profile_cannot_be_revalidated_as_complete():
    result = prepare(prepared(parent=uuid4()))
    for name in (
        "owner_authenticated",
        "recovery_verified",
        "processing_authorized",
        "current_facts_verified",
    ):
        assert getattr(result, name) is getattr(result.fragment, name) is False
        with pytest.raises(ValueError):
            replace(result, **{name: True})
    with pytest.raises(ValidationError):
        f.ClaudeHistoricalFragmentProfileV1.model_validate(
            result.profile.model_copy(update={"lineage_complete": True})
        )
    assert "Invented" not in repr(result) and "Invented" not in repr(result.fragment)


def test_present_forward_parent_remains_hard_hold():
    later = uuid4()
    row = {
        "uuid": str(later),
        "sender": "human",
        "text": "Invented later",
        "content": [],
        "created_at": "2026-10-06T13:00:00Z",
        "updated_at": "2026-10-06T13:00:00Z",
        "parent_message_uuid": str(ZERO),
    }
    with pytest.raises(ValueError):
        prepared(parent=later, siblings=(row,))


def test_existing_unselected_message_holds_after_selected_positive():
    other = uuid4()
    row = {
        "uuid": str(other),
        "sender": "assistant",
        "text": "Invented unselected suggestion",
        "content": [],
        "created_at": "2026-10-06T13:00:00Z",
        "updated_at": "2026-10-06T13:00:00Z",
        "parent_message_uuid": str(uuid4()),
    }
    read = prepared(parent=uuid4(), siblings=(row,))
    assert prepare(read).fragment.message_id == MID
    with pytest.raises(f.ClaudeHistoricalFragmentError):
        prepare(read, message_id=other)


@pytest.mark.parametrize(
    "field,value",
    [
        ("coverage", "SELECTED_MESSAGE_ONLY"),
        ("format", "zac-claude-canonical-original-message-profile-v2"),
        ("thread_context_complete", True),
        ("message_capacity_bytes", 128001),
    ],
)
def test_fragment_profile_discriminator_and_limits_remain_closed(field, value):
    profile = prepare(prepared(parent=uuid4())).profile
    with pytest.raises(ValidationError):
        f.ClaudeHistoricalFragmentProfileV1.model_validate(
            profile.model_copy(update={field: value})
        )
    with pytest.raises(ValidationError):
        old.ClaudeLargeOriginalMessageProfile.model_validate(profile.model_dump(mode="json"))


def test_unrebound_proposal_role_change_holds():
    read = prepared(parent=uuid4())
    # This earlier control changes the proposal without rebinding its hash.
    # The separate coherent-envelope control reaches actual record-role checks.
    proposal = read.proposal.model_copy(
        update={
            "selections": (read.proposal.selections[0].model_copy(update={"role": "ASSISTANT"}),)
        }
    )
    with pytest.raises(f.ClaudeHistoricalFragmentError):
        prepare(replace(read, proposal=proposal))


@pytest.mark.parametrize(
    "fault",
    [
        "gap",
        "parent_zero",
        "parent_self",
        "selected_uuid",
        "role",
        "date_absent",
        "date_order",
        "date_flag",
        "custody_date_flag",
        "acquired",
        "exported",
        "range",
        "span",
        "current_hash",
        "current_weaker",
        "joint",
        "tip",
        "legacy_size",
        "file_hash",
    ],
)
def test_profile_revalidation_owns_closed_relationships(fault):
    profile = prepare(prepared(parent=uuid4())).profile
    assert f.ClaudeHistoricalFragmentProfileV1.model_validate(profile) == profile
    selection = profile.selection
    updates = {
        "gap": {"lineage_gap": "INHERITED_MISSING_ANCESTOR"},
        "parent_zero": {"parent_id": ZERO},
        "parent_self": {"parent_id": UUID(selection.original_id)},
        "selected_uuid": {"selection": selection.model_copy(update={"original_id": "not-a-uuid"})},
        "role": {"selection": selection.model_copy(update={"role": "TRANSCRIPT"})},
        "date_absent": {"selection": selection.model_copy(update={"reported_at": None})},
        "date_order": {"reported_updated_at": selection.reported_at - timedelta(seconds=1)},
        "date_flag": {"selected_dates_after_acquired_at": True},
        "custody_date_flag": {
            "selected_dates_after_acquired_at": True,
            "reported_updated_at": profile.declared_acquired_at + timedelta(seconds=1),
            "custody_selected_dates_after_acquired_at": False,
        },
        "acquired": {"declared_acquired_at": profile.declared_captured_at + timedelta(seconds=1)},
        "exported": {"declared_exported_at": profile.declared_acquired_at + timedelta(seconds=1)},
        "range": {"character_start": 9, "character_end": 8},
        "span": {
            "selection": selection.model_copy(update={"end": selection.start + 128001}),
            "original_file_bytes": 200000,
        },
        "current_hash": {
            "current_original_reference": profile.current_original_reference.model_copy(
                update={"content_hash": "0" * 64}
            )
        },
        "current_weaker": {
            "current_companion_reference": profile.current_companion_reference.model_copy(
                update={"effective_classification": C.PUBLIC}
            )
        },
        "joint": {"joint_output_classification": C.PUBLIC},
        "tip": {"original_tip_id": uuid4()},
        "legacy_size": {"original_within_legacy_byte_limit": False},
        "file_hash": {"original_file_hash": "0" * 64},
    }[fault]
    with pytest.raises(ValidationError):
        f.ClaudeHistoricalFragmentProfileV1.model_validate(profile.model_copy(update=updates))


def test_inherited_profile_pairing_is_owned_on_revalidation():
    missing, parent = uuid4(), uuid4()
    earlier = {
        "uuid": str(parent),
        "sender": "assistant",
        "text": "Invented prior fragment",
        "content": [],
        "created_at": "2026-10-06T11:00:00Z",
        "updated_at": "2026-10-06T11:00:00Z",
        "parent_message_uuid": str(missing),
    }
    profile = prepare(prepared(parent=parent, prefixes=(earlier,))).profile
    assert f.ClaudeHistoricalFragmentProfileV1.model_validate(profile) == profile
    with pytest.raises(ValidationError):
        f.ClaudeHistoricalFragmentProfileV1.model_validate(
            profile.model_copy(update={"lineage_gap": "DIRECT_MISSING_PARENT"})
        )


def test_hash_consistent_role_fault_reaches_actual_record_validator(monkeypatch):
    read = prepared(parent=uuid4())
    assert prepare(read).fragment.historical_role == "USER"
    proposal = read.proposal.model_copy(
        update={
            "selections": (read.proposal.selections[0].model_copy(update={"role": "ASSISTANT"}),)
        }
    )
    raw = f.canonical_bytes(proposal.model_dump(mode="json"))
    envelope = f._envelope(proposal, str(read.original_binding_reference.source_id))
    companion = f.canonical_bytes(json.loads(envelope)["companion"])
    companion_ref = read.companion_binding_reference.model_copy(
        update={"content_hash": content_hash_of(envelope)}
    )
    changed = replace(
        read,
        proposal=proposal,
        proposal_hash=content_hash_of(raw),
        envelope_raw=envelope,
        companion_raw=companion,
        companion_binding_reference=companion_ref,
        companion_reference=companion_ref,
    )
    assert content_hash_of(changed.envelope_raw) == changed.companion_reference.content_hash
    assert content_hash_of(raw) == changed.proposal_hash
    actual = f._validated
    entered, rejected = [], []

    def observed(*args, **kwargs):
        entered.append(True)
        try:
            return actual(*args, **kwargs)
        except ValueError:
            rejected.append(True)
            raise

    monkeypatch.setattr(f, "_validated", observed)
    with pytest.raises(f.ClaudeHistoricalFragmentError):
        prepare(changed)
    assert entered == rejected == [True]
    from zacai.claude_custody_selection import ClaudeCustodySelectionError

    with pytest.raises(ClaudeCustodySelectionError):
        f.inspect_claude_custody_selection(
            companion,
            read.original_raw,
            expected_companion_hash=content_hash_of(companion),
            expected_original_reference=read.original_binding_reference,
            expected_account_ref=proposal.account_ref,
            expected_exported_at=proposal.exported_at,
        )
