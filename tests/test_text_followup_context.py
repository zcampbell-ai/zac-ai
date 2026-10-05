"""Invented canonical bytes/Source objects with an in-memory ledger seam.

The real turn capture/parser and packet source/byte loaders run; SQL/recovery is
mocked and makes no actual off-device claim. No model, account or runtime calls.
"""

from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_text_turn_capture import fixture as capture_fixture
from zacai.intelligence import briefing_delivery, contextual_storage
from zacai.intelligence.contextual_evaluation import encode_contextual_packet
from zacai.intelligence.followup_generation import prepare_followup_request
from zacai.intelligence.text_followup import (
    FOLLOWUP_CAPABILITY,
    FOLLOWUP_INSTRUCTION,
    TextFollowupError,
)
from zacai.intelligence.work_proposals import packet_fingerprint
from zacai.interfaces import text_followup_context as module
from zacai.interfaces import text_turn_capture
from zacai.interfaces.private_web import OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem


@pytest.fixture
def fixture(monkeypatch):
    state = capture_fixture.__wrapped__(monkeypatch)
    factory = state.client._factory
    factory.new = factory.dirty = factory.deleted = frozenset()
    # Store the actual canonical packet bytes and exact Source metadata, not just
    # a shaped reference or callback returning a made-up packet.
    raw = encode_contextual_packet(
        state.packet.review,
        state.packet.context(),
        builder_id=state.packet.builder_id,
        created_at=state.packet.created_at,
    )
    digest = packet_fingerprint(state.packet)
    assert state.receipt.locator.packet_digest == digest
    state.raw[digest] = raw
    packet_source = Source(
        id=state.receipt.locator.packet_source_id,
        system=SourceSystem.MANUAL,
        trust_boundary=B.BRAINSTORM,
        data_classification=C.CONFIDENTIAL,
        content_hash=digest,
        content_location=digest,
        external_ref=f"contextual-review-packet/{digest}",
        captured_at=state.packet.created_at,
    )
    state.sources[packet_source.external_ref] = packet_source
    for item in state.packet.task.context:
        ref = item.reference
        source = Source(
            id=ref.source_id,
            system=SourceSystem.MANUAL,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            content_hash=ref.content_hash,
            content_location=ref.content_hash,
            external_ref=f"invented-evidence/{ref.source_id}",
            captured_at=state.packet.created_at,
        )
        state.sources[source.external_ref] = source

    def get_source(session, *, source_id, requestor_boundaries):
        source = session.get(Source, source_id)
        return source if source and source.trust_boundary in requestor_boundaries else None

    def label(session, *, source_id):
        return session.get(Source, source_id).data_classification

    monkeypatch.setattr(contextual_storage, "get_source", get_source)
    monkeypatch.setattr(contextual_storage, "get_effective_source_classification", label)
    monkeypatch.setattr(
        briefing_delivery, "load_contextual_packet", contextual_storage.load_contextual_packet
    )

    def record(session, **fields):
        source = Source(id=uuid4(), **fields)
        session.pending[source.external_ref] = source
        return source, True

    monkeypatch.setattr(text_turn_capture, "record_source", record)
    state.assembler = module.CanonicalFollowupAssembler(capture=state.client)
    return state


def assemble(state, saved):
    return state.assembler.assemble(
        principal=state.inputs["principal"],
        source_id=saved.source_id,
        expected_turn_digest=saved.turn_digest,
        retained_receipt=state.receipt,
        expected_receipt_digest=state.inputs["expected_receipt_digest"],
        recovery_receipt=saved.recovery_receipt,
    )


def test_canonical_turn_and_actual_packet_bytes_assemble_fixed_v1_context(fixture):
    state = fixture
    saved = state.client.capture(**state.inputs)
    before = state.rechecks
    assembled = assemble(state, saved)
    context = assembled.context
    assert assembled.saved_turn == saved and state.rechecks == before + 2
    assert context.user_reference == saved.reference
    assert (
        context.packet_reference.content_hash
        == state.receipt.locator.packet_digest
        == packet_fingerprint(context.packet)
    )
    assert context.task.required_capabilities == frozenset({FOLLOWUP_CAPABILITY})
    assert context.task.instruction == FOLLOWUP_INSTRUCTION
    assert context.task.event.correlation_id == saved.turn.conversation_id
    assert context.task.event.occurred_at == saved.turn.recorded_at
    assert context.task.max_output_tokens == 512 and context.task.max_latency_ms == 60_000
    assert context.task.max_estimated_cost_usd == 0.0
    assert tuple(context.task.context[1:]) == state.packet.task.context
    assert not assembled.processing_authorized and not assembled.execution_authorized
    assert saved.turn.original_text not in repr(assembled)
    assert prepare_followup_request(context).processing_authorized is False


def test_exact_envelope_preserved_but_question_projection_and_offsets_are_explicit(fixture):
    state = fixture
    original = " \r\n  How does café change this?  \r\n"
    saved = state.client.capture(**{**state.inputs, "original_utf8": original.encode()})
    assembled = assemble(state, saved)
    projected = assembled.context.task.context[0].untrusted_text
    assert assembled.saved_turn.turn.original_text == original
    assert projected == original.strip()
    offset = assembled.user_original_offset
    assert original[offset : offset + len(projected)] == projected


def test_explicit_direct_parent_projection_does_not_disclose_ancestors(fixture):
    state = fixture
    grandparent = state.client.capture(**state.inputs)
    parent = state.client.capture(
        **{
            **state.inputs,
            "request_id": uuid4(),
            "original_utf8": b"  Parent question only?\r\n",
            "parent_references": (grandparent.reference,),
        }
    )
    child = state.client.capture(
        **{
            **state.inputs,
            "request_id": uuid4(),
            "original_utf8": b"How about that parent?",
            "parent_references": (parent.reference,),
        }
    )
    assembled = assemble(state, child)
    assert assembled.direct_parent_turns == (parent.turn,)
    assert assembled.context.parent_references == (parent.reference,)
    ids = {i.reference.source_id for i in assembled.context.task.context}
    assert parent.source_id in ids and grandparent.source_id not in ids
    item = next(
        i for i in assembled.context.task.context if i.reference.source_id == parent.source_id
    )
    assert item.untrusted_text == parent.turn.original_text.strip()
    assert assembled.parent_original_offsets == ((parent.source_id, 2),)


def test_pending_parent_needs_no_fabricated_individual_receipt_for_child_scope(fixture):
    state = fixture
    state.fail_protect = True
    with pytest.raises(text_turn_capture.TextTurnCaptureError):
        state.client.capture(**state.inputs)
    source = next(s for s in state.sources.values() if s.system == SourceSystem.USER_INSTRUCTION)
    parent_ref = text_turn_capture.EvidenceReference(
        source_id=source.id,
        content_hash=source.content_hash,
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.CONFIDENTIAL,
    )
    assert source.id not in state.turn_receipts
    state.fail_protect = False
    child = state.client.capture(
        **{
            **state.inputs,
            "request_id": uuid4(),
            "original_utf8": b"Continue the pending question?",
            "parent_references": (parent_ref,),
        }
    )
    assembled = assemble(state, child)
    assert source.id not in state.turn_receipts
    assert assembled.context.parent_references == (parent_ref,)
    # Real adapter must recover the child plus explicit parent dependency; this
    # mock tests receipt selection only, never asserts actual recovered coverage.


@pytest.mark.parametrize(
    "failure",
    [
        "owner",
        "parent_classification",
        "packet_bytes",
        "original_evidence_classification",
        "clock",
        "recovery",
    ],
)
def test_canonical_or_recovery_change_holds_before_assembly_release(fixture, failure):
    state = fixture
    parent = state.client.capture(**state.inputs)
    child = state.client.capture(
        **{**state.inputs, "request_id": uuid4(), "parent_references": (parent.reference,)}
    )
    if failure == "owner":
        state.owner = OwnerGrant(
            Identity(state.owner.identity.issuer, "different-owner"), state.owner.scopes
        )
    elif failure == "parent_classification":
        next(
            s for s in state.sources.values() if s.id == parent.source_id
        ).data_classification = C.HIGHLY_RESTRICTED
    elif failure == "packet_bytes":
        state.raw[state.receipt.locator.packet_digest] = b"corrupt invented packet"
    elif failure == "original_evidence_classification":
        next(
            s
            for s in state.sources.values()
            if s.id == state.packet.task.context[0].reference.source_id
        ).data_classification = C.HIGHLY_RESTRICTED
    elif failure == "clock":
        state.now -= timedelta(seconds=1)
    else:
        state.fail_recheck = True
    with pytest.raises(TextFollowupError) as err:
        assemble(state, child)
    assert err.value.__context__ is None


def test_revocation_during_final_recovery_holds_and_task_identity_is_stable(fixture):
    state = fixture
    saved = state.client.capture(**state.inputs)
    first = assemble(state, saved)
    state.now += timedelta(seconds=1)
    second = assemble(state, saved)
    assert first.context.task.task_id == second.context.task.task_id
    assert first.context.task.event.event_id == second.context.task.event.event_id
    assert second.context.task.event.observed_at > first.context.task.event.observed_at
    initial = state.rechecks

    def changed():
        if state.rechecks == initial + 2:
            state.owner = OwnerGrant(
                Identity(state.owner.identity.issuer, "changed-owner"), state.owner.scopes
            )

    state.after_recheck = changed
    with pytest.raises(TextFollowupError):
        assemble(state, saved)


def test_duck_capture_cannot_supply_mock_success_as_canonical_host(fixture):
    with pytest.raises(TextFollowupError):
        module.CanonicalFollowupAssembler(capture=object())


@pytest.mark.parametrize("stage", ["first_load_completion", "final_load_completion"])
def test_inner_load_clock_observation_cannot_be_lost_between_composition_calls(fixture, stage):
    state = fixture
    saved = state.client.capture(**state.inputs)
    baseline = state.now
    offsets = [20, 100, 90] if stage == "first_load_completion" else [20, 30, 40, 50, 100, 90]
    values = iter(baseline + timedelta(seconds=n) for n in offsets)
    state.client._clock = lambda: next(values)
    with pytest.raises(TextFollowupError):
        assemble(state, saved)
    assert state.client._last_observed == baseline + timedelta(seconds=100)
    with pytest.raises(StopIteration):
        next(values)
