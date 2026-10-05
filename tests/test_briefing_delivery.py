"""Invented retained receipts/packets; no auth, network or live release."""

from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_contextual_storage import stored as stored_fixture
from tests.test_selected_briefing import selected as original_selected
from zacai.contextual_recovery_record import (
    ContextualRecoveryReceipt,
    RecoveryLocator,
    encode_recovery_receipt,
)
from zacai.gateway import ActionType
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import briefing_delivery
from zacai.intelligence.contextual_evaluation import (
    decode_contextual_packet,
    encode_contextual_packet,
)
from zacai.intelligence.selected_briefing import render_selected_briefing
from zacai.intelligence.work_proposals import (
    ProposedStep,
    WorkProposal,
    packet_fingerprint,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state_repository import elevate_source_classification


def selected(boundary=B.BRAINSTORM, classification=C.CONFIDENTIAL):
    original = original_selected()
    items = tuple(
        item.model_copy(
            update={
                "reference": item.reference.model_copy(
                    update={
                        "trust_boundary": boundary,
                        "effective_classification": classification,
                    }
                ),
            }
        )
        for item in original.task.context
    )
    event = original.task.event.model_copy(
        update={
            "trust_boundary": boundary,
            "data_classification": classification,
            "provenance": tuple(item.reference for item in items),
        }
    )
    task = original.task.model_copy(update={"context": items, "event": event})
    context = original.context()
    context = type(context)(task, context.meeting_source_id, context.related_source_ids)
    return decode_contextual_packet(
        encode_contextual_packet(
            original.review.model_copy(update={"data_classification": classification}),
            context,
            builder_id=original.builder_id,
            created_at=original.created_at,
        )
    )


def checkpoint(packet, source_id=None):
    # Deliberately fabricated test receipt: shape/hash are consistency checks,
    # never proof of encrypted recovery or authenticity.
    locator = RecoveryLocator(
        locator_id=uuid4(),
        packet_source_id=source_id or uuid4(),
        packet_digest=packet_fingerprint(packet),
        task_id=packet.task.task_id,
        builder_id=packet.builder_id,
        created_at=packet.created_at + timedelta(seconds=1),
    )
    prefix = f"BRAINSTORM/state/contextual-packet-{locator.packet_source_id}"
    return ContextualRecoveryReceipt(
        locator=locator,
        locator_source_id=uuid4(),
        locator_digest=content_hash_of(canonical_bytes(locator.model_dump(mode="json"))),
        verified_at=locator.created_at + timedelta(seconds=1),
        artifact_backup_run_id=uuid4(),
        audit_source_ids=(),
        state_object=f"{prefix}/{'1' * 64}.age",
        state_ciphertext_hash="1" * 64,
        state_plaintext_hash="2" * 64,
        journal_object=f"{prefix}/journal-{'3' * 64}.age",
        journal_ciphertext_hash="3" * 64,
        journal_plaintext_hash="4" * 64,
    )


def args(receipt):
    return {
        "artifacts": object(),
        "retained_receipt": receipt,
        "expected_receipt_digest": content_hash_of(encode_recovery_receipt(receipt)),
        "authorized_boundaries": frozenset({B.BRAINSTORM}),
        "allowed_classifications": frozenset({C.CONFIDENTIAL}),
        "as_of": receipt.verified_at,
    }


def test_release_derives_identity_only_from_retained_receipt_and_preserves_display(monkeypatch):
    packet = selected()
    receipt = checkpoint(packet)
    inputs = args(receipt)
    calls = []
    marker_session = object()

    def load(session, **kw):
        assert session is marker_session
        calls.append(kw)
        return packet

    monkeypatch.setattr(briefing_delivery, "load_contextual_packet", load)
    html = briefing_delivery.render_retained_briefing(marker_session, **inputs)
    assert html == render_selected_briefing(packet, as_of=receipt.verified_at)
    assert calls == [
        {
            "artifacts": inputs["artifacts"],
            "source_id": receipt.locator.packet_source_id,
            "expected_digest": receipt.locator.packet_digest,
            "authorized_boundaries": inputs["authorized_boundaries"],
            "allowed_classifications": inputs["allowed_classifications"],
        }
    ]
    assert "Reporting validation remains underway." in html


@pytest.mark.parametrize("bad", ["digest", "digest_shape", "receipt_tamper", "naive", "future"])
def test_invalid_checkpoint_rejects_before_packet_artifact_io(monkeypatch, bad):
    packet = selected()
    receipt = checkpoint(packet)
    inputs = args(receipt)
    if bad == "digest":
        inputs["expected_receipt_digest"] = "0" * 64
    elif bad == "digest_shape":
        inputs["expected_receipt_digest"] = "private sentinel"
    elif bad == "receipt_tamper":
        inputs["retained_receipt"] = receipt.model_copy(update={"locator_digest": "0" * 64})
    elif bad == "naive":
        inputs["as_of"] = receipt.verified_at.replace(tzinfo=None)
    else:
        inputs["as_of"] = receipt.verified_at - timedelta(microseconds=1)

    def never(*a, **kw):
        pytest.fail("invalid checkpoint must reject before packet load")

    monkeypatch.setattr(briefing_delivery, "load_contextual_packet", never)
    with pytest.raises(ValueError, match="^retained briefing unavailable or mismatched$") as error:
        briefing_delivery.render_retained_briefing(object(), **inputs)
    assert error.value.__context__ is None


@pytest.mark.parametrize("field", ["task_id", "builder_id", "created_at"])
def test_valid_receipt_for_wrong_packet_cannot_release(monkeypatch, field):
    packet = selected()
    receipt = checkpoint(packet)
    update = {field: packet.created_at - timedelta(seconds=1) if field == "created_at" else uuid4()}
    locator = receipt.locator.model_copy(update=update)
    receipt = receipt.model_copy(
        update={
            "locator": locator,
            "locator_digest": content_hash_of(canonical_bytes(locator.model_dump(mode="json"))),
        }
    )
    monkeypatch.setattr(briefing_delivery, "load_contextual_packet", lambda *a, **kw: packet)

    def never(*a, **kw):
        pytest.fail("binding failure must precede rendering")

    monkeypatch.setattr(briefing_delivery, "render_selected_briefing", never)
    with pytest.raises(ValueError, match="^retained briefing unavailable or mismatched$") as error:
        briefing_delivery.render_retained_briefing(object(), **args(receipt))
    assert error.value.__context__ is None


def test_load_failure_never_releases_private_error_or_renders(monkeypatch):
    receipt = checkpoint(selected())

    def fail(*a, **kw):
        raise RuntimeError("private source path and secret sentinel")

    monkeypatch.setattr(briefing_delivery, "load_contextual_packet", fail)
    with pytest.raises(ValueError, match="^retained briefing unavailable or mismatched$") as error:
        briefing_delivery.render_retained_briefing(object(), **args(receipt))
    assert error.value.__context__ is None


def test_work_proposal_binding_is_not_bypassed_at_release(monkeypatch):
    packet = selected()
    receipt = checkpoint(packet)
    proposal = WorkProposal(
        packet_digest="0" * 64,
        item_index=0,
        outcome="Check the sample",
        steps=(
            ProposedStep(
                instruction="Inspect invented sample",
                action_type=ActionType.READ_DATA,
                destination="local sample",
                method="local checker",
            ),
        ),
        completion_check="Compare the output with expected values",
    )
    monkeypatch.setattr(briefing_delivery, "load_contextual_packet", lambda *a, **kw: packet)
    with pytest.raises(ValueError, match="^retained briefing unavailable or mismatched$"):
        briefing_delivery.render_retained_briefing(
            object(), **args(receipt), work_view=True, work_proposals=(proposal,)
        )


@pytest.fixture
def delivery_stored(test_session_factory, tmp_path):
    return stored_fixture.__wrapped__(test_session_factory, tmp_path)


@pytest.mark.parametrize("denial", ["boundary", "classification", "evidence_elevated"])
def test_canonical_acl_is_refreshed_at_release(delivery_stored, denial):
    factory, store, payload, sid, context, _ = delivery_stored
    packet = decode_contextual_packet(payload)
    receipt = checkpoint(packet, sid)
    inputs = args(receipt)
    inputs["artifacts"] = store
    if denial == "boundary":
        inputs["authorized_boundaries"] = frozenset({B.PERSONAL})
    elif denial == "classification":
        inputs["allowed_classifications"] = frozenset({C.PUBLIC})
    with factory() as session:
        if denial == "evidence_elevated":
            elevate_source_classification(
                session,
                source_id=context.meeting_source_id,
                trust_boundary=B.BRAINSTORM,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="invented privacy correction",
                elevated_by="test",
            )
            session.commit()
        with pytest.raises(
            ValueError, match="^retained briefing unavailable or mismatched$"
        ) as error:
            briefing_delivery.render_retained_briefing(session, **inputs)
        assert error.value.__context__ is None
        assert not session.new and not session.dirty and not session.deleted


def test_canonical_release_reads_only_and_keeps_exact_packet(delivery_stored):
    factory, store, payload, sid, _, _ = delivery_stored
    packet = decode_contextual_packet(payload)
    receipt = checkpoint(packet, sid)
    inputs = args(receipt)
    inputs["artifacts"] = store
    with factory() as session:
        html = briefing_delivery.render_retained_briefing(session, **inputs)
        assert html == render_selected_briefing(packet, as_of=receipt.verified_at)
        assert not session.new and not session.dirty and not session.deleted
        assert session.get_transaction() is not None


@pytest.mark.parametrize("scope", ["personal", "shared", "public", "restricted"])
def test_receipt_family_cannot_release_other_packet_boundaries_or_classifications(
    monkeypatch, scope
):
    packet = selected(
        boundary=B.PERSONAL
        if scope == "personal"
        else B.SHARED
        if scope == "shared"
        else B.BRAINSTORM,
        classification=C.PUBLIC
        if scope == "public"
        else C.HIGHLY_RESTRICTED
        if scope == "restricted"
        else C.CONFIDENTIAL,
    )
    receipt = checkpoint(packet)
    monkeypatch.setattr(briefing_delivery, "load_contextual_packet", lambda *a, **kw: packet)

    def never(*a, **kw):
        pytest.fail("receipt family mismatch must reject before renderer")

    monkeypatch.setattr(briefing_delivery, "render_selected_briefing", never)
    with pytest.raises(ValueError, match="^retained briefing unavailable or mismatched$"):
        briefing_delivery.render_retained_briefing(object(), **args(receipt))
