"""Trusted canonical follow-up assembly; no model, consent, route or HTTP action.

Canonical envelopes retain exact original UTF-8 text. Existing ContextItem Text
contracts strip outer whitespace: question/parent context is an explicit .strip()
projection and its citation offsets refer to that projection. Leading offsets
below map projected user spans back to immutable envelope text. No canonical
contract changes or ancestor plaintext grants are made. Keep frame locals private.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from uuid import UUID, uuid5

from zacai.contextual_recovery_record import ContextualRecoveryReceipt
from zacai.intelligence.briefing_delivery import load_retained_packet
from zacai.intelligence.contracts import (
    ContextItem,
    Importance,
    IntelligenceTask,
    ZacEvent,
)
from zacai.intelligence.text_followup import (
    FOLLOWUP_CAPABILITY,
    FOLLOWUP_INSTRUCTION,
    FollowupContext,
    TextFollowupError,
)
from zacai.intelligence.work_proposals import packet_fingerprint
from zacai.interfaces.private_web import InterfacePrincipal
from zacai.interfaces.text_turn_capture import (
    CanonicalTextTurnCapture,
    SavedTextTurn,
    TextTurn,
    TextTurnRecoveryReceipt,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation
from zacai.state import Source

_NAMESPACE = UUID("72d8d62f-867f-51dd-bd35-e04b6477ed45")


@dataclass(frozen=True)
class AssembledFollowup:
    """Protected host composition, not model-processing/release authorization."""

    context: FollowupContext = field(repr=False)
    saved_turn: SavedTextTurn = field(repr=False)
    direct_parent_turns: tuple[TextTurn, ...] = field(repr=False)

    @property
    def user_original_offset(self) -> int:
        """Python code-point offset into immutable original_text, not UTF-8/UTF-16."""
        text = self.saved_turn.turn.original_text
        return len(text) - len(text.lstrip())

    @property
    def parent_original_offsets(self) -> tuple[tuple[UUID, int], ...]:
        """Direct-parent Source IDs and Python code-point offsets into original_text."""
        return tuple(
            (ref.source_id, len(turn.original_text) - len(turn.original_text.lstrip()))
            for ref, turn in zip(
                self.saved_turn.turn.parent_references, self.direct_parent_turns, strict=True
            )
        )

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def execution_authorized(self) -> Literal[False]:
        return False


class CanonicalFollowupAssembler:
    """Exact trusted capture dependency; its own factory/artifacts/clock are reused.

    Capture.load performs real required recovery before and after composition,
    with fresh owner/source/packet/parent checks. This does not grant inference or
    prove relevance/semantic quality; a concrete processing claim and final fresh
    release gate remain required. Repeated restores are conservative mechanics,
    not a latency or production-readiness promise.
    """

    def __init__(self, *, capture: CanonicalTextTurnCapture) -> None:
        if type(capture) is not CanonicalTextTurnCapture:
            raise TextFollowupError("canonical follow-up assembler unavailable")
        self._capture = capture

    def assemble(
        self,
        *,
        principal: InterfacePrincipal,
        source_id: UUID,
        expected_turn_digest: str,
        retained_receipt: ContextualRecoveryReceipt,
        expected_receipt_digest: str,
        recovery_receipt: TextTurnRecoveryReceipt,
    ) -> AssembledFollowup:
        result: AssembledFollowup | None = None
        try:
            c = self._capture

            def load() -> SavedTextTurn:
                return c.load(
                    principal=principal,
                    source_id=source_id,
                    expected_turn_digest=expected_turn_digest,
                    retained_receipt=retained_receipt,
                    expected_receipt_digest=expected_receipt_digest,
                    recovery_receipt=recovery_receipt,
                )

            first = load()
            now = c._now()
            c._principal(principal, now)
            parents: list[TextTurn] = []
            with c._factory() as session:
                _assert_ledger_isolation(session)
                packet = load_retained_packet(
                    session,
                    artifacts=c._artifacts,
                    retained_receipt=retained_receipt,
                    expected_receipt_digest=expected_receipt_digest,
                    authorized_boundaries=frozenset({B.BRAINSTORM}),
                    allowed_classifications=frozenset({C.CONFIDENTIAL}),
                    as_of=now,
                )
                if packet_fingerprint(packet) != first.turn.packet_reference.content_hash:
                    raise ValueError("retained packet bytes differ")
                c._check(
                    session,
                    principal,
                    first.turn,
                    retained_receipt,
                    expected_receipt_digest,
                    now,
                    source_id=source_id,
                )
                for ref in first.turn.parent_references:
                    parent_source = session.get(Source, ref.source_id)
                    if parent_source is None or parent_source.content_hash != ref.content_hash:
                        raise ValueError("selected parent missing")
                    parent, _ = c._read(session, parent_source)
                    parents.append(parent)
            final = load()
            observed = c._now()
            if (
                type(observed) is not datetime
                or observed.utcoffset() is None
                or observed < now
                or observed < final.recovery_receipt.verified_at
                or final != first
            ):
                raise ValueError("follow-up changed during composition")
            c._principal(principal, observed)
            question = ContextItem(
                reference=final.reference, untrusted_text=final.turn.original_text.strip()
            )
            parent_items = tuple(
                ContextItem(reference=ref, untrusted_text=turn.original_text.strip())
                for ref, turn in zip(final.turn.parent_references, parents, strict=True)
            )
            if question.untrusted_text != final.turn.original_text.strip() or any(
                item.untrusted_text != turn.original_text.strip()
                for item, turn in zip(parent_items, parents, strict=True)
            ):
                raise ValueError("unexpected original-text projection")
            event_id = uuid5(
                _NAMESPACE, f"packet-followup-event/{source_id}/{expected_turn_digest}"
            )
            event = ZacEvent(
                event_id=event_id,
                event_type="packet_followup_requested",
                producer="private_text_host",
                occurred_at=final.turn.recorded_at,
                observed_at=observed,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.CONFIDENTIAL,
                provenance=(
                    final.reference,
                    final.turn.packet_reference,
                    *(i.reference for i in packet.task.context),
                    *final.turn.parent_references,
                ),
                correlation_id=final.turn.conversation_id,
                importance=Importance.IMPORTANT,
                confidence=1.0,
            )
            task = IntelligenceTask(
                task_id=uuid5(
                    _NAMESPACE, f"packet-followup-task/{source_id}/{expected_turn_digest}"
                ),
                event=event,
                required_capabilities=frozenset({FOLLOWUP_CAPABILITY}),
                instruction=FOLLOWUP_INSTRUCTION,
                context=(question, *packet.task.context, *parent_items),
                max_latency_ms=60_000,
                max_estimated_cost_usd=0.0,
                max_output_tokens=512,
            )
            context = FollowupContext(
                task,
                packet,
                final.reference,
                final.turn.packet_reference,
                final.turn.parent_references,
            )
            result = AssembledFollowup(context, final, tuple(parents))
        except Exception:  # noqa: BLE001,S110 - private canonical/backend diagnostics
            pass
        if result is None:
            raise TextFollowupError("canonical follow-up unavailable or unprotected")
        return result
