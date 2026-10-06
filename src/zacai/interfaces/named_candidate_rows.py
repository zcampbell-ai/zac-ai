"""Canonical row inventory for named owner decisions, never permission.

Callers supply an already observed host time and hold their own trusted SQL or
checkpoint lease. This reader performs no host callbacks, authentication,
recovery, runtime probing or clock I/O. Actual admission and independently
retained recovery are mandatory separate gates outside the transaction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid5

from sqlalchemy.orm import Session

from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.intelligence.contextual_storage import load_contextual_packet
from zacai.intelligence.contracts import (
    ContextItem,
    EvidenceReference,
    Importance,
    IntelligenceTask,
    ZacEvent,
)
from zacai.intelligence.followup_generation import prepare_followup_request
from zacai.intelligence.text_followup import (
    FOLLOWUP_CAPABILITY,
    FOLLOWUP_INSTRUCTION,
    FollowupContext,
)
from zacai.intelligence.work_proposals import packet_fingerprint
from zacai.interfaces.followup_authorization import followup_content_digest
from zacai.interfaces.named_followup_decision import (
    NamedFollowupDecision,
    decode_named_decision,
    encode_named_decision,
)
from zacai.interfaces.text_followup_context import _NAMESPACE
from zacai.interfaces.text_turn_capture import decode_text_turn
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation, _bytes
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_effective_source_classification


class NamedDecisionInventoryError(ValueError):
    """Fixed diagnostic without Source text, identifiers or exception chains."""


@dataclass(frozen=True)
class NamedDecisionInventory:
    decision: NamedFollowupDecision = field(repr=False)
    hashes: tuple[tuple[UUID, str], ...] = field(repr=False)


def verify_named_candidate_rows(
    session: Session,
    *,
    artifacts: ArtifactStore,
    decision: NamedFollowupDecision,
    as_of: datetime,
) -> NamedDecisionInventory:
    """Resolve the exact committed decision and explicit direct dependencies.

    Candidate need not yet be committed; return proves dependencies only.
    Ancestor bodies are not traversed. Original packet evidence is ACL/hash-gated
    here and decrypted artifact identity is verified by the concrete checkpoint.
    Expired decisions may be inventoried for historical receipt-only repair;
    processing expiry remains enforced by the separate active authority gate.
    """
    result: NamedDecisionInventory | None = None
    try:
        _assert_ledger_isolation(session)
        if type(as_of) is not datetime or as_of.utcoffset() is None:
            raise ValueError("aware observed time required")
        hashes: dict[UUID, str] = {}

        def add(ref: EvidenceReference, system: SourceSystem | None) -> Source:
            if type(ref) is not EvidenceReference or ref.source_id in hashes:
                raise ValueError("invalid distinct reference")
            row = session.get(Source, ref.source_id)
            if (
                row is None
                or (system is not None and row.system != system)
                or ref.trust_boundary is not B.BRAINSTORM
                or ref.effective_classification is not C.CONFIDENTIAL
                or row.trust_boundary != B.BRAINSTORM
                or row.data_classification != C.CONFIDENTIAL
                or get_effective_source_classification(session, source_id=row.id) != C.CONFIDENTIAL
                or row.content_hash != ref.content_hash
                or row.captured_at > as_of
            ):
                raise ValueError("canonical dependency unavailable")
            hashes[row.id] = ref.content_hash
            return row

        decision = decode_named_decision(encode_named_decision(decision))
        if decision.bound_at > as_of:
            raise ValueError("candidate decision is future dated")
        m, scope = decision.manifest, decision.run_scope
        question_source = add(decision.question_reference, SourceSystem.USER_INSTRUCTION)
        question = decode_text_turn(_bytes(session, artifacts, question_source))
        if (
            question_source.external_ref != f"text-turn/{question.request_id}"
            or question_source.captured_at != question.recorded_at
            or (question.issuer, question.subject) != (m.actor_issuer, m.actor_subject)
            or (question.request_id, question.conversation_id) != (m.request_id, m.conversation_id)
            or question.packet_reference != m.packet_reference
            or question.packet_receipt_digest != m.packet_receipt_digest
            or question.parent_references != tuple(p.reference for p in m.parents)
            or content_hash_of(question.original_text.encode("utf-8"))
            != decision.original_utf8_digest
            or not decision.admitted_at
            <= question.recorded_at
            <= decision.original_observed_at
            <= decision.bound_at
        ):
            raise ValueError("canonical question differs")
        parents = []
        for ref in question.parent_references:
            parent_source = add(ref, SourceSystem.USER_INSTRUCTION)
            parent = decode_text_turn(_bytes(session, artifacts, parent_source))
            if (
                parent_source.external_ref != f"text-turn/{parent.request_id}"
                or parent_source.captured_at != parent.recorded_at
                or (parent.issuer, parent.subject) != (question.issuer, question.subject)
                or parent.conversation_id != question.conversation_id
                or parent.packet_reference != question.packet_reference
                or parent.packet_receipt_digest != question.packet_receipt_digest
                or parent.recorded_at > question.recorded_at
                or parent.request_id == question.request_id
            ):
                raise ValueError("canonical direct parent differs")
            parents.append(parent)
        add(m.packet_reference, SourceSystem.MANUAL)
        packet = load_contextual_packet(
            session,
            artifacts=artifacts,
            source_id=m.packet_reference.source_id,
            expected_digest=m.packet_reference.content_hash,
            authorized_boundaries=frozenset({B.BRAINSTORM}),
            allowed_classifications=frozenset({C.CONFIDENTIAL}),
        )
        refs = tuple(item.reference for item in packet.task.context)
        if (
            packet_fingerprint(packet) != m.packet_reference.content_hash
            or packet.created_at > m.issued_at
            or refs != m.evidence_references
            or scope.context_references
            != (decision.question_reference, *refs, *question.parent_references)
        ):
            raise ValueError("canonical packet context differs")
        for ref in refs:
            add(ref, None)
        # Rebuild the existing canonical assembler wire solely from verified
        # rows; no recovery/session/runtime callback occurs in this transaction.
        ref = decision.question_reference
        event = ZacEvent(
            event_id=uuid5(_NAMESPACE, f"packet-followup-event/{ref.source_id}/{ref.content_hash}"),
            event_type="packet_followup_requested",
            producer="private_text_host",
            occurred_at=question.recorded_at,
            observed_at=decision.original_observed_at,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            provenance=(ref, question.packet_reference, *refs, *question.parent_references),
            correlation_id=question.conversation_id,
            importance=Importance.IMPORTANT,
            confidence=1.0,
        )
        task = IntelligenceTask(
            task_id=uuid5(_NAMESPACE, f"packet-followup-task/{ref.source_id}/{ref.content_hash}"),
            event=event,
            required_capabilities=frozenset({FOLLOWUP_CAPABILITY}),
            instruction=FOLLOWUP_INSTRUCTION,
            context=(
                ContextItem(reference=ref, untrusted_text=question.original_text.strip()),
                *packet.task.context,
                *(
                    ContextItem(reference=r, untrusted_text=p.original_text.strip())
                    for r, p in zip(question.parent_references, parents, strict=True)
                ),
            ),
            max_latency_ms=60_000,
            max_estimated_cost_usd=0.0,
            max_output_tokens=512,
        )
        request = prepare_followup_request(
            FollowupContext(
                task, packet, ref, question.packet_reference, question.parent_references
            )
        )
        if (
            request.digest != decision.prepared_request_digest
            or followup_content_digest(request) != scope.content_digest
            or (task.max_latency_ms, task.max_output_tokens, task.max_estimated_cost_usd)
            != (scope.max_latency_ms, scope.max_output_tokens, scope.max_estimated_cost_usd)
        ):
            raise ValueError("actual canonical prepared request differs")
        result = NamedDecisionInventory(decision, tuple(hashes.items()))
    except Exception:  # noqa: BLE001,S110 - fixed private-safe diagnostics
        pass
    if result is None:
        raise NamedDecisionInventoryError("canonical named decision inventory unavailable")
    return result
