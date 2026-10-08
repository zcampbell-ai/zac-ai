"""Dormant once-only post-RELEASE packet retention, not reviewed delivery.

Real owner processing decision, purpose-specific withdrawal and authenticated
whole-answer assessment remain activation prerequisites. A trusted host owns the
concrete graph; this operation does not sandbox callback writes/commits.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from uuid import UUID

from zacai.backup_artifacts import (
    PersonalFullOriginalBackupPlan,
    prepare_personal_encrypted_custody_backup_plan,
)
from zacai.contextual_authorization import (
    CanonicalPersonalFragmentAuthorization,
    encode_history_fragment_claim,
    load_history_fragment_claim,
    load_history_fragment_consent,
)
from zacai.contextual_protection import (
    PersonalFragmentCleanupUncertain,
    PersonalFragmentRecoveryReceipt,
)
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contextual_evaluation import ContextualOutcome
from zacai.intelligence.contextual_generation import ContextualDraft
from zacai.intelligence.contextual_storage import (
    capture_history_fragment_contextual_packet,
    load_history_fragment_contextual_packet,
)
from zacai.intelligence.contracts import UsageObservation
from zacai.intelligence.history_fragment_contextual_codec import (
    HistoryFragmentContextualPacketV1,
    HistoryFragmentContextualRequestV1,
    encode_history_fragment_contextual_packet,
    encode_history_fragment_contextual_request,
)
from zacai.intelligence.local_contextual_runtime import (
    FragmentLocalContextualRuntime,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


class PersonalFragmentOutputError(RuntimeError):
    """Fixed hold; disable traceback locals for private arguments/frames."""


@dataclass(frozen=True, repr=False)
class PersonalFragmentRetainedOutput:
    source_id: UUID
    packet_digest: str
    packet: HistoryFragmentContextualPacketV1
    usage: UsageObservation
    recovery_receipt: PersonalFragmentRecoveryReceipt
    outcome: ContextualOutcome = field(default=ContextualOutcome.NEEDS_REVIEW, init=False)
    authenticated_review: Literal[False] = field(default=False, init=False)
    delivered: Literal[False] = field(default=False, init=False)


_BOUNDARIES = frozenset({B.PERSONAL})
_LABELS = frozenset({C.HIGHLY_RESTRICTED})


def _origin(
    gate: CanonicalPersonalFragmentAuthorization,
    runtime: FragmentLocalContextualRuntime,
    request: HistoryFragmentContextualRequestV1,
    draft: ContextualDraft,
) -> UsageObservation:
    if (
        gate._phase != "OUTPUT_ENTERED"
        or gate._released is None
        or gate._runtime is not runtime
        or gate._request is not request
        or type(runtime) is not FragmentLocalContextualRuntime
        or type(request) is not HistoryFragmentContextualRequestV1
        or type(draft) is not ContextualDraft
        or not runtime.did_transport_attempt
        or not runtime._attempted
        or runtime._prepared is not None
        or runtime.usage is None
    ):
        raise ValueError("exact completed origin required")
    gate._descriptor(request, gate._released)
    usage = UsageObservation.model_validate(runtime.usage)
    checked = ContextualDraft.model_validate(draft)
    if (
        content_hash_of(canonical_bytes(checked.model_dump(mode="json")))
        != gate._released.output_digest
        or content_hash_of(canonical_bytes(usage.model_dump(mode="json")))
        != gate._released.usage_digest
    ):
        raise ValueError("exact released output observations required")
    return usage


def _current_owner_time(gate: CanonicalPersonalFragmentAuthorization) -> datetime:
    gate._owner()
    now = gate._clock()
    if not gate._consent.approved_at <= now < gate._consent.expires_at:
        raise ValueError("original consent expired")
    return now


def _reopen(
    gate: CanonicalPersonalFragmentAuthorization,
    sid: UUID,
    digest: str,
) -> tuple[HistoryFragmentContextualPacketV1, PersonalFullOriginalBackupPlan]:
    if gate._claim is None or gate._claim_reference is None:
        raise ValueError("original canonical claim required")
    with gate._factory() as session:
        session.begin()
        entry = gate._physical_transaction(session)
        plan = prepare_personal_encrypted_custody_backup_plan(session)
        gate._same_physical_transaction(session, entry)
        expected = {UUID(row["id"]): row["content_hash"] for row in json.loads(plan.rows)}
        if (
            plan.engine is not gate._protector._engine
            or expected.get(sid) != digest
            or expected.get(gate._consent_reference.source_id)
            != gate._consent_reference.content_hash
            or expected.get(gate._claim_reference.source_id) != gate._claim_reference.content_hash
        ):
            raise ValueError("new full checkpoint must contain original authorities")
        packet = load_history_fragment_contextual_packet(
            session,
            artifacts=gate._artifacts,
            source_id=sid,
            expected_digest=digest,
            expected_request=gate._request,
            authorized_boundaries=_BOUNDARIES,
            allowed_classifications=_LABELS,
        )
        gate._same_physical_transaction(session, entry)
        consent = load_history_fragment_consent(
            session,
            artifacts=gate._artifacts,
            reference=gate._consent_reference,
            expected_consent=gate._consent,
            expected_request=gate._request,
        )
        gate._same_physical_transaction(session, entry)
        claim = load_history_fragment_claim(
            session,
            artifacts=gate._artifacts,
            reference=gate._claim_reference,
            expected_consent=gate._consent,
            expected_claim=gate._claim,
            expected_request=gate._request,
        )
        gate._same_physical_transaction(session, entry)
        if consent != gate._consent or claim != gate._claim:
            raise ValueError("original canonical authority differs")
        if prepare_personal_encrypted_custody_backup_plan(session) != plan:
            raise ValueError("typed authority full snapshot changed")
        gate._same_physical_transaction(session, entry)
    return packet, plan


def _terminal(
    gate: CanonicalPersonalFragmentAuthorization,
    receipt: PersonalFragmentRecoveryReceipt,
    packet: HistoryFragmentContextualPacketV1,
    sid: UUID,
    digest: str,
    expected_plan: PersonalFullOriginalBackupPlan,
) -> None:
    """Only actual scalar SQL/journal and trusted clock after terminal recovery."""
    if gate._claim_reference is None:
        raise ValueError("original claim missing")
    receipt = PersonalFragmentRecoveryReceipt.model_validate(receipt)
    if (
        receipt.packet_reference.source_id != sid
        or receipt.packet_reference.content_hash != digest
        or receipt.packet_reference.trust_boundary is not B.PERSONAL
        or receipt.packet_reference.effective_classification is not C.HIGHLY_RESTRICTED
        or receipt.task_id != gate._request.task.task_id
        or receipt.builder_id != gate._consent.builder_id
        or receipt.packet_created_at != packet.created_at
        or receipt.original_observed_at != gate._request.observed_at
        or receipt.request_digest
        != content_hash_of(encode_history_fragment_contextual_request(gate._request))
    ):
        raise ValueError("exact output receipt binding required")
    with gate._factory() as session:
        session.begin()
        entry = gate._physical_transaction(session)
        plan = prepare_personal_encrypted_custody_backup_plan(session)
        gate._same_physical_transaction(session, entry)
        rows = json.loads(plan.rows)
        hashes = tuple(
            sorted(
                ((UUID(row["id"]), row["content_hash"]) for row in rows), key=lambda p: str(p[0])
            )
        )
        fingerprints = tuple(
            sorted(
                ((UUID(row["id"]), content_hash_of(canonical_bytes(row))) for row in rows),
                key=lambda p: str(p[0]),
            )
        )
        if (
            plan.engine is not gate._protector._engine
            or plan != expected_plan
            or content_hash_of(plan.rows) != receipt.full_plan_digest
            or hashes != receipt.full_boundary_source_hashes
            or fingerprints != receipt.full_boundary_source_fingerprints
            or dict(hashes).get(gate._consent_reference.source_id)
            != gate._consent_reference.content_hash
            or dict(hashes).get(gate._claim_reference.source_id)
            != gate._claim_reference.content_hash
            or dict(hashes).get(sid) != digest
        ):
            raise ValueError("complete output checkpoint changed")
        gate._same_physical_transaction(session, entry)
    if (
        content_hash_of(gate._protector._run_row(receipt.artifact_backup_run_id))
        != receipt.live_journal_digest
    ):
        raise ValueError("output operational journal changed")
    gate._graph_check()
    if not gate._consent.approved_at <= gate._clock() < gate._consent.expires_at:
        raise ValueError("original consent expired at terminal boundary")


def retain_personal_history_fragment_output(
    authorization: CanonicalPersonalFragmentAuthorization,
    *,
    runtime: FragmentLocalContextualRuntime,
    request: HistoryFragmentContextualRequestV1,
    draft: ContextualDraft,
) -> PersonalFragmentRetainedOutput:
    """Consume the actual issuer RELEASED once; return retained NEEDS_REVIEW only.

    No model call or repeated RELEASE occurs. Every entered failure/interruption
    permanently holds this instance; durable packet/orphan evidence may remain for
    manual reconciliation. No repair/retry/delete. Genuine withdrawal and whole
    answer review remain activation gates. Cancellation propagates after burning.
    """
    result = None
    cleanup_uncertain = False
    try:
        if type(authorization) is not CanonicalPersonalFragmentAuthorization:
            raise TypeError("actual original issuer required")
        gate = authorization
        with gate._lock:
            if gate._phase != "RELEASED":
                raise ValueError("one original released output required")
            gate._phase = "OUTPUT_ENTERED"
            try:
                released = gate._released
                usage = _origin(gate, runtime, request, draft)
                claim, claim_reference = gate._claim, gate._claim_reference
                if claim is None or claim_reference is None:
                    raise ValueError("original claim required")
                claim_bytes = encode_history_fragment_claim(claim)
                if content_hash_of(claim_bytes) != claim_reference.content_hash:
                    raise ValueError("original claim binding changed")
                review = runtime.resolve_fragment(draft, request)
                _origin(gate, runtime, request, draft)
                created_at = _current_owner_time(gate)
                payload = encode_history_fragment_contextual_packet(
                    review,
                    request,
                    builder_id=gate._consent.builder_id,
                    created_at=created_at,
                )
                digest = content_hash_of(payload)
                with gate._factory() as session:
                    session.begin()
                    entry = gate._physical_transaction(session)
                    from zacai.backup_artifacts import _assert_personal_custody_append_capacity

                    _assert_personal_custody_append_capacity(session, 1)
                    sid = capture_history_fragment_contextual_packet(
                        session,
                        artifacts=gate._artifacts,
                        payload=payload,
                        authorized_boundaries=_BOUNDARIES,
                        allowed_classifications=_LABELS,
                    )
                    from zacai.backup_artifacts import (
                        prepare_personal_encrypted_custody_backup_plan,
                    )

                    prepare_personal_encrypted_custody_backup_plan(session)
                    gate._same_physical_transaction(session, entry)
                    session.commit()
                _current_owner_time(gate)
                packet, expected_plan = _reopen(gate, sid, digest)
                if (
                    packet.builder_id != gate._consent.builder_id
                    or packet.created_at != created_at
                    or packet.review != review
                    or encode_history_fragment_contextual_request(packet.request())
                    != encode_history_fragment_contextual_request(request)
                ):
                    raise ValueError("captured output differs")
                _current_owner_time(gate)
                _origin(gate, runtime, request, draft)
                receipt = gate._protector.protect(
                    source_id=sid,
                    expected_digest=digest,
                    expected_request=request,
                )
                _terminal(gate, receipt, packet, sid, digest, expected_plan)
                # No arbitrary owner/body callbacks after final recovery proof.
                if (
                    gate._released is not released
                    or gate._claim is not claim
                    or gate._claim_reference is not claim_reference
                    or encode_history_fragment_claim(claim) != claim_bytes
                    or _origin(gate, runtime, request, draft) != usage
                ):
                    raise ValueError("released origin changed")
                result = PersonalFragmentRetainedOutput(sid, digest, packet, usage, receipt)
                gate._phase = "OUTPUT_RETAINED"
            finally:
                if result is None:
                    gate._phase = "OUTPUT_HELD"
    except PersonalFragmentCleanupUncertain:
        cleanup_uncertain = True
    except Exception:  # noqa: BLE001,S110 - fixed error outside private exception context
        pass
    if result is None:
        if cleanup_uncertain:
            raise PersonalFragmentCleanupUncertain(
                "PERSONAL recovery cleanup uncertain; operator review required"
            )
        raise PersonalFragmentOutputError("PERSONAL fragment output unavailable or consumed")
    return result
