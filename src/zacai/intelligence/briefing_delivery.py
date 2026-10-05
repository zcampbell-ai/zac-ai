"""Host-only selected briefing release composition, without an HTTP endpoint.

The outer host MUST authenticate the user, resolve current boundary/classification
scope, and obtain an independently retained, verified recovery receipt and its
hash. Neither the receipt nor hash may come from a client request. This function
checks binding and fresh canonical source access; it cannot establish receipt
origin, validate encrypted object availability today, or authenticate a session.
This existing receipt family covers only BRAINSTORM/CONFIDENTIAL packets.
A retained receipt proves the historical checkpoint, not current business status.
No credentials, packet paths, clients, model calls, writes or dispatch are used.
"""

from __future__ import annotations

import re
from datetime import datetime

from sqlalchemy.orm import Session

from zacai.contextual_recovery_record import ContextualRecoveryReceipt, encode_recovery_receipt
from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.intelligence.contextual_evaluation import ContextualPacket
from zacai.intelligence.contextual_storage import load_contextual_packet
from zacai.intelligence.decision_cards import DecisionCardRenderMode, render_decision_cards
from zacai.intelligence.selected_briefing import render_selected_briefing
from zacai.intelligence.work_proposals import WorkPreference, WorkProposal
from zacai.interfaces.private_web import InterfacePrincipal, OwnerGrant
from zacai.policy import DataClassification, TrustBoundary


def render_retained_briefing(
    session: Session,
    *,
    artifacts: ArtifactStore,
    retained_receipt: ContextualRecoveryReceipt,
    expected_receipt_digest: str,
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
    as_of: datetime,
    work_proposals: tuple[WorkProposal, ...] = (),
    work_preferences: tuple[WorkPreference, ...] = (),
    work_view: bool = False,
) -> str:
    """Recheck exact checkpoint binding and canonical ACLs before returning HTML.

    Packet identity is derived exclusively from the host-retained receipt. This
    ``as_of`` comes from the trusted host clock, never client/model input. This
    is a read-only composition, not authentication, disclosure authorization or
    verification of fresh backups. Its caller must never log local variables.
    Future HTTP delivery additionally needs a private authenticated transport,
    no-store responses, safe session handling and approved deployment.
    """
    result: str | None = None
    try:
        packet = _retained_packet(
            session,
            artifacts=artifacts,
            retained_receipt=retained_receipt,
            expected_receipt_digest=expected_receipt_digest,
            authorized_boundaries=authorized_boundaries,
            allowed_classifications=allowed_classifications,
            as_of=as_of,
        )
        result = render_selected_briefing(
            packet,
            as_of=as_of,
            work_proposals=work_proposals,
            work_preferences=work_preferences,
            work_view=work_view,
        )
    except Exception:  # noqa: BLE001, S110 - fixed diagnostic without private exception chains
        pass
    if result is None:
        raise ValueError("retained briefing unavailable or mismatched")
    return result


def load_retained_packet(
    session: Session,
    *,
    artifacts: ArtifactStore,
    retained_receipt: ContextualRecoveryReceipt,
    expected_receipt_digest: str,
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
    as_of: datetime,
) -> ContextualPacket:
    receipt = ContextualRecoveryReceipt.model_validate(retained_receipt)
    if (
        re.fullmatch(r"[0-9a-f]{64}", expected_receipt_digest) is None
        or content_hash_of(encode_recovery_receipt(receipt)) != expected_receipt_digest
        or as_of.tzinfo is None
        or as_of.utcoffset() is None
        or as_of < receipt.verified_at
    ):
        raise ValueError("retained checkpoint mismatch")
    packet = load_contextual_packet(
        session,
        artifacts=artifacts,
        source_id=receipt.locator.packet_source_id,
        expected_digest=receipt.locator.packet_digest,
        authorized_boundaries=authorized_boundaries,
        allowed_classifications=allowed_classifications,
    )
    # The protector creates the locator after packet capture/commit, using
    # a new clock reading (contextual_protection.py), so equality is wrong.
    # Exact packet bytes/digest already bind the earlier packet timestamp.
    if (
        packet.task.event.trust_boundary != TrustBoundary.BRAINSTORM
        or packet.review.data_classification != DataClassification.CONFIDENTIAL
        or packet.task.task_id != receipt.locator.task_id
        or packet.builder_id != receipt.locator.builder_id
        or packet.created_at > receipt.locator.created_at
    ):
        raise ValueError("packet checkpoint mismatch")
    return packet


def render_retained_decision_cards(
    session: Session,
    *,
    artifacts: ArtifactStore,
    retained_receipt: ContextualRecoveryReceipt,
    expected_receipt_digest: str,
    principal: InterfacePrincipal,
    as_of: datetime,
    work_proposals: tuple[WorkProposal, ...] = (),
    work_preferences: tuple[WorkPreference, ...] = (),
    selected_item: int = 0,
) -> str:
    """Host-only protected cards, ready for host-managed same-origin logout.

    Host authenticates and refreshes this principal first, and independently
    retrieves the retained receipt/digest. HTTP callers supply none of these
    objects, paths or scope values. Only BRAINSTORM classifications are used;
    PERSONAL/SHARED scope cannot expand this receipt family's permissions.
    Renderer still emits no active approval form or grants. The host may add
    its own reviewed logout form; this function never mounts or dispatches it.
    """
    result: str | None = None
    try:
        if type(principal) is not InterfacePrincipal:
            raise ValueError("invalid principal")
        grant = OwnerGrant(principal.identity, principal.scopes)
        scope = next(s for s in grant.scopes if s.boundary == TrustBoundary.BRAINSTORM)
        packet = _retained_packet(
            session,
            artifacts=artifacts,
            retained_receipt=retained_receipt,
            expected_receipt_digest=expected_receipt_digest,
            authorized_boundaries=frozenset({TrustBoundary.BRAINSTORM}),
            allowed_classifications=scope.classifications,
            as_of=as_of,
        )
        result = render_decision_cards(
            packet,
            work_proposals,
            work_preferences,
            selected_item=selected_item,
            render_mode=DecisionCardRenderMode.HOST_LOGOUT,
        )
    except Exception:  # noqa: BLE001, S110 - no retained/private diagnostics
        pass
    if result is None:
        raise ValueError("retained decision cards unavailable or mismatched")
    return result


# Preserve the existing private helper binding for compatibility.
_retained_packet = load_retained_packet
