"""Explicit canonical packet capture/load; no enabled runtime or approval issuer.

Hosts authenticate callers and commit before invoking recovery protection. Packet
Sources join the existing artifact inventory. Capture alone proves no backup,
freshness, semantic quality or permission to dispatch. Orphans on rollback follow
the existing artifact-store policy; no automatic cleanup occurs.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.intelligence.contextual_evaluation import ContextualPacket, decode_contextual_packet
from zacai.intelligence.contracts import classification_covers
from zacai.policy import (
    AccessRequest,
    DataClassification,
    Destination,
    TrustBoundary,
    evaluate_access,
)
from zacai.state import SourceSystem
from zacai.state_repository import get_effective_source_classification, get_source, record_source


def _access(
    boundary: TrustBoundary,
    label: DataClassification,
    boundaries: frozenset[TrustBoundary],
    labels: frozenset[DataClassification],
) -> None:
    if (
        label not in labels
        or not evaluate_access(
            AccessRequest(
                data_boundary=boundary,
                data_classification=label,
                requestor_boundaries=boundaries,
                destination=Destination.LOCAL,
            )
        ).allowed
    ):
        raise ValueError("packet access denied")


def capture_contextual_packet(
    session: Session,
    *,
    artifacts: ArtifactStore,
    payload: bytes,
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
) -> UUID:
    """Register exact bytes, verifying canonical evidence metadata first.

    Does not commit or call models/backups. The host must separately refresh
    entity/project/meeting relationships and record truthful run provenance.
    """
    try:
        if session.new or session.dirty or session.deleted:
            raise ValueError("unrelated pending writes")
        packet = decode_contextual_packet(payload)
        boundary = packet.task.event.trust_boundary
        label = packet.review.data_classification
        _access(boundary, label, authorized_boundaries, allowed_classifications)
        for item in packet.task.context:
            ref = item.reference
            _access(
                ref.trust_boundary,
                ref.effective_classification,
                authorized_boundaries,
                allowed_classifications,
            )
            if not classification_covers(label, ref.effective_classification):
                raise ValueError("packet weaker than evidence")
            source = get_source(
                session, source_id=ref.source_id, requestor_boundaries=authorized_boundaries
            )
            if (
                source is None
                or source.trust_boundary != boundary
                or ref.trust_boundary != boundary
                or source.content_hash != ref.content_hash
                or get_effective_source_classification(session, source_id=source.id)
                != ref.effective_classification
            ):
                raise ValueError("canonical evidence mismatch")
        digest = content_hash_of(payload)
        with session.begin_nested():
            location = artifacts.put(boundary, digest, payload)
            if artifacts.get(boundary, location) != payload:
                raise ValueError("packet write integrity mismatch")
            source, _ = record_source(
                session,
                trust_boundary=boundary,
                data_classification=label,
                system=SourceSystem.MANUAL,
                external_ref=f"contextual-review-packet/{digest}",
                content_hash=digest,
                content_location=location,
                captured_at=packet.created_at,
            )
            if (
                source.content_location != location
                or source.data_classification != label
                or source.content_hash != digest
                or source.trust_boundary != boundary
                or source.system != SourceSystem.MANUAL
                or source.external_ref != f"contextual-review-packet/{digest}"
                or get_effective_source_classification(session, source_id=source.id) != label
            ):
                raise ValueError("packet source mismatch")
            return source.id
    except Exception:  # noqa: BLE001, S110 - private metadata/backend diagnostics
        pass
    raise ValueError("contextual packet capture unavailable or mismatched")


def load_contextual_packet(
    session: Session,
    *,
    artifacts: ArtifactStore,
    source_id: UUID,
    expected_digest: str,
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
) -> ContextualPacket:
    """Check canonical ACL/classification before artifact I/O, then exact bytes.

    Caller owns the independently retained expected digest. Loading is not proof
    of encrypted recovery and does not restore source permissions or freshness.
    """
    try:
        if session.new or session.dirty or session.deleted:
            raise ValueError("unrelated pending writes")
        source = get_source(
            session, source_id=source_id, requestor_boundaries=authorized_boundaries
        )
        if (
            source is None
            or source.system != SourceSystem.MANUAL
            or source.content_hash != expected_digest
            or source.external_ref != f"contextual-review-packet/{expected_digest}"
            or not source.content_location
        ):
            raise ValueError("packet source mismatch")
        label = get_effective_source_classification(session, source_id=source.id)
        _access(source.trust_boundary, label, authorized_boundaries, allowed_classifications)
        raw = artifacts.get(source.trust_boundary, source.content_location)
        if content_hash_of(raw) != expected_digest:
            raise ValueError("packet read integrity mismatch")
        packet = decode_contextual_packet(raw)
        if (
            packet.task.event.trust_boundary != source.trust_boundary
            or packet.review.data_classification != label
        ):
            raise ValueError("packet label mismatch")
        # Recheck all contributing source labels before returning copied evidence.
        for item in packet.task.context:
            ref = item.reference
            _access(
                ref.trust_boundary,
                ref.effective_classification,
                authorized_boundaries,
                allowed_classifications,
            )
            if not classification_covers(label, ref.effective_classification):
                raise ValueError("packet weaker than evidence")
            evidence = get_source(
                session, source_id=ref.source_id, requestor_boundaries=authorized_boundaries
            )
            if (
                evidence is None
                or evidence.trust_boundary != source.trust_boundary
                or evidence.content_hash != ref.content_hash
                or get_effective_source_classification(session, source_id=ref.source_id)
                != ref.effective_classification
            ):
                raise ValueError("copied evidence changed")
        return packet
    except Exception:  # noqa: BLE001, S110 - no private diagnostics in error chains
        pass
    raise ValueError("contextual packet load unavailable or mismatched")
