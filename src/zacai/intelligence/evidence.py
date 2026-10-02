"""Read-only host bridge from canonical Source to a D032 evidence snapshot."""

from uuid import UUID

from sqlalchemy.orm import Session

from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import TrustBoundary
from zacai.state_repository import get_effective_source_classification, get_source


def resolve_evidence_reference(
    session: Session,
    *,
    source_id: UUID,
    requestor_boundaries: frozenset[TrustBoundary],
) -> EvidenceReference:
    """Resolve current metadata; never read raw content or change canonical state.

    Missing/unauthorized sources produce the same error. Only content-addressed
    Sources can support this version of the source-backed event contract. Refresh
    at future dispatch boundaries: an old snapshot cannot prove current labels.
    """
    source = get_source(session, source_id=source_id, requestor_boundaries=requestor_boundaries)
    if source is None:
        raise ValueError("source not found or not authorized")
    if source.content_hash is None:
        raise ValueError("source lacks a content hash")
    return EvidenceReference(
        source_id=source.id,
        content_hash=source.content_hash,
        trust_boundary=source.trust_boundary,
        effective_classification=get_effective_source_classification(session, source_id=source.id),
    )
