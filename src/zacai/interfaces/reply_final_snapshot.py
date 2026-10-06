"""Final canonical reply ACL/cancellation snapshot, never processing authority.

Detailed immutable byte/provenance checks and actual current owner/session/recovery
must finish first. This rows-only helper performs no private artifact reads or
callbacks. Historical cancellation is labelled, not renewed or erased.
"""

from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation
from zacai.state import Source, SourceClassificationElevation, SourceSystem


def verify_reply_final_snapshot(
    session: Session,
    *,
    references: tuple[EvidenceReference, ...],
    consent_source_id: UUID,
    active: bool,
) -> bool:
    """Return cancellation observed in the same final dependency ACL snapshot."""
    _assert_ledger_isolation(session)
    if (
        type(references) is not tuple
        or not references
        or len(references) > 64
        or type(consent_source_id) is not UUID
        or type(active) is not bool
    ):
        raise ValueError("closed reply inventory required")
    hashes: dict[UUID, str] = {}
    for original in references:
        if type(original) is not EvidenceReference:
            raise ValueError("exact reference required")
        ref = EvidenceReference.model_validate(original)
        if (
            ref.trust_boundary is not B.BRAINSTORM
            or ref.effective_classification is not C.CONFIDENTIAL
            or (ref.source_id in hashes and hashes[ref.source_id] != ref.content_hash)
        ):
            raise ValueError("reply inventory differs")
        hashes[ref.source_id] = ref.content_hash
    if consent_source_id not in hashes:
        raise ValueError("original consent omitted")
    expected = {}
    for sid, digest in hashes.items():
        row = session.get(Source, sid)
        if (
            row is None
            or row.content_hash != digest
            or row.trust_boundary is not B.BRAINSTORM
            or row.data_classification is not C.CONFIDENTIAL
        ):
            raise ValueError("reply canonical Source differs")
        expected[sid] = (
            row.id,
            row.system,
            row.external_ref,
            row.content_hash,
            row.content_location,
            row.captured_at,
            row.trust_boundary,
            row.data_classification,
            C.CONFIDENTIAL,
        )
    # Mirrors state_repository.get_effective_source_classification exactly.
    latest = (
        select(SourceClassificationElevation.new_classification)
        .where(SourceClassificationElevation.source_id == Source.id)
        .order_by(SourceClassificationElevation.elevated_at.desc())
        .limit(1)
        .correlate(Source)
        .scalar_subquery()
    )
    cancelled_ref = f"packet-followup-revocation/{consent_source_id}"
    observed = session.execute(
        select(
            Source.id,
            Source.system,
            Source.external_ref,
            Source.content_hash,
            Source.content_location,
            Source.captured_at,
            Source.trust_boundary,
            Source.data_classification,
            func.coalesce(latest, Source.data_classification),
        ).where(
            or_(
                Source.id.in_(tuple(hashes)),
                (Source.system == SourceSystem.USER_INSTRUCTION)
                & (Source.external_ref == cancelled_ref),
            )
        )
    ).all()
    seen = set()
    revoked = False
    for observed_row in observed:
        if observed_row[1] == SourceSystem.USER_INSTRUCTION and observed_row[2] == cancelled_ref:
            revoked = True
            continue
        if observed_row[0] in seen or expected.get(observed_row[0]) != tuple(observed_row):
            raise ValueError("reply final canonical snapshot held")
        seen.add(observed_row[0])
    if seen != set(hashes) or (active and revoked):
        raise ValueError("reply final presence or cancellation held")
    return revoked
