"""Explicit canonical work-journal snapshots, not enabled workflow dispatch.

Existing append-only Sources and artifact inventory hold exact journal bytes.
No mutable latest pointer exists: callers retain expected snapshot digests and
serialize their writes. Divergent snapshots are not automatically reconciled.
Capture does not commit, protect recovery, authenticate observations or certify
completion. The host must protect state/artifacts before release, as for packets.
"""

from __future__ import annotations

import re
from datetime import datetime
from uuid import UUID

from sqlalchemy.orm import Session

from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.intelligence.contextual_storage import load_contextual_packet
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.work_tracking import (
    WorkJournal,
    decode_work_journal,
    validate_journal_packet,
)
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
        raise ValueError("journal access denied")


def _reference(
    session: Session,
    ref: EvidenceReference,
    boundaries: frozenset[TrustBoundary],
    labels: frozenset[DataClassification],
    *,
    recorded_at: datetime,
) -> None:
    _access(ref.trust_boundary, ref.effective_classification, boundaries, labels)
    source = get_source(session, source_id=ref.source_id, requestor_boundaries=boundaries)
    if (
        source is None
        or source.trust_boundary != ref.trust_boundary
        or source.content_hash != ref.content_hash
        or source.captured_at > recorded_at
        or get_effective_source_classification(session, source_id=source.id)
        != ref.effective_classification
    ):
        raise ValueError("journal evidence changed")


def _validate(
    session: Session,
    artifacts: ArtifactStore,
    journal: WorkJournal,
    boundaries: frozenset[TrustBoundary],
    labels: frozenset[DataClassification],
) -> None:
    _access(journal.trust_boundary, journal.data_classification, boundaries, labels)
    # Check every source ACL before any contributing artifact read.
    _reference(
        session, journal.packet_reference, boundaries, labels, recorded_at=journal.created_at
    )
    for observation in journal.observations:
        for ref in observation.evidence:
            _reference(session, ref, boundaries, labels, recorded_at=observation.recorded_at)
    packet = load_contextual_packet(
        session,
        artifacts=artifacts,
        source_id=journal.packet_reference.source_id,
        expected_digest=journal.packet_reference.content_hash,
        authorized_boundaries=boundaries,
        allowed_classifications=labels,
    )
    validate_journal_packet(journal, packet)


def capture_work_journal(
    session: Session,
    *,
    artifacts: ArtifactStore,
    payload: bytes,
    now: datetime,
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
) -> UUID:
    """Exact snapshot at injected trusted host time, never report-supplied time.

    ``now`` is supplied by the trusted host clock, not by agents or model output.
    No canonical business-fact promotion or authentication occurs here.
    """
    try:
        if session.new or session.dirty or session.deleted:
            raise ValueError("unrelated pending writes")
        journal = decode_work_journal(payload)
        if (
            now.utcoffset() is None
            or journal.created_at > now
            or any(observation.recorded_at > now for observation in journal.observations)
        ):
            raise ValueError("journal timestamp ahead of host clock")
        _validate(session, artifacts, journal, authorized_boundaries, allowed_classifications)
        digest = content_hash_of(payload)
        with session.begin_nested():
            location = artifacts.put(journal.trust_boundary, digest, payload)
            if artifacts.get(journal.trust_boundary, location) != payload:
                raise ValueError("journal integrity mismatch")
            source, _ = record_source(
                session,
                trust_boundary=journal.trust_boundary,
                data_classification=journal.data_classification,
                system=SourceSystem.MANUAL,
                external_ref=f"work-journal-snapshot/{digest}",
                content_hash=digest,
                content_location=location,
                captured_at=now,
            )
            if (
                source.trust_boundary != journal.trust_boundary
                or source.content_hash != digest
                or source.captured_at > now
                or source.content_location != location
                or source.system != SourceSystem.MANUAL
                or source.external_ref != f"work-journal-snapshot/{digest}"
                or get_effective_source_classification(session, source_id=source.id)
                != journal.data_classification
            ):
                raise ValueError("journal source mismatch")
            return source.id
    except Exception:  # noqa: BLE001, S110 - private-safe fixed diagnostics
        pass
    raise ValueError("work journal capture unavailable or mismatched")


def load_work_journal(
    session: Session,
    *,
    artifacts: ArtifactStore,
    source_id: UUID,
    expected_digest: str,
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
) -> WorkJournal:
    """Caller-owned exact receipt; no latest lookup or recovery guarantee."""
    try:
        if session.new or session.dirty or session.deleted:
            raise ValueError("unrelated pending writes")
        if (
            type(expected_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
        ):
            raise ValueError("invalid expected digest")
        source = get_source(
            session, source_id=source_id, requestor_boundaries=authorized_boundaries
        )
        if (
            source is None
            or source.system != SourceSystem.MANUAL
            or source.content_hash != expected_digest
            or source.external_ref != f"work-journal-snapshot/{expected_digest}"
            or not source.content_location
        ):
            raise ValueError("journal source mismatch")
        label = get_effective_source_classification(session, source_id=source.id)
        _access(source.trust_boundary, label, authorized_boundaries, allowed_classifications)
        payload = artifacts.get(source.trust_boundary, source.content_location)
        if content_hash_of(payload) != expected_digest:
            raise ValueError("journal integrity mismatch")
        journal = decode_work_journal(payload)
        if (
            journal.trust_boundary != source.trust_boundary
            or journal.data_classification != label
            or journal.created_at > source.captured_at
            or any(
                observation.recorded_at > source.captured_at for observation in journal.observations
            )
        ):
            raise ValueError("journal label mismatch")
        _validate(session, artifacts, journal, authorized_boundaries, allowed_classifications)
        return journal
    except Exception:  # noqa: BLE001, S110
        pass
    raise ValueError("work journal load unavailable or mismatched")
