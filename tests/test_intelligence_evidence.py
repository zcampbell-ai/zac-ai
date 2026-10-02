"""D032 read-only resolution of canonical effective source classification.

All writes are synthetic fixtures rolled back by D027's db_session. No live
source, account, network, credential or external model is used.
"""

from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.evidence import resolve_evidence_reference
from zacai.policy import DataClassification, TrustBoundary
from zacai.state import Source, SourceSystem
from zacai.state_repository import elevate_source_classification, record_source


def test_elevation_is_resolved_from_canonical_state_and_old_snapshot_stays_historical(
    db_session: Session,
    tmp_path: Path,
) -> None:
    store = LocalFilesystemArtifactStore(tmp_path / "synthetic-artifacts")
    raw = b"Synthetic evidence only; no real transcript."
    digest = content_hash_of(raw)
    location = store.put(TrustBoundary.BRAINSTORM, digest, raw)
    source, _ = record_source(
        db_session,
        trust_boundary=TrustBoundary.BRAINSTORM,
        data_classification=DataClassification.INTERNAL,
        system=SourceSystem.MANUAL,
        content_hash=digest,
        content_location=location,
    )
    boundaries = frozenset({TrustBoundary.BRAINSTORM})
    first = resolve_evidence_reference(
        db_session, source_id=source.id, requestor_boundaries=boundaries
    )
    elevate_source_classification(
        db_session,
        source_id=source.id,
        trust_boundary=TrustBoundary.BRAINSTORM,
        new_classification=DataClassification.HIGHLY_RESTRICTED,
        reason="Synthetic elevation test",
        elevated_by="synthetic-fixture",
    )
    current = resolve_evidence_reference(
        db_session, source_id=source.id, requestor_boundaries=boundaries
    )
    assert source.data_classification == DataClassification.INTERNAL
    assert first.effective_classification == DataClassification.INTERNAL
    assert current.effective_classification == DataClassification.HIGHLY_RESTRICTED
    assert current.content_hash == digest
    assert current.source_id == first.source_id
    assert current.trust_boundary == TrustBoundary.BRAINSTORM


@pytest.mark.parametrize("boundaries", [frozenset(), frozenset({TrustBoundary.SHARED})])
def test_unauthorized_and_missing_sources_are_indistinguishable(
    db_session: Session,
    boundaries: frozenset[TrustBoundary],
) -> None:
    source = Source(
        trust_boundary=TrustBoundary.PERSONAL,
        data_classification=DataClassification.INTERNAL,
        system=SourceSystem.MANUAL,
    )
    db_session.add(source)
    db_session.flush()
    for source_id in (source.id, uuid4()):
        with pytest.raises(ValueError, match="source not found or not authorized"):
            resolve_evidence_reference(
                db_session,
                source_id=source_id,
                requestor_boundaries=boundaries,
            )


def test_v1_requires_content_addressed_source(db_session: Session) -> None:
    source = Source(
        trust_boundary=TrustBoundary.BRAINSTORM,
        data_classification=DataClassification.INTERNAL,
        system=SourceSystem.MANUAL,
    )
    db_session.add(source)
    db_session.flush()
    with pytest.raises(ValueError, match="lacks a content hash"):
        resolve_evidence_reference(
            db_session,
            source_id=source.id,
            requestor_boundaries=frozenset({TrustBoundary.BRAINSTORM}),
        )
