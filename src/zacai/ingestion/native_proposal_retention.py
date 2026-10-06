"""Exact native proposal integrity evidence; no approval, commit or recovery.

Caller supplies already permitted wire inputs and serializes first inserts.
Artifact writes may leave unreferenced orphans on failure. No account, provider,
model, backup or current-fact effects occur. Original selection bytes are private.
Store callbacks are trusted and must not control transactions or issue direct
SQL. Identity/liveness checks detect Session-API boundary changes only; Core,
SQL or driver commits/rollbacks are not portably detected. No sandbox or undo
of already durable commits. Hosts must disable traceback local capture.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.ingestion.native_source_capture import (
    GmailCaptureInput,
    SlackCaptureInput,
    prepare_native_batch_proposal,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation
from zacai.state import Source, SourceClassificationElevation, SourceSystem
from zacai.state_repository import record_source, source_classification_elevation_strength

MAX_PROPOSAL_BYTES = 32_000


class NativeProposalRetentionError(RuntimeError):
    """Fixed message, no chained errors; traceback locals may remain private."""


def _clean(session: Session) -> None:
    if session.new or session.dirty or session.deleted:
        raise ValueError("pending unit of work")


def _time(value: datetime) -> datetime:
    if type(value) is not datetime or value.utcoffset() is None:
        raise ValueError("aware host time")
    return value.astimezone(UTC)


def _get(session: Session, artifacts: ArtifactStore, location: str) -> bytes:
    outer, nested = session.get_transaction(), session.get_nested_transaction()
    if outer is None or not outer.is_active:
        raise ValueError("live caller transaction")
    raw = artifacts.get(B.BRAINSTORM, location)
    if (
        session.get_transaction() is not outer
        or not outer.is_active
        or session.get_nested_transaction() is not nested
        or (nested is not None and not nested.is_active)
    ):
        raise ValueError("store changed transaction")
    return raw


def _put(session: Session, artifacts: ArtifactStore, digest: str, raw: bytes) -> str:
    outer, nested = session.get_transaction(), session.get_nested_transaction()
    if outer is None or not outer.is_active:
        raise ValueError("live caller transaction")
    location = artifacts.put(B.BRAINSTORM, digest, raw)
    if (
        session.get_transaction() is not outer
        or not outer.is_active
        or session.get_nested_transaction() is not nested
        or (nested is not None and not nested.is_active)
    ):
        raise ValueError("store changed transaction")
    return location


def _proposal(
    batch_id: UUID,
    raw: bytes,
    expected: str,
    gmail: tuple[GmailCaptureInput, ...],
    slack: tuple[SlackCaptureInput, ...],
) -> str:
    if (
        type(batch_id) is not UUID
        or type(raw) is not bytes
        or not 0 < len(raw) <= MAX_PROPOSAL_BYTES
        or type(expected) is not str
        or content_hash_of(raw) != expected
        or prepare_native_batch_proposal(batch_id=batch_id, gmail_inputs=gmail, slack_inputs=slack)
        != raw
    ):
        raise ValueError("exact bounded public proposal")
    return "native-source-proposal/" + str(batch_id)


def _rows(session: Session, external: str) -> list[dict[str, Any]]:
    _clean(session)
    latest = (
        select(SourceClassificationElevation.new_classification)
        .where(SourceClassificationElevation.source_id == Source.id)
        .order_by(
            source_classification_elevation_strength().desc(),
            SourceClassificationElevation.elevated_at.desc(),
        )
        .limit(1)
        .correlate(Source)
        .scalar_subquery()
    )
    with session.no_autoflush:
        result = list(
            session.execute(
                select(
                    *Source.__table__.columns,
                    func.coalesce(latest, Source.data_classification).label("effective"),
                )
                .where(Source.external_ref == external)
                .limit(2)
            ).mappings()
        )
    return [dict(row) for row in result]


def _valid(row: dict[str, Any], digest: str, now: datetime) -> None:
    if (
        type(row["id"]) is not UUID
        or row["system"] is not SourceSystem.MANUAL
        or row["trust_boundary"] is not B.BRAINSTORM
        or row["data_classification"] is not C.CONFIDENTIAL
        or row["effective"] is not C.CONFIDENTIAL
        or row["content_hash"] != digest
        or _time(row["captured_at"]) > now
        or type(row["content_location"]) is not str
        or not 0 < len(row["content_location"]) <= 2048
        or row["supersedes_source_id"] is not None
    ):
        raise ValueError("exact fixed proposal family")


def _read(session: Session, artifacts: ArtifactStore, row: dict[str, Any], raw: bytes) -> None:
    _clean(session)
    returned = _get(session, artifacts, row["content_location"])
    _clean(session)
    if type(returned) is not bytes or returned != raw:
        raise ValueError("exact original readback")


def _final(session: Session, external: str, original: dict[str, Any]) -> None:
    # Complete Source columns and effective classification; no callbacks afterward.
    rows = _rows(session, external)
    if rows != [original]:
        raise ValueError("final source observation changed")


def retain_native_proposal(
    session: Session,
    *,
    artifacts: ArtifactStore,
    batch_id: UUID,
    proposal_raw: bytes,
    expected_proposal_hash: str,
    gmail_inputs: tuple[GmailCaptureInput, ...],
    slack_inputs: tuple[SlackCaptureInput, ...],
    retained_at: datetime,
) -> EvidenceReference:
    """Return uncommitted integrity reference only. Host owns permission/commit.

    There is no authorization from USER_INSTRUCTION text or proposal hashes.
    The caller must serialize first inserts; Source's revision primitive alone
    does not serialize two distinct first-ever inserts of the same identity.
    """
    result = None
    try:
        _clean(session)
        _assert_ledger_isolation(session)
        now = _time(retained_at)
        external = _proposal(
            batch_id, proposal_raw, expected_proposal_hash, gmail_inputs, slack_inputs
        )
        prior = _rows(session, external)
        location: str | None = None
        if len(prior) > 1:
            raise ValueError("ambiguous proposal")
        if prior:
            _valid(prior[0], expected_proposal_hash, now)
            _read(session, artifacts, prior[0], proposal_raw)
            _final(session, external, prior[0])
        else:
            location = _put(session, artifacts, expected_proposal_hash, proposal_raw)
            _clean(session)
            if type(location) is not str or not 0 < len(location) <= 2048:
                raise ValueError("location")
            if (
                type(returned := _get(session, artifacts, location)) is not bytes
                or returned != proposal_raw
            ):
                raise ValueError("artifact roundtrip")
            _clean(session)
        with session.begin_nested():
            current = _rows(session, external)
            if current != prior:
                raise ValueError("proposal changed before write")
            if not current:
                if location is None:
                    raise ValueError("missing location")
                record_source(
                    session,
                    trust_boundary=B.BRAINSTORM,
                    data_classification=C.CONFIDENTIAL,
                    system=SourceSystem.MANUAL,
                    content_hash=expected_proposal_hash,
                    content_location=location,
                    external_ref=external,
                    captured_at=now,
                )
                session.flush()
            actual = _rows(session, external)
            if len(actual) != 1:
                raise ValueError("missing proposal")
            row = actual[0]
            _valid(row, expected_proposal_hash, now)
            _read(session, artifacts, row, proposal_raw)
            _final(session, external, row)
            reference = EvidenceReference(
                source_id=row["id"],
                content_hash=expected_proposal_hash,
                trust_boundary=B.BRAINSTORM,
                effective_classification=C.CONFIDENTIAL,
            )
        # Successful flush/RELEASE is required, but this is still uncommitted.
        result = reference
    except Exception:  # noqa: BLE001,S110 - sanitize outside handler
        pass
    if result is None:
        raise NativeProposalRetentionError("native proposal retention held")
    return result


def load_retained_native_proposal(
    session: Session,
    *,
    artifacts: ArtifactStore,
    proposal_reference: EvidenceReference,
    batch_id: UUID,
    expected_proposal_hash: str,
    as_of: datetime,
) -> bytes:
    """Read post-read-bounded retained bytes, never authenticate or repair.

    This is post-read-bounded evidence readback, not proposal schema validation.
    The existing native inventory loader subsequently reconstructs exact public
    proposal bytes from original provider Sources. No inputs are fetched here.
    """
    result = None
    try:
        _clean(session)
        _assert_ledger_isolation(session)
        now = _time(as_of)
        if type(batch_id) is not UUID:
            raise ValueError("exact batch UUID")
        external = "native-source-proposal/" + str(batch_id)
        if type(proposal_reference) is not EvidenceReference:
            raise ValueError("exact reference")
        ref = EvidenceReference.model_validate(proposal_reference)
        if (
            ref.trust_boundary is not B.BRAINSTORM
            or ref.effective_classification is not C.CONFIDENTIAL
            or type(expected_proposal_hash) is not str
            or ref.content_hash != expected_proposal_hash
            or type(ref.source_id) is not UUID
            or type(ref.content_hash) is not str
        ):
            raise ValueError("fixed read scope")
        rows = _rows(session, external)
        if len(rows) != 1:
            raise ValueError("missing or ambiguous proposal")
        row = rows[0]
        _valid(row, expected_proposal_hash, now)
        if row["id"] != ref.source_id or row["content_hash"] != ref.content_hash:
            raise ValueError("exact source binding")
        _clean(session)
        proposal_raw = _get(session, artifacts, row["content_location"])
        _clean(session)
        if (
            type(proposal_raw) is not bytes
            or not 0 < len(proposal_raw) <= MAX_PROPOSAL_BYTES
            or content_hash_of(proposal_raw) != expected_proposal_hash
        ):
            raise ValueError("exact bounded retained bytes")
        _final(session, external, row)
        result = proposal_raw
    except Exception:  # noqa: BLE001,S110 - sanitize outside handler
        pass
    if result is None:
        raise NativeProposalRetentionError("native proposal retention held")
    return result
