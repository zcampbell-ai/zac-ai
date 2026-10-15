"""Complete declaration custody/recovery, without processing or admission."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from time import monotonic as _NATIVE_MONOTONIC
from typing import Literal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from zacai.backup_artifacts import _assert_personal_custody_append_capacity
from zacai.claude_original_capture import ClaudeArtifactRootIdentity, _artifact_profile, _root_check
from zacai.contextual_authorization import (
    _FRAGMENT_OWNER_SCOPE,
    _assert_fragment_generation_unconsumed,
)
from zacai.host_clock import HostObservedClock
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.contextual_storage import _fragment_rows, _history_reconstruct
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.fragment_publication_generation import (
    _same_output_commit_transaction as _same_commit,
)
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.intelligence.history_contextual_codec import (
    HistoryContextualRequestV1,
    decode_history_contextual_request,
)
from zacai.intelligence.history_generation_review_declaration import (
    MAX_DECLARATION_BYTES,
    HistoryConsentV1,
    HistoryGenerationReviewDeclarationV1,
    decode_history_consent,
    decode_history_generation_review_declaration,
    encode_history_generation_review_declaration,
    history_generation_review_declaration_digest,
)
from zacai.interfaces.named_session_binding import NamedSessionOperation, VerifiedNamedSession
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _lock
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source

BOUNDARIES = frozenset({B.PERSONAL})
LABELS = frozenset({C.HIGHLY_RESTRICTED})


class HistoryDeclarationRetentionError(ValueError):
    """Fixed safe HOLD; a canonical declaration may already be committed."""


@dataclass(frozen=True, repr=False)
class HistoryDeclarationContext:
    expected_root: ClaudeArtifactRootIdentity
    expected_account_ref: str
    expected_exported_at: datetime | None


@dataclass(frozen=True, repr=False)
class RetainedHistoryDeclarationV1:
    reference: EvidenceReference = field(repr=False)
    declaration: HistoryGenerationReviewDeclarationV1 = field(repr=False)
    publication_digest: str
    captured_at: datetime

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def owner_admitted(self) -> Literal[False]:
        return False


def history_declaration_owner(
    operation: NamedSessionOperation, clock: HostObservedClock, consent: HistoryConsentV1
) -> VerifiedNamedSession:
    """Actual signed operation last, then callback-free original-window checks."""
    if type(operation) is not NamedSessionOperation or type(clock) is not HostObservedClock:
        raise ValueError("actual original operation and clock required")
    if operation.host_clock is not clock:
        raise ValueError("original operation clock required")
    clock()
    owner = operation.recheck(consent.original_session_binding)
    with clock._lock:
        now = clock._last
    if (
        type(owner) is not VerifiedNamedSession
        or now is None
        or owner.principal.scopes != _FRAGMENT_OWNER_SCOPE
        or owner.principal.identity.issuer != consent.owner_issuer
        or owner.principal.identity.subject != consent.owner_subject
        or owner.binding_digest != consent.original_session_binding
        or owner.issued_at != consent.original_session_issued_at
        or owner.effective_expires_at != consent.original_session_expires_at
        or not consent.approved_at <= now < consent.expires_at
        or not owner.issued_at <= now < owner.effective_expires_at
    ):
        raise ValueError("current original signed owner/window required")
    return owner


def _parts(
    declaration: HistoryGenerationReviewDeclarationV1,
) -> tuple[bytes, HistoryConsentV1, HistoryContextualRequestV1]:
    raw = encode_history_generation_review_declaration(declaration)
    return (
        raw,
        decode_history_consent(declaration.generation_consent_json.encode()),
        decode_history_contextual_request(declaration.generation_request_json.encode()),
    )


def _prefix(generation_id: UUID) -> str:
    return f"personal-history-complete-declaration-v1/{generation_id}/"


def _ids(session: Session, generation_id: UUID) -> tuple[UUID, ...]:
    return tuple(
        session.scalars(
            select(Source.id)
            .where(
                Source.trust_boundary == B.PERSONAL,
                Source.system == SourceSystem.MANUAL,
                Source.external_ref.like(_prefix(generation_id) + "%"),
            )
            .limit(2)
        )
    )


def _namespace(declaration: HistoryGenerationReviewDeclarationV1) -> str:
    raw, g, _ = _parts(declaration)
    return (
        _prefix(g.id)
        + content_hash_of(raw)
        + "/"
        + history_generation_review_declaration_digest(declaration)
        + "/"
        + g.request_digest
    )


def _reconstruct(
    session: Session,
    artifacts: LocalFilesystemArtifactStore,
    context: HistoryDeclarationContext,
    declaration: HistoryGenerationReviewDeclarationV1,
) -> None:
    if type(context) is not HistoryDeclarationContext:
        raise ValueError("exact original reconstruction settings required")
    _history_reconstruct(
        session,
        artifacts=artifacts,
        expected_root=context.expected_root,
        expected_account_ref=context.expected_account_ref,
        expected_exported_at=context.expected_exported_at,
        request=_parts(declaration)[2],
        authorized_boundaries=BOUNDARIES,
        allowed_classifications=LABELS,
    )


def _load(
    session: Session,
    artifacts: LocalFilesystemArtifactStore,
    context: HistoryDeclarationContext,
    reference: EvidenceReference,
    declaration: HistoryGenerationReviewDeclarationV1,
) -> RetainedHistoryDeclarationV1:
    raw, g, _ = _parts(declaration)
    if (
        type(artifacts) is not LocalFilesystemArtifactStore
        or type(reference) is not EvidenceReference
        or reference.source_id.int == 0
        or reference.content_hash != content_hash_of(raw)
        or reference.trust_boundary is not B.PERSONAL
        or reference.effective_classification is not C.HIGHLY_RESTRICTED
    ):
        raise ValueError("exact complete own Source required")
    entry = _physical(session)
    complete = tuple(sorted((*g.provenance, reference), key=lambda r: str(r.source_id)))
    if len({r.source_id for r in complete}) != len(complete) or len(complete) > 95:
        raise ValueError("bounded distinct full declaration union required")
    before = _fragment_rows(session, complete, BOUNDARIES, LABELS)
    rows = [dict(r) for r in before if dict(r)["id"] == reference.source_id]
    if (
        not rows
        or {row["lineage_id"] for row in rows} != {reference.source_id}
        or _ids(session, g.id) != (reference.source_id,)
    ):
        raise ValueError("single immutable declaration identity required")
    captured = rows[0]["captured_at"]
    if type(captured) is not datetime or captured.utcoffset() is None:
        raise ValueError("aware original capture time required")
    for row in rows:
        if (
            row["system"] is not SourceSystem.MANUAL
            or row["external_ref"] != _namespace(declaration)
            or row["supersedes_source_id"] is not None
            or row["data_classification"] is not C.HIGHLY_RESTRICTED
            or row["captured_at"] != captured
            or not declaration.approved_at <= captured < declaration.expires_at
        ):
            raise ValueError("exact declaration Source metadata required")
    _same(session, entry)
    _reconstruct(session, artifacts, context, declaration)
    _same(session, entry)
    if _fragment_rows(session, complete, BOUNDARIES, LABELS) != before or _ids(session, g.id) != (
        reference.source_id,
    ):
        raise ValueError("current original union changed")
    location = rows[0]["content_location"]
    if type(location) is not str:
        raise ValueError("bounded own location required")
    returned = artifacts.get_bounded(B.PERSONAL, location, max_bytes=MAX_DECLARATION_BYTES)
    _same(session, entry)
    if (
        content_hash_of(returned) != reference.content_hash
        or returned != raw
        or decode_history_generation_review_declaration(returned) != declaration
    ):
        raise ValueError("exact full declaration bytes required")
    after = _fragment_rows(session, complete, BOUNDARIES, LABELS)
    final_ids = _ids(session, g.id)
    _same(session, entry)
    if after != before or final_ids != (reference.source_id,):
        raise ValueError("final complete declaration union/identity changed")
    return RetainedHistoryDeclarationV1(
        reference, declaration, history_generation_review_declaration_digest(declaration), captured
    )


def load_history_review_declaration(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    context: HistoryDeclarationContext,
    reference: EvidenceReference,
    expected_declaration: HistoryGenerationReviewDeclarationV1,
) -> RetainedHistoryDeclarationV1:
    result = None
    try:
        result = _load(session, artifacts, context, reference, expected_declaration)
    except Exception:  # noqa: BLE001
        result = None
    if result is None:
        raise HistoryDeclarationRetentionError("canonical complete declaration unavailable")
    return result


def capture_history_review_declaration(
    *,
    factory: sessionmaker[Session],
    artifacts: LocalFilesystemArtifactStore,
    context: HistoryDeclarationContext,
    declaration: HistoryGenerationReviewDeclarationV1,
    operation: NamedSessionOperation,
    clock: HostObservedClock,
) -> RetainedHistoryDeclarationV1:
    """Actual commit/close/reopen; failures never repair or renew declaration.

    Caller must treat a HOLD as possibly committed; this is custody only.
    Cancellation/consumption and admission checks remain separate consumers.
    """
    result = None
    try:
        raw, g, _ = _parts(declaration)
        # Own declaration occupies one slot in the unchanged 95-reference
        # canonical loader/recovery union. Refuse before any custody write.
        if len(g.provenance) + 1 > 95:
            raise ValueError("complete declaration union capacity exceeded")
        if type(factory) is not sessionmaker or type(artifacts) is not LocalFilesystemArtifactStore:
            raise ValueError("concrete canonical factory/store required")
        # Anchor before the first wall-clock/owner observation. This bound is
        # never renewed and does not promise owner continuity during SQL.
        started = _NATIVE_MONOTONIC()
        history_declaration_owner(operation, clock, g)
        with clock._lock:
            observed = clock._last
        if observed is None:
            raise ValueError("original owner clock observation required")
        deadline = started + (g.expires_at - observed).total_seconds()
        # Clean read preparation only. Close before artifact/clock/owner
        # callbacks; the write lease below admits no such callbacks.
        with factory() as session:
            session.begin()
            entry = _physical(session)
            _assert_fragment_generation_unconsumed(session, g.id)
            before = _fragment_rows(session, g.provenance, BOUNDARIES, LABELS)
            _same(session, entry)
            _reconstruct(session, artifacts, context, declaration)
            _same(session, entry)
            if _fragment_rows(session, g.provenance, BOUNDARIES, LABELS) != before:
                raise ValueError("original reconstruction union changed")
            ids = _ids(session, g.id)
            if len(ids) > 1:
                raise ValueError("conflicting complete publication")
            if ids:
                existing_reference = EvidenceReference(
                    source_id=ids[0],
                    content_hash=content_hash_of(raw),
                    trust_boundary=B.PERSONAL,
                    effective_classification=C.HIGHLY_RESTRICTED,
                )
                existing = _load(session, artifacts, context, existing_reference, declaration)
                existing_rows = _fragment_rows(
                    session, (*g.provenance, existing_reference), BOUNDARIES, LABELS
                )
                existing_own = [
                    dict(r) for r in existing_rows if dict(r)["id"] == existing_reference.source_id
                ]
                if not existing_own:
                    raise ValueError("existing immutable declaration metadata required")
                candidate_location = existing_own[0]["content_location"]
                if type(candidate_location) is not str:
                    raise ValueError("existing immutable artifact locator required")
                location = candidate_location
            prepared_refs = (*g.provenance, existing_reference) if ids else g.provenance
            prepared_rows = existing_rows if ids else before
            _same(session, entry)
        # Content-addressed preparation may leave an orphan on later HOLD;
        # never delete, repair, remint or treat it as canonical admission.
        _root_check(artifacts, context.expected_root)
        if not ids:
            location = artifacts.put(B.PERSONAL, content_hash_of(raw), raw)
        returned = artifacts.get_bounded(B.PERSONAL, location, max_bytes=MAX_DECLARATION_BYTES)
        _artifact_profile(artifacts, B.PERSONAL, location)
        _root_check(artifacts, context.expected_root)
        if returned != raw or location != artifacts.location_for(content_hash_of(raw)):
            raise ValueError("exact immutable prepared artifact required")
        captured = clock() if not ids else existing.captured_at
        history_declaration_owner(operation, clock, g)
        if not declaration.approved_at <= captured < declaration.expires_at:
            raise ValueError("original capture window required")
        if _NATIVE_MONOTONIC() >= deadline:
            raise ValueError("original capture window expired")
        # Parent lock and all canonical race checks happen only after the last
        # owner callback. No artifact/owner/host-clock callback inside this lease.
        with factory() as session:
            session.begin()
            _lock(session, g.id)
            entry = _physical(session)
            _assert_fragment_generation_unconsumed(session, g.id)
            if (
                _fragment_rows(session, prepared_refs, BOUNDARIES, LABELS) != prepared_rows
                or _ids(session, g.id) != ids
            ):
                raise ValueError("prepared union or namespace changed")
            _same(session, entry)
            if not ids:
                _assert_personal_custody_append_capacity(session, 8)
                _same(session, entry)
                own, _ = record_source(
                    session,
                    trust_boundary=B.PERSONAL,
                    data_classification=C.HIGHLY_RESTRICTED,
                    system=SourceSystem.MANUAL,
                    external_ref=_namespace(declaration),
                    content_hash=content_hash_of(raw),
                    content_location=location,
                    captured_at=captured,
                )
                sid = own.id
            else:
                sid = ids[0]
            reference = EvidenceReference(
                source_id=sid,
                content_hash=content_hash_of(raw),
                trust_boundary=B.PERSONAL,
                effective_classification=C.HIGHLY_RESTRICTED,
            )
            # Actual reader cannot reopen in an assigned write transaction.
            # Check pending own scalar metadata; full paired reconstruction is
            # mandatory below in the fresh transaction after commit/close.
            pending = _fragment_rows(session, (*g.provenance, reference), BOUNDARIES, LABELS)
            owned = [dict(row) for row in pending if dict(row)["id"] == reference.source_id]
            if (
                not owned
                or _ids(session, g.id) != (reference.source_id,)
                or any(
                    row["system"] is not SourceSystem.MANUAL
                    or row["external_ref"] != _namespace(declaration)
                    or row["data_classification"] is not C.HIGHLY_RESTRICTED
                    or row["content_hash"] != reference.content_hash
                    or row["supersedes_source_id"] is not None
                    or row["lineage_id"] != reference.source_id
                    or (
                        not ids
                        and (row["captured_at"] != captured or row["content_location"] != location)
                    )
                    for row in owned
                )
                or _fragment_rows(session, g.provenance, BOUNDARIES, LABELS) != before
            ):
                raise ValueError("pending actual declaration metadata changed")
            _assert_fragment_generation_unconsumed(session, g.id)
            _same(session, entry)  # Includes the last blocking physical SQL.
            if _NATIVE_MONOTONIC() >= deadline:
                raise ValueError("original capture window expired before commit")
            _same_commit(session, entry)  # Callback-free physical scalar check.
            session.commit()
        history_declaration_owner(operation, clock, g)
        with factory() as session:
            session.begin()
            reopened = _load(session, artifacts, context, reference, declaration)
            entry = _physical(session)
            complete = tuple(sorted((*g.provenance, reference), key=lambda r: str(r.source_id)))
            baseline = _fragment_rows(session, complete, BOUNDARIES, LABELS)
            _same(session, entry)
        history_declaration_owner(operation, clock, g)
        with factory() as session:
            session.begin()
            entry = _physical(session)
            final = _fragment_rows(session, complete, BOUNDARIES, LABELS)
            final_ids = _ids(session, g.id)
            _assert_fragment_generation_unconsumed(session, g.id)
            _same(session, entry)
            if final != baseline or final_ids != (reference.source_id,):
                raise ValueError("final custody union changed")
        if _NATIVE_MONOTONIC() >= deadline:
            raise ValueError("original capture window expired before acknowledgment")
        result = reopened
    except Exception:  # noqa: BLE001
        result = None
    if result is None:
        raise HistoryDeclarationRetentionError("complete declaration custody unavailable")
    return result
