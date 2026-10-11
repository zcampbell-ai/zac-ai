"""Read existing complete-declaration custody after an uncertain save.

This never writes, retries, repairs or reissues an action. An absent row is an
uncertain HOLD, not evidence that an earlier writer could not commit. Fresh
same-owner preservation access does not renew the original processing window.
Host code must drain prior writers and keep traceback locals private. Signed
owner checks run outside canonical SQL leases; no continuous owner lease or
same-user filesystem atomicity is claimed.
"""

from __future__ import annotations

from time import monotonic as _NATIVE_MONOTONIC

from sqlalchemy.orm import Session, sessionmaker

from zacai.contextual_authorization import _FRAGMENT_OWNER_SCOPE
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.contextual_storage import _fragment_rows
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.intelligence.history_generation_review_declaration import (
    HistoryGenerationReviewDeclarationV1,
)
from zacai.intelligence.history_review_retention import (
    BOUNDARIES,
    LABELS,
    HistoryDeclarationContext,
    RetainedHistoryDeclarationV1,
    _ids,
    _load,
    _parts,
)
from zacai.interfaces.named_session_binding import NamedSessionOperation, VerifiedNamedSession
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


class HistoryDeclarationReconciliationError(ValueError):
    """Fixed uncertain custody HOLD, never a retry or processing decision."""


def reconcile_history_declaration_custody(
    *,
    factory: sessionmaker[Session],
    artifacts: LocalFilesystemArtifactStore,
    context: HistoryDeclarationContext,
    expected_declaration: HistoryGenerationReviewDeclarationV1,
    operation: NamedSessionOperation,
) -> RetainedHistoryDeclarationV1:
    """Return only an exact existing declaration under current preservation access.

    The original declaration may be expired. Its original capture time, identity
    and bytes must still validate. This result is custody only: all inherited
    authority flags stay false and fresh subject-specific recovery is separate.
    """
    result = None
    try:
        if (
            type(factory) is not sessionmaker
            or type(artifacts) is not LocalFilesystemArtifactStore
            or type(context) is not HistoryDeclarationContext
            or type(operation) is not NamedSessionOperation
        ):
            raise ValueError("concrete preservation inputs required")
        raw, consent, _ = _parts(expected_declaration)
        started = _NATIVE_MONOTONIC()
        owner = operation.establish()
        clock = operation.host_clock
        with clock._lock:
            observed = clock._last
        if (
            type(owner) is not VerifiedNamedSession
            or observed is None
            or owner.principal.scopes != _FRAGMENT_OWNER_SCOPE
            or owner.principal.identity.issuer != consent.owner_issuer
            or owner.principal.identity.subject != consent.owner_subject
            or not owner.issued_at <= observed < owner.effective_expires_at
        ):
            raise ValueError("current same enrolled preservation owner required")
        deadline = started + (owner.effective_expires_at - observed).total_seconds()
        with factory() as session:
            session.begin()
            entry = _physical(session)
            ids = _ids(session, consent.id)
            if len(ids) != 1:
                raise ValueError("exact existing custody not established")
            reference = EvidenceReference(
                source_id=ids[0],
                content_hash=content_hash_of(raw),
                trust_boundary=B.PERSONAL,
                effective_classification=C.HIGHLY_RESTRICTED,
            )
            complete = tuple(sorted((*consent.provenance, reference), key=lambda r: str(r.source_id)))
            # The expected complete subject is supplied by trusted host
            # composition, not discovered from unvalidated private body bytes.
            baseline = _fragment_rows(session, complete, BOUNDARIES, LABELS)
            _same(session, entry)
            retained = _load(session, artifacts, context, reference, expected_declaration)
            if _fragment_rows(session, complete, BOUNDARIES, LABELS) != baseline:
                raise ValueError("expected preservation subject changed during read")
            _same(session, entry)
        # An artifact/read callback may have changed owner state. Verify the
        # actual signed preservation session after the read lease closes.
        current = operation.receipt_only(owner.principal)
        if (
            type(current) is not VerifiedNamedSession
            or current.binding_digest != owner.binding_digest
            or current.issued_at != owner.issued_at
            or current.effective_expires_at != owner.effective_expires_at
        ):
            raise ValueError("preservation session changed")
        with factory() as session:
            session.begin()
            entry = _physical(session)
            final = _fragment_rows(session, complete, BOUNDARIES, LABELS)
            final_ids = _ids(session, consent.id)
            _same(session, entry)
            if final != baseline or final_ids != (reference.source_id,):
                raise ValueError("current exact custody changed")
        if _NATIVE_MONOTONIC() >= deadline:
            raise ValueError("preservation window expired")
        result = retained
    except Exception:  # noqa: BLE001
        result = None
    if result is None:
        raise HistoryDeclarationReconciliationError("complete declaration custody unresolved")
    return result
