"""D034J trusted operator consent ledger outside agents, no public issuer.

Canonical USER_INSTRUCTION Sources attest an actual human decision. This code
cannot authenticate chat messages or protect against hostile Python/DB admins.
No live approval, recovery verifier, endpoint or automatic consent is supplied.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence.review_evaluation import review_context_digest
from zacai.intelligence.review_freshness import review_evidence_digest
from zacai.intelligence.review_generation import ReviewDraft, ReviewRequest, prepare_review_request
from zacai.intelligence.review_host import ReviewSelection
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_effective_source_classification, record_source


class ReviewAuthorizationError(RuntimeError):
    """Fixed diagnostics, no private source or backend text."""


class ReviewConsent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")
    format: Literal["zac-review-consent-v1"] = "zac-review-consent-v1"
    id: UUID
    selection: ReviewSelection
    boundary: Literal[B.BRAINSTORM] = B.BRAINSTORM
    classification: Literal[C.CONFIDENTIAL] = C.CONFIDENTIAL
    route: ModelRoute
    model_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    prepared_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    approved_at: AwareDatetime
    expires_at: AwareDatetime
    human_reference: str = Field(min_length=1, max_length=500, strict=True)
    state_recovery_reference: str = Field(min_length=1, max_length=500, strict=True)
    artifact_recovery_reference: str = Field(min_length=1, max_length=500, strict=True)
    credential_recovery_reference: str = Field(min_length=1, max_length=500, strict=True)

    @model_validator(mode="after")
    def bounded_scope(self) -> ReviewConsent:
        if self.route.destination != Destination.LOCAL or not (
            timedelta(0) < self.expires_at - self.approved_at <= timedelta(minutes=15)
        ):
            raise ValueError("invalid bounded review consent")
        if len(self.selection.earlier) > 7 or len(self.selection.projects) > 3:
            raise ValueError("selection outside bounded review limits")
        if any(
            not value.strip()
            for value in (
                self.human_reference,
                self.state_recovery_reference,
                self.artifact_recovery_reference,
                self.credential_recovery_reference,
            )
        ):
            raise ValueError("empty operator reference")
        return self


class ReviewRecoveryGate(Protocol):
    def preflight(self, consent: ReviewConsent) -> None:
        """Verify actual current recovery/escrow evidence, not reference equality.

        Mandatory trusted adapter. No permissive production backend is shipped.
        The host separately commits pre-context denial metadata before a truthful
        task exists; this gate must never manufacture a task or permission grant.
        """
        ...


def prepared_review_digest(request: ReviewRequest) -> str:
    """Bind exact evidence, limits and generation instructions across reassembly.

    Fresh task/event/observation UUIDs do not invalidate human consent. Claims
    separately bind the actual task/context. Hashes remain classified metadata.
    """
    if request != prepare_review_request(request.context):
        raise ReviewAuthorizationError("modified review request")
    raw = json.dumps(
        {
            "evidence": review_evidence_digest(request.context),
            "instruction": request.instruction,
            "passages": request.evidence_json,
            "output_schema": ReviewDraft.model_json_schema(),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def _lock(session: Session, approval_id: UUID) -> None:
    session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": approval_id.int % 2**63})


def _find(session: Session, ref: str, system: SourceSystem) -> Source | None:
    return session.execute(
        select(Source).where(
            Source.trust_boundary == B.BRAINSTORM,
            Source.system == system,
            Source.external_ref == ref,
        )
    ).scalar_one_or_none()


def _bytes(session: Session, store: ArtifactStore, source: Source) -> bytes:
    if (
        not source.content_location
        or not source.content_hash
        or get_effective_source_classification(session, source_id=source.id) != C.CONFIDENTIAL
    ):
        raise ReviewAuthorizationError("review authority unavailable")
    raw = store.get(B.BRAINSTORM, source.content_location)
    if len(raw) > 32_000 or content_hash_of(raw) != source.content_hash:
        raise ReviewAuthorizationError("review authority integrity failed")
    return raw


def _write(
    session: Session, store: ArtifactStore, ref: str, system: SourceSystem, raw: bytes, at: datetime
) -> UUID:
    digest = content_hash_of(raw)
    prior = _find(session, ref, system)
    if prior is not None:
        if _bytes(session, store, prior) != raw:
            raise ReviewAuthorizationError("review authority cannot be revised")
        return prior.id
    location = store.put(B.BRAINSTORM, digest, raw)
    if content_hash_of(store.get(B.BRAINSTORM, location)) != digest:
        raise ReviewAuthorizationError("review authority integrity failed")
    source, _ = record_source(
        session,
        trust_boundary=B.BRAINSTORM,
        data_classification=C.CONFIDENTIAL,
        system=system,
        external_ref=ref,
        content_hash=digest,
        content_location=location,
        captured_at=at,
    )
    return source.id


def record_review_consent(
    session: Session, *, store: ArtifactStore, consent: ReviewConsent
) -> UUID:
    """Trusted operator only AFTER human decision and actual recovery checks.

    Caller owns commit; strings attest evidence but do not establish it. No API,
    agent/tool issuer or message parser exists. No gateway DENY can be overridden.
    """
    consent = ReviewConsent.model_validate(consent)
    _lock(session, consent.id)
    return _write(
        session,
        store,
        f"review-consent/{consent.id}",
        SourceSystem.USER_INSTRUCTION,
        consent.model_dump_json().encode(),
        consent.approved_at,
    )


def _load(
    session: Session, store: ArtifactStore, approval_id: UUID, now: datetime
) -> ReviewConsent:
    source = session.get(Source, approval_id)
    if (
        source is None
        or source.trust_boundary != B.BRAINSTORM
        or (source.system != SourceSystem.USER_INSTRUCTION)
    ):
        raise ReviewAuthorizationError("review authority unavailable")
    consent = ReviewConsent.model_validate_json(_bytes(session, store, source))
    if (
        source.external_ref != f"review-consent/{consent.id}"
        or now.utcoffset() is None
        or not (consent.approved_at <= now < consent.expires_at)
    ):
        raise ReviewAuthorizationError("review authority inactive")
    if (
        _find(session, f"review-revocation/{approval_id}", SourceSystem.USER_INSTRUCTION)
        is not None
    ):
        raise ReviewAuthorizationError("review authority revoked")
    return consent


def revoke_review_consent(
    session: Session,
    *,
    store: ArtifactStore,
    approval_id: UUID,
    human_reference: str,
    revoked_at: datetime,
) -> UUID:
    """Append a human revocation under the same lock as claim; never renew."""
    if revoked_at.utcoffset() is None or not human_reference.strip() or len(human_reference) > 500:
        raise ReviewAuthorizationError("invalid revocation reference")
    _lock(session, approval_id)
    # Verify canonical identity; revocation is allowed even after consent expiry.
    source = session.get(Source, approval_id)
    if (
        source is None
        or source.trust_boundary != B.BRAINSTORM
        or (source.system != SourceSystem.USER_INSTRUCTION)
    ):
        raise ReviewAuthorizationError("review authority unavailable")
    consent = ReviewConsent.model_validate_json(_bytes(session, store, source))
    if source.external_ref != f"review-consent/{consent.id}":
        raise ReviewAuthorizationError("review authority unavailable")
    raw = json.dumps(
        {
            "format": "zac-review-revocation-v1",
            "approval_id": str(approval_id),
            "human_reference": human_reference,
            "revoked_at": revoked_at.isoformat(),
        },
        sort_keys=True,
    ).encode()
    return _write(
        session,
        store,
        f"review-revocation/{approval_id}",
        SourceSystem.USER_INSTRUCTION,
        raw,
        revoked_at,
    )


def _selection_matches(scope: ReviewConsent, request: ReviewRequest) -> bool:
    selected = scope.selection.selected
    related = {item.source_id for item in scope.selection.earlier} | {
        item.source_id for item in scope.selection.projects
    }
    meetings = {selected.meeting_id} | {item.meeting_id for item in scope.selection.earlier}
    actual = {
        entity.entity_id
        for entity in request.context.task.event.related_entities
        if entity.entity_type == "Meeting"
    }
    return (
        request.context.meeting_source_id == selected.source_id
        and request.context.related_source_ids == related
        and actual == meetings
    )


class CanonicalReviewAuthorization:
    """One-shot Source ledger. Must be invoked through the existing review host.

    Source artifacts/claims use the existing encryption/recovery seam. Locking
    serializes trusted claim/revocation; not a sandbox against arbitrary DB writes.
    """

    def __init__(
        self,
        *,
        factory: sessionmaker[Session],
        store: ArtifactStore,
        approval_id: UUID,
        recovery: ReviewRecoveryGate,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._factory, self._store, self._approval = factory, store, approval_id
        self._recovery, self._clock = recovery, clock
        self._preflighted: str | None = None

    def preflight(self, selection: ReviewSelection, route: ModelRoute, model_digest: str) -> None:
        try:
            self._preflighted = None
            with self._factory() as session:
                scope = _load(session, self._store, self._approval, self._clock())
                if (
                    scope.selection != selection
                    or scope.route != route
                    or (scope.model_digest != model_digest)
                    or _find(session, f"review-claim/{self._approval}", SourceSystem.MANUAL)
                    is not None
                ):
                    raise ValueError("scope mismatch or consumed")
            self._recovery.preflight(scope)
            self._preflighted = content_hash_of(scope.model_dump_json().encode())
        except Exception:  # noqa: BLE001 - keep authority/backend diagnostics private
            raise ReviewAuthorizationError("review authorization preflight failed") from None

    def claim(
        self,
        run_id: UUID,
        request: ReviewRequest,
        route: ModelRoute,
        model_digest: str,
        now: datetime,
    ) -> None:
        try:
            with self._factory() as session:
                _lock(session, self._approval)
                scope = _load(session, self._store, self._approval, now)
                if (
                    self._preflighted != content_hash_of(scope.model_dump_json().encode())
                    or scope.route != route
                    or scope.model_digest != model_digest
                    or not _selection_matches(scope, request)
                    or scope.prepared_digest != prepared_review_digest(request)
                    or request.context.task.event.trust_boundary != scope.boundary
                    or request.context.task.event.data_classification != scope.classification
                    or _find(session, f"review-claim/{self._approval}", SourceSystem.MANUAL)
                    is not None
                ):
                    raise ValueError("scope mismatch or consumed")
                self._recovery.preflight(scope)
                raw = json.dumps(
                    {
                        "format": "zac-review-claim-v1",
                        "approval_id": str(self._approval),
                        "run_id": str(run_id),
                        "context_digest": review_context_digest(request.context),
                        "prepared_digest": scope.prepared_digest,
                    },
                    sort_keys=True,
                ).encode()
                _write(
                    session,
                    self._store,
                    f"review-claim/{self._approval}",
                    SourceSystem.MANUAL,
                    raw,
                    now,
                )
                session.commit()  # durable consume precedes model dispatch
        except Exception:  # noqa: BLE001
            raise ReviewAuthorizationError("review authorization claim failed") from None

    def recheck(self, run_id: UUID, request: ReviewRequest, now: datetime) -> None:
        try:
            with self._factory() as session:
                scope = _load(session, self._store, self._approval, now)
                claim = _find(session, f"review-claim/{self._approval}", SourceSystem.MANUAL)
                if claim is None:
                    raise ValueError("missing claim")
                value = json.loads(_bytes(session, self._store, claim))
                if value != {
                    "format": "zac-review-claim-v1",
                    "approval_id": str(self._approval),
                    "run_id": str(run_id),
                    "context_digest": review_context_digest(request.context),
                    "prepared_digest": scope.prepared_digest,
                } or (
                    prepared_review_digest(request) != scope.prepared_digest
                    or not _selection_matches(scope, request)
                ):
                    raise ValueError("claim binding changed")
                self._recovery.preflight(scope)
        except Exception:  # noqa: BLE001
            raise ReviewAuthorizationError("review authorization recheck failed") from None
