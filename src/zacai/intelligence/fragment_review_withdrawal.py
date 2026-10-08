"""Historical declaration comparison only; no cancel intent or processing authority."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from zacai import contextual_authorization as auth
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.contextual_storage import _fragment_rows
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.fragment_review_declaration import (
    MAX_DECLARATION_BYTES,
    FragmentGenerationReviewDeclarationV2,
    decode_fragment_generation_review_declaration,
    fragment_generation_review_declaration_digest,
)
from zacai.intelligence.fragment_review_retention import _namespace, _parts, _physical, _same
from zacai.intelligence.history_fragment_contextual_codec import HistoryFragmentContextualRequestV1
from zacai.interfaces.fragment_publication_web import (
    _FragmentPostObservation,
    _PostedFragmentAction,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem


class FragmentWithdrawalTargetError(ValueError):
    """Fixed private-safe historical comparison diagnostic."""


@dataclass(frozen=True, repr=False)
class HistoricalFragmentDeclarationTarget:
    reference: EvidenceReference = field(repr=False)
    declaration: FragmentGenerationReviewDeclarationV2 = field(repr=False)
    generation: auth.HistoryFragmentConsentV1 = field(repr=False)
    request: HistoryFragmentContextualRequestV1 = field(repr=False)
    publication_digest: str
    captured_at: datetime

    @property
    def cancel_authorized(self) -> Literal[False]:
        return False

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def owner_authenticated(self) -> Literal[False]:
        return False


def _target(
    session: Session,
    artifacts: LocalFilesystemArtifactStore,
    reference: EvidenceReference,
    declaration: FragmentGenerationReviewDeclarationV2,
) -> HistoricalFragmentDeclarationTarget:
    raw, generation, request = _parts(declaration)
    if (
        type(artifacts) is not LocalFilesystemArtifactStore
        or type(reference) is not EvidenceReference
        or reference.source_id.int == 0
        or reference.content_hash != content_hash_of(raw)
        or reference.trust_boundary is not B.PERSONAL
        or reference.effective_classification is not C.HIGHLY_RESTRICTED
    ):
        raise ValueError("exact historical publication reference required")
    entry = _physical(session)
    # Only the publication is accessed. Embedded input references remain dated
    # comparison data: cancellation must not depend on their current eligibility.
    before = _fragment_rows(session, (reference,), auth._FRAGMENT_BOUNDARIES, auth._FRAGMENT_LABELS)
    rows = [dict(row) for row in before]
    if len(rows) != 1 or rows[0]["id"] != reference.source_id:
        raise ValueError("single immutable publication Source required")
    row = rows[0]
    captured = row["captured_at"]
    if (
        row["lineage_id"] != reference.source_id
        or row["system"] is not SourceSystem.MANUAL
        or row["external_ref"] != _namespace(declaration)
        or row["supersedes_source_id"] is not None
        or type(captured) is not datetime
        or captured.utcoffset() is None
        or not declaration.approved_at <= captured < declaration.expires_at
        or type(row["content_location"]) is not str
    ):
        raise ValueError("historical publication metadata mismatch")
    prefix = f"personal-history-fragment-declaration-v2/{generation.id}/"

    def unique() -> None:
        ids = tuple(
            session.scalars(
                select(Source.id)
                .where(
                    Source.trust_boundary == B.PERSONAL,
                    Source.system == SourceSystem.MANUAL,
                    Source.external_ref.like(prefix + "%"),
                )
                .limit(2)
            )
        )
        _same(session, entry)
        if ids != (reference.source_id,):
            raise ValueError("historical publication parent prefix conflict")

    unique()
    returned = artifacts.get_bounded(
        B.PERSONAL, row["content_location"], max_bytes=MAX_DECLARATION_BYTES
    )
    _same(session, entry)
    if returned != raw or decode_fragment_generation_review_declaration(returned) != declaration:
        raise ValueError("exact historical publication bytes required")
    after = _fragment_rows(session, (reference,), auth._FRAGMENT_BOUNDARIES, auth._FRAGMENT_LABELS)
    _same(session, entry)
    if after != before:
        raise ValueError("historical publication changed during read")
    unique()
    return HistoricalFragmentDeclarationTarget(
        reference,
        declaration,
        generation,
        request,
        fragment_generation_review_declaration_digest(declaration),
        captured,
    )


def load_historical_fragment_declaration_target(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    reference: EvidenceReference,
    expected_declaration: FragmentGenerationReviewDeclarationV2,
) -> HistoricalFragmentDeclarationTarget:
    """Read exact own target, not its current task inputs, without authorizing cancel.

    Caller supplies a live clean physical transaction and current target reference.
    Original owner/request/window are immutable reported comparison data. No current
    cookie, human intent, owner permission, recovery or processing proof is minted.
    """
    result = None
    try:
        result = _target(session, artifacts, reference, expected_declaration)
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentWithdrawalTargetError("historical fragment target unavailable")
    return result


# The browser token is imported locally by the writer to preserve the existing
# historical reader's dependency direction. No independent token can be minted here.
MAX_WITHDRAWAL_BYTES = 16000


def _withdrawal_namespace(generation_id: UUID) -> str:
    from uuid import UUID

    if type(generation_id) is not UUID or generation_id.int == 0:
        raise ValueError("exact original generation required")
    return f"personal-history-fragment-withdrawal/{generation_id}"


def _withdrawal_ids(session: Session, generation_id: UUID) -> tuple[UUID, ...]:
    return tuple(
        session.scalars(
            select(Source.id)
            .where(
                Source.trust_boundary == B.PERSONAL,
                Source.system == SourceSystem.USER_INSTRUCTION,
                Source.external_ref == _withdrawal_namespace(generation_id),
            )
            .limit(2)
        )
    )


def assert_fragment_publication_not_withdrawn(session: Session, *, generation_id: UUID) -> None:
    """Negative gate only; any committed cancellation row denies without backup.

    Consumers must call under the original generation lock at their own dispatch
    boundaries. Absence is NOT admission, current owner or recovery proof.
    Corrupt/multiple observations remain denial, never repair/re-enable.
    """
    valid = False
    try:
        entry = _physical(session)
        ids = _withdrawal_ids(session, generation_id)
        _same(session, entry)
        valid = not ids
    except Exception:  # noqa: BLE001,S110
        pass
    if not valid:
        raise FragmentWithdrawalTargetError("fragment publication inactive")


def _binding(target: HistoricalFragmentDeclarationTarget) -> dict[str, Any]:
    return {
        "format": "zac-fragment-publication-withdrawal-v1",
        "publication_reference": target.reference.model_dump(mode="json"),
        "publication_digest": target.publication_digest,
        "generation_id": str(target.generation.id),
        "request_digest": target.generation.request_digest,
        "owner_issuer": target.generation.owner_issuer,
        "owner_subject": target.generation.owner_subject,
        "original_approved_at": target.declaration.approved_at.isoformat(),
        "original_expires_at": target.declaration.expires_at.isoformat(),
    }


@dataclass(frozen=True, repr=False)
class RetainedFragmentWithdrawal:
    reference: EvidenceReference
    target: HistoricalFragmentDeclarationTarget = field(repr=False)
    canonical_body: bytes = field(repr=False)
    observed_at: datetime

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def recovery_verified(self) -> Literal[False]:
        return False


def _decode_withdrawal(raw: bytes, target: HistoricalFragmentDeclarationTarget) -> dict[str, Any]:
    import json
    from uuid import UUID

    from zacai.ingestion.artifact_store import canonical_bytes

    if type(raw) is not bytes or not 0 < len(raw) <= MAX_WITHDRAWAL_BYTES:
        raise ValueError("bounded cancellation bytes required")
    data = json.loads(raw.decode("utf-8", errors="strict"))
    expected = _binding(target)
    if (
        type(data) is not dict
        or set(data)
        != set(expected)
        | {
            "current_session_binding",
            "current_session_issued_at",
            "current_session_expires_at",
            "observed_at",
        }
        or any(data[k] != value for k, value in expected.items())
        or canonical_bytes(data) != raw
    ):
        raise ValueError("exact original cancellation target required")
    EvidenceReference.model_validate(data["publication_reference"])
    if str(UUID(data["generation_id"])) != data["generation_id"]:
        raise ValueError("canonical generation identity required")
    import re

    if type(data["current_session_binding"]) is not str or not re.fullmatch(
        r"[0-9a-f]{64}", data["current_session_binding"]
    ):
        raise ValueError("exact current session observation required")
    dates = []
    for name in ("current_session_issued_at", "observed_at", "current_session_expires_at"):
        value = data[name]
        if type(value) is not str:
            raise ValueError("aware cancellation observation required")
        parsed = datetime.fromisoformat(value)
        if parsed.utcoffset() is None or parsed.isoformat() != value:
            raise ValueError("exact aware cancellation observation required")
        dates.append(parsed)
    if not dates[0] <= dates[1] < dates[2]:
        raise ValueError("current action window required")
    return data


def _publication_ids(
    session: Session, target: HistoricalFragmentDeclarationTarget
) -> tuple[UUID, ...]:
    return tuple(
        session.scalars(
            select(Source.id)
            .where(
                Source.trust_boundary == B.PERSONAL,
                Source.system == SourceSystem.MANUAL,
                Source.external_ref.like(
                    f"personal-history-fragment-declaration-v2/{target.generation.id}/%"
                ),
            )
            .limit(2)
        )
    )


def _snapshot(
    session: Session,
    target: HistoricalFragmentDeclarationTarget,
    refs: tuple[EvidenceReference, ...],
) -> tuple[tuple[tuple[str, object], ...], ...]:
    entry = _physical(session)
    rows = _fragment_rows(session, refs, auth._FRAGMENT_BOUNDARIES, auth._FRAGMENT_LABELS)
    if _publication_ids(session, target) != (target.reference.source_id,):
        raise ValueError("historical publication prefix changed")
    _same(session, entry)
    return rows


def _load_withdrawal(
    session: Session,
    artifacts: LocalFilesystemArtifactStore,
    reference: EvidenceReference,
    declaration: FragmentGenerationReviewDeclarationV2,
) -> RetainedFragmentWithdrawal:
    from zacai.ingestion.artifact_store import canonical_bytes

    target = _target(session, artifacts, reference, declaration)
    entry = _physical(session)
    ids = _withdrawal_ids(session, target.generation.id)
    if len(ids) != 1:
        raise ValueError("single cancellation observation required")
    source = session.get(Source, ids[0])
    if source is None or type(source.content_hash) is not str:
        raise ValueError("canonical cancellation Source required")
    own = EvidenceReference(
        source_id=source.id,
        content_hash=source.content_hash,
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    before = _snapshot(session, target, (reference, own))
    selected = [dict(r) for r in before if dict(r)["id"] == own.source_id]
    if len(selected) != 1:
        raise ValueError("single cancellation lineage required")
    row = selected[0]
    if (
        row["system"] is not SourceSystem.USER_INSTRUCTION
        or row["external_ref"] != _withdrawal_namespace(target.generation.id)
        or row["lineage_id"] != own.source_id
        or row["supersedes_source_id"] is not None
    ):
        raise ValueError("immutable cancellation metadata required")
    location = row["content_location"]
    if type(location) is not str:
        raise ValueError("exact cancellation artifact location required")
    raw = artifacts.get_bounded(B.PERSONAL, location, max_bytes=MAX_WITHDRAWAL_BYTES)
    _same(session, entry)
    data = _decode_withdrawal(raw, target)
    at = datetime.fromisoformat(data["observed_at"])
    if row["captured_at"] != at or content_hash_of(raw) != own.content_hash:
        raise ValueError("exact cancellation Source bytes/time required")
    if (
        _snapshot(session, target, (reference, own)) != before
        or _withdrawal_ids(session, target.generation.id) != ids
    ):
        raise ValueError("cancellation changed during body callback")
    _same(session, entry)
    # Re-encoding was checked above; returned body remains exact stored bytes.
    assert canonical_bytes(data) == raw
    return RetainedFragmentWithdrawal(own, target, raw, at)


def load_fragment_publication_withdrawal(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    publication_reference: EvidenceReference,
    expected_declaration: FragmentGenerationReviewDeclarationV2,
) -> RetainedFragmentWithdrawal:
    result = None
    try:
        result = _load_withdrawal(session, artifacts, publication_reference, expected_declaration)
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentWithdrawalTargetError("canonical fragment withdrawal unavailable")
    return result


def _action_owner(observation: _FragmentPostObservation) -> None:
    from zacai.claude_local_custody import _SCOPE
    from zacai.interfaces.fragment_publication_web import _FragmentPostObservation, _same_current

    if type(observation) is not _FragmentPostObservation or observation.purpose != "WITHDRAW":
        raise ValueError("exact observed cancellation required")
    current = observation.operation.recheck(observation.current_session.binding_digest)
    _, generation, _ = _parts(observation.publication)
    now = observation.operation.host_clock()
    if (
        not _same_current(current, observation.current_session)
        or current.principal.scopes != _SCOPE
        or (current.principal.identity.issuer, current.principal.identity.subject)
        != (generation.owner_issuer, generation.owner_subject)
        or not current.issued_at <= observation.observed_at <= now < current.effective_expires_at
    ):
        raise ValueError("original actor/current cancellation session required")


def withdraw_fragment_publication(
    *,
    factory: sessionmaker[Session],
    artifacts: LocalFilesystemArtifactStore,
    action: _PostedFragmentAction,
) -> RetainedFragmentWithdrawal:
    """Consume genuine WITHDRAW POST once, append USER_INSTRUCTION, commit/reopen.

    Owner callbacks are outside SQL. New cancellation immediately denies active
    checks, even if acknowledgement/recovery later fails. No processing deadline
    renewal, deletion, retry or repair; fresh browser action may observe exact
    committed replay. Publication and input custody remain untouched.
    """
    from sqlalchemy.orm import sessionmaker

    from zacai.ingestion.artifact_store import canonical_bytes
    from zacai.interfaces.fragment_publication_web import _consume_fragment_post
    from zacai.review_authorization import _lock
    from zacai.state_repository import record_source

    result = None
    try:
        observation = _consume_fragment_post(action, purpose="WITHDRAW")
        if type(factory) is not sessionmaker or type(artifacts) is not LocalFilesystemArtifactStore:
            raise ValueError("canonical withdrawal factory/store required")
        _action_owner(observation)
        with factory() as session:
            session.begin()
            _lock(session, _parts(observation.publication)[1].id)
            target = _target(session, artifacts, observation.reference, observation.publication)
            baseline = _snapshot(session, target, (target.reference,))
            prior = _withdrawal_ids(session, target.generation.id)
            if len(prior) > 1:
                raise ValueError("conflicting cancellation namespace")
            if prior:
                _load_withdrawal(session, artifacts, target.reference, target.declaration)
        if not prior:
            current = observation.current_session
            data = dict(
                _binding(target),
                current_session_binding=current.binding_digest,
                current_session_issued_at=current.issued_at.isoformat(),
                current_session_expires_at=current.effective_expires_at.isoformat(),
                observed_at=observation.observed_at.isoformat(),
            )
            raw = canonical_bytes(data)
            _decode_withdrawal(raw, target)
            location = artifacts.put(B.PERSONAL, content_hash_of(raw), raw)
            if artifacts.get_bounded(B.PERSONAL, location, max_bytes=MAX_WITHDRAWAL_BYTES) != raw:
                raise ValueError("complete stored cancellation bytes required")
        _action_owner(observation)
        with factory() as session:
            session.begin()
            _lock(session, target.generation.id)
            entry = _physical(session)
            if (
                _snapshot(session, target, (target.reference,)) != baseline
                or _withdrawal_ids(session, target.generation.id) != prior
            ):
                raise ValueError("cancellation target/namespace changed before write")
            if not prior:
                source, new = record_source(
                    session,
                    trust_boundary=B.PERSONAL,
                    data_classification=C.HIGHLY_RESTRICTED,
                    system=SourceSystem.USER_INSTRUCTION,
                    external_ref=_withdrawal_namespace(target.generation.id),
                    content_hash=content_hash_of(raw),
                    content_location=location,
                    captured_at=observation.observed_at,
                )
                if not new:
                    raise ValueError("unexpected cancellation revision/replay")
                ids: tuple[UUID, ...] = (source.id,)
            else:
                ids = prior
            if _withdrawal_ids(session, target.generation.id) != ids:
                raise ValueError("cancellation write identity conflict")
            _same(session, entry)
            session.commit()
        _action_owner(observation)
        with factory() as session:
            session.begin()
            reopened = _load_withdrawal(session, artifacts, target.reference, target.declaration)
            if reopened.reference.source_id != ids[0]:
                raise ValueError("exact committed cancellation required")
            complete = (target.reference, reopened.reference)
            after = _snapshot(session, target, complete)
        _action_owner(observation)
        with factory() as session:
            session.begin()
            entry = _physical(session)
            if (
                _snapshot(session, target, complete) != after
                or _withdrawal_ids(session, target.generation.id) != ids
            ):
                raise ValueError("final cancellation changed before acknowledgement")
            _same(session, entry)
        result = reopened
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentWithdrawalTargetError("fragment withdrawal unavailable")
    return result
