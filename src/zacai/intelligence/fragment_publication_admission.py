"""Canonical browser-observed fragment publication, never dispatch permission.

Only the concrete HTTP controller's consumed POST observation can reach the
writer. MANUAL publication custody, caller declarations and encoded constructors
cannot mint this observation. Trusted host code is not a callback sandbox.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from zacai import contextual_authorization as auth
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contextual_storage import _fragment_profile_lineage, _fragment_rows
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.intelligence.fragment_review_declaration import (
    FragmentGenerationReviewDeclarationV2,
    fragment_generation_review_declaration_digest,
)
from zacai.intelligence.fragment_review_retention import (
    _parts,
    _physical,
    _same,
    load_fragment_review_declaration,
)
from zacai.interfaces.host_clock import HostObservedClock
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _lock
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source

if TYPE_CHECKING:
    from zacai.interfaces.fragment_publication_web import _PostedFragmentAction

MAX_ADMISSION_BYTES = 16000


class FragmentPublicationAdmissionError(ValueError):
    """Fixed safe acknowledgment error; no approval inferred from failure."""


class FragmentPublicationAdmissionV1(Contract):
    format: Literal["zac-history-fragment-publication-admission-v1"] = (
        "zac-history-fragment-publication-admission-v1"
    )
    action: Literal["approve_fragment_generation_and_review"] = (
        "approve_fragment_generation_and_review"
    )
    publication_reference: EvidenceReference = Field(repr=False)
    publication_digest: Digest
    generation_id: UUID
    task_id: UUID
    builder_id: UUID
    request_digest: Digest
    review_profile_digest: Digest
    actor_issuer: str = Field(strict=True, min_length=1, max_length=500, repr=False)
    actor_subject: str = Field(strict=True, min_length=1, max_length=500, repr=False)
    original_session_binding: Digest = Field(repr=False)
    original_session_issued_at: AwareDatetime
    original_session_expires_at: AwareDatetime
    original_approved_at: AwareDatetime
    expires_at: AwareDatetime
    observed_action_at: AwareDatetime

    @model_validator(mode="after")
    def exact_window(self) -> Self:
        r = self.publication_reference
        if (
            r.source_id.int == 0
            or r.trust_boundary is not B.PERSONAL
            or r.effective_classification is not C.HIGHLY_RESTRICTED
            or any(x.int == 0 for x in (self.generation_id, self.task_id, self.builder_id))
            or not self.original_session_issued_at
            <= self.original_approved_at
            <= self.observed_action_at
            < self.expires_at
            <= self.original_session_expires_at
        ):
            raise ValueError("exact original browser action window required")
        return self

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def reviewer_authenticated(self) -> Literal[False]:
        return False


def encode_fragment_publication_admission(value: FragmentPublicationAdmissionV1) -> bytes:
    result = None
    try:
        if type(value) is not FragmentPublicationAdmissionV1:
            raise ValueError("exact action family required")
        raw = canonical_bytes(
            FragmentPublicationAdmissionV1.model_validate(value).model_dump(mode="json")
        )
        if len(raw) > MAX_ADMISSION_BYTES:
            raise ValueError("bounded action required")
        result = raw
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationAdmissionError("fragment publication action unavailable")
    return result


def decode_fragment_publication_admission(raw: bytes) -> FragmentPublicationAdmissionV1:
    result = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_ADMISSION_BYTES:
            raise ValueError("bounded action required")

        def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
            out: dict[str, object] = {}
            for key, value in items:
                if key in out:
                    raise ValueError("duplicate field")
                out[key] = value
            return out

        result = FragmentPublicationAdmissionV1.model_validate_json(
            canonical_bytes(json.loads(raw, object_pairs_hook=pairs)), strict=True
        )
        if encode_fragment_publication_admission(result) != raw:
            raise ValueError("canonical action required")
    except Exception:  # noqa: BLE001
        result = None
    if result is None:
        raise FragmentPublicationAdmissionError("fragment publication action unavailable")
    return result


def _binding(
    value: FragmentPublicationAdmissionV1, publication: FragmentGenerationReviewDeclarationV2
) -> None:
    _, g, _ = _parts(publication)
    raw = encode_fragment_publication_admission(value)
    if (
        value.publication_digest != fragment_generation_review_declaration_digest(publication)
        or value.publication_reference.content_hash != content_hash_of(_parts(publication)[0])
        or (
            value.generation_id,
            value.task_id,
            value.builder_id,
            value.request_digest,
            value.review_profile_digest,
        )
        != (g.id, g.task_id, g.builder_id, g.request_digest, publication.review_profile_digest)
        or (
            value.actor_issuer,
            value.actor_subject,
            value.original_session_binding,
            value.original_session_issued_at,
            value.original_session_expires_at,
            value.original_approved_at,
            value.expires_at,
        )
        != (
            g.owner_issuer,
            g.owner_subject,
            g.original_session_binding,
            g.original_session_issued_at,
            g.original_session_expires_at,
            g.approved_at,
            g.expires_at,
        )
        or not raw
        or publication.review is None
    ):
        raise ValueError("full original publication action differs")


def _prefix(value: FragmentPublicationAdmissionV1) -> str:
    return f"personal-history-fragment-publication-admission/{value.generation_id}/"


def _namespace(value: FragmentPublicationAdmissionV1) -> str:
    return (
        _prefix(value)
        + value.publication_digest
        + "/"
        + content_hash_of(encode_fragment_publication_admission(value))
    )


def _ids(
    session: Session, prefix: str, *, system: SourceSystem = SourceSystem.USER_INSTRUCTION
) -> tuple[UUID, ...]:
    return tuple(
        session.scalars(
            select(Source.id)
            .where(
                Source.trust_boundary == B.PERSONAL,
                Source.system == system,
                Source.external_ref.like(prefix + "%"),
            )
            .limit(2)
        )
    )


def _not_withdrawn(session: Session, generation_id: UUID) -> None:
    # No cancellation writer is claimed here. Any matching canonical namespace
    # holds, including malformed/duplicate targets; no private cancellation body.
    if _ids(session, f"personal-history-fragment-withdrawal/{generation_id}"):
        raise ValueError("publication withdrawn or cancellation state ambiguous")


@dataclass(frozen=True, repr=False)
class RetainedFragmentPublicationAdmission:
    reference: EvidenceReference
    admission: FragmentPublicationAdmissionV1 = field(repr=False)
    captured_at: datetime


def load_fragment_publication_admission(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    reference: EvidenceReference,
    expected_admission: FragmentPublicationAdmissionV1,
    expected_publication: FragmentGenerationReviewDeclarationV2,
) -> RetainedFragmentPublicationAdmission:
    result = None
    try:
        _binding(expected_admission, expected_publication)
        raw = encode_fragment_publication_admission(expected_admission)
        if (
            type(artifacts) is not LocalFilesystemArtifactStore
            or type(reference) is not EvidenceReference
            or reference.content_hash != content_hash_of(raw)
            or reference.trust_boundary is not B.PERSONAL
            or reference.effective_classification is not C.HIGHLY_RESTRICTED
        ):
            raise ValueError("exact action Source required")
        _, g, _ = _parts(expected_publication)
        entry = _physical(session)
        selected = (*g.provenance, expected_admission.publication_reference, reference)
        rows = _fragment_rows(session, selected, auth._FRAGMENT_BOUNDARIES, auth._FRAGMENT_LABELS)
        _fragment_profile_lineage(_parts(expected_publication)[2], rows)
        _not_withdrawn(session, g.id)
        if _ids(
            session, f"personal-history-fragment-declaration-v2/{g.id}/", system=SourceSystem.MANUAL
        ) != (expected_admission.publication_reference.source_id,):
            raise ValueError("full publication identity changed")
        if _ids(session, _prefix(expected_admission)) != (reference.source_id,):
            raise ValueError("unique original action required")
        row = next(dict(v) for v in rows if dict(v)["id"] == reference.source_id)
        if (
            row["system"] is not SourceSystem.USER_INSTRUCTION
            or row["external_ref"] != _namespace(expected_admission)
            or row["supersedes_source_id"] is not None
            or row["captured_at"] != expected_admission.observed_action_at
        ):
            raise ValueError("canonical action namespace/time required")
        load_fragment_review_declaration(
            session,
            artifacts=artifacts,
            reference=expected_admission.publication_reference,
            expected_declaration=expected_publication,
        )
        _same(session, entry)
        location, captured = row["content_location"], row["captured_at"]
        if (
            type(location) is not str
            or not isinstance(captured, datetime)
            or captured.utcoffset() is None
        ):
            raise ValueError("bounded Source location/time required")
        returned = artifacts.get_bounded(B.PERSONAL, location, max_bytes=MAX_ADMISSION_BYTES)
        _same(session, entry)
        if returned != raw or decode_fragment_publication_admission(returned) != expected_admission:
            raise ValueError("exact action bytes required")
        if (
            _fragment_rows(session, selected, auth._FRAGMENT_BOUNDARIES, auth._FRAGMENT_LABELS)
            != rows
        ):
            raise ValueError("full action union changed")
        _fragment_profile_lineage(_parts(expected_publication)[2], rows)
        _not_withdrawn(session, g.id)
        if _ids(
            session, f"personal-history-fragment-declaration-v2/{g.id}/", system=SourceSystem.MANUAL
        ) != (expected_admission.publication_reference.source_id,):
            raise ValueError("full publication identity changed")
        if _ids(session, _prefix(expected_admission)) != (reference.source_id,):
            raise ValueError("action identity changed")
        _same(session, entry)
        result = RetainedFragmentPublicationAdmission(reference, expected_admission, captured)
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationAdmissionError("fragment publication action unavailable")
    return result


def _record_posted_fragment_admission(
    *,
    factory: sessionmaker[Session],
    artifacts: LocalFilesystemArtifactStore,
    action: _PostedFragmentAction,
    clock: HostObservedClock,
) -> RetainedFragmentPublicationAdmission:
    from zacai.interfaces.fragment_publication_web import _consume_fragment_post

    result = None
    try:
        observed = _consume_fragment_post(action, purpose="APPROVE")
        publication, reference, operation = (
            observed.publication,
            observed.reference,
            observed.operation,
        )
        _, g, _ = _parts(publication)
        from zacai.intelligence.fragment_publication_generation import (
            _assert_publication_review_provenance,
        )

        _assert_publication_review_provenance(publication)
        auth._fragment_decision_owner(operation, clock, g)
        value = FragmentPublicationAdmissionV1(
            publication_reference=reference,
            publication_digest=fragment_generation_review_declaration_digest(publication),
            generation_id=g.id,
            task_id=g.task_id,
            builder_id=g.builder_id,
            request_digest=g.request_digest,
            review_profile_digest=publication.review_profile_digest,
            actor_issuer=g.owner_issuer,
            actor_subject=g.owner_subject,
            original_session_binding=g.original_session_binding,
            original_session_issued_at=g.original_session_issued_at,
            original_session_expires_at=g.original_session_expires_at,
            original_approved_at=g.approved_at,
            expires_at=g.expires_at,
            observed_action_at=observed.observed_at,
        )
        _binding(value, publication)
        raw = encode_fragment_publication_admission(value)
        with factory() as session:
            session.begin()
            _lock(session, g.id)
            entry = _physical(session)
            auth._assert_fragment_generation_unconsumed(session, g.id)
            _same(session, entry)
            _not_withdrawn(session, g.id)
            before = _fragment_rows(
                session,
                (*g.provenance, reference),
                auth._FRAGMENT_BOUNDARIES,
                auth._FRAGMENT_LABELS,
            )
            load_fragment_review_declaration(
                session, artifacts=artifacts, reference=reference, expected_declaration=publication
            )
            _same(session, entry)
            if _ids(session, _prefix(value)):
                raise ValueError("existing action cannot be renewed or redispatched")
            from zacai.backup_artifacts import _assert_personal_custody_append_capacity

            _assert_personal_custody_append_capacity(session, 7)
            location = artifacts.put(B.PERSONAL, content_hash_of(raw), raw)
            _same(session, entry)
            returned = artifacts.get_bounded(B.PERSONAL, location, max_bytes=MAX_ADMISSION_BYTES)
            _same(session, entry)
            if (
                returned != raw
                or _fragment_rows(
                    session,
                    (*g.provenance, reference),
                    auth._FRAGMENT_BOUNDARIES,
                    auth._FRAGMENT_LABELS,
                )
                != before
                or not value.observed_action_at <= clock() < value.expires_at
            ):
                raise ValueError("original action changed before commit")
            _same(session, entry)
            _not_withdrawn(session, g.id)
            if _ids(session, _prefix(value)):
                raise ValueError("action appeared during capture")
            auth._assert_fragment_generation_unconsumed(session, g.id)
            _assert_personal_custody_append_capacity(session, 7)
            _same(session, entry)
            row, new = record_source(
                session,
                trust_boundary=B.PERSONAL,
                data_classification=C.HIGHLY_RESTRICTED,
                system=SourceSystem.USER_INSTRUCTION,
                external_ref=_namespace(value),
                content_hash=content_hash_of(raw),
                content_location=location,
                captured_at=value.observed_action_at,
            )
            if not new:
                raise ValueError("original action required")
            own = EvidenceReference(
                source_id=row.id,
                content_hash=content_hash_of(raw),
                trust_boundary=B.PERSONAL,
                effective_classification=C.HIGHLY_RESTRICTED,
            )
            load_fragment_publication_admission(
                session,
                artifacts=artifacts,
                reference=own,
                expected_admission=value,
                expected_publication=publication,
            )
            _same(session, entry)
            auth._assert_fragment_generation_unconsumed(session, g.id)
            _assert_personal_custody_append_capacity(session, 6)
            _same(session, entry)
            session.commit()
        auth._fragment_decision_owner(operation, clock, g)
        with factory() as session:
            session.begin()
            saved = load_fragment_publication_admission(
                session,
                artifacts=artifacts,
                reference=own,
                expected_admission=value,
                expected_publication=publication,
            )
            baseline = _fragment_rows(
                session,
                (*g.provenance, reference, own),
                auth._FRAGMENT_BOUNDARIES,
                auth._FRAGMENT_LABELS,
            )
        auth._fragment_decision_owner(operation, clock, g)
        with factory() as session:
            session.begin()
            entry = _physical(session)
            final = _fragment_rows(
                session,
                (*g.provenance, reference, own),
                auth._FRAGMENT_BOUNDARIES,
                auth._FRAGMENT_LABELS,
            )
            _fragment_profile_lineage(_parts(publication)[2], final)
            if final != baseline or _ids(
                session,
                f"personal-history-fragment-declaration-v2/{g.id}/",
                system=SourceSystem.MANUAL,
            ) != (reference.source_id,):
                raise ValueError("full publication/union changed before acknowledgment")
            _not_withdrawn(session, g.id)
            if _ids(session, _prefix(value)) != (own.source_id,):
                raise ValueError("final action identity changed")
            _same(session, entry)
        result = saved
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentPublicationAdmissionError("fragment publication action not acknowledged")
    return result


class PersonalFragmentPublicationAdmissionReceiptV1(Contract):
    """Closed full-purpose bytes recovery observation; no human/claim authority."""

    format: Literal["zac-personal-fragment-publication-admission-recovery-v1"] = (
        "zac-personal-fragment-publication-admission-recovery-v1"
    )
    admission_reference: EvidenceReference = Field(repr=False)
    admission_digest: Digest
    observed_action_at: AwareDatetime
    publication_reference: EvidenceReference = Field(repr=False)
    publication_digest: Digest
    request_digest: Digest
    review_profile_digest: Digest | None
    selected_references: tuple[EvidenceReference, ...] = Field(repr=False)
    full_plan_digest: Digest
    full_boundary_source_hashes: tuple[tuple[UUID, Digest], ...] = Field(repr=False)
    full_boundary_source_fingerprints: tuple[tuple[UUID, Digest], ...] = Field(repr=False)
    task_id: UUID
    builder_id: UUID
    original_observed_at: AwareDatetime
    declared_window_started_at: AwareDatetime
    expires_at: AwareDatetime
    original_session_binding: Digest = Field(repr=False)
    original_session_issued_at: AwareDatetime
    original_session_expires_at: AwareDatetime
    verified_at: AwareDatetime
    artifact_backup_run_id: UUID
    live_journal_digest: Digest
    state_ciphertext_hash: Digest
    state_plaintext_hash: Digest
    journal_ciphertext_hash: Digest
    journal_plaintext_hash: Digest

    @model_validator(mode="after")
    def closed_publication(self) -> Self:
        hashes = dict(self.full_boundary_source_hashes)
        if (
            any(
                v.int == 0
                for v in (
                    self.task_id,
                    self.builder_id,
                    self.publication_reference.source_id,
                    self.artifact_backup_run_id,
                )
            )
            or not 1 <= len(self.selected_references) <= 96
            or tuple(sorted(self.selected_references, key=lambda r: str(r.source_id)))
            != self.selected_references
            or len({r.source_id for r in self.selected_references}) != len(self.selected_references)
            or self.publication_reference not in self.selected_references
            or any(
                r.trust_boundary is not B.PERSONAL
                or r.effective_classification is not C.HIGHLY_RESTRICTED
                for r in self.selected_references
            )
            or not 1 <= len(hashes) == len(self.full_boundary_source_hashes) <= 4096
            or tuple(sorted(self.full_boundary_source_hashes, key=lambda r: str(r[0])))
            != self.full_boundary_source_hashes
            or tuple(sid for sid, _ in self.full_boundary_source_hashes)
            != tuple(sid for sid, _ in self.full_boundary_source_fingerprints)
            or any(hashes.get(r.source_id) != r.content_hash for r in self.selected_references)
            or not self.original_session_issued_at
            <= self.declared_window_started_at
            <= self.verified_at
            < self.expires_at
            <= self.original_session_expires_at
            or self.original_observed_at > self.declared_window_started_at
        ):
            raise ValueError("closed full publication recovery observation required")
        if (
            self.admission_reference not in self.selected_references
            or self.admission_reference.content_hash != self.admission_digest
            or self.admission_reference.source_id == self.publication_reference.source_id
            or not self.declared_window_started_at
            <= self.observed_action_at
            <= self.verified_at
            < self.expires_at
        ):
            raise ValueError("exact observed action receipt required")
        return self

    @property
    def prefix(self) -> str:
        return f"PERSONAL/state/history-fragment-admission-{self.admission_reference.source_id}"

    @property
    def state_object(self) -> str:
        return f"{self.prefix}/state-{self.state_ciphertext_hash}.age"

    @property
    def journal_object(self) -> str:
        return f"{self.prefix}/journal-{self.journal_ciphertext_hash}.age"

    @property
    def receipt_object(self) -> str:
        return f"{self.prefix}/receipt-{self.admission_digest}.age"

    @property
    def owner_admitted(self) -> Literal[False]:
        return False

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def reviewer_authenticated(self) -> Literal[False]:
        return False

    @property
    def recovery_verified(self) -> Literal[False]:
        return False


def encode_fragment_publication_admission_receipt(
    value: PersonalFragmentPublicationAdmissionReceiptV1,
) -> bytes:
    if type(value) is not PersonalFragmentPublicationAdmissionReceiptV1:
        raise ValueError("exact declaration receipt required")
    raw = canonical_bytes(
        PersonalFragmentPublicationAdmissionReceiptV1.model_validate(value).model_dump(mode="json")
    )
    if not 0 < len(raw) <= 2_000_000:
        raise ValueError("bounded declaration receipt required")
    return raw


def decode_fragment_publication_admission_receipt(
    raw: bytes,
) -> PersonalFragmentPublicationAdmissionReceiptV1:
    from zacai.intelligence.review_context import _unique_pairs

    if type(raw) is not bytes or not 0 < len(raw) <= 2_000_000:
        raise ValueError("bounded declaration receipt required")
    result = PersonalFragmentPublicationAdmissionReceiptV1.model_validate(
        json.loads(raw, object_pairs_hook=_unique_pairs)
    )
    if encode_fragment_publication_admission_receipt(result) != raw:
        raise ValueError("canonical declaration receipt required")
    return result
