"""Canonical custody of a full prospective declaration, never human admission.

Signed original-owner continuity authorizes this mechanical custody operation
only. The embedded decision metadata is caller declaration, not a newly observed
human action. No generation/review claim accepts this retained family. Actual
browser-owned publication approval and its consuming backend remain separate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session, SessionTransaction, sessionmaker

from zacai import contextual_authorization as auth
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contextual_storage import (
    _fragment_profile_lineage,
    _fragment_rows,
    _fragment_same_transaction,
    _fragment_transaction,
)
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.intelligence.fragment_review_declaration import (
    MAX_DECLARATION_BYTES,
    FragmentGenerationReviewDeclarationV2,
    decode_fragment_generation_review_declaration,
    encode_fragment_generation_review_declaration,
    fragment_generation_review_declaration_digest,
)
from zacai.intelligence.history_fragment_contextual_codec import (
    HistoryFragmentContextualRequestV1,
    decode_history_fragment_contextual_request,
)
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionOperation
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _lock
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source


class FragmentDeclarationRetentionError(ValueError):
    """Fixed private-safe custody diagnostic, never an approval verdict."""


@dataclass(frozen=True, repr=False)
class RetainedFragmentDeclarationV2:
    reference: EvidenceReference = field(repr=False)
    declaration: FragmentGenerationReviewDeclarationV2 = field(repr=False)
    publication_digest: str
    captured_at: datetime

    @property
    def owner_admitted(self) -> Literal[False]:
        return False

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def reviewer_authenticated(self) -> Literal[False]:
        return False


def _parts(
    declaration: FragmentGenerationReviewDeclarationV2,
) -> tuple[bytes, auth.HistoryFragmentConsentV1, HistoryFragmentContextualRequestV1]:
    raw = encode_fragment_generation_review_declaration(declaration)
    generation = auth.decode_history_fragment_consent(declaration.generation_consent_json.encode())
    request = decode_history_fragment_contextual_request(
        declaration.generation_request_json.encode()
    )
    auth._fragment_consent_request(generation, request)
    return raw, generation, request


def _namespace(declaration: FragmentGenerationReviewDeclarationV2) -> str:
    raw, generation, _ = _parts(declaration)
    union = content_hash_of(
        canonical_bytes({"provenance": [r.model_dump(mode="json") for r in generation.provenance]})
    )
    return (
        f"personal-history-fragment-declaration-v2/{generation.id}/"
        f"{content_hash_of(raw)}/{fragment_generation_review_declaration_digest(declaration)}/"
        f"{generation.request_digest}/{union}"
    )


# Scoped reuse of the issuer's concrete physical transaction contract. Legacy
# generic helpers and V1 admission behavior remain unchanged.
def _physical(
    session: Session,
) -> tuple[SessionTransaction, SessionTransaction | None, object, object]:
    from psycopg import Connection as PsycopgConnection
    from psycopg.pq import TransactionStatus

    outer, nested = _fragment_transaction(session)
    connection = session.connection()
    driver = connection.connection.driver_connection
    if (
        not isinstance(driver, PsycopgConnection)
        or driver.autocommit is not False
        or driver.closed
        or driver.broken
        or driver.info.transaction_status is not TransactionStatus.INTRANS
        or not connection.in_transaction()
    ):
        raise ValueError("live physical declaration transaction required")
    return outer, nested, connection, driver


def _same(
    session: Session, entry: tuple[SessionTransaction, SessionTransaction | None, object, object]
) -> None:
    _fragment_same_transaction(session, (entry[0], entry[1]))
    if any(a is not b for a, b in zip(_physical(session), entry, strict=True)):
        raise ValueError("original declaration transaction changed")


def _load(
    session: Session,
    artifacts: LocalFilesystemArtifactStore,
    reference: EvidenceReference,
    declaration: FragmentGenerationReviewDeclarationV2,
) -> RetainedFragmentDeclarationV2:
    raw, generation, request = _parts(declaration)
    if (
        type(artifacts) is not LocalFilesystemArtifactStore
        or type(reference) is not EvidenceReference
        or reference.content_hash != content_hash_of(raw)
        or reference.source_id.int == 0
        or reference.trust_boundary is not B.PERSONAL
        or reference.effective_classification is not C.HIGHLY_RESTRICTED
    ):
        raise ValueError("exact own full-declaration Source required")
    entry = _physical(session)
    complete = (*generation.provenance, reference)
    if len({r.source_id for r in complete}) != len(complete):
        raise ValueError("distinct declaration and complete input union required")
    before = _fragment_rows(session, complete, auth._FRAGMENT_BOUNDARIES, auth._FRAGMENT_LABELS)
    _fragment_profile_lineage(request, before)
    rows = [dict(r) for r in before if dict(r)["id"] == reference.source_id]
    if not rows or len({r["lineage_id"] for r in rows}) != 1:
        raise ValueError("unique own declaration required before body")
    captured = rows[0]["captured_at"]
    if type(captured) is not datetime or captured.utcoffset() is None:
        raise ValueError("aware original capture time required")
    for row in rows:
        if (
            row["system"] is not SourceSystem.MANUAL
            or row["external_ref"] != _namespace(declaration)
            or row["supersedes_source_id"] is not None
            or type(row["captured_at"]) is not datetime
            or row["captured_at"].utcoffset() is None
            or row["captured_at"] != captured
            or not declaration.approved_at <= captured < declaration.expires_at
        ):
            raise ValueError("canonical declaration metadata mismatch")
    prefix = f"personal-history-fragment-declaration-v2/{generation.id}/"
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
    if ids != (reference.source_id,) or type(rows[0]["content_location"]) is not str:
        raise ValueError("single immutable full-declaration identity required")
    returned = artifacts.get_bounded(
        B.PERSONAL, rows[0]["content_location"], max_bytes=MAX_DECLARATION_BYTES
    )
    _same(session, entry)
    if returned != raw or decode_fragment_generation_review_declaration(returned) != declaration:
        raise ValueError("exact full publication bytes required")
    after = _fragment_rows(session, complete, auth._FRAGMENT_BOUNDARIES, auth._FRAGMENT_LABELS)
    _fragment_profile_lineage(request, after)
    _same(session, entry)
    if after != before:
        raise ValueError("complete declaration Source union changed")
    final_ids = tuple(
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
    if final_ids != (reference.source_id,):
        raise ValueError("declaration identity changed during body callback")
    return RetainedFragmentDeclarationV2(
        reference, declaration, fragment_generation_review_declaration_digest(declaration), captured
    )


def load_fragment_review_declaration(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    reference: EvidenceReference,
    expected_declaration: FragmentGenerationReviewDeclarationV2,
) -> RetainedFragmentDeclarationV2:
    result = None
    try:
        result = _load(session, artifacts, reference, expected_declaration)
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentDeclarationRetentionError("canonical full declaration unavailable")
    return result


def capture_fragment_review_declaration(
    *,
    factory: sessionmaker[Session],
    artifacts: LocalFilesystemArtifactStore,
    declaration: FragmentGenerationReviewDeclarationV2,
    operation: NamedSessionOperation,
    clock: HostObservedClock,
) -> RetainedFragmentDeclarationV2:
    """Record prospective bytes for custody, NOT a fresh human processing action.

    No action/signature metadata is fabricated. Declared original expiry is fixed.
    Matching committed failures remain recorded; conflicting publication holds.
    Actual owner callbacks are outside SQL, final scalar rows after last callback.
    """
    result = None
    try:
        raw, generation, request = _parts(declaration)
        from zacai.intelligence.fragment_publication_generation import (
            _assert_publication_review_provenance,
        )

        _assert_publication_review_provenance(declaration)
        if type(factory) is not sessionmaker or type(artifacts) is not LocalFilesystemArtifactStore:
            raise ValueError("canonical declaration factory/store required")
        auth._fragment_decision_owner(operation, clock, generation)
        with factory() as session:
            session.begin()
            _lock(session, generation.id)
            entry = _physical(session)
            auth._assert_fragment_generation_unconsumed(session, generation.id)
            _same(session, entry)
            before = _fragment_rows(
                session, generation.provenance, auth._FRAGMENT_BOUNDARIES, auth._FRAGMENT_LABELS
            )
            _fragment_profile_lineage(request, before)
            prefix = f"personal-history-fragment-declaration-v2/{generation.id}/"
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
            if len(ids) > 1:
                raise ValueError("conflicting declaration identity")
            if not ids:
                from zacai.backup_artifacts import _assert_personal_custody_append_capacity

                _assert_personal_custody_append_capacity(session, 8)
                location = artifacts.put(B.PERSONAL, content_hash_of(raw), raw)
                _same(session, entry)
                returned = artifacts.get_bounded(
                    B.PERSONAL, location, max_bytes=MAX_DECLARATION_BYTES
                )
                _same(session, entry)
                if (
                    returned != raw
                    or _fragment_rows(
                        session,
                        generation.provenance,
                        auth._FRAGMENT_BOUNDARIES,
                        auth._FRAGMENT_LABELS,
                    )
                    != before
                ):
                    raise ValueError("full declaration input changed before record")
                captured = clock()
                _same(session, entry)
                if not declaration.approved_at <= captured < declaration.expires_at:
                    raise ValueError("original declaration window closed")
                if (
                    _fragment_rows(
                        session,
                        generation.provenance,
                        auth._FRAGMENT_BOUNDARIES,
                        auth._FRAGMENT_LABELS,
                    )
                    != before
                ):
                    raise ValueError("canonical inputs changed during capture clock callback")
                auth._assert_fragment_generation_unconsumed(session, generation.id)
                _assert_personal_custody_append_capacity(session, 8)
                _same(session, entry)
                source, _ = record_source(
                    session,
                    trust_boundary=B.PERSONAL,
                    data_classification=C.HIGHLY_RESTRICTED,
                    system=SourceSystem.MANUAL,
                    external_ref=_namespace(declaration),
                    content_hash=content_hash_of(raw),
                    content_location=location,
                    captured_at=captured,
                )
                sid = source.id
            else:
                sid = ids[0]
            reference = EvidenceReference(
                source_id=sid,
                content_hash=content_hash_of(raw),
                trust_boundary=B.PERSONAL,
                effective_classification=C.HIGHLY_RESTRICTED,
            )
            _load(session, artifacts, reference, declaration)
            _same(session, entry)
            if not ids:
                _assert_personal_custody_append_capacity(session, 7)
                _same(session, entry)
            auth._assert_fragment_generation_unconsumed(session, generation.id)
            _same(session, entry)
            session.commit()
        auth._fragment_decision_owner(operation, clock, generation)
        with factory() as session:
            session.begin()
            reopened = _load(session, artifacts, reference, declaration)
            reopened_entry = _physical(session)
            baseline = _fragment_rows(
                session,
                (*generation.provenance, reference),
                auth._FRAGMENT_BOUNDARIES,
                auth._FRAGMENT_LABELS,
            )
            _same(session, reopened_entry)
        auth._fragment_decision_owner(operation, clock, generation)
        with factory() as session:
            session.begin()
            final_entry = _physical(session)
            final = _fragment_rows(
                session,
                (*generation.provenance, reference),
                auth._FRAGMENT_BOUNDARIES,
                auth._FRAGMENT_LABELS,
            )
            _fragment_profile_lineage(request, final)
            _same(session, final_entry)
            if final != baseline:
                raise ValueError("final complete declaration rows changed")
            final_ids = tuple(
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
            _same(session, final_entry)
            if final_ids != (reference.source_id,):
                raise ValueError("declaration identity changed before custody acknowledgement")
        result = reopened
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise FragmentDeclarationRetentionError("full declaration custody unavailable")
    return result


class PersonalFragmentDeclarationReceiptV2(Contract):
    """Closed full-purpose bytes recovery observation; no human/claim authority."""

    format: Literal["zac-personal-history-fragment-declaration-recovery-v2"] = (
        "zac-personal-history-fragment-declaration-recovery-v2"
    )
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
            or not 1 <= len(self.selected_references) <= 95
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
        return self

    @property
    def prefix(self) -> str:
        return f"PERSONAL/state/history-fragment-declaration-{self.publication_reference.source_id}"

    @property
    def state_object(self) -> str:
        return f"{self.prefix}/state-{self.state_ciphertext_hash}.age"

    @property
    def journal_object(self) -> str:
        return f"{self.prefix}/journal-{self.journal_ciphertext_hash}.age"

    @property
    def receipt_object(self) -> str:
        return f"{self.prefix}/receipt-{self.publication_digest}.age"

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


def encode_fragment_declaration_receipt(value: PersonalFragmentDeclarationReceiptV2) -> bytes:
    if type(value) is not PersonalFragmentDeclarationReceiptV2:
        raise ValueError("exact declaration receipt required")
    raw = canonical_bytes(
        PersonalFragmentDeclarationReceiptV2.model_validate(value).model_dump(mode="json")
    )
    if not 0 < len(raw) <= 2_000_000:
        raise ValueError("bounded declaration receipt required")
    return raw


def decode_fragment_declaration_receipt(raw: bytes) -> PersonalFragmentDeclarationReceiptV2:
    from zacai.intelligence.review_context import _unique_pairs

    if type(raw) is not bytes or not 0 < len(raw) <= 2_000_000:
        raise ValueError("bounded declaration receipt required")
    result = PersonalFragmentDeclarationReceiptV2.model_validate(
        json.loads(raw, object_pairs_hook=_unique_pairs)
    )
    if encode_fragment_declaration_receipt(result) != raw:
        raise ValueError("canonical declaration receipt required")
    return result
