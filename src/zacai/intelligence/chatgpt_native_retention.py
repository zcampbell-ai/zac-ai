"""Add-only native declaration/association custody, never processing admission.

No event authorizing processing, claim, review or runtime is emitted. Readonly
loads compare real current Sources/artifacts and never create/repair/renew them.
Original current owner callbacks remain outside canonical SQL leases. An ACK
failure after attempted commit preserves possibly committed custody; never retry.
Any no-ACK after artifact preparation, including a failed sync, requires operator
verification before recapturing that declaration, even with fresh source IDs.
Host serialization must prevent concurrent legacy writes to the same store.
Shutdown classes remain shutdown signals with a fixed failure message; other
BaseException callbacks become safe ordinary or uncertain retention errors.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from time import monotonic as _MONOTONIC
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from zacai.backup_artifacts import _assert_personal_custody_append_capacity
from zacai.chatgpt_native_custody import _bound_factory, _host, _scope, _standard_factory
from zacai.claude_original_capture import ClaudeArtifactRootIdentity, _artifact_profile, _root_check
from zacai.contextual_authorization import _assert_fragment_generation_unconsumed
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.chatgpt_native_task import (
    MAX_REQUEST_BYTES,
    ChatGPTNativeTaskDeclarationV1,
    ChatGPTNativeTaskRequestV1,
    decode_chatgpt_native_task_declaration,
    decode_chatgpt_native_task_request,
    encode_chatgpt_native_task_declaration,
    load_chatgpt_native_task_request,
    native_task_references,
)
from zacai.intelligence.contextual_storage import _fragment_rows
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.intelligence.fragment_publication_generation import _same_output_commit_transaction
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.intelligence.review_context import _unique_pairs
from zacai.interfaces.named_session_binding import NamedSessionOperation
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _lock
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source

BOUNDS = frozenset({B.PERSONAL})
LABELS = frozenset({C.HIGHLY_RESTRICTED})
MAX_DECLARATION_BYTES = MAX_REQUEST_BYTES + 16_000
MAX_ASSOCIATION_BYTES = 32_000


class NativeTaskRetentionError(ValueError):
    """Fixed safe no-ACK; does not establish custody/processing authority."""


class NativeTaskRetentionUncertain(NativeTaskRetentionError):
    """Commit may have happened; preserve originals, stop and reconcile."""


class ChatGPTNativeTaskAssociationV1(Contract):
    format: Literal["zac-chatgpt-native-task-association-v1"] = (
        "zac-chatgpt-native-task-association-v1"
    )
    declaration_id: UUID
    declaration_reference: EvidenceReference
    native_capture_id: UUID
    original_task_id: UUID
    derived_task_id: UUID
    request_digest: Digest
    wire_digest: Digest
    counter_digest: Digest
    source_references: tuple[EvidenceReference, ...] = Field(
        min_length=1, max_length=94, repr=False
    )

    @model_validator(mode="after")
    def distinct_association(self) -> Self:
        refs = (*self.source_references, self.declaration_reference)
        if (
            any(
                i.int == 0
                for i in (
                    self.declaration_id,
                    self.native_capture_id,
                    self.original_task_id,
                    self.derived_task_id,
                )
            )
            or len({r.source_id for r in refs}) != len(refs)
            or any(
                r.source_id.int == 0
                or r.trust_boundary is not B.PERSONAL
                or r.effective_classification is not C.HIGHLY_RESTRICTED
                for r in refs
            )
            or tuple(sorted(self.source_references, key=lambda r: str(r.source_id)))
            != self.source_references
        ):
            raise ValueError("exact immutable native association required")
        return self

    @property
    def processing_authorized(self) -> Literal[False]:
        return False


def _association(
    declaration: ChatGPTNativeTaskDeclarationV1, reference: EvidenceReference
) -> ChatGPTNativeTaskAssociationV1:
    request = decode_chatgpt_native_task_request(declaration.request_json.encode())
    return ChatGPTNativeTaskAssociationV1(
        declaration_id=declaration.id,
        declaration_reference=reference,
        native_capture_id=request.profile.capture_id,
        original_task_id=request.profile.original_task.task_id,
        derived_task_id=request.profile.derived_task_id,
        request_digest=declaration.request_digest,
        wire_digest=declaration.wire_digest,
        counter_digest=content_hash_of(
            canonical_bytes(declaration.counter.model_dump(mode="json"))
        ),
        source_references=native_task_references(request),
    )


def _association_raw(value: ChatGPTNativeTaskAssociationV1) -> bytes:
    raw = canonical_bytes(
        ChatGPTNativeTaskAssociationV1.model_validate(value.model_dump(mode="json")).model_dump(
            mode="json"
        )
    )
    if not 0 < len(raw) <= MAX_ASSOCIATION_BYTES:
        raise ValueError("bounded association required")
    return raw


def _prefix(declaration_id: UUID) -> str:
    return f"personal-chatgpt-native-task/{declaration_id}/"


def _ids(session: Session, declaration_id: UUID) -> tuple[UUID, ...]:
    return tuple(
        session.scalars(
            select(Source.id)
            .where(
                Source.trust_boundary == B.PERSONAL,
                Source.system == SourceSystem.MANUAL,
                Source.external_ref.like(_prefix(declaration_id) + "%"),
            )
            .order_by(Source.id)
            .limit(3)
        )
    )


def _names(
    declaration: ChatGPTNativeTaskDeclarationV1, refs: tuple[EvidenceReference, EvidenceReference]
) -> tuple[str, str]:
    return (
        _prefix(declaration.id) + "declaration/" + refs[0].content_hash,
        _prefix(declaration.id) + "association/" + refs[1].content_hash,
    )


@dataclass(frozen=True, repr=False)
class RetainedChatGPTNativeTaskV1:
    declaration_reference: EvidenceReference
    association_reference: EvidenceReference
    declaration: ChatGPTNativeTaskDeclarationV1 = field(repr=False)
    association: ChatGPTNativeTaskAssociationV1 = field(repr=False)
    captured_at: datetime

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def owner_admitted(self) -> Literal[False]:
        return False

    @property
    def runtime_ready(self) -> Literal[False]:
        return False

    @property
    def reviewer_ready(self) -> Literal[False]:
        return False


def _parts(
    declaration: ChatGPTNativeTaskDeclarationV1,
) -> tuple[
    bytes, ChatGPTNativeTaskDeclarationV1, ChatGPTNativeTaskRequestV1, tuple[EvidenceReference, ...]
]:
    raw = encode_chatgpt_native_task_declaration(declaration)
    stable = decode_chatgpt_native_task_declaration(raw)
    request = decode_chatgpt_native_task_request(stable.request_json.encode())
    refs = native_task_references(request)
    if len(refs) + 2 > 96:
        raise ValueError("bounded full retained union required")
    return raw, stable, request, refs


def _owner(
    inputs: NamedOwnerHostInputs,
    operation: NamedSessionOperation,
    declaration: ChatGPTNativeTaskDeclarationV1,
) -> datetime:
    _host(inputs, operation)
    inputs.clock()
    actual = operation.recheck(declaration.original_session_binding)
    with inputs.clock._lock:
        now = inputs.clock._last
    if (
        now is None
        or (actual.principal.identity.issuer, actual.principal.identity.subject)
        != (declaration.actor_issuer, declaration.actor_subject)
        or actual.issued_at != declaration.original_session_issued_at
        or actual.effective_expires_at != declaration.original_session_expires_at
        or not declaration.prepared_at <= now < declaration.expires_at
        or not actual.issued_at <= now < actual.effective_expires_at
    ):
        raise ValueError("original current native custody owner/window required")
    for ref in native_task_references(
        decode_chatgpt_native_task_request(declaration.request_json.encode())
    ):
        _scope(actual, ref)  # pure gateway from this exact freshly verified principal
    return now


def _snapshot(
    session: Session,
    declaration: ChatGPTNativeTaskDeclarationV1,
    refs: tuple[EvidenceReference, EvidenceReference],
    complete: tuple[EvidenceReference, ...],
    locations: tuple[str, str] | None = None,
    captured_at: datetime | None = None,
) -> tuple[tuple[tuple[tuple[str, object], ...], ...], datetime | None]:
    names = _names(declaration, refs)
    rows = _fragment_rows(session, complete, BOUNDS, LABELS)
    if _ids(session, declaration.id) != tuple(sorted((r.source_id for r in refs), key=str)):
        raise ValueError("single paired namespace required")
    actual_captured: datetime | None = None
    for index, reference in enumerate(refs):
        own = [dict(row) for row in rows if dict(row)["id"] == reference.source_id]
        if not own:
            raise ValueError("own Source missing")
        date = own[0]["captured_at"]
        if (
            type(date) is not datetime
            or date.utcoffset() is None
            or not declaration.prepared_at <= date < declaration.expires_at
        ):
            raise ValueError("original capture date required")
        if actual_captured is None:
            actual_captured = date
        if date != actual_captured or (captured_at is not None and date != captured_at):
            raise ValueError("paired capture time required")
        for row in own:
            if (
                row["system"] is not SourceSystem.MANUAL
                or row["external_ref"] != names[index]
                or row["data_classification"] is not C.HIGHLY_RESTRICTED
                or row["supersedes_source_id"] is not None
                or row["lineage_id"] != reference.source_id
                or row["content_hash"] != reference.content_hash
                or row["captured_at"] != date
                or (locations is not None and row["content_location"] != locations[index])
            ):
                raise ValueError("exact immutable own Source metadata required")
    return rows, actual_captured


def _load(
    session: Session,
    artifacts: LocalFilesystemArtifactStore,
    refs: tuple[EvidenceReference, EvidenceReference],
    declaration: ChatGPTNativeTaskDeclarationV1,
    boundaries: frozenset[B],
    labels: frozenset[C],
) -> RetainedChatGPTNativeTaskV1:
    raw, stable, request, dependencies = _parts(declaration)
    if (
        type(artifacts) is not LocalFilesystemArtifactStore
        or type(boundaries) is not frozenset
        or type(labels) is not frozenset
        or boundaries != BOUNDS
        or labels != LABELS
        or type(refs) is not tuple
        or len(refs) != 2
        or any(type(r) is not EvidenceReference for r in refs)
        or len({r.source_id for r in (*dependencies, *refs)}) != len(dependencies) + 2
        or refs[0].content_hash != content_hash_of(raw)
    ):
        raise ValueError("exact distinct current native custody pair required")
    association = _association(stable, refs[0])
    association_raw = _association_raw(association)
    if refs[1].content_hash != content_hash_of(association_raw):
        raise ValueError("exact association binding required")
    complete = tuple(sorted((*dependencies, *refs), key=lambda r: str(r.source_id)))
    entry = _physical(session)
    before, captured = _snapshot(session, stable, refs, complete)
    for reference in refs:
        own = [dict(row) for row in before if dict(row)["id"] == reference.source_id]
        if any(
            row["content_location"] != artifacts.location_for(reference.content_hash) for row in own
        ):
            raise ValueError("canonical content-addressed own locator required before bytes")
    _same(session, entry)
    load_chatgpt_native_task_request(
        session,
        artifacts=artifacts,
        expected_request=request,
        authorized_boundaries=BOUNDS,
        allowed_classifications=LABELS,
    )
    # Body callback may add sibling or alter own union: recheck before own bytes.
    if _snapshot(session, stable, refs, complete)[0] != before:
        raise ValueError("paired union changed after original body")
    _same(session, entry)
    for reference, expected, limit in zip(
        refs, (raw, association_raw), (MAX_DECLARATION_BYTES, MAX_ASSOCIATION_BYTES), strict=True
    ):
        row = next(dict(row) for row in before if dict(row)["id"] == reference.source_id)
        location = row["content_location"]
        if type(location) is not str:
            raise ValueError("exact own artifact locator required")
        returned = artifacts.get_bounded(B.PERSONAL, location, max_bytes=limit)
        _same(session, entry)
        if (
            type(returned) is not bytes
            or content_hash_of(returned) != reference.content_hash
            or returned != expected
        ):
            raise ValueError("exact canonical native own bytes required")
        if _snapshot(session, stable, refs, complete)[0] != before:
            raise ValueError("paired union changed after own bytes")
        _same(session, entry)
    if (
        decode_chatgpt_native_task_declaration(raw) != stable
        or ChatGPTNativeTaskAssociationV1.model_validate(
            json.loads(association_raw, object_pairs_hook=_unique_pairs)
        )
        != association
    ):
        raise ValueError("canonical pair decode required")
    if captured is None:
        raise ValueError("actual paired date required")
    return RetainedChatGPTNativeTaskV1(refs[0], refs[1], stable, association, captured)


def load_retained_chatgpt_native_task(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    declaration_reference: EvidenceReference,
    association_reference: EvidenceReference,
    expected_declaration: ChatGPTNativeTaskDeclarationV1,
    authorized_boundaries: frozenset[B],
    allowed_classifications: frozenset[C],
) -> RetainedChatGPTNativeTaskV1:
    result = None
    try:
        _, stable, _, _ = _parts(expected_declaration)
        refs = tuple(
            EvidenceReference.model_validate(r.model_dump(mode="json"))
            for r in (declaration_reference, association_reference)
        )
        result = _load(
            session,
            artifacts,
            (refs[0], refs[1]),
            stable,
            authorized_boundaries,
            allowed_classifications,
        )
    except Exception:  # noqa: BLE001,S110 - fixed outside handler; no private diagnostics
        pass
    if result is None:
        raise NativeTaskRetentionError("retained native task unavailable")
    return result


def capture_chatgpt_native_task_declaration(
    *,
    factory: sessionmaker[Session],
    artifacts: LocalFilesystemArtifactStore,
    expected_root: ClaudeArtifactRootIdentity,
    declaration: ChatGPTNativeTaskDeclarationV1,
    declaration_source_id: UUID,
    association_source_id: UUID,
    inputs: NamedOwnerHostInputs,
    operation: NamedSessionOperation,
) -> RetainedChatGPTNativeTaskV1:
    """Atomic immutable two-Source custody, outer commit/close/fresh real reload.

    Occupied namespaces always refuse this capture; only explicit readonly load
    of known exact bindings may examine committed custody. No automatic retry.
    Final owner observation is finite; late external changes are not barred.
    """
    result = None
    possibly_committed = False
    shutdown: type[KeyboardInterrupt | SystemExit] | None = None
    try:
        started = _MONOTONIC()
        raw, stable, request, dependencies = _parts(declaration)
        _standard_factory(factory)
        factory_class = factory.class_
        options = dict(factory.kw)
        if (
            type(declaration_source_id) is not UUID
            or type(association_source_id) is not UUID
            or declaration_source_id.int == 0
            or association_source_id.int == 0
            or len(
                {r.source_id for r in dependencies} | {declaration_source_id, association_source_id}
            )
            != len(dependencies) + 2
        ):
            raise ValueError("exact distinct preallocated own IDs required")
        first = EvidenceReference(
            source_id=declaration_source_id,
            trust_boundary=B.PERSONAL,
            effective_classification=C.HIGHLY_RESTRICTED,
            content_hash=content_hash_of(raw),
        )
        association = _association(stable, first)
        associated_raw = _association_raw(association)
        second = EvidenceReference(
            source_id=association_source_id,
            trust_boundary=B.PERSONAL,
            effective_classification=C.HIGHLY_RESTRICTED,
            content_hash=content_hash_of(associated_raw),
        )
        refs = (first, second)
        complete = tuple(sorted((*dependencies, *refs), key=lambda r: str(r.source_id)))
        _root_check(artifacts, expected_root)
        observed = _owner(inputs, operation, stable)
        deadline = started + (stable.expires_at - observed).total_seconds()
        _bound_factory(factory, factory_class, options)
        with factory() as session:
            session.begin()
            entry = _physical(session)
            if (
                _ids(session, stable.id)
                or session.get(Source, first.source_id) is not None
                or session.get(Source, second.source_id) is not None
            ):
                raise ValueError("occupied immutable native task refused")
            _assert_fragment_generation_unconsumed(session, stable.id)
            before = _fragment_rows(session, dependencies, BOUNDS, LABELS)
            _same(session, entry)
            load_chatgpt_native_task_request(
                session,
                artifacts=artifacts,
                expected_request=request,
                authorized_boundaries=BOUNDS,
                allowed_classifications=LABELS,
            )
            if _fragment_rows(session, dependencies, BOUNDS, LABELS) != before or _ids(
                session, stable.id
            ):
                raise ValueError("current preparation union/namespace changed")
            _same(session, entry)
        _owner(inputs, operation, stable)
        locations = []
        for encoded, reference, limit in zip(
            (raw, associated_raw), refs, (MAX_DECLARATION_BYTES, MAX_ASSOCIATION_BYTES), strict=True
        ):
            _root_check(artifacts, expected_root)
            location = artifacts.put_durable(
                B.PERSONAL, reference.content_hash, encoded, max_bytes=limit
            )
            _owner(inputs, operation, stable)
            _bound_factory(factory, factory_class, options)
            _root_check(artifacts, expected_root)
            returned = artifacts.get_bounded(B.PERSONAL, location, max_bytes=limit)
            _artifact_profile(artifacts, B.PERSONAL, location)
            _root_check(artifacts, expected_root)
            _owner(inputs, operation, stable)
            if returned != encoded or location != artifacts.location_for(reference.content_hash):
                raise ValueError("exact immutable artifact preparation required")
            locations.append(location)
        captured = _owner(inputs, operation, stable)
        _bound_factory(factory, factory_class, options)
        if _MONOTONIC() >= deadline:
            raise ValueError("original retention window exhausted")
        with factory() as session:
            session.begin()
            _lock(session, stable.id)
            entry = _physical(session)
            _assert_fragment_generation_unconsumed(session, stable.id)
            if (
                _fragment_rows(session, dependencies, BOUNDS, LABELS) != before
                or _ids(session, stable.id)
                or session.get(Source, first.source_id) is not None
                or session.get(Source, second.source_id) is not None
            ):
                raise ValueError("prepared current union/namespace changed")
            _same(session, entry)
            _assert_personal_custody_append_capacity(session, 2)
            _same(session, entry)
            for reference, location, name in zip(
                refs, locations, _names(stable, refs), strict=True
            ):
                own, new = record_source(
                    session,
                    trust_boundary=B.PERSONAL,
                    data_classification=C.HIGHLY_RESTRICTED,
                    system=SourceSystem.MANUAL,
                    external_ref=name,
                    content_hash=reference.content_hash,
                    content_location=location,
                    captured_at=captured,
                    preallocated_source_id=reference.source_id,
                )
                if not new or own.id != reference.source_id:
                    raise ValueError("new exact immutable rows required")
            _snapshot(session, stable, refs, complete, (locations[0], locations[1]), captured)
            if _fragment_rows(session, dependencies, BOUNDS, LABELS) != before:
                raise ValueError("pending original union changed")
            _assert_fragment_generation_unconsumed(session, stable.id)
            _same(session, entry)
            if _MONOTONIC() >= deadline:
                raise ValueError("original retention window exhausted before commit")
            _same_output_commit_transaction(session, entry)
            possibly_committed = True
            session.commit()
        _owner(inputs, operation, stable)
        _bound_factory(factory, factory_class, options)
        with factory() as session:
            session.begin()
            loaded = _load(session, artifacts, refs, stable, BOUNDS, LABELS)
            entry = _physical(session)
            if loaded.captured_at != captured:
                raise ValueError("original paired capture time changed")
            baseline = _snapshot(
                session, stable, refs, complete, (locations[0], locations[1]), captured
            )[0]
            _same(session, entry)
        _root_check(artifacts, expected_root)
        _owner(inputs, operation, stable)
        _bound_factory(factory, factory_class, options)
        with factory() as session:
            session.begin()
            entry = _physical(session)
            if (
                _snapshot(session, stable, refs, complete, (locations[0], locations[1]), captured)[
                    0
                ]
                != baseline
            ):
                raise ValueError("terminal paired union changed")
            _assert_fragment_generation_unconsumed(session, stable.id)
            _same(session, entry)
        if _MONOTONIC() >= deadline:
            raise ValueError("original window exhausted before ACK")
        result = loaded
    except KeyboardInterrupt:
        shutdown = KeyboardInterrupt
    except SystemExit:
        shutdown = SystemExit
    except BaseException:  # noqa: BLE001,S110 - fixed safe failure outside handler
        pass
    if shutdown is not None:
        if possibly_committed:
            raise shutdown("native task custody interrupted; preserve and reconcile") from (
                NativeTaskRetentionUncertain(
                    "native task custody uncertain; preserve and reconcile"
                )
            )
        raise shutdown("native task custody interrupted; preserve and reconcile")
    if result is None:
        if possibly_committed:
            raise NativeTaskRetentionUncertain(
                "native task custody uncertain; preserve and reconcile"
            )
        raise NativeTaskRetentionError("native task custody unavailable; stop and reconcile")
    return result
