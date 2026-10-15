"""One owner-attested managed catalog capture and complete BRAINSTORM checkpoint.

Shared application logic, not a route, connector, permission issuer or model task.
The existing named-session implementation remains an authentication dependency.
Trusted host wiring must separately approve actual source scope, full-boundary
backup geography/credentials/recovered identity and the exclusive restore window.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from threading import Lock, RLock
from typing import Any, Literal, cast
from uuid import UUID, uuid5

from sqlalchemy import UUID as SqlUUID
from sqlalchemy import DateTime, Text, func, select, true
from sqlalchemy import Enum as SqlEnum
from sqlalchemy.engine import Engine
from sqlalchemy.sql import ColumnElement

from zacai.claude_original_capture import observe_claude_artifact_root
from zacai.contextual_protection import BrainstormContextualProtector, ProtectedState
from zacai.host_clock import HostObservedClock
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.ingestion.managed_app_catalog_observation import (
    ManagedAppCatalogObservationPreparationV1,
    prepare_managed_app_catalog_observation,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.interfaces.checkpoint_lease import checkpoint_lease
from zacai.interfaces.named_session_binding import NamedSessionOperation, VerifiedNamedSession
from zacai.managed_catalog_admission import (
    CatalogBirthGuard,
    catalog_claim_root,
    claim_catalog_capture,
)
from zacai.managed_catalog_recovery import CatalogRecoveryReceiptV1, publish_catalog_receipt
from zacai.owner_authority import BoundaryScope, Identity
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _lock
from zacai.review_protection import assert_local_review_state_engine
from zacai.state import Source, SourceClassificationElevation, SourceSystem
from zacai.state_repository import (
    record_source,
    source_classification_elevation_strength,
)

_DECISION_KEY = object()
_NAMESPACE = UUID("876e0807-d65c-4be4-843b-0aab2fec6107")


class ManagedCatalogCustodyError(ValueError):
    """Fixed terminal hold; commit or backup may already exist. Never auto-retry."""


def _rebuild(
    p: ManagedAppCatalogObservationPreparationV1,
) -> ManagedAppCatalogObservationPreparationV1:
    if type(p) is not ManagedAppCatalogObservationPreparationV1:
        raise ValueError("exact catalog preparation required")
    rebuilt = prepare_managed_app_catalog_observation(
        raw=p.artifacts[0].original_bytes,
        scope=p.companion.scope,
        requestor_boundaries=frozenset({B.BRAINSTORM}),
        allowed_classifications=frozenset({p.companion.scope.classification}),
    )
    if rebuilt != p:
        raise ValueError("exact complete catalog preparation changed")
    return rebuilt


def catalog_capture_review_digest(
    request_id: UUID,
    preparation: ManagedAppCatalogObservationPreparationV1,
    expires_at: datetime,
) -> str:
    """Comparison against the exact configured display, never owner authority."""
    p = _rebuild(preparation)
    if (
        type(request_id) is not UUID
        or not request_id.int
        or type(expires_at) is not datetime
        or expires_at.utcoffset() is None
    ):
        raise ValueError("exact configured request/window required")
    return content_hash_of(
        canonical_bytes(
            {
                "format": "zac-managed-catalog-capture-review-v1",
                "request_id": str(request_id),
                "scope": p.companion.scope.model_dump(mode="json"),
                "artifacts": [
                    {
                        "namespace": a.external_ref,
                        "hash": a.content_hash,
                        "classification": a.classification.value,
                    }
                    for a in p.artifacts
                ],
                "expires_at": expires_at.isoformat(),
            }
        )
    )


@dataclass(frozen=True, repr=False)
class _ManagedCatalogOwnerDecision:
    """Private transport-issued witness, meaningful only with actual operation checks.

    A key or dataclass is not an authentication sandbox against trusted Python.
    Only the reviewed same-cookie/CSRF transport observer issues this witness.
    """

    request_id: UUID
    selection_digest: str
    expires_at: datetime
    observed_at: datetime
    owner: VerifiedNamedSession
    operation: NamedSessionOperation
    _key: object
    _once: list[bool] = field(default_factory=lambda: [False], repr=False)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def consume(self) -> None:
        with self._lock:
            if self._key is not _DECISION_KEY or self._once != [False]:
                raise ValueError("unobserved or consumed catalog decision")
            self._once[0] = True


@dataclass(frozen=True, repr=False)
class ManagedCatalogCheckpoint:
    references: tuple[EvidenceReference, EvidenceReference, EvidenceReference]
    request_id: UUID
    selection_digest: str
    captured_at: datetime
    verified_at: datetime
    full_source_inventory_digest: str
    protection: ProtectedState
    recovery_receipt: CatalogRecoveryReceiptV1
    processing_authorized: Literal[False] = field(default=False, init=False)
    current_facts_verified: Literal[False] = field(default=False, init=False)
    off_device_verified: Literal[False] = field(default=False, init=False)


def _scalar(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _same_capture_instant(raw: object, expected: datetime) -> bool:
    """Canonical timezone normalization must not change an aware instant."""
    if type(raw) is not str or len(raw) > 100:
        return False
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return False
    return (
        parsed.utcoffset() is not None and expected.utcoffset() is not None and parsed == expected
    )


_SOURCE_COLUMNS = (
    "id",
    "trust_boundary",
    "data_classification",
    "system",
    "external_ref",
    "captured_at",
    "excerpt",
    "content_hash",
    "content_location",
    "supersedes_source_id",
)


def _source_columns() -> tuple[ColumnElement[Any], ...]:
    """Closed current Source schema: four Text fields need the SQL width gate."""
    table = Source.__table__
    expected_types = (SqlUUID, SqlEnum, SqlEnum, SqlEnum, Text, DateTime, Text, Text, Text, SqlUUID)
    if (
        tuple(table.columns.keys()) != _SOURCE_COLUMNS
        or tuple(type(column.type) for column in table.columns) != expected_types
        or cast(DateTime, table.c.captured_at.type).timezone is not True
    ):
        raise ValueError("closed reviewed Source schema required before inventory query")
    return tuple(table.c[name] for name in _SOURCE_COLUMNS)


class CanonicalManagedCatalogCapture:
    """One exact capture/checkpoint action; no standalone append is public.

    Final acknowledgement requires full recovery and fresh current source/owner
    readback. Failure is terminal even when append/backup committed. There is no
    restart/read-existing repair API here; uncertain custody needs reconciliation.
    """

    def __init__(
        self,
        *,
        protector: BrainstormContextualProtector,
        operation: NamedSessionOperation,
        expected_identity: Identity,
        request_id: UUID,
        preparation: ManagedAppCatalogObservationPreparationV1,
        expires_at: datetime,
    ) -> None:
        failed = False
        try:
            if (
                type(protector) is not BrainstormContextualProtector
                or type(operation) is not NamedSessionOperation
                or type(operation.host_clock) is not HostObservedClock
                or type(expected_identity) is not Identity
                or type(protector._artifacts) is not LocalFilesystemArtifactStore
                or not isinstance(protector._engine, Engine)
                or protector._approval_id is not None
                or protector._factory.kw.get("bind") is not protector._engine
                or protector._factory.kw.get("binds")
            ):
                raise ValueError("exact trusted host graph required")
            _source_columns()
            assert_local_review_state_engine(cast(Engine, protector._engine))
            self._engine: Engine = cast(Engine, protector._engine)
            self._artifacts: LocalFilesystemArtifactStore = protector._artifacts
            self._artifact_pin = observe_claude_artifact_root(self._artifacts)
            self._preparation = _rebuild(preparation)
            self._digest = catalog_capture_review_digest(request_id, preparation, expires_at)
            self._protector, self._operation = protector, operation
            self._identity, self._request_id, self._expires = (
                expected_identity,
                request_id,
                expires_at,
            )
            self._clock = operation.host_clock
            self._claim_root = catalog_claim_root(protector._cache)
            self._claim_guard: CatalogBirthGuard | None = None
            self._guard_pin: CatalogBirthGuard | None = None
            self._pins = (
                protector._factory,
                protector._engine,
                protector._artifacts,
                protector._objects,
                protector._reader,
                protector._restoration,
            )
            self._settings = (
                protector._recipient,
                protector._identity,
                protector._cache,
                self._engine.url,
                protector._factory.class_,
            )
            self._operation_pins = (operation._read, operation._host_clock, operation._source)
            self._lock, self._phase = RLock(), "NEW"
        except Exception:  # noqa: BLE001 - private-safe constructor failure
            failed = True
        if failed:
            raise ManagedCatalogCustodyError("managed catalog capture configuration rejected")

    def _configuration(self) -> None:
        _source_columns()
        p, op = self._protector, self._operation
        if (
            any(
                a is not b
                for a, b in zip(
                    self._pins,
                    (p._factory, p._engine, p._artifacts, p._objects, p._reader, p._restoration),
                    strict=True,
                )
            )
            or self._settings
            != (p._recipient, p._identity, p._cache, self._engine.url, p._factory.class_)
            or any(
                a is not b
                for a, b in zip(
                    self._operation_pins, (op._read, op._host_clock, op._source), strict=True
                )
            )
            or observe_claude_artifact_root(self._artifacts) != self._artifact_pin
            or op.host_clock is not self._clock
            or p._factory.kw.get("bind") is not p._engine
            or p._factory.kw.get("binds")
            or catalog_capture_review_digest(self._request_id, self._preparation, self._expires)
            != self._digest
        ):
            raise ValueError("original catalog capture graph changed")
        if catalog_claim_root(p._cache) != self._claim_root:
            raise ValueError("original disclosed claim location changed")
        if self._guard_pin is not None:
            if (
                self._claim_guard is not self._guard_pin
                or type(self._claim_guard) is not CatalogBirthGuard
                or self._claim_guard._root != self._claim_root
                or self._claim_guard._request != str(self._request_id)
            ):
                raise ValueError("original catalog birth guard changed")
            self._claim_guard.recheck()
        elif self._claim_guard is not None:
            raise ValueError("unexpected catalog birth guard")

    def _owner(self, decision: _ManagedCatalogOwnerDecision) -> VerifiedNamedSession:
        self._configuration()
        current = self._operation.recheck(decision.owner.binding_digest)
        label = self._preparation.companion.scope.classification
        now = self._clock()
        if (
            current != decision.owner
            or current.principal.identity != self._identity
            or current.principal.scopes != (BoundaryScope(B.BRAINSTORM, frozenset({label})),)
            or self._preparation.companion.scope.inspected_at > decision.observed_at
            or not decision.observed_at <= now < self._expires <= current.effective_expires_at
            or self._expires - decision.observed_at > timedelta(minutes=15)
        ):
            raise ValueError("current original scoped catalog owner required")
        self._configuration()  # owner callbacks cannot replace the live birth marker
        return current

    def _append(
        self,
        decision: _ManagedCatalogOwnerDecision,
    ) -> tuple[EvidenceReference, EvidenceReference, EvidenceReference]:
        p, preparation = self._protector, self._preparation
        label = preparation.companion.scope.classification
        decision_raw = canonical_bytes(
            {
                "format": "zac-managed-catalog-owner-capture-v1",
                "request_id": str(self._request_id),
                "selection_digest": self._digest,
                "owner_issuer": decision.owner.principal.identity.issuer,
                "owner_subject": decision.owner.principal.identity.subject,
                "original_session_binding": decision.owner.binding_digest,
                "observed_at": decision.observed_at.isoformat(),
                "expires_at": self._expires.isoformat(),
                "scope": preparation.companion.scope.model_dump(mode="json"),
                "raw_digest": preparation.artifacts[0].content_hash,
                "companion_digest": preparation.artifacts[1].content_hash,
                "action": "CAPTURE_SELECTED_NAVIGATION_ONLY",
                "processing_authorized": False,
                "current_facts_verified": False,
            }
        )
        decision_ref = f"managed-app-catalog-owner-capture/{self._request_id}"
        values = [
            (a.external_ref, a.content_hash, a.original_bytes, SourceSystem.MANUAL)
            for a in preparation.artifacts
        ]
        values.append(
            (
                decision_ref,
                content_hash_of(decision_raw),
                decision_raw,
                SourceSystem.USER_INSTRUCTION,
            )
        )
        locations = []
        for _, digest, raw, _ in values:
            self._owner(decision)
            location = self._artifacts.put_durable(B.BRAINSTORM, digest, raw, max_bytes=256000)
            self._owner(decision)
            if self._artifacts.get_bounded(B.BRAINSTORM, location, max_bytes=256000) != raw:
                raise ValueError("exact catalog custody readback differs")
            locations.append(location)
        self._owner(decision)
        refs = []
        with p._factory() as session:
            for namespace, _, _, _ in sorted(values):
                _lock(session, uuid5(_NAMESPACE, namespace))
            physical = _physical(session)
            for (namespace, digest, _, system), location in zip(values, locations, strict=True):
                # First bounded capture only. Existing namespaces must be
                # reconciled rather than replayed or revived as a new action.
                if session.scalar(
                    select(Source.id).where(Source.external_ref == namespace).limit(1)
                ):
                    raise ValueError("catalog namespace already exists; reconcile")
                if self._clock() >= self._expires:
                    raise ValueError("catalog capture original window expired")
                source, created = record_source(
                    session,
                    trust_boundary=B.BRAINSTORM,
                    data_classification=label,
                    system=system,
                    external_ref=namespace,
                    content_hash=digest,
                    content_location=location,
                    captured_at=decision.observed_at,
                    preallocated_source_id=uuid5(_NAMESPACE, namespace + "/" + digest),
                )
                if not created or source.data_classification is not label:
                    raise ValueError("exact new catalog identity required")
                refs.append(
                    EvidenceReference(
                        source_id=source.id,
                        content_hash=digest,
                        trust_boundary=B.BRAINSTORM,
                        effective_classification=label,
                    )
                )
            _same(session, physical)
            if self._clock() >= self._expires:
                raise ValueError("catalog capture expired before commit")
            session.commit()
        if len(refs) != 3:
            raise ValueError("complete catalog pair and owner decision required")
        return refs[0], refs[1], refs[2]

    def _readback(
        self,
        refs: tuple[EvidenceReference, EvidenceReference, EvidenceReference],
        observed_at: datetime,
    ) -> bytes:
        # Use the same server-width-guarded full metadata observation. Do not
        # first ORM-load selected unbounded Text or multiply excerpts in a
        # lineage join. Tip checks below return UUIDs only.
        import json

        p, label = self._protector, self._preparation.companion.scope.classification
        first = self._inventory()
        by_id = {row["id"]: row for row in json.loads(first)["rows"]}
        namespaces = [a.external_ref for a in self._preparation.artifacts]
        namespaces.append(f"managed-app-catalog-owner-capture/{self._request_id}")
        selected = []
        for index, (ref, namespace) in enumerate(zip(refs, namespaces, strict=True)):
            row = by_id.get(str(ref.source_id))
            system = SourceSystem.MANUAL if index < 2 else SourceSystem.USER_INSTRUCTION
            if (
                row is None
                or row["external_ref"] != namespace
                or row["system"] != system.value
                or row["trust_boundary"] != B.BRAINSTORM.value
                or row["data_classification"] != label.value
                or row["effective"] != label.value
                or row["content_hash"] != ref.content_hash
                or not _same_capture_instant(row["captured_at"], observed_at)
                or type(row["content_location"]) is not str
                or ref.source_id != uuid5(_NAMESPACE, namespace + "/" + ref.content_hash)
                or index < 2
                and ref.content_hash != self._preparation.artifacts[index].content_hash
            ):
                raise ValueError("exact current catalog source metadata required")
            with p._factory() as session:
                superseded = select(Source.supersedes_source_id).where(
                    Source.supersedes_source_id.is_not(None)
                )
                tips = list(
                    session.scalars(
                        select(Source.id)
                        .where(
                            Source.system == system,
                            Source.external_ref == namespace,
                            Source.trust_boundary == B.BRAINSTORM,
                            Source.id.not_in(superseded),
                        )
                        .limit(2)
                    )
                )
                if tips != [ref.source_id]:
                    raise ValueError("catalog source revision stale or ambiguous")
            raw = self._artifacts.get_bounded(
                B.BRAINSTORM, row["content_location"], max_bytes=256000
            )
            if content_hash_of(raw) != ref.content_hash:
                raise ValueError("catalog retained bytes changed")
            selected.append(row)
        if self._inventory() != first:
            raise ValueError("full source metadata changed during catalog reads")
        return canonical_bytes({"rows": selected})

    def _inventory(self) -> bytes:
        # One bounded Source/elevation snapshot, including existing excerpt
        # fields but never artifact bytes. Host separately authorizes this full-
        # boundary backup scope, not model use.
        columns = _source_columns()
        effective = (
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
        candidates = (
            select(
                Source.external_ref, Source.excerpt, Source.content_hash, Source.content_location
            )
            .where(Source.trust_boundary == B.BRAINSTORM)
            .limit(4097)
            .cte("managed_catalog_inventory_candidates")
        )
        width = sum(
            func.octet_length(func.coalesce(column, ""))
            for column in (
                candidates.c.external_ref,
                candidates.c.excerpt,
                candidates.c.content_hash,
                candidates.c.content_location,
            )
        )
        sizes = (
            select(
                func.count().label("row_count"),
                func.coalesce(func.sum(width), 0).label("text_bytes"),
                func.coalesce(func.max(width), 0).label("max_text_bytes"),
            )
            .select_from(candidates)
            .cte("managed_catalog_inventory_sizes")
        )
        with self._protector._factory() as session:
            # A single SQL statement refuses all rows server-side BEFORE any
            # unbounded Source Text is materialized in Python. Rowcount is not
            # a byte bound. Do not fetch a permitted subset when over capacity.
            rows = list(
                session.execute(
                    select(
                        *columns,
                        func.coalesce(effective, Source.data_classification).label("effective"),
                    )
                    .select_from(Source)
                    .join(sizes, true())
                    .where(
                        Source.trust_boundary == B.BRAINSTORM,
                        sizes.c.row_count > 0,
                        sizes.c.row_count <= 4096,
                        sizes.c.text_bytes <= 4_000_000,
                        sizes.c.max_text_bytes <= 4_000_000,
                    )
                    .order_by(Source.id)
                    .limit(4097)
                ).mappings()
            )
            if not rows or len(rows) > 4096:
                raise ValueError("bounded complete BRAINSTORM Source inventory required")
            raw = canonical_bytes(
                {"rows": [{str(key): _scalar(value) for key, value in row.items()} for row in rows]}
            )
            if len(raw) > 8_000_000:
                raise ValueError("bounded encoded Source inventory required")
            return raw

    def capture(self, decision: _ManagedCatalogOwnerDecision) -> ManagedCatalogCheckpoint:
        if not self._lock.acquire(blocking=False):
            raise ManagedCatalogCustodyError("managed catalog capture held; reconcile custody")
        result = None
        try:
            if self._phase != "NEW":
                raise ValueError("catalog action already entered")
            self._phase = "ENTERED"  # original one-shot before any private I/O
            if (
                type(decision) is not _ManagedCatalogOwnerDecision
                or decision.operation is not self._operation
                or decision.request_id != self._request_id
                or decision.expires_at != self._expires
                or decision.selection_digest != self._digest
            ):
                raise ValueError("exact observed catalog decision required")
            decision.consume()
            self._owner(decision)
            guard = claim_catalog_capture(
                root=self._claim_root,
                request_id=self._request_id,
                selection_digest=self._digest,
                original_binding=decision.owner.binding_digest,
                owner_fingerprint=content_hash_of(
                    canonical_bytes(
                        {
                            "issuer": self._identity.issuer,
                            "subject": self._identity.subject,
                        }
                    )
                ),
                expires_at=self._expires,
            )
            self._claim_guard = self._guard_pin = guard
            self._owner(decision)
            with checkpoint_lease(self._protector, self._lock) as require:
                self._owner(decision)
                refs = self._append(decision)
                self._owner(decision)
                rows = self._readback(refs, decision.observed_at)
                inventory = self._inventory()
                self._owner(decision)
                protected = self._protector._protect_state(
                    {ref.source_id: ref.content_hash for ref in refs},
                    f"BRAINSTORM/state/managed-app-catalog-{self._request_id}",
                )
                self._owner(decision)
                if type(protected) is not ProtectedState:
                    raise ValueError("actual complete catalog checkpoint required")
                if (
                    self._readback(refs, decision.observed_at) != rows
                    or self._inventory() != inventory
                ):
                    raise ValueError("complete catalog/source inventory changed during recovery")
                self._owner(decision)
                # Canonical final observations follow the last owner callback.
                if (
                    self._readback(refs, decision.observed_at) != rows
                    or self._inventory() != inventory
                ):
                    raise ValueError("terminal catalog recovery preimages changed")
                require()
                verified = self._clock()
                receipt = publish_catalog_receipt(
                    protector=self._protector,
                    operation=self._operation,
                    expected_identity=self._identity,
                    original_binding=decision.owner.binding_digest,
                    references=refs,
                    request_id=self._request_id,
                    selection_digest=self._digest,
                    captured_at=decision.observed_at,
                    verified_at=verified,
                    full_inventory_utf8=inventory,
                    protection=protected,
                )
                if (
                    type(receipt) is not CatalogRecoveryReceiptV1
                    or receipt.references != refs
                    or receipt.request_id != self._request_id
                    or receipt.selection_digest != self._digest
                    or receipt.captured_at != decision.observed_at
                    or receipt.verified_at != verified
                    or receipt.full_source_inventory_digest != content_hash_of(inventory)
                    or receipt.artifact_backup_run_id != protected.artifact_backup_run_id
                    or receipt.state_object != protected.state_object
                    or receipt.journal_object != protected.journal_object
                    or receipt.state_plaintext_hash != protected.state_plaintext_hash
                    or receipt.journal_plaintext_hash != protected.journal_plaintext_hash
                ):
                    raise ValueError("exact durable catalog receipt required")
            self._owner(decision)
            if self._readback(refs, decision.observed_at) != rows or self._inventory() != inventory:
                raise ValueError("catalog source changed before acknowledgement")
            self._configuration()  # final live birth/graph proof, no owner callback or Source I/O
            final_time = self._clock()
            if not decision.observed_at <= verified <= final_time < self._expires:
                raise ValueError("catalog original deadline expired during final readback")
            result = ManagedCatalogCheckpoint(
                refs,
                self._request_id,
                self._digest,
                decision.observed_at,
                final_time,
                content_hash_of(inventory),
                protected,
                receipt,
            )
            self._phase = "COMPLETE"
        except BaseException:  # noqa: BLE001 - committed/interrupt uncertainty is terminal
            if self._phase == "ENTERED":
                self._phase = "HELD"
        finally:
            self._lock.release()
        if result is None:
            raise ManagedCatalogCustodyError("managed catalog capture held; reconcile custody")
        return result
