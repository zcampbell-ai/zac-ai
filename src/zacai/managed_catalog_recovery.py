"""Durable catalog recovery observations, never capture or processing authority.

The existing canonical owner decision locates a retained encrypted receipt in
the existing backup store. Publication runs inside the capture's real lease;
read-only reopen uses a fresh actual owner session and its own recovery lease.
Historical whole-boundary proof is distinct from current selected-source access.
Construction performs no I/O. Trusted host wiring and exclusive recovery window
remain required; local object clients do not establish off-device availability.

The shared PostgreSQL lease serializes cooperating writers. The controlled
writer refuses an existing receipt; the object store's unconditional put is
not storage-enforced create-only against foreign writers. Host wiring must
provide trusted writers and exclusive receipt custody. Public-recipient age
encryption supplies confidentiality/ciphertext integrity, not sender identity.
All participating writers must use PostgreSQL lease 73403416. The host must
exclusively control writer credentials and the receipt/checkpoint object prefix,
canonical Source and local artifact custody, and the configured encryption
identity. No foreign or administrative writes may occur during verification.
Historical union verification establishes consistency of the trusted writer's
snapshot/journal/artifacts, not authenticity against a re-forged complete chain.
Only the selected three Sources are independently joined to current canonical
rows/ACLs. Unselected history is never promoted to a current verified fact.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import RLock
from typing import Literal, Self
from uuid import UUID, uuid5

from pydantic import AwareDatetime, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import UUID as SqlUUID
from sqlalchemy import DateTime, Text, func, select, text, true
from sqlalchemy import Enum as SqlEnum
from sqlalchemy.engine import Engine

from zacai import backup
from zacai.backup_artifacts import age_decrypt, age_encrypt, backup_object_key_for
from zacai.contextual_protection import BrainstormContextualProtector, ProtectedState
from zacai.host_clock import HostObservedClock
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.ingestion.managed_app_catalog_observation import (
    ManagedAppCatalogObservationPreparationV1,
    ManagedAppCatalogObservationScopeV1,
    _pairs,
    prepare_managed_app_catalog_observation,
)
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.interfaces.checkpoint_lease import checkpoint_lease
from zacai.interfaces.named_session_binding import (
    NamedSessionOperation,
    VerifiedNamedSession,
)
from zacai.owner_authority import BoundaryScope, Identity
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation
from zacai.review_protection import (
    _SELECTED_SOURCE_COLUMNS,
    assert_local_review_state_engine,
)
from zacai.state import Source, SourceClassificationElevation, SourceSystem
from zacai.state_repository import source_classification_elevation_strength

_NAMESPACE = UUID("876e0807-d65c-4be4-843b-0aab2fec6107")
_MAX_RECEIPT = 1_000_000
_SOURCE_COLUMNS = frozenset(_SELECTED_SOURCE_COLUMNS)


def _source_columns():
    # Same closed Source contract as the reviewed custody reader. Keep this
    # neutral leaf independent of custody, which imports its publisher.
    table = Source.__table__
    types = (SqlUUID, SqlEnum, SqlEnum, SqlEnum, Text, DateTime, Text, Text, Text, SqlUUID)
    if (
        tuple(table.columns.keys()) != _SELECTED_SOURCE_COLUMNS
        or tuple(type(column.type) for column in table.columns) != types
        or table.c.captured_at.type.timezone is not True
    ):
        raise ValueError("closed reviewed Source schema required before selected query")
    return tuple(table.c[name] for name in _SELECTED_SOURCE_COLUMNS)


class CatalogRecoveryError(ValueError):
    """Fixed terminal diagnostic; no repair or action acknowledgement implied."""


class _CaptureAttestation(Contract):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)
    format: Literal["zac-managed-catalog-owner-capture-v1"]
    request_id: UUID
    selection_digest: Digest
    owner_issuer: str = Field(min_length=1, max_length=200, repr=False)
    owner_subject: str = Field(min_length=1, max_length=200, repr=False)
    original_session_binding: Digest = Field(repr=False)
    observed_at: AwareDatetime
    expires_at: AwareDatetime
    scope: ManagedAppCatalogObservationScopeV1 = Field(repr=False)
    raw_digest: Digest
    companion_digest: Digest
    action: Literal["CAPTURE_SELECTED_NAVIGATION_ONLY"]
    processing_authorized: Literal[False]
    current_facts_verified: Literal[False]

    @field_validator("processing_authorized", "current_facts_verified", mode="before")
    @classmethod
    def false_only(cls, value):
        if value is not False:
            raise ValueError("historical observation only")
        return value

    @model_validator(mode="after")
    def window(self) -> Self:
        if (
            not self.request_id.int
            or not self.scope.inspected_at <= self.observed_at < self.expires_at
            or self.expires_at - self.observed_at > timedelta(minutes=15)
        ):
            raise ValueError("exact historical capture window required")
        return self


class CatalogRecoveryReceiptV1(Contract):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)
    format: Literal["zac-managed-catalog-recovery-v1"] = "zac-managed-catalog-recovery-v1"
    request_id: UUID
    selection_digest: Digest
    references: tuple[EvidenceReference, EvidenceReference, EvidenceReference] = Field(repr=False)
    captured_at: AwareDatetime
    verified_at: AwareDatetime
    full_source_inventory_digest: Digest
    historical_source_hashes: tuple[tuple[UUID, Digest | None], ...] = Field(
        min_length=3, max_length=4096, repr=False
    )
    artifact_backup_run_id: UUID
    state_ciphertext_hash: Digest
    state_plaintext_hash: Digest
    journal_ciphertext_hash: Digest
    journal_plaintext_hash: Digest

    @model_validator(mode="after")
    def exact(self) -> Self:
        ids = tuple(sid for sid, _ in self.historical_source_hashes)
        label = self.references[0].effective_classification
        if (
            not self.request_id.int
            or not self.artifact_backup_run_id.int
            or self.verified_at < self.captured_at
            or label not in (C.CONFIDENTIAL, C.HIGHLY_RESTRICTED)
            or len(set(ids)) != len(ids)
            or ids != tuple(sorted(ids, key=str))
            or any(not sid.int for sid in ids)
            or len({r.source_id for r in self.references}) != 3
            or any(
                r.trust_boundary is not B.BRAINSTORM
                or r.effective_classification is not label
                or dict(self.historical_source_hashes).get(r.source_id) != r.content_hash
                for r in self.references
            )
        ):
            raise ValueError("exact catalog recovery subject required")
        return self

    @property
    def prefix(self) -> str:
        return f"BRAINSTORM/state/managed-app-catalog-{self.request_id}"

    @property
    def receipt_object(self) -> str:
        return f"{self.prefix}/receipt-{self.references[2].content_hash}.age"

    @property
    def state_object(self) -> str:
        return f"{self.prefix}/{self.state_ciphertext_hash}.age"

    @property
    def journal_object(self) -> str:
        return f"{self.prefix}/journal-{self.journal_ciphertext_hash}.age"

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def execution_authorized(self) -> Literal[False]:
        return False

    @property
    def recovery_verified(self) -> Literal[False]:
        return False  # Decoding a dated receipt does not repeat verification.


def encode_catalog_receipt(value: CatalogRecoveryReceiptV1) -> bytes:
    if type(value) is not CatalogRecoveryReceiptV1:
        raise ValueError("exact catalog receipt required")
    raw = canonical_bytes(CatalogRecoveryReceiptV1.model_validate(value).model_dump(mode="json"))
    if len(raw) > _MAX_RECEIPT:
        raise ValueError("bounded catalog receipt required")
    return raw


def decode_catalog_receipt(raw: bytes) -> CatalogRecoveryReceiptV1:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_RECEIPT:
        raise ValueError("bounded catalog receipt bytes required")
    value = CatalogRecoveryReceiptV1.model_validate(json.loads(raw, object_pairs_hook=_pairs))
    if encode_catalog_receipt(value) != raw:
        raise ValueError("canonical catalog receipt required")
    return value


@dataclass(frozen=True, repr=False)
class _Selection:
    attestation: _CaptureAttestation
    preparation: ManagedAppCatalogObservationPreparationV1
    references: tuple[EvidenceReference, EvidenceReference, EvidenceReference]
    rows: bytes


@dataclass(frozen=True, repr=False)
class ReopenedCatalog:
    preparation: ManagedAppCatalogObservationPreparationV1 = field(repr=False)
    references: tuple[EvidenceReference, EvidenceReference, EvidenceReference] = field(repr=False)
    receipt: CatalogRecoveryReceiptV1 = field(repr=False)
    checked_at: datetime
    processing_authorized: Literal[False] = field(default=False, init=False)
    execution_authorized: Literal[False] = field(default=False, init=False)
    capture_authorized: Literal[False] = field(default=False, init=False)
    current_facts_verified: Literal[False] = field(default=False, init=False)
    off_device_verified: Literal[False] = field(default=False, init=False)


def _inventory_hashes(raw: bytes) -> tuple[tuple[UUID, str | None], ...]:
    if type(raw) is not bytes or not 0 < len(raw) <= 8_000_000:
        raise ValueError("bounded historical inventory required")
    value = json.loads(raw, object_pairs_hook=_pairs)
    if (
        type(value) is not dict
        or set(value) != {"rows"}
        or type(value["rows"]) is not list
        or not 3 <= len(value["rows"]) <= 4096
        or canonical_bytes(value) != raw
    ):
        raise ValueError("exact historical inventory required")
    pairs = []
    for row in value["rows"]:
        if (
            set(row) != _SOURCE_COLUMNS | {"effective"}
            or row["trust_boundary"] != B.BRAINSTORM.value
        ):
            raise ValueError("closed historical Source metadata required")
        pairs.append((UUID(row["id"]), row["content_hash"]))
    if len(dict(pairs)) != len(pairs) or pairs != sorted(pairs, key=lambda p: str(p[0])):
        raise ValueError("unique ordered historical Source inventory required")
    return tuple(pairs)


class CanonicalManagedCatalogRecovery:
    """Fresh owner read/recovery join; never creates or repairs a missing receipt."""

    def __init__(
        self,
        *,
        protector: BrainstormContextualProtector,
        operation: NamedSessionOperation,
        expected_identity: Identity,
    ):
        configured = False
        try:
            self._configure(protector, operation, expected_identity)
            configured = True
        except Exception:  # noqa: BLE001,S110 - fixed configuration diagnostics
            pass
        if not configured:
            raise CatalogRecoveryError("catalog recovery configuration rejected")

    def _configure(self, protector, operation, expected_identity):
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
            raise CatalogRecoveryError("catalog recovery configuration rejected")
        assert_local_review_state_engine(protector._engine)
        self._p, self._op, self._identity = protector, operation, expected_identity
        self._clock, self._lock = operation.host_clock, RLock()
        self._pins = (
            protector._factory,
            protector._engine,
            protector._artifacts,
            protector._objects,
            protector._reader,
            protector._restoration,
            operation._read,
            operation._host_clock,
            operation._source,
        )
        self._settings = (
            protector._recipient,
            protector._identity,
            protector._cache,
            protector._engine.url,
            protector._factory.class_,
        )

    def _configuration(self):
        p, op = self._p, self._op
        if (
            any(
                a is not b
                for a, b in zip(
                    self._pins,
                    (
                        p._factory,
                        p._engine,
                        p._artifacts,
                        p._objects,
                        p._reader,
                        p._restoration,
                        op._read,
                        op._host_clock,
                        op._source,
                    ),
                    strict=True,
                )
            )
            or self._settings
            != (p._recipient, p._identity, p._cache, p._engine.url, p._factory.class_)
            or p._factory.kw.get("bind") is not p._engine
            or p._factory.kw.get("binds")
            or p._approval_id is not None
            or op.host_clock is not self._clock
        ):
            raise ValueError("original catalog recovery graph required")

    def _owner(self, binding: str | None = None) -> VerifiedNamedSession:
        self._configuration()
        owner = self._op.establish() if binding is None else self._op.recheck(binding)
        self._configuration()
        if owner.principal.identity != self._identity:
            raise ValueError("current configured catalog owner required")
        return owner

    @staticmethod
    def _access(owner, label):
        if owner.principal.scopes != (BoundaryScope(B.BRAINSTORM, frozenset({label})),):
            raise ValueError("exact current catalog read scope required")

    def _rows(self, ids: tuple[UUID, ...]) -> dict[UUID, dict]:
        columns_to_read = _source_columns()
        if not 1 <= len(ids) <= 3 or len(set(ids)) != len(ids):
            raise ValueError("bounded selected Source ids required")
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
                Source.external_ref,
                Source.excerpt,
                Source.content_hash,
                Source.content_location,
            )
            .where(Source.id.in_(ids), Source.trust_boundary == B.BRAINSTORM)
            .cte("catalog_selected_candidates")
        )
        width = sum(func.octet_length(func.coalesce(c, "")) for c in candidates.c)
        sizes = (
            select(
                func.count().label("n"),
                func.coalesce(func.sum(width), 0).label("total"),
                func.coalesce(func.max(width), 0).label("widest"),
            )
            .select_from(candidates)
            .cte("catalog_selected_sizes")
        )
        with self._p._factory() as session:
            _assert_ledger_isolation(session)
            if session.scalar(text("SELECT current_database()")) != self._p._engine.url.database:
                raise ValueError("catalog session target differs")
            columns = session.scalars(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema='public' AND table_name='source' LIMIT 32"
                )
            ).all()
            if len(columns) != len(_SOURCE_COLUMNS) or set(columns) != _SOURCE_COLUMNS:
                raise ValueError("closed actual Source schema required")
            rows = list(
                session.execute(
                    select(
                        *columns_to_read,
                        func.coalesce(effective, Source.data_classification).label("effective"),
                    )
                    .select_from(Source)
                    .join(sizes, true())
                    .where(
                        Source.id.in_(ids),
                        Source.trust_boundary == B.BRAINSTORM,
                        sizes.c.n == len(ids),
                        sizes.c.total <= 192000,
                        sizes.c.widest <= 64000,
                    )
                    .limit(4)
                ).mappings()
            )
        if len(rows) != len(ids):
            raise ValueError("bounded complete selected metadata required")
        return {row["id"]: dict(row) for row in rows}

    def _tip(self, row):
        with self._p._factory() as session:
            superseded = select(Source.supersedes_source_id).where(
                Source.supersedes_source_id.is_not(None)
            )
            tips = list(
                session.scalars(
                    select(Source.id)
                    .where(
                        Source.system == row["system"],
                        Source.external_ref == row["external_ref"],
                        Source.trust_boundary == B.BRAINSTORM,
                        Source.id.not_in(superseded),
                    )
                    .limit(2)
                )
            )
        if tips != [row["id"]]:
            raise ValueError("unique current catalog tip required")

    def _bytes(self, ref, row, owner):
        self._access(owner, row["effective"])
        if (
            ref.trust_boundary is not B.BRAINSTORM
            or row["trust_boundary"] is not B.BRAINSTORM
            or row["content_hash"] != ref.content_hash
            or row["effective"] is not ref.effective_classification
            or row["data_classification"] is not ref.effective_classification
            or row["excerpt"] is not None
            or row["supersedes_source_id"] is not None
        ):
            raise ValueError("exact selected Source ACL/provenance required")
        self._tip(row)
        raw = self._p._artifacts.get_bounded(
            B.BRAINSTORM, row["content_location"], max_bytes=256000
        )
        if content_hash_of(raw) != ref.content_hash:
            raise ValueError("selected retained bytes differ")
        return raw

    def _selection(self, decision_reference, owner) -> _Selection:
        if (
            type(decision_reference) is not EvidenceReference
            or not decision_reference.source_id.int
            or decision_reference.trust_boundary is not B.BRAINSTORM
            or decision_reference.effective_classification
            not in (C.CONFIDENTIAL, C.HIGHLY_RESTRICTED)
        ):
            raise ValueError("explicit catalog decision reference required")
        self._access(owner, decision_reference.effective_classification)
        first = self._rows((decision_reference.source_id,))[decision_reference.source_id]
        raw = self._bytes(decision_reference, first, owner)
        decision = _CaptureAttestation.model_validate(json.loads(raw, object_pairs_hook=_pairs))
        # Retain original ISO spellings: current core writes aware datetimes via isoformat.
        if canonical_bytes(json.loads(raw, object_pairs_hook=_pairs)) != raw:
            raise ValueError("canonical capture attestation required")
        label = decision.scope.classification
        self._access(owner, label)
        if (
            Identity(decision.owner_issuer, decision.owner_subject) != self._identity
            or first["external_ref"] != f"managed-app-catalog-owner-capture/{decision.request_id}"
            or first["system"] is not SourceSystem.USER_INSTRUCTION
            or first["captured_at"] != decision.observed_at
        ):
            raise ValueError("exact original catalog actor/decision required")
        raw_namespace = decision.scope.raw_namespace()
        companion_namespace = (
            raw_namespace.replace(
                "managed-app-catalog-observation/",
                "managed-app-catalog-observation-companion/",
                1,
            )
            + f"/raw/{decision.raw_digest}"
        )
        namespaces = (raw_namespace, companion_namespace, first["external_ref"])
        digests = (
            decision.raw_digest,
            decision.companion_digest,
            decision_reference.content_hash,
        )
        refs = tuple(
            EvidenceReference(
                source_id=uuid5(_NAMESPACE, n + "/" + d),
                content_hash=d,
                trust_boundary=B.BRAINSTORM,
                effective_classification=label,
            )
            for n, d in zip(namespaces, digests, strict=True)
        )
        if refs[2] != decision_reference:
            raise ValueError("exact deterministic decision Source required")
        rows = self._rows(tuple(r.source_id for r in refs))
        values = []
        for index, (ref, namespace) in enumerate(zip(refs, namespaces, strict=True)):
            row = rows[ref.source_id]
            if (
                row["external_ref"] != namespace
                or row["captured_at"] != decision.observed_at
                or row["system"]
                is not (SourceSystem.MANUAL if index < 2 else SourceSystem.USER_INSTRUCTION)
            ):
                raise ValueError("exact selected catalog lineage required")
            values.append(self._bytes(ref, row, owner))
        if values[2] != raw:
            raise ValueError("decision changed during selected reads")
        preparation = prepare_managed_app_catalog_observation(
            raw=values[0],
            scope=decision.scope,
            requestor_boundaries=frozenset({B.BRAINSTORM}),
            allowed_classifications=frozenset({label}),
        )
        if values[1] != preparation.artifacts[1].original_bytes:
            raise ValueError("exact catalog companion required")
        review = canonical_bytes(
            {
                "format": "zac-managed-catalog-capture-review-v1",
                "request_id": str(decision.request_id),
                "scope": decision.scope.model_dump(mode="json"),
                "artifacts": [
                    {
                        "namespace": a.external_ref,
                        "hash": a.content_hash,
                        "classification": a.classification.value,
                    }
                    for a in preparation.artifacts
                ],
                "expires_at": decision.expires_at.isoformat(),
            }
        )
        if content_hash_of(review) != decision.selection_digest:
            raise ValueError("exact historical selection review required")

        # This scalar preimage includes all Source columns and current effective ACL.
        def scalar(value):
            if isinstance(value, (B, C, SourceSystem)):
                return value.value
            if isinstance(value, UUID):
                return str(value)
            if isinstance(value, datetime):
                return value.isoformat()
            return value

        preimage = canonical_bytes(
            {
                "rows": [
                    {key: scalar(value) for key, value in rows[r.source_id].items()} for r in refs
                ]
            }
        )
        return _Selection(decision, preparation, refs, preimage)

    def _verify(self, receipt, selected):
        p = self._p
        observations = []
        if (
            receipt.references != selected.references
            or receipt.request_id != selected.attestation.request_id
            or receipt.selection_digest != selected.attestation.selection_digest
            or receipt.captured_at != selected.attestation.observed_at
            or not receipt.captured_at <= receipt.verified_at < selected.attestation.expires_at
            or receipt.verified_at > self._clock()
        ):
            raise ValueError("exact dated catalog receipt required")
        for digest in {d for _, d in receipt.historical_source_hashes if d is not None}:
            raw = p._read(backup_object_key_for(B.BRAINSTORM, digest), 8_500_000)
            if content_hash_of(age_decrypt(raw, p._identity)) != digest:
                raise ValueError("historical artifact recovery differs")
            observations.append(
                (backup_object_key_for(B.BRAINSTORM, digest), content_hash_of(raw), 8_500_000)
            )
        recovered = []
        for key, cipher_hash, plain_hash, limit in (
            (
                receipt.state_object,
                receipt.state_ciphertext_hash,
                receipt.state_plaintext_hash,
                65_000_000,
            ),
            (
                receipt.journal_object,
                receipt.journal_ciphertext_hash,
                receipt.journal_plaintext_hash,
                4_100_000,
            ),
        ):
            ciphertext = p._read(key, limit)
            plain = age_decrypt(ciphertext, p._identity)
            if content_hash_of(ciphertext) != cipher_hash or content_hash_of(plain) != plain_hash:
                raise ValueError("exact historical checkpoint bytes required")
            recovered.append(plain)
            observations.append((key, cipher_hash, limit))
        backup._csv_columns("artifact_backup_run", recovered[1])
        runs = [
            row
            for row in csv.DictReader(io.StringIO(recovered[1].decode()))
            if row["id"] == str(receipt.artifact_backup_run_id)
        ]
        if (
            len(runs) != 1
            or runs[0]["trust_boundary"] != B.BRAINSTORM.value
            or runs[0]["status"] != "SUCCEEDED"
        ):
            raise ValueError("exact successful historical backup run required")
        started, finished = (
            datetime.fromisoformat(runs[0][name]) for name in ("started_at", "finished_at")
        )
        if not receipt.captured_at <= started <= finished <= receipt.verified_at:
            raise ValueError("historical backup chronology differs")
        # The separately reviewed generic seam must check the EXACT historical
        # Source union in the restored DB, while current provenance is selected3.
        # An older verifier lacking this keyword fails closed; never omit it.
        p._restoration.verify(
            recovered[0],
            {r.source_id: r.content_hash for r in receipt.references},
            current_selected_sources=p._engine,
            operational_journal=recovered[1],
            expected_historical_source_hashes=dict(receipt.historical_source_hashes),
        )
        return observations

    def _reobserve(self, observations):
        for key, digest, limit in observations:
            if content_hash_of(self._p._read(key, limit)) != digest:
                raise ValueError("historical recovery object changed during verification")

    def reopen(self, *, decision_reference: EvidenceReference) -> ReopenedCatalog:
        result = None
        try:
            with self._lock:
                owner = self._owner()
                binding = owner.binding_digest
                selected = self._selection(decision_reference, owner)
                key = (
                    f"BRAINSTORM/state/managed-app-catalog-{selected.attestation.request_id}"
                    f"/receipt-{decision_reference.content_hash}.age"
                )
                with checkpoint_lease(self._p, self._lock) as require:
                    receipt_cipher = self._p._read(key, _MAX_RECEIPT + 1000)
                    receipt = decode_catalog_receipt(age_decrypt(receipt_cipher, self._p._identity))
                    if receipt.receipt_object != key:
                        raise ValueError("exact catalog receipt key required")
                    observations = self._verify(receipt, selected)
                    self._reobserve(
                        [*observations, (key, content_hash_of(receipt_cipher), _MAX_RECEIPT + 1000)]
                    )
                    require()
                owner = self._owner(binding)
                if self._selection(decision_reference, owner) != selected:
                    raise ValueError("selected catalog changed during recovery")
                # No owner callbacks after final canonical observations.
                now = self._clock()
                self._configuration()
                if not receipt.verified_at <= now < owner.effective_expires_at:
                    raise ValueError("current recovery session window required")
                result = ReopenedCatalog(selected.preparation, selected.references, receipt, now)
        except Exception:  # noqa: BLE001,S110 - cancellation propagates without a result
            pass
        if result is None:
            raise CatalogRecoveryError("catalog recovery unavailable; reconcile custody")
        return result


def publish_catalog_receipt(
    *,
    protector: BrainstormContextualProtector,
    operation: NamedSessionOperation,
    expected_identity: Identity,
    original_binding: str,
    references: tuple[EvidenceReference, EvidenceReference, EvidenceReference],
    request_id: UUID,
    selection_digest: str,
    captured_at: datetime,
    verified_at: datetime,
    full_inventory_utf8: bytes,
    protection: ProtectedState,
) -> CatalogRecoveryReceiptV1:
    """Capture wiring only: original window, cooperating-writer exclusive lease.

    A durable receipt may exist after acknowledgement loss. Reopen can observe
    its custody proof but cannot retry/renew the one-use capture or process data.
    Existing receipt refusal is the controlled writer policy, not an atomic
    create-only primitive against foreign storage writers. See module limits.
    Control-flow cancellation propagates; the capture caller stays terminal.
    """
    result = None
    try:
        gate = CanonicalManagedCatalogRecovery(
            protector=protector,
            operation=operation,
            expected_identity=expected_identity,
        )
        if not callable(protector._lease_guard) or type(protection) is not ProtectedState:
            raise ValueError("existing actual capture checkpoint lease required")
        require = protector._lease_guard
        require()
        owner = gate._owner(original_binding)
        selected = gate._selection(references[2], owner)
        decision = selected.attestation
        if (
            selected.references != references
            or decision.request_id != request_id
            or decision.selection_digest != selection_digest
            or decision.observed_at != captured_at
            or decision.original_session_binding != original_binding
        ):
            raise ValueError("exact original capture publication required")
        receipt = CatalogRecoveryReceiptV1(
            request_id=request_id,
            selection_digest=selection_digest,
            references=references,
            captured_at=captured_at,
            verified_at=verified_at,
            full_source_inventory_digest=content_hash_of(full_inventory_utf8),
            historical_source_hashes=_inventory_hashes(full_inventory_utf8),
            artifact_backup_run_id=protection.artifact_backup_run_id,
            state_ciphertext_hash=protection.state_ciphertext_hash,
            state_plaintext_hash=protection.state_plaintext_hash,
            journal_ciphertext_hash=protection.journal_ciphertext_hash,
            journal_plaintext_hash=protection.journal_plaintext_hash,
        )
        if (
            protection.state_object != receipt.state_object
            or protection.journal_object != receipt.journal_object
        ):
            raise ValueError("exact existing capture checkpoint namespace required")
        if protector._reader.exists(receipt.receipt_object):
            raise ValueError("existing catalog receipt never replaced")
        observations = gate._verify(receipt, selected)
        owner = gate._owner(original_binding)
        if (
            gate._selection(references[2], owner) != selected
            or gate._clock() >= decision.expires_at
        ):
            raise ValueError("original catalog action expired or changed")
        ciphertext = age_encrypt(encode_catalog_receipt(receipt), protector._recipient)
        if not 0 < len(ciphertext) <= _MAX_RECEIPT + 1000:
            raise ValueError("bounded encrypted receipt required")
        require()
        if protector._reader.exists(receipt.receipt_object):
            raise ValueError("existing catalog receipt never replaced")
        owner = gate._owner(original_binding)
        if gate._selection(references[2], owner) != selected or not gate._clock() < min(
            decision.expires_at, owner.effective_expires_at
        ):
            raise ValueError("original catalog action changed before receipt write")
        protector._put(receipt.receipt_object, ciphertext)
        returned = protector._read(receipt.receipt_object, _MAX_RECEIPT + 1000)
        if (
            returned != ciphertext
            or decode_catalog_receipt(age_decrypt(returned, protector._identity)) != receipt
        ):
            raise ValueError("exact encrypted receipt readback required")
        gate._reobserve(observations)
        require()
        owner = gate._owner(original_binding)
        if gate._selection(references[2], owner) != selected:
            raise ValueError("catalog changed before receipt acknowledgement")
        now = gate._clock()
        gate._configuration()
        if not now < min(decision.expires_at, owner.effective_expires_at):
            raise ValueError("original catalog publication window expired")
        result = receipt
    except Exception:  # noqa: BLE001,S110 - cancellation propagates to terminal capture
        pass
    if result is None:
        raise CatalogRecoveryError("catalog receipt publication held; reconcile custody")
    return result
