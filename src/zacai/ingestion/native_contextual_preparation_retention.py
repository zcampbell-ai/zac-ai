"""Canonical native preparation integrity only, never human or model permission.

Caller owns access, first-insertion serialization and commit, and must roll back
the outer transaction after any hold (a flushed row can remain pending). Artifact callbacks
are trusted and transaction changes hold. MANUAL metadata is not an instruction.
No account, model, recovery, consent or active processing is invoked here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from zacai.contextual_authorization import prepared_native_contextual_digest
from zacai.ingestion.artifact_store import ArtifactStore, canonical_bytes, content_hash_of
from zacai.ingestion.native_proposal_retention import (
    _clean,
    _get,
    _put,
    _rows,
    _time,
    _valid,
    load_retained_native_proposal,
)
from zacai.intelligence import native_contextual_assembly as assembly
from zacai.intelligence.contextual_generation import (
    ContextualRequestV2,
    decode_native_contextual_request,
    encode_native_contextual_request,
    prepare_native_contextual_request,
)
from zacai.intelligence.contextual_host import (
    assemble_contextual_context,
    contextual_request_digest,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.native_context_metadata import NativeEvidenceSpan
from zacai.intelligence.native_evidence_context import append_native_evidence_context
from zacai.intelligence.project_review_context import ReviewedProjectEvidence
from zacai.intelligence.review_context import MeetingEvidence
from zacai.intelligence.review_freshness import review_evidence_digest
from zacai.intelligence.review_host import ReviewSelection
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation
from zacai.state import SourceSystem
from zacai.state_repository import record_source

MAX_BINDING_BYTES = 512_000


class NativePreparationRetentionError(ValueError):
    """Fixed private-safe hold, with no chained private validation details."""


@dataclass(frozen=True, repr=False)
class RetainedNativeContextualPreparation:
    reference: EvidenceReference
    request: ContextualRequestV2
    selection: assembly.NativeContextualSelection
    binding_bytes: bytes
    captured_at: datetime
    dependency_reference: EvidenceReference
    dependency_bytes: bytes
    own_source_fingerprints: tuple[tuple[UUID, str], ...]
    processing_authorized: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)
    facts_confirmed: Literal[False] = field(default=False, init=False)


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate binding key")
        result[key] = value
    return result


def _decode(
    raw: bytes,
) -> tuple[assembly.NativeContextualSelection, ContextualRequestV2, dict[str, object]]:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BINDING_BYTES:
        raise ValueError("bounded binding bytes")
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")),
    )
    if (
        type(value) is not dict
        or set(value)
        != {
            "format",
            "selection",
            "original_task",
            "request",
            "request_digest",
            "prepared_digest",
            "hashes",
            "source_fingerprints",
            "relationship_fingerprint",
        }
        or value["format"] != "zac-native-contextual-assembly-binding-v2"
        or canonical_bytes(value) != raw
    ):
        raise ValueError("closed canonical binding")
    selection = assembly.NativeContextualSelection.model_validate(value["selection"])
    request = decode_native_contextual_request(canonical_bytes(value["request"]))
    if (
        canonical_bytes(value["original_task"]).decode() != request.original_task_json
        or contextual_request_digest(request) != value["request_digest"]
        or prepared_native_contextual_digest(request) != value["prepared_digest"]
        or selection.batch_reference != request.batch_reference
        or selection.intake_instruction_reference != request.approval_reference
        or selection.proposal_reference != request.proposal_reference
        or tuple((item.source_id, item.field, item.spans[0]) for item in selection.native)
        != tuple(
            (entry.reference.source_id, entry.field, entry.source_span)
            for entry in request.sidecar.entries
        )
    ):
        raise ValueError("exact original task/request/selection roles")
    hashes = _pairs(value["hashes"])
    fingerprints = _pairs(value["source_fingerprints"])
    if hashes != {
        ref.source_id: ref.content_hash for ref in request.context.task.event.provenance
    } or set(fingerprints) != set(hashes):
        raise ValueError("complete exact canonical union")
    _digest(value["relationship_fingerprint"])
    return selection, request, value


def _digest(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise ValueError("exact digest")
    return value


def _pairs(value: object) -> dict[UUID, str]:
    if type(value) is not list or not 1 <= len(value) <= assembly.MAX_REFERENCES:
        raise ValueError("bounded exact union")
    result = {}
    for item in value:
        if type(item) is not list or len(item) != 2 or type(item[0]) is not str:
            raise ValueError("exact union pair")
        sid = UUID(item[0])
        if str(sid) != item[0] or sid in result:
            raise ValueError("distinct canonical UUID")
        result[sid] = _digest(item[1])
    return result


class _CurrentPreparationStore:
    """Exact selected current rights/fingerprints before every private read."""

    def __init__(
        self,
        session: Session,
        artifacts: ArtifactStore,
        refs: tuple[EvidenceReference, ...],
        fingerprints: dict[UUID, str],
        now: datetime,
        outer: object,
        nested: object,
    ):
        self.session, self.artifacts = session, artifacts
        self.refs, self.fingerprints, self.now = refs, fingerprints, now
        self.outer, self.nested = outer, nested

    def _check(self) -> None:
        session = self.session
        if (
            session.get_transaction() is not self.outer
            or not getattr(self.outer, "is_active", False)
            or session.get_nested_transaction() is not self.nested
            or (self.nested is not None and not getattr(self.nested, "is_active", False))
        ):
            raise ValueError("private read transaction changed")
        _clean(session)
        if assembly._rows(session, self.refs, self.now) != self.fingerprints:
            raise ValueError("selected current data changed before private read")

    def get(self, trust_boundary: B, content_location: str) -> bytes:
        from sqlalchemy import select

        from zacai.state import Source

        self._check()
        if trust_boundary is not B.BRAINSTORM or type(content_location) is not str:
            raise ValueError("fixed selected read scope")
        with self.session.no_autoflush:
            locations = set(
                self.session.scalars(
                    select(Source.content_location).where(
                        Source.id.in_(tuple(ref.source_id for ref in self.refs))
                    )
                )
            )
        if content_location not in locations:
            raise ValueError("unselected private location")
        raw = self.artifacts.get(trust_boundary, content_location)
        self._check()
        return raw

    def put(self, trust_boundary: B, content_hash: str, raw_bytes: bytes) -> str:
        raise ValueError("read-only native preparation proof")


def _recheck(
    session: Session,
    factory: sessionmaker[Session],
    artifacts: ArtifactStore,
    selection: assembly.NativeContextualSelection,
    request: ContextualRequestV2,
    value: dict[str, object],
    now: datetime,
) -> None:
    if factory.kw.get("bind") is not session.get_bind():
        raise ValueError("same actual canonical engine")
    refs = request.context.task.event.provenance
    fingerprints = _pairs(value["source_fingerprints"])
    if (
        assembly._rows(session, refs, now) != fingerprints
        or assembly._base_relationships(session, selection) != value["relationship_fingerprint"]
    ):
        raise ValueError("current canonical source/relationship changed")
    outer, nested = session.get_transaction(), session.get_nested_transaction()
    if outer is None or not outer.is_active:
        raise ValueError("live canonical transaction")
    scoped = _CurrentPreparationStore(session, artifacts, refs, fingerprints, now, outer, nested)
    original = request.context.task.model_validate_json(request.original_task_json)
    context = ReviewContext(
        original,
        request.context.meeting_source_id,
        frozenset(
            item.reference.source_id
            for item in original.context
            if item.reference.source_id != request.context.meeting_source_id
        ),
    )
    proposal = load_retained_native_proposal(
        session,
        artifacts=scoped,
        proposal_reference=selection.proposal_reference,
        batch_id=selection.batch_id,
        expected_proposal_hash=selection.approved_proposal_hash,
        as_of=now,
    )
    projection = append_native_evidence_context(
        session,
        artifacts=scoped,
        context=context,
        proposal_reference=selection.proposal_reference,
        batch_reference=selection.batch_reference,
        approval_reference=selection.intake_instruction_reference,
        approved_proposal_raw=proposal,
        selections=selection.native,
        authorized_boundaries=frozenset({B.BRAINSTORM}),
        allowed_classifications=frozenset({C.CONFIDENTIAL}),
        observed_at=request.context.task.event.observed_at,
    )
    if encode_native_contextual_request(
        prepare_native_contextual_request(projection)
    ) != encode_native_contextual_request(request):
        raise ValueError("immutable reconstructed request changed")
    current_base = assemble_contextual_context(
        factory,
        artifacts=scoped,
        selection=selection.base_selection(),
        authorized_boundaries=frozenset({B.BRAINSTORM}),
        allowed_classifications=frozenset({C.CONFIDENTIAL}),
        now=original.event.observed_at,
        max_output_tokens=original.max_output_tokens,
    )
    if review_evidence_digest(current_base) != review_evidence_digest(context):
        raise ValueError("original base evidence changed")
    _clean(session)
    if (
        session.get_transaction() is not outer
        or not outer.is_active
        or session.get_nested_transaction() is not nested
        or (nested is not None and not nested.is_active)
    ):
        raise ValueError("callback changed canonical transaction")
    # Callback-free live relationship and complete Source observations after reads.
    if (
        assembly._base_relationships(session, selection) != value["relationship_fingerprint"]
        or assembly._rows(session, refs, now) != fingerprints
    ):
        raise ValueError("final canonical binding changed")


def _external(request: ContextualRequestV2) -> str:
    return "native-contextual-preparation/" + str(request.context.task.task_id)


def _retain_body(
    session: Session,
    *,
    factory: sessionmaker[Session],
    artifacts: ArtifactStore,
    preparation: assembly.NativeContextualPreparation,
    retained_at: datetime,
) -> EvidenceReference:
    """Uncommitted integrity reference. Serialize first insert; roll back on hold."""
    result = None
    try:
        _clean(session)
        _assert_ledger_isolation(session)
        now = _time(retained_at)
        if type(preparation) is not assembly.NativeContextualPreparation:
            raise ValueError("exact preparation")
        selection, request, value = _decode(preparation.binding_bytes)
        if (
            selection != preparation.selection
            or request != preparation.request
            or _pairs(value["hashes"]) != dict(preparation.hashes)
            or _pairs(value["source_fingerprints"]) != dict(preparation.source_fingerprints)
            or value["relationship_fingerprint"] != preparation.relationship_fingerprint
            or now < request.context.task.event.observed_at
        ):
            raise ValueError("immutable original preparation")
        _recheck(session, factory, artifacts, selection, request, value, now)
        raw = preparation.binding_bytes
        digest = content_hash_of(raw)
        external = _external(request)
        prior = _rows(session, external)
        if len(prior) > 1:
            raise ValueError("ambiguous preparation")
        location = None
        if prior:
            _valid(prior[0], digest, now)
            if _get(session, artifacts, prior[0]["content_location"]) != raw:
                raise ValueError("original retained bytes changed")
        else:
            location = _put(session, artifacts, digest, raw)
            if (
                type(location) is not str
                or not 0 < len(location) <= 2048
                or _get(session, artifacts, location) != raw
            ):
                raise ValueError("artifact roundtrip")
        _recheck(session, factory, artifacts, selection, request, value, now)
        with session.begin_nested():
            if _rows(session, external) != prior:
                raise ValueError("preparation changed before write")
            if not prior:
                if location is None:
                    raise ValueError("missing artifact location")
                record_source(
                    session,
                    trust_boundary=B.BRAINSTORM,
                    data_classification=C.CONFIDENTIAL,
                    system=SourceSystem.MANUAL,
                    content_hash=digest,
                    content_location=location,
                    external_ref=external,
                    captured_at=now,
                )
                session.flush()
            rows = _rows(session, external)
            if len(rows) != 1:
                raise ValueError("one canonical preparation")
            _valid(rows[0], digest, now)
            reference = EvidenceReference(
                source_id=rows[0]["id"],
                content_hash=digest,
                trust_boundary=B.BRAINSTORM,
                effective_classification=C.CONFIDENTIAL,
            )
        result = reference
    except Exception:  # noqa: BLE001,S110 - sanitize outside private handler
        pass
    if result is None:
        raise NativePreparationRetentionError("native preparation retention held")
    return result


def _load_body(
    session: Session,
    *,
    factory: sessionmaker[Session],
    artifacts: ArtifactStore,
    reference: EvidenceReference,
    as_of: datetime,
    dependency_reference: EvidenceReference,
    dependency_bytes: bytes,
    own_source_fingerprints: tuple[tuple[UUID, str], ...],
) -> RetainedNativeContextualPreparation:
    """Current data revalidation only. Never repair, refresh IDs or grant inference."""
    result = None
    try:
        _clean(session)
        _assert_ledger_isolation(session)
        now = _time(as_of)
        if (
            type(reference) is not EvidenceReference
            or reference.trust_boundary is not B.BRAINSTORM
            or reference.effective_classification is not C.CONFIDENTIAL
        ):
            raise ValueError("exact current data reference")
        from sqlalchemy import select

        from zacai.state import Source

        with session.no_autoflush:
            external = session.execute(
                select(Source.external_ref).where(Source.id == reference.source_id)
            ).scalar_one()
        if type(external) is not str or not external.startswith("native-contextual-preparation/"):
            raise ValueError("exact preparation namespace")
        rows = _rows(session, external)
        if len(rows) != 1 or rows[0]["id"] != reference.source_id:
            raise ValueError("exact canonical preparation")
        row = rows[0]
        _valid(row, reference.content_hash, now)
        raw = _get(session, artifacts, row["content_location"])
        if content_hash_of(raw) != reference.content_hash:
            raise ValueError("exact retained hash")
        selection, request, value = _decode(raw)
        if (
            _external(request) != external
            or _time(row["captured_at"]) < request.context.task.event.observed_at
        ):
            raise ValueError("original retention chronology")
        _recheck(session, factory, artifacts, selection, request, value, now)
        if _rows(session, external) != rows:
            raise ValueError("final preparation changed")
        result = RetainedNativeContextualPreparation(
            reference,
            request,
            selection,
            raw,
            _time(row["captured_at"]),
            dependency_reference,
            dependency_bytes,
            own_source_fingerprints,
        )
    except Exception:  # noqa: BLE001,S110 - sanitize outside private handler
        pass
    if result is None:
        raise NativePreparationRetentionError("native preparation retention held")
    return result


@dataclass(frozen=True, repr=False)
class PairedNativePreparationReferences:
    """Canonical body plus dependency-only header; neither grants permission."""

    body_reference: EvidenceReference
    dependency_reference: EvidenceReference

    def __post_init__(self) -> None:
        for reference in (self.body_reference, self.dependency_reference):
            if (
                type(reference) is not EvidenceReference
                or EvidenceReference.model_validate(reference) != reference
                or reference.trust_boundary is not B.BRAINSTORM
                or reference.effective_classification is not C.CONFIDENTIAL
            ):
                raise ValueError("exact fixed own references")
        if self.body_reference.source_id == self.dependency_reference.source_id:
            raise ValueError("distinct own references")


def _header_external(task_id: UUID) -> str:
    return "native-contextual-preparation-dependencies/" + str(task_id)


def _header_selection(selection: assembly.NativeContextualSelection) -> dict[str, object]:
    metadata = selection.model_dump(mode="json")
    metadata["native"] = [
        {key: value for key, value in item.items() if key != "relevance_reason"}
        for item in metadata["native"]
    ]
    return metadata


def _canonical_uuid(value: object) -> UUID:
    if type(value) is not str:
        raise ValueError("exact UUID string")
    result = UUID(value)
    if str(result) != value:
        raise ValueError("canonical UUID")
    return result


def _decode_header_selection(value: object) -> ReviewSelection:
    if (
        type(value) is not dict
        or set(value)
        != {
            "format",
            "selected",
            "earlier",
            "projects",
            "batch_id",
            "batch_reference",
            "intake_instruction_reference",
            "proposal_reference",
            "approved_proposal_hash",
            "native",
        }
        or value["format"] != "zac-native-contextual-selection-v1"
    ):
        raise ValueError("closed non-plaintext selection metadata")

    def meeting(item: object) -> MeetingEvidence:
        if type(item) is not dict or set(item) != {"meeting_id", "source_id"}:
            raise ValueError("exact meeting metadata")
        return MeetingEvidence(
            _canonical_uuid(item["meeting_id"]), _canonical_uuid(item["source_id"])
        )

    def project(item: object) -> ReviewedProjectEvidence:
        if type(item) is not dict or set(item) != {"association_id", "source_id"}:
            raise ValueError("exact project metadata")
        return ReviewedProjectEvidence(
            _canonical_uuid(item["association_id"]), _canonical_uuid(item["source_id"])
        )

    if (
        type(value["earlier"]) is not list
        or len(value["earlier"]) > 7
        or type(value["projects"]) is not list
        or len(value["projects"]) > 3
        or type(value["native"]) is not list
        or not 1 <= len(value["native"]) <= 4
    ):
        raise ValueError("bounded metadata selectors")
    base = ReviewSelection(
        meeting(value["selected"]),
        tuple(meeting(item) for item in value["earlier"]),
        tuple(project(item) for item in value["projects"]),
    )
    _canonical_uuid(value["batch_id"])
    controls = tuple(
        EvidenceReference.model_validate(value[key])
        for key in ("batch_reference", "intake_instruction_reference", "proposal_reference")
    )
    if controls[2].content_hash != _digest(value["approved_proposal_hash"]) or any(
        ref.trust_boundary is not B.BRAINSTORM or ref.effective_classification is not C.CONFIDENTIAL
        for ref in controls
    ):
        raise ValueError("exact fixed control metadata")
    native_ids = []
    for item in value["native"]:
        if type(item) is not dict or set(item) != {
            "source_id",
            "content_hash",
            "field",
            "field_text_hash",
            "spans",
        }:
            raise ValueError("closed native metadata, no relevance prose")
        native_ids.append(_canonical_uuid(item["source_id"]))
        _digest(item["content_hash"])
        _digest(item["field_text_hash"])
        if (
            item["field"] not in {"text", "rfc822_utf8"}
            or type(item["spans"]) is not list
            or len(item["spans"]) != 1
        ):
            raise ValueError("exact field/span selector")
        NativeEvidenceSpan.model_validate(item["spans"][0])
    all_ids = (
        [item.source_id for item in (base.selected, *base.earlier)]
        + [item.source_id for item in base.projects]
        + [ref.source_id for ref in controls]
        + native_ids
    )
    if (
        len(set(all_ids)) != len(all_ids)
        or len({item.meeting_id for item in (base.selected, *base.earlier)})
        != len(base.earlier) + 1
    ):
        raise ValueError("distinct closed metadata roles")
    return base


def _header_bytes(
    body_reference: EvidenceReference,
    selection: assembly.NativeContextualSelection,
    request: ContextualRequestV2,
    value: dict[str, object],
) -> bytes:
    return canonical_bytes(
        {
            "format": "zac-native-contextual-preparation-dependencies-v2",
            "task_id": str(request.context.task.task_id),
            "body_reference": body_reference.model_dump(mode="json"),
            "selection": _header_selection(selection),
            "dependencies": [
                ref.model_dump(mode="json") for ref in request.context.task.event.provenance
            ],
            "source_fingerprints": value["source_fingerprints"],
            "relationship_fingerprint": value["relationship_fingerprint"],
            "original_observed_at": _time(request.context.task.event.observed_at).isoformat(),
        }
    )


def _decode_header(
    raw: bytes,
) -> tuple[
    UUID,
    EvidenceReference,
    ReviewSelection,
    tuple[EvidenceReference, ...],
    dict[UUID, str],
    str,
    datetime,
]:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BINDING_BYTES:
        raise ValueError("bounded dependency header")
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")),
    )
    if (
        type(value) is not dict
        or set(value)
        != {
            "format",
            "task_id",
            "body_reference",
            "selection",
            "dependencies",
            "source_fingerprints",
            "relationship_fingerprint",
            "original_observed_at",
        }
        or value["format"] != "zac-native-contextual-preparation-dependencies-v2"
        or canonical_bytes(value) != raw
        or type(value["task_id"]) is not str
        or type(value["dependencies"]) is not list
        or type(value["original_observed_at"]) is not str
    ):
        raise ValueError("closed canonical dependency header")
    task_id = UUID(value["task_id"])
    if str(task_id) != value["task_id"]:
        raise ValueError("canonical task UUID")
    body = EvidenceReference.model_validate(value["body_reference"])
    selection = _decode_header_selection(value["selection"])
    refs = tuple(EvidenceReference.model_validate(item) for item in value["dependencies"])
    fingerprints = _pairs(value["source_fingerprints"])
    if (
        not 1 <= len(refs) <= assembly.MAX_REFERENCES - 2
        or len({ref.source_id for ref in refs}) != len(refs)
        or set(fingerprints) != {ref.source_id for ref in refs}
        or body.source_id in fingerprints
        or any(
            ref.trust_boundary is not B.BRAINSTORM
            or ref.effective_classification is not C.CONFIDENTIAL
            for ref in (*refs, body)
        )
    ):
        raise ValueError("complete bounded fixed dependency union")
    observed = _time(datetime.fromisoformat(value["original_observed_at"]))
    if observed.isoformat() != value["original_observed_at"]:
        raise ValueError("canonical original time")
    return (
        task_id,
        body,
        selection,
        refs,
        fingerprints,
        _digest(value["relationship_fingerprint"]),
        observed,
    )


class _SelectedReadGuard:
    """Fresh selected dependency rights/relationships around artifact callbacks.

    Own pair rows have separate public loader before-body and final scalar checks."""

    def __init__(
        self,
        session: Session,
        artifacts: ArtifactStore,
        refs: tuple[EvidenceReference, ...],
        fingerprints: dict[UUID, str],
        selection: assembly.NativeContextualSelection | ReviewSelection,
        relationship: str,
        now: datetime,
    ):
        self.session, self.artifacts = session, artifacts
        self.refs, self.fingerprints = refs, fingerprints
        self.selection, self.relationship, self.now = selection, relationship, now
        self.outer, self.nested = session.get_transaction(), session.get_nested_transaction()

    def _check(self) -> None:
        _clean(self.session)
        if (
            self.outer is None
            or not self.outer.is_active
            or self.session.get_transaction() is not self.outer
            or self.session.get_nested_transaction() is not self.nested
            or (self.nested is not None and not self.nested.is_active)
            or assembly._rows(self.session, self.refs, self.now) != self.fingerprints
            or assembly._base_relationships(self.session, self.selection) != self.relationship
        ):
            raise ValueError("current dependency read gate held")

    def get(self, trust_boundary: B, content_location: str) -> bytes:
        self._check()
        if trust_boundary is not B.BRAINSTORM:
            raise ValueError("fixed dependency boundary")
        raw = self.artifacts.get(trust_boundary, content_location)
        self._check()
        return raw

    def put(self, trust_boundary: B, content_hash: str, raw_bytes: bytes) -> str:
        self._check()
        if trust_boundary is not B.BRAINSTORM:
            raise ValueError("fixed dependency boundary")
        location = self.artifacts.put(trust_boundary, content_hash, raw_bytes)
        self._check()
        return location


def retain_native_contextual_preparation(
    session: Session,
    *,
    factory: sessionmaker[Session],
    artifacts: ArtifactStore,
    preparation: assembly.NativeContextualPreparation,
    retained_at: datetime,
) -> PairedNativePreparationReferences:
    """Atomically retain paired metadata/body rows, caller commits or rolls back.

    Existing unpaired bodies are held, never automatically upgraded or repaired.
    First-insert host serialization remains required. Orphan artifacts may remain.
    """
    result = None
    try:
        _clean(session)
        _assert_ledger_isolation(session)
        now = _time(retained_at)
        if type(preparation) is not assembly.NativeContextualPreparation:
            raise ValueError("exact preparation")
        selection, request, value = _decode(preparation.binding_bytes)
        refs = request.context.task.event.provenance
        if len(refs) + 2 > assembly.MAX_REFERENCES:
            raise ValueError("complete paired union capacity")
        fingerprints = _pairs(value["source_fingerprints"])
        # _retain_body runs both complete reconstruction checks under the
        # relationship-aware guard below, before any body write/read. No raw
        # redundant prerequisite traversal precedes that guarded pair boundary.
        external = _header_external(request.context.task.task_id)
        before = _rows(session, external)
        body_before = _rows(session, _external(request))
        if bool(before) != bool(body_before) or len(before) > 1 or len(body_before) > 1:
            raise ValueError("exact existing complete pair required")
        # All own row metadata is checked before private replay bytes.
        if before:
            _valid(before[0], before[0]["content_hash"], now)
            _valid(body_before[0], content_hash_of(preparation.binding_bytes), now)
        with session.begin_nested():
            guard = _SelectedReadGuard(
                session,
                artifacts,
                refs,
                fingerprints,
                selection,
                str(value["relationship_fingerprint"]),
                now,
            )
            body = _retain_body(
                session, factory=factory, artifacts=guard, preparation=preparation, retained_at=now
            )
            raw = _header_bytes(body, selection, request, value)
            _decode_header(raw)
            digest = content_hash_of(raw)
            if before:
                _valid(before[0], digest, now)
                if _get(session, guard, before[0]["content_location"]) != raw:
                    raise ValueError("exact original header bytes")
            else:
                location = _put(session, guard, digest, raw)
                if _get(session, guard, location) != raw:
                    raise ValueError("header artifact roundtrip")
                record_source(
                    session,
                    trust_boundary=B.BRAINSTORM,
                    data_classification=C.CONFIDENTIAL,
                    system=SourceSystem.MANUAL,
                    content_hash=digest,
                    content_location=location,
                    external_ref=external,
                    captured_at=now,
                )
                session.flush()
            header_rows = _rows(session, external)
            body_rows = _rows(session, _external(request))
            if (
                len(header_rows) != 1
                or len(body_rows) != 1
                or body_rows[0]["id"] != body.source_id
                or _time(header_rows[0]["captured_at"]) != _time(body_rows[0]["captured_at"])
            ):
                raise ValueError("complete same-capture pair")
            _valid(header_rows[0], digest, now)
            _valid(body_rows[0], body.content_hash, now)
            guard._check()
            pair = PairedNativePreparationReferences(
                body,
                EvidenceReference(
                    source_id=header_rows[0]["id"],
                    content_hash=digest,
                    trust_boundary=B.BRAINSTORM,
                    effective_classification=C.CONFIDENTIAL,
                ),
            )
        result = pair
    except Exception:  # noqa: BLE001,S110 - fixed public hold outside handler
        pass
    if result is None:
        raise NativePreparationRetentionError("native preparation retention held")
    return result


def load_retained_native_contextual_preparation(
    session: Session,
    *,
    factory: sessionmaker[Session],
    artifacts: ArtifactStore,
    reference: PairedNativePreparationReferences,
    as_of: datetime,
) -> RetainedNativeContextualPreparation:
    """Read header/current complete rights before opening the text-bearing body."""
    result = None
    try:
        _clean(session)
        _assert_ledger_isolation(session)
        session.connection()  # Establish caller transaction before any artifact callback.
        entry_outer, entry_nested = session.get_transaction(), session.get_nested_transaction()
        if entry_outer is None or not entry_outer.is_active:
            raise ValueError("live caller entry transaction")
        now = _time(as_of)
        if type(reference) is not PairedNativePreparationReferences:
            raise ValueError("exact paired preparation references required")
        PairedNativePreparationReferences(reference.body_reference, reference.dependency_reference)
        from sqlalchemy import select

        from zacai.state import Source

        with session.no_autoflush:
            body_external = session.scalar(
                select(Source.external_ref).where(Source.id == reference.body_reference.source_id)
            )
        if type(body_external) is not str or not body_external.startswith(
            "native-contextual-preparation/"
        ):
            raise ValueError("exact own body namespace")
        initial_body_rows = _rows(session, body_external)
        if (
            len(initial_body_rows) != 1
            or initial_body_rows[0]["id"] != reference.body_reference.source_id
        ):
            raise ValueError("exact initial body row")
        _valid(initial_body_rows[0], reference.body_reference.content_hash, now)
        with session.no_autoflush:
            header_external = session.scalar(
                select(Source.external_ref).where(
                    Source.id == reference.dependency_reference.source_id
                )
            )
        if type(header_external) is not str or not header_external.startswith(
            "native-contextual-preparation-dependencies/"
        ):
            raise ValueError("exact header namespace")
        header_rows = _rows(session, header_external)
        if (
            len(header_rows) != 1
            or header_rows[0]["id"] != reference.dependency_reference.source_id
        ):
            raise ValueError("exact canonical header")
        _valid(header_rows[0], reference.dependency_reference.content_hash, now)
        raw = _get(session, artifacts, header_rows[0]["content_location"])
        if content_hash_of(raw) != reference.dependency_reference.content_hash:
            raise ValueError("exact header artifact hash")
        task_id, body, selection, refs, fingerprints, relationship, observed = _decode_header(raw)
        if (
            body != reference.body_reference
            or header_external != _header_external(task_id)
            or reference.dependency_reference.source_id in fingerprints
            or _time(header_rows[0]["captured_at"]) < observed
            or body_external != "native-contextual-preparation/" + str(task_id)
        ):
            raise ValueError("exact paired role/chronology")
        body_rows = _rows(session, "native-contextual-preparation/" + str(task_id))
        if len(body_rows) != 1 or body_rows[0]["id"] != body.source_id:
            raise ValueError("exact same-task body")
        _valid(body_rows[0], body.content_hash, now)
        if _time(body_rows[0]["captured_at"]) != _time(header_rows[0]["captured_at"]):
            raise ValueError("same original pair capture")
        guard = _SelectedReadGuard(
            session, artifacts, refs, fingerprints, selection, relationship, now
        )
        guard._check()
        # Own rows and complete selected rights checked immediately before private body.
        if _rows(session, header_external) != header_rows:
            raise ValueError("header changed after callback")
        saved = _load_body(
            session,
            factory=factory,
            artifacts=guard,
            reference=body,
            as_of=now,
            dependency_reference=reference.dependency_reference,
            dependency_bytes=raw,
            own_source_fingerprints=(
                (body.source_id, assembly._fingerprint(body_rows[0])),
                (reference.dependency_reference.source_id, assembly._fingerprint(header_rows[0])),
            ),
        )
        full_selection, request, value = _decode(saved.binding_bytes)
        if raw != _header_bytes(body, full_selection, request, value):
            raise ValueError("exact body/header dependent bytes")
        guard._check()
        if (
            _rows(session, header_external) != header_rows
            or _rows(session, "native-contextual-preparation/" + str(task_id)) != body_rows
        ):
            raise ValueError("final own pair rows changed")
        if (
            session.get_transaction() is not entry_outer
            or not entry_outer.is_active
            or session.get_nested_transaction() is not entry_nested
            or (entry_nested is not None and not entry_nested.is_active)
        ):
            raise ValueError("caller transaction changed across header/body load")
        result = saved
    except Exception:  # noqa: BLE001,S110 - fixed public hold outside handler
        pass
    if result is None:
        raise NativePreparationRetentionError("native preparation retention held")
    return result
