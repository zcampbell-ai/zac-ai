"""Explicit canonical packet capture/load; no enabled runtime or approval issuer.

Hosts authenticate callers and commit before invoking recovery protection. Packet
Sources join the existing artifact inventory. Capture alone proves no backup,
freshness, semantic quality or permission to dispatch. Orphans on rollback follow
the existing artifact-store policy; no automatic cleanup occurs.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.intelligence.contextual_evaluation import ContextualPacket, decode_contextual_packet
from zacai.intelligence.contracts import classification_covers
from zacai.policy import (
    AccessRequest,
    DataClassification,
    Destination,
    TrustBoundary,
    evaluate_access,
)
from zacai.state import SourceSystem
from zacai.state_repository import get_effective_source_classification, get_source, record_source


def _access(
    boundary: TrustBoundary,
    label: DataClassification,
    boundaries: frozenset[TrustBoundary],
    labels: frozenset[DataClassification],
) -> None:
    if (
        label not in labels
        or not evaluate_access(
            AccessRequest(
                data_boundary=boundary,
                data_classification=label,
                requestor_boundaries=boundaries,
                destination=Destination.LOCAL,
            )
        ).allowed
    ):
        raise ValueError("packet access denied")


def capture_contextual_packet(
    session: Session,
    *,
    artifacts: ArtifactStore,
    payload: bytes,
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
) -> UUID:
    """Register exact bytes, verifying canonical evidence metadata first.

    Does not commit or call models/backups. The host must separately refresh
    entity/project/meeting relationships and record truthful run provenance.
    """
    try:
        if session.new or session.dirty or session.deleted:
            raise ValueError("unrelated pending writes")
        packet = decode_contextual_packet(payload)
        boundary = packet.task.event.trust_boundary
        label = packet.review.data_classification
        _access(boundary, label, authorized_boundaries, allowed_classifications)
        for item in packet.task.context:
            ref = item.reference
            _access(
                ref.trust_boundary,
                ref.effective_classification,
                authorized_boundaries,
                allowed_classifications,
            )
            if not classification_covers(label, ref.effective_classification):
                raise ValueError("packet weaker than evidence")
            source = get_source(
                session, source_id=ref.source_id, requestor_boundaries=authorized_boundaries
            )
            if (
                source is None
                or source.trust_boundary != boundary
                or ref.trust_boundary != boundary
                or source.content_hash != ref.content_hash
                or get_effective_source_classification(session, source_id=source.id)
                != ref.effective_classification
            ):
                raise ValueError("canonical evidence mismatch")
        digest = content_hash_of(payload)
        with session.begin_nested():
            location = artifacts.put(boundary, digest, payload)
            if artifacts.get(boundary, location) != payload:
                raise ValueError("packet write integrity mismatch")
            source, _ = record_source(
                session,
                trust_boundary=boundary,
                data_classification=label,
                system=SourceSystem.MANUAL,
                external_ref=f"contextual-review-packet/{digest}",
                content_hash=digest,
                content_location=location,
                captured_at=packet.created_at,
            )
            if (
                source.content_location != location
                or source.data_classification != label
                or source.content_hash != digest
                or source.trust_boundary != boundary
                or source.system != SourceSystem.MANUAL
                or source.external_ref != f"contextual-review-packet/{digest}"
                or get_effective_source_classification(session, source_id=source.id) != label
            ):
                raise ValueError("packet source mismatch")
            return source.id
    except Exception:  # noqa: BLE001, S110 - private metadata/backend diagnostics
        pass
    raise ValueError("contextual packet capture unavailable or mismatched")


def load_contextual_packet(
    session: Session,
    *,
    artifacts: ArtifactStore,
    source_id: UUID,
    expected_digest: str,
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
) -> ContextualPacket:
    """Check canonical ACL/classification before artifact I/O, then exact bytes.

    Caller owns the independently retained expected digest. Loading is not proof
    of encrypted recovery and does not restore source permissions or freshness.
    """
    try:
        if session.new or session.dirty or session.deleted:
            raise ValueError("unrelated pending writes")
        source = get_source(
            session, source_id=source_id, requestor_boundaries=authorized_boundaries
        )
        if (
            source is None
            or source.system != SourceSystem.MANUAL
            or source.content_hash != expected_digest
            or source.external_ref != f"contextual-review-packet/{expected_digest}"
            or not source.content_location
        ):
            raise ValueError("packet source mismatch")
        label = get_effective_source_classification(session, source_id=source.id)
        _access(source.trust_boundary, label, authorized_boundaries, allowed_classifications)
        raw = artifacts.get(source.trust_boundary, source.content_location)
        if content_hash_of(raw) != expected_digest:
            raise ValueError("packet read integrity mismatch")
        packet = decode_contextual_packet(raw)
        if (
            packet.task.event.trust_boundary != source.trust_boundary
            or packet.review.data_classification != label
        ):
            raise ValueError("packet label mismatch")
        # Recheck all contributing source labels before returning copied evidence.
        for item in packet.task.context:
            ref = item.reference
            _access(
                ref.trust_boundary,
                ref.effective_classification,
                authorized_boundaries,
                allowed_classifications,
            )
            if not classification_covers(label, ref.effective_classification):
                raise ValueError("packet weaker than evidence")
            evidence = get_source(
                session, source_id=ref.source_id, requestor_boundaries=authorized_boundaries
            )
            if (
                evidence is None
                or evidence.trust_boundary != source.trust_boundary
                or evidence.content_hash != ref.content_hash
                or get_effective_source_classification(session, source_id=ref.source_id)
                != ref.effective_classification
            ):
                raise ValueError("copied evidence changed")
        return packet
    except Exception:  # noqa: BLE001, S110 - no private diagnostics in error chains
        pass
    raise ValueError("contextual packet load unavailable or mismatched")

# Explicit fragment family only. Expected provenance is a trusted locator set,
# never permission, source authentication, recovery or a reviewer assessment.
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import SessionTransaction, aliased

from zacai.claude_historical_fragment import ClaudeHistoricalFragmentProfileV1
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.history_contextual_codec import MAX_PACKET_BYTES
from zacai.intelligence.history_fragment_contextual_codec import (
    HistoryFragmentContextualPacketV1,
    HistoryFragmentContextualRequestV1,
    decode_history_fragment_contextual_packet,
    encode_history_fragment_contextual_request,
)
from zacai.review_authorization import _assert_ledger_isolation
from zacai.state import Source, SourceClassificationElevation
from zacai.state_repository import source_classification_elevation_strength


def history_fragment_packet_provenance(
    packet: HistoryFragmentContextualPacketV1,
) -> tuple[EvidenceReference, ...]:
    """Complete declared original/derived/profile union, not canonical proof."""
    if type(packet) is not HistoryFragmentContextualPacketV1:
        raise ValueError("exact fragment packet required")
    return _fragment_request_provenance(packet.request())


def _fragment_request_provenance(
    request: HistoryFragmentContextualRequestV1,
) -> tuple[EvidenceReference, ...]:
    encode_history_fragment_contextual_request(request)
    profile = ClaudeHistoricalFragmentProfileV1.model_validate_json(request.profile_json)
    values = (*request.original_task.event.provenance, *request.task.event.provenance)
    refs: dict[UUID, EvidenceReference] = {}
    for ref in values:
        if type(ref) is not EvidenceReference or ref.source_id.int == 0:
            raise ValueError("exact Source reference required")
        if ref.source_id in refs and refs[ref.source_id] != ref:
            raise ValueError("conflicting Source declaration")
        refs[ref.source_id] = ref
    # Immutable capture labels are observations. The paired current role owns
    # present ACL for the same identity/hash; elevation is not a hash conflict.
    current = (profile.current_original_reference, profile.current_companion_reference)
    for binding, live in zip((profile.original_binding_reference,
                             profile.companion_binding_reference), current, strict=True):
        if binding.source_id == live.source_id:
            if (binding.content_hash != live.content_hash
                or binding.trust_boundary != live.trust_boundary
                or not classification_covers(live.effective_classification,
                                             binding.effective_classification)):
                raise ValueError("binding/current identity conflict")
        else:
            if binding.source_id in refs and refs[binding.source_id] != binding:
                raise ValueError("conflicting immutable binding")
            refs[binding.source_id] = binding
        if live.source_id in refs and refs[live.source_id] != live:
            raise ValueError("conflicting current Source declaration")
        refs[live.source_id] = live
    if not 1 <= len(refs) <= 96:
        raise ValueError("bounded complete fragment provenance required")
    return tuple(sorted(refs.values(), key=lambda ref: str(ref.source_id)))


def _fragment_transaction(session: Session) -> tuple[SessionTransaction, SessionTransaction | None]:
    if not isinstance(session, Session) or session.new or session.dirty or session.deleted:
        raise ValueError("clean canonical transaction required")
    _assert_ledger_isolation(session)
    outer, nested = session.get_transaction(), session.get_nested_transaction()
    if outer is None or not outer.is_active or (nested is not None and not nested.is_active):
        raise ValueError("live caller transaction required")
    return outer, nested


def _fragment_rows(
    session: Session, refs: tuple[EvidenceReference, ...],
    boundaries: frozenset[TrustBoundary], labels: frozenset[DataClassification],
) -> tuple[tuple[tuple[str, object], ...], ...]:
    if (type(refs) is not tuple or not 1 <= len(refs) <= 96
        or len({ref.source_id for ref in refs}) != len(refs)
        or any(type(ref) is not EvidenceReference for ref in refs)
        or len(boundaries) != 1
        or not boundaries <= frozenset({TrustBoundary.PERSONAL, TrustBoundary.BRAINSTORM})):
        raise ValueError("one explicit boundary and exact complete refs required")
    boundary = next(iter(boundaries))
    for ref in refs:
        if ref.trust_boundary != boundary:
            raise ValueError("mixed boundary unavailable")
        _access(boundary, ref.effective_classification, boundaries, labels)
    effective = (select(SourceClassificationElevation.new_classification)
        .where(SourceClassificationElevation.source_id == Source.id)
        .order_by(source_classification_elevation_strength().desc(),
                  SourceClassificationElevation.elevated_at.desc()).limit(1)
        .correlate(Source).scalar_subquery())
    label = func.coalesce(effective, Source.data_classification)
    lineage = aliased(Source)
    bad_elevation = select(SourceClassificationElevation.id).where(
        SourceClassificationElevation.source_id == Source.id,
        SourceClassificationElevation.trust_boundary != Source.trust_boundary,
    ).exists().correlate(Source)
    # Namespace lineage contains identifiers/scalars only, never other revisions'
    # excerpts. All requested full rows and their lineage share ONE SQL snapshot.
    lineage_names = ("id", "trust_boundary", "data_classification", "system",
                     "external_ref", "captured_at", "content_hash", "content_location",
                     "supersedes_source_id")
    columns = (*Source.__table__.columns, label.label("effective"),
               *(getattr(lineage, name).label("lineage_" + name) for name in lineage_names))
    permitted = or_(*(and_(Source.id == ref.source_id,
                          Source.trust_boundary == ref.trust_boundary,
                          Source.content_hash == ref.content_hash,
                          label == ref.effective_classification,
                          Source.data_classification.in_(tuple(c for c in DataClassification
                              if classification_covers(ref.effective_classification, c))),
                          ~bad_elevation) for ref in refs))
    family = and_(lineage.trust_boundary == Source.trust_boundary,
                  lineage.system == Source.system,
                  lineage.external_ref == Source.external_ref,
                  Source.external_ref.is_not(None))
    with session.no_autoflush:
        rows = tuple(session.execute(select(*columns).outerjoin(lineage, family)
            .where(permitted).order_by(Source.id, lineage.id)
            .limit(96 * 129 + 1)).mappings())
    if len(rows) > 96 * 129 or {row["id"] for row in rows} != {r.source_id for r in refs}:
        raise ValueError("complete bounded Source snapshot required")
    expected = {ref.source_id: ref for ref in refs}
    for row in rows:
        ref = expected[row["id"]]
        if (row["trust_boundary"] != boundary or row["content_hash"] != ref.content_hash
            or row["effective"] != ref.effective_classification
            or type(row["content_location"]) is not str or not row["content_location"]
            or not classification_covers(row["effective"], row["data_classification"])):
            raise ValueError("selected current Source mismatch")
        _access(boundary, row["effective"], boundaries, labels)
    return tuple(tuple((str(key), value) for key, value in row.items()) for row in rows)



def _fragment_same_transaction(
    session: Session, entry: tuple[SessionTransaction, SessionTransaction | None],
) -> None:
    if (session.new or session.dirty or session.deleted
        or session.get_transaction() is not entry[0] or not entry[0].is_active
        or session.get_nested_transaction() is not entry[1]
        or (entry[1] is not None and not entry[1].is_active)):
        raise ValueError("callback changed clean caller transaction")


def _fragment_external(digest: str, request: HistoryFragmentContextualRequestV1) -> str:
    encoded = encode_history_fragment_contextual_request(request)
    return f"history-fragment-contextual-packet/{digest}/{content_hash_of(encoded)}"


def _fragment_profile_lineage(
    request: HistoryFragmentContextualRequestV1,
    snapshot: tuple[tuple[tuple[str, object], ...], ...],
) -> None:
    profile = ClaudeHistoricalFragmentProfileV1.model_validate_json(request.profile_json)
    for ref, companion in ((profile.current_original_reference, False),
                           (profile.current_companion_reference, True)):
        rows = [dict(row) for row in snapshot if dict(row)["id"] == ref.source_id]
        lineage = {row["lineage_id"]: row for row in rows}
        namespace = (f"claude-original-companion/{profile.custody_id}/{profile.proposal_hash}"
                     if companion else f"claude-original/{profile.custody_id}")
        if (not rows or any(row["system"] is not SourceSystem.MANUAL
                            or row["external_ref"] != namespace for row in rows)
            or None in lineage or len(lineage) > 128):
            raise ValueError("bounded canonical custody lineage required")
        children = {row["lineage_supersedes_source_id"] for row in rows
                    if row["lineage_supersedes_source_id"] is not None}
        if not children <= set(lineage):
            raise ValueError("broken custody lineage")
        tips = set(lineage) - children
        if len(tips) != 1:
            raise ValueError("ambiguous custody lineage")
        if companion:
            if len(lineage) != 1 or tips != {ref.source_id}:
                raise ValueError("exact unique companion required")
        else:
            tip = next(iter(tips))
            if (tip != profile.original_tip_id
                or profile.superseded_at_read != (tip != ref.source_id)):
                raise ValueError("custody lineage read observation changed")
        # Every row must be in one acyclic chain to the actual unambiguous tip.
        visited: set[object] = set()
        current = next(iter(tips))
        while current is not None:
            if current in visited or current not in lineage:
                raise ValueError("custody lineage cycle")
            visited.add(current)
            current = lineage[current]["lineage_supersedes_source_id"]
        if visited != set(lineage):
            raise ValueError("disconnected custody lineage")


def capture_history_fragment_contextual_packet(
    session: Session, *, artifacts: LocalFilesystemArtifactStore, payload: bytes,
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
) -> UUID:
    """Capture exact fragment bytes; caller commits, refreshes relationships and
    authenticates owner/claim/recovery separately. Roll back after a hold.
    """
    result = None
    try:
        if type(artifacts) is not LocalFilesystemArtifactStore:
            raise ValueError("concrete bounded local packet store required")
        entry = _fragment_transaction(session)
        packet = decode_history_fragment_contextual_packet(payload)
        refs = history_fragment_packet_provenance(packet)
        before = _fragment_rows(session, refs, authorized_boundaries, allowed_classifications)
        request = packet.request()
        _fragment_profile_lineage(request, before)
        boundary = request.task.event.trust_boundary
        label = packet.review.data_classification
        _access(boundary, label, authorized_boundaries, allowed_classifications)
        if any(not classification_covers(label, ref.effective_classification) for ref in refs):
            raise ValueError("packet weaker than complete provenance")
        digest = content_hash_of(payload)
        from zacai.backup_artifacts import _assert_personal_custody_append_capacity

        _assert_personal_custody_append_capacity(session, 1)
        with session.begin_nested():
            nested = session.get_nested_transaction()
            location = artifacts.put(boundary, digest, payload)
            _fragment_same_transaction(session, (entry[0], nested))
            readback = artifacts.get_bounded(boundary, location, max_bytes=MAX_PACKET_BYTES)
            _fragment_same_transaction(session, (entry[0], nested))
            if readback != payload:
                raise ValueError("packet integrity")
            if (session.get_transaction() is not entry[0]
                or session.get_nested_transaction() is not nested
                or _fragment_rows(session, refs, authorized_boundaries,
                                  allowed_classifications) != before):
                raise ValueError("Source or transaction changed during write")
            _assert_personal_custody_append_capacity(session, 1)
            _fragment_same_transaction(session, (entry[0], nested))
            source, _ = record_source(session, trust_boundary=boundary,
                data_classification=label, system=SourceSystem.MANUAL,
                external_ref=_fragment_external(digest, request),
                content_hash=digest, content_location=location, captured_at=packet.created_at)
            _fragment_same_transaction(session, (entry[0], nested))
            if (source.content_hash != digest or source.content_location != location
                or source.system != SourceSystem.MANUAL
                or source.trust_boundary != boundary or source.data_classification != label
                or source.external_ref != _fragment_external(digest, request)
                or source.supersedes_source_id is not None
                or source.captured_at != packet.created_at
                or get_effective_source_classification(session, source_id=source.id) != label
                or _fragment_rows(session, refs, authorized_boundaries,
                                  allowed_classifications) != before):
                raise ValueError("exact packet Source mismatch")
            pending = source.id
            own = EvidenceReference(source_id=pending, content_hash=digest,
                trust_boundary=boundary, effective_classification=label)
            complete = tuple(sorted((*refs, own), key=lambda ref: str(ref.source_id)))
            complete_before = _fragment_rows(session, complete, authorized_boundaries,
                                             allowed_classifications)
        _fragment_same_transaction(session, entry)
        if _fragment_rows(session, complete, authorized_boundaries,
                          allowed_classifications) != complete_before:
            raise ValueError("final complete Source snapshot changed")
        result = pending
    except Exception:  # noqa: BLE001,S110 - fixed private-safe error outside handler
        pass
    if result is None:
        raise ValueError("fragment packet capture unavailable or mismatched")
    return result



def load_history_fragment_contextual_packet(
    session: Session, *, artifacts: LocalFilesystemArtifactStore, source_id: UUID,
    expected_digest: str, expected_request: HistoryFragmentContextualRequestV1,
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
) -> HistoryFragmentContextualPacketV1:
    """Exact trusted retained request locator, canonically bound before body read.

    Request/Source metadata is not authenticated processing or recovery authority.
    Caller owns relationships/owner/recovery and rollback after any hold.
    """
    result = None
    try:
        if type(artifacts) is not LocalFilesystemArtifactStore:
            raise ValueError("concrete bounded local packet store required")
        entry = _fragment_transaction(session)
        retained = encode_history_fragment_contextual_request(expected_request)
        refs = _fragment_request_provenance(expected_request)
        boundary = expected_request.task.event.trust_boundary
        label = expected_request.task.event.data_classification
        own = EvidenceReference(source_id=source_id, content_hash=expected_digest,
            trust_boundary=boundary, effective_classification=label)
        complete = tuple(sorted((*refs, own), key=lambda ref: str(ref.source_id)))
        before = _fragment_rows(session, complete, authorized_boundaries, allowed_classifications)
        _fragment_profile_lineage(expected_request, before)
        row = next(dict(values) for values in before if dict(values)["id"] == source_id)
        if (row["system"] != SourceSystem.MANUAL
            or row["external_ref"] != _fragment_external(expected_digest, expected_request)
            or row["supersedes_source_id"] is not None):
            raise ValueError("exact bound packet/request locator mismatch")
        location = row["content_location"]
        if type(location) is not str:
            raise ValueError("exact packet artifact locator required")
        raw = artifacts.get_bounded(boundary, location, max_bytes=MAX_PACKET_BYTES)
        _fragment_same_transaction(session, entry)
        if content_hash_of(raw) != expected_digest:
            raise ValueError("packet integrity")
        packet = decode_history_fragment_contextual_packet(raw)
        if (encode_history_fragment_contextual_request(packet.request()) != retained
            or history_fragment_packet_provenance(packet) != refs
            or packet.request().task.event.trust_boundary != boundary
            or packet.review.data_classification != label
            or packet.created_at != row["captured_at"]
            or any(not classification_covers(label, ref.effective_classification) for ref in refs)):
            raise ValueError("packet components/Source metadata mismatch")
        _fragment_same_transaction(session, entry)
        after = _fragment_rows(session, complete, authorized_boundaries, allowed_classifications)
        _fragment_profile_lineage(expected_request, after)
        if after != before:
            raise ValueError("final complete Source observation changed")
        result = packet
    except Exception:  # noqa: BLE001,S110 - fixed error outside private handler
        pass
    if result is None:
        raise ValueError("fragment packet load unavailable or mismatched")
    return result


# Complete MESSAGE V2 history is a distinct inert retention family. These joins
# authenticate retained bytes/current Source metadata, never owner permission.
from datetime import datetime

from zacai.claude_original_capture import ClaudeArtifactRootIdentity
from zacai.claude_original_read import load_claude_original
from zacai.intelligence.history_context_metadata import (
    ClaudeMessageMetadata,
    HistoryMessageSpan,
    prepare_claude_history_context_preview,
)
from zacai.intelligence.history_contextual_codec import (
    HistoryContextualPacketV1,
    HistoryContextualRequestV1,
    decode_history_contextual_packet,
    encode_history_contextual_request,
    prepare_history_contextual_request,
)


def _history_request_provenance(request: HistoryContextualRequestV1) -> tuple[EvidenceReference, ...]:
    encode_history_contextual_request(request)
    refs: dict[UUID, EvidenceReference] = {}
    for ref in (*request.task.event.provenance,
                *(item.reference for item in request.task.context)):
        if ref.source_id in refs and refs[ref.source_id] != ref:
            raise ValueError("inconsistent complete history provenance")
        refs[ref.source_id] = ref
    for entry in request.sidecar.entries:
        if type(entry) is not ClaudeMessageMetadata:
            raise ValueError("complete Claude message metadata required")
        for current, binding in (
            (entry.current_original_reference, entry.original_binding_reference),
            (entry.current_companion_reference, entry.companion_binding_reference),
        ):
            if refs.get(current.source_id) != current:
                raise ValueError("complete current history reference required")
            prior = refs.get(binding.source_id)
            if prior is not None:
                if (prior.content_hash != binding.content_hash
                    or prior.trust_boundary != binding.trust_boundary
                    or not classification_covers(prior.effective_classification,
                                                 binding.effective_classification)):
                    raise ValueError("immutable history binding differs")
            else:
                refs[binding.source_id] = binding
    if not 1 <= len(refs) <= 95:
        raise ValueError("bounded complete history provenance required")
    return tuple(refs[key] for key in sorted(refs, key=str))


def history_packet_provenance(packet: HistoryContextualPacketV1) -> tuple[EvidenceReference, ...]:
    """Canonical complete-message evidence inventory, without permission flags."""
    packet = HistoryContextualPacketV1.model_validate(packet.model_dump(mode="json"))
    return _history_request_provenance(packet.request())


def _history_external(digest: str, request: HistoryContextualRequestV1) -> str:
    return f"history-contextual-packet/{digest}/{content_hash_of(encode_history_contextual_request(request))}"


def _history_reconstruct(
    session: Session, *, artifacts: LocalFilesystemArtifactStore,
    expected_root: ClaudeArtifactRootIdentity, expected_account_ref: str,
    expected_exported_at: datetime | None, request: HistoryContextualRequestV1,
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
) -> None:
    # No caller-supplied custody dataclass is admitted: the real canonical reader
    # verifies both original artifacts and their namespace/current observations.
    entries = request.sidecar.entries
    if not entries or any(type(e) is not ClaudeMessageMetadata for e in entries):
        raise ValueError("complete message family required")
    first = entries[0]
    if not isinstance(first, ClaudeMessageMetadata):
        raise TypeError("complete message family required")
    read = load_claude_original(
        session, artifacts=artifacts, expected_root=expected_root,
        original_reference=first.current_original_reference,
        companion_reference=first.current_companion_reference,
        expected_account_ref=expected_account_ref, expected_exported_at=expected_exported_at,
        requestor_boundaries=authorized_boundaries,
        allowed_classifications=allowed_classifications,
    )
    selections = tuple(HistoryMessageSpan(message_id=e.message_id,
        character_start=e.character_start, character_end=e.character_end)
        for e in entries if isinstance(e, ClaudeMessageMetadata))
    original = request.original_context()
    preview = prepare_claude_history_context_preview(original, read,
        selections=selections, observed_at=first.projection_observed_at, route=request.route)
    rebuilt = prepare_history_contextual_request(preview, original_context=original,
                                                 route=request.route)
    if encode_history_contextual_request(rebuilt) != encode_history_contextual_request(request):
        raise ValueError("canonical original message reconstruction differs")


def _history_own(
    snapshot: tuple[tuple[tuple[str, object], ...], ...], ref: EvidenceReference,
    request: HistoryContextualRequestV1,
) -> dict[str, object]:
    rows = [dict(row) for row in snapshot if dict(row)["id"] == ref.source_id]
    if (not rows or {r["lineage_id"] for r in rows} != {ref.source_id}
        or any(r["system"] is not SourceSystem.MANUAL
               or r["external_ref"] != _history_external(ref.content_hash, request)
               or r["supersedes_source_id"] is not None
               or r["data_classification"] != ref.effective_classification for r in rows)):
        raise ValueError("unique complete history packet namespace required")
    return rows[0]


def capture_history_contextual_packet(
    session: Session, *, artifacts: LocalFilesystemArtifactStore,
    expected_root: ClaudeArtifactRootIdentity, expected_account_ref: str,
    expected_exported_at: datetime | None, payload: bytes,
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
) -> UUID:
    """Retain complete MESSAGE V2 packet under caller-owned commit/rollback.

    No admission, model dispatch, owner authentication or recovery is produced.
    The canonical original reader requires a clean, unwritten outer transaction.
    Roll back the caller-owned outer transaction after any hold before reuse.
    """
    from zacai.backup_artifacts import _assert_personal_custody_append_capacity
    from zacai.intelligence.fragment_review_retention import _physical, _same

    result = None
    try:
        if type(artifacts) is not LocalFilesystemArtifactStore:
            raise ValueError("concrete bounded local store required")
        outer = _physical(session)
        packet = decode_history_contextual_packet(payload)
        request = packet.request()
        refs = history_packet_provenance(packet)
        boundary = request.task.event.trust_boundary
        label = packet.review.data_classification
        _access(boundary, label, authorized_boundaries, allowed_classifications)
        if any(not classification_covers(label, r.effective_classification) for r in refs):
            raise ValueError("packet weaker than provenance")
        before = _fragment_rows(session, refs, authorized_boundaries, allowed_classifications)
        _same(session, outer)
        _history_reconstruct(session, artifacts=artifacts, expected_root=expected_root,
            expected_account_ref=expected_account_ref, expected_exported_at=expected_exported_at,
            request=request, authorized_boundaries=authorized_boundaries,
            allowed_classifications=allowed_classifications)
        _same(session, outer)
        if _fragment_rows(session, refs, authorized_boundaries, allowed_classifications) != before:
            raise ValueError("original union changed during reconstruction")
        digest = content_hash_of(payload)
        if boundary is TrustBoundary.PERSONAL:
            _assert_personal_custody_append_capacity(session, 1)
        _same(session, outer)
        with session.begin_nested():
            entry = _physical(session)
            location = artifacts.put(boundary, digest, payload)
            _same(session, entry)
            raw = artifacts.get_bounded(boundary, location, max_bytes=MAX_PACKET_BYTES)
            _same(session, entry)
            if (raw != payload or _fragment_rows(session, refs, authorized_boundaries,
                                                 allowed_classifications) != before):
                raise ValueError("packet or original union changed")
            if boundary is TrustBoundary.PERSONAL:
                _assert_personal_custody_append_capacity(session, 1)
            _same(session, entry)
            source, _ = record_source(session, trust_boundary=boundary,
                data_classification=label, system=SourceSystem.MANUAL,
                external_ref=_history_external(digest, request), content_hash=digest,
                content_location=location, captured_at=packet.created_at)
            _same(session, entry)
            own = EvidenceReference(source_id=source.id, content_hash=digest,
                trust_boundary=boundary, effective_classification=label)
            complete = tuple(sorted((*refs, own), key=lambda r: str(r.source_id)))
            final = _fragment_rows(session, complete, authorized_boundaries, allowed_classifications)
            row = _history_own(final, own, request)
            if row["captured_at"] != packet.created_at or row["content_location"] != location:
                raise ValueError("packet Source metadata differs")
            if _fragment_rows(session, refs, authorized_boundaries, allowed_classifications) != before:
                raise ValueError("original union changed during capture")
            _same(session, entry)
            pending = source.id
        _same(session, outer)
        after = _fragment_rows(session, complete, authorized_boundaries, allowed_classifications)
        _history_own(after, own, request)
        _same(session, outer)
        if after != final:
            raise ValueError("complete final union changed")
        result = pending
    except Exception:  # noqa: BLE001,S110 - fixed cause-free hold outside handler
        pass
    if result is None:
        raise ValueError("complete history packet capture unavailable or mismatched")
    return result


def load_history_contextual_packet(
    session: Session, *, artifacts: LocalFilesystemArtifactStore,
    expected_root: ClaudeArtifactRootIdentity, expected_account_ref: str,
    expected_exported_at: datetime | None, expected_packet_reference: EvidenceReference,
    expected_request: HistoryContextualRequestV1,
    authorized_boundaries: frozenset[TrustBoundary],
    allowed_classifications: frozenset[DataClassification],
) -> HistoryContextualPacketV1:
    """Bounded paired reconstruction and exact packet reopen, with no authority."""
    from zacai.intelligence.fragment_review_retention import _physical, _same

    result = None
    try:
        if type(artifacts) is not LocalFilesystemArtifactStore:
            raise ValueError("concrete bounded local store required")
        entry = _physical(session)
        retained = encode_history_contextual_request(expected_request)
        refs = _history_request_provenance(expected_request)
        boundary = expected_request.task.event.trust_boundary
        if type(expected_packet_reference) is not EvidenceReference:
            raise ValueError("exact retained packet binding required")
        own = EvidenceReference.model_validate(expected_packet_reference.model_dump(mode="json"))
        label = own.effective_classification
        if (own.trust_boundary is not boundary
            or not classification_covers(label, expected_request.task.event.data_classification)
            or any(not classification_covers(label, r.effective_classification) for r in refs)):
            raise ValueError("packet binding weaker than request/provenance")
        if own.source_id in {r.source_id for r in refs}:
            raise ValueError("distinct complete packet Source required")
        complete = tuple(sorted((*refs, own), key=lambda r: str(r.source_id)))
        before = _fragment_rows(session, complete, authorized_boundaries, allowed_classifications)
        row = _history_own(before, own, expected_request)
        _same(session, entry)
        _history_reconstruct(session, artifacts=artifacts, expected_root=expected_root,
            expected_account_ref=expected_account_ref, expected_exported_at=expected_exported_at,
            request=expected_request, authorized_boundaries=authorized_boundaries,
            allowed_classifications=allowed_classifications)
        _same(session, entry)
        if _fragment_rows(session, complete, authorized_boundaries, allowed_classifications) != before:
            raise ValueError("complete union changed during reconstruction")
        location = row["content_location"]
        if type(location) is not str:
            raise ValueError("packet location required")
        raw = artifacts.get_bounded(boundary, location, max_bytes=MAX_PACKET_BYTES)
        _same(session, entry)
        if content_hash_of(raw) != own.content_hash:
            raise ValueError("complete packet integrity differs")
        packet = decode_history_contextual_packet(raw)
        if (encode_history_contextual_request(packet.request()) != retained
            or history_packet_provenance(packet) != refs
            or packet.review.data_classification != label
            or packet.created_at != row["captured_at"]
            or any(not classification_covers(label, r.effective_classification) for r in refs)):
            raise ValueError("packet/request/Source metadata differs")
        after = _fragment_rows(session, complete, authorized_boundaries, allowed_classifications)
        _history_own(after, own, expected_request)
        _same(session, entry)
        if after != before:
            raise ValueError("final complete union changed")
        result = packet
    except Exception:  # noqa: BLE001,S110 - fixed cause-free hold outside handler
        pass
    if result is None:
        raise ValueError("complete history packet load unavailable or mismatched")
    return result
