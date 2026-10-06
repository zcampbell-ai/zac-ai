"""Dormant trusted-host custody library; declarations never authenticate approval.

The caller authenticates exact approved proposal bytes, current LOCAL rights and
protection prerequisites. Caller owns serialization, outer commit and recovery.
Artifacts can remain orphaned on hold; roll back the caller transaction. No model,
current fact, account ownership or recovery authority is returned.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from zacai.claude_custody_selection import inspect_claude_custody_selection
from zacai.claude_history_index import (
    MAX_INPUT_BYTES,
    ClaudeConversationSpan,
    ClaudeMessageSpan,
    index_claude_member_history,
)
from zacai.history_manifest import (
    MAX_MANIFEST_BYTES,
    MAX_RECORD_BYTES,
    MAX_RECORDS,
    HistorySelection,
    OpaqueId,
)
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference, classification_covers
from zacai.policy import AccessRequest, Destination, evaluate_access
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation
from zacai.state import Source, SourceClassificationElevation, SourceSystem
from zacai.state_repository import record_source, source_classification_elevation_strength

MAX_ORIGINAL_REVISIONS = 128


class ClaudeOriginalCaptureError(ValueError):
    """Fixed public diagnostics only; hosts must disable traceback-local capture."""


class ClaudeCustodyProposal(Contract):
    format: Literal["zac-claude-original-custody-proposal-v1"] = Field(repr=False)
    custody_id: UUID = Field(repr=False)
    original_hash: Digest = Field(repr=False)
    original_bytes: Annotated[int, Field(gt=0, le=MAX_INPUT_BYTES, strict=True)] = Field(repr=False)
    account_ref: OpaqueId = Field(repr=False)
    exported_at: AwareDatetime | None = Field(repr=False)
    acquired_at: AwareDatetime = Field(repr=False)
    captured_at: AwareDatetime = Field(repr=False)
    boundary: B = Field(repr=False)
    classification: C = Field(repr=False)
    boundary_scope: Literal["ONE_REVIEWED_BOUNDARY"] = Field(repr=False)
    coverage: Literal["SELECTED_RECORDS_ONLY"] = Field(repr=False)
    selections: tuple[HistorySelection, ...] = Field(
        min_length=1, max_length=MAX_RECORDS, repr=False
    )

    @field_validator("exported_at", "acquired_at", "captured_at", mode="before")
    @classmethod
    def explicit_date(cls, value: object) -> object:
        if value is None or type(value) is datetime:
            return value
        if type(value) is str and "T" in value:
            return value
        raise ValueError("explicit time required")

    @field_validator("exported_at", "acquired_at", "captured_at")
    @classmethod
    def utc_date(cls, value: datetime | None) -> datetime | None:
        return value.astimezone(UTC) if value is not None else None

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if (
            self.custody_id.int == 0
            or self.boundary == B.SHARED
            or self.acquired_at > self.captured_at
            or (self.exported_at is not None and self.exported_at > self.acquired_at)
        ):
            raise ValueError("closed custody declaration required")
        seen = set()
        spans: list[tuple[int, int]] = []
        for choice in self.selections:
            identity = UUID(choice.original_id)
            if (
                str(identity) != choice.original_id
                or identity.int == 0
                or identity in seen
                or not 0 <= choice.start < choice.end <= self.original_bytes
                or choice.end - choice.start > MAX_RECORD_BYTES
                or any(choice.start < end and choice.end > start for start, end in spans)
            ):
                raise ValueError("exact bounded selected spans required")
            seen.add(identity)
            spans.append((choice.start, choice.end))
        return self


@dataclass(frozen=True, repr=False)
class UncommittedClaudeCustody:
    original_reference: EvidenceReference
    companion_reference: EvidenceReference
    proposal_hash: str
    original_captured_at: datetime
    captured_new_ids: tuple[UUID, ...]
    committed: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)
    capture_authorized: Literal[False] = field(default=False, init=False)
    processing_authorized: Literal[False] = field(default=False, init=False)
    current_facts_verified: Literal[False] = field(default=False, init=False)


def _pairs(values: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _number(value: str) -> None:
    raise ValueError("unsupported number")


def _integer(value: str) -> int:
    if len(value) > 20:
        raise ValueError("number capacity")
    return int(value)


def _validated(raw: bytes, original: bytes) -> ClaudeCustodyProposal:
    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= MAX_MANIFEST_BYTES
        or type(original) is not bytes
        or not 0 < len(original) <= MAX_INPUT_BYTES
    ):
        raise ValueError("bounded bytes required")
    proposal = ClaudeCustodyProposal.model_validate(
        json.loads(
            raw,
            object_pairs_hook=_pairs,
            parse_int=_integer,
            parse_float=_number,
            parse_constant=_number,
        )
    )
    if (
        canonical_bytes(proposal.model_dump(mode="json")) != raw
        or len(original) != proposal.original_bytes
        or content_hash_of(original) != proposal.original_hash
    ):
        raise ValueError("exact original/proposal required")
    index = index_claude_member_history(original, expected_file_hash=proposal.original_hash)
    records: dict[str, tuple[str, ClaudeConversationSpan | ClaudeMessageSpan]] = {}
    for conversation in index.conversations:
        records[str(conversation.original_id)] = ("CONVERSATION", conversation)
        for message in conversation.messages:
            records[str(message.original_id)] = (message.historical_role, message)
    for choice in proposal.selections:
        if choice.original_id not in records:
            raise ValueError("absent original identity")
        role, record = records[choice.original_id]
        if (
            choice.role != role
            or (choice.start, choice.end) != (record.record.start, record.record.end)
            or choice.reported_at != record.reported_created_at
            or content_hash_of(original[choice.start : choice.end]) != choice.content_hash
            or (
                proposal.exported_at is not None
                and (
                    record.reported_created_at > proposal.exported_at
                    or record.reported_updated_at > proposal.exported_at
                )
            )
        ):
            raise ValueError("selected historical record differs")
    # Exact canonical envelope capacity, using a UUID-width sizing string only.
    # This is NOT an EvidenceReference or a claimed/preassigned database ID.
    if len(_envelope(proposal, "00000000-0000-0000-0000-000000000000")) > MAX_MANIFEST_BYTES:
        raise ValueError("companion capacity")
    return proposal


def _envelope(proposal: ClaudeCustodyProposal, source_id: str) -> bytes:
    ref = {
        "source_id": source_id,
        "content_hash": proposal.original_hash,
        "trust_boundary": proposal.boundary.value,
        "effective_classification": proposal.classification.value,
    }
    return canonical_bytes(
        {
            "format": "zac-claude-captured-companion-v1",
            "proposal": proposal.model_dump(mode="json"),
            "original_captured_at": proposal.captured_at.isoformat().replace("+00:00", "Z"),
            "companion": {
                "format": "zac-claude-whole-original-selection-v1",
                "provider": "CLAUDE",
                "original_reference": ref,
                "original_file_hash": proposal.original_hash,
                "original_file_bytes": proposal.original_bytes,
                "account_ref": proposal.account_ref,
                "exported_at": proposal.model_dump(mode="json")["exported_at"],
                "boundary": proposal.boundary.value,
                "classification": proposal.classification.value,
                "boundary_scope": "ONE_REVIEWED_BOUNDARY",
                "coverage": "SELECTED_RECORDS_ONLY",
                "selections": [x.model_dump(mode="json") for x in proposal.selections],
            },
        }
    )


def prepare_claude_custody_proposal(
    *,
    custody_id: UUID,
    original_raw: bytes,
    account_ref: str,
    exported_at: datetime | None,
    acquired_at: datetime,
    captured_at: datetime,
    boundary: B,
    classification: C,
    selections: tuple[HistorySelection, ...],
) -> bytes:
    result = None
    try:
        if type(original_raw) is not bytes or not 0 < len(original_raw) <= MAX_INPUT_BYTES:
            raise ValueError("original capacity")
        proposal = ClaudeCustodyProposal(
            format="zac-claude-original-custody-proposal-v1",
            custody_id=custody_id,
            original_hash=content_hash_of(original_raw),
            original_bytes=len(original_raw),
            account_ref=account_ref,
            exported_at=exported_at,
            acquired_at=acquired_at,
            captured_at=captured_at,
            boundary=boundary,
            classification=classification,
            boundary_scope="ONE_REVIEWED_BOUNDARY",
            coverage="SELECTED_RECORDS_ONLY",
            selections=selections,
        )
        raw = canonical_bytes(proposal.model_dump(mode="json"))
        _validated(raw, original_raw)
        result = raw
    except Exception:  # noqa: BLE001,S110 - fixed public diagnostics only
        pass
    if result is None:
        raise ClaudeOriginalCaptureError("Claude custody proposal held")
    return result


def _clean(session: Session) -> None:
    if session.new or session.dirty or session.deleted:
        raise ValueError("clean unit of work required")


class _SourceRow(Contract):
    id: UUID = Field(repr=False)
    trust_boundary: B = Field(repr=False)
    data_classification: C = Field(repr=False)
    system: SourceSystem = Field(repr=False)
    external_ref: str | None = Field(repr=False)
    captured_at: AwareDatetime = Field(repr=False)
    excerpt: str | None = Field(repr=False)
    content_hash: str | None = Field(repr=False)
    content_location: str | None = Field(repr=False)
    supersedes_source_id: UUID | None = Field(repr=False)
    effective: C = Field(repr=False)


def _rows(session: Session, external: str) -> tuple[_SourceRow, ...]:
    latest = (
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
    columns = [
        getattr(Source, name)
        for name in (
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
    ]
    return tuple(
        _SourceRow.model_validate(dict(row))
        for row in session.execute(
            select(*columns, func.coalesce(latest, Source.data_classification).label("effective"))
            .where(Source.external_ref == external)
            .order_by(Source.id)
            .limit(MAX_ORIGINAL_REVISIONS + 1)
        ).mappings()
    )


def _original_lineage(rows: tuple[_SourceRow, ...]) -> None:
    if not rows:
        return
    by_id = {row.id: row for row in rows}
    if len(by_id) != len(rows):
        raise ValueError("ambiguous original lineage")
    children: dict[UUID, UUID] = {}
    roots = []
    for row in rows:
        parent = row.supersedes_source_id
        if parent is None:
            roots.append(row.id)
        elif (
            parent not in by_id
            or parent in children
            or parent == row.id
            or by_id[parent].captured_at > row.captured_at
        ):
            raise ValueError("foreign/forked original revision")
        else:
            children[parent] = row.id
    if len(roots) != 1:
        raise ValueError("original revision root differs")
    visited = set()
    current = roots[0]
    while current not in visited:
        visited.add(current)
        if current not in children:
            break
        current = children[current]
    if visited != by_id.keys():
        raise ValueError("disconnected/cyclic original revision")


def _rights(
    rows: tuple[_SourceRow, ...],
    proposal: ClaudeCustodyProposal,
    requestor: frozenset[B],
    classes: frozenset[C],
) -> None:
    if len(rows) > MAX_ORIGINAL_REVISIONS:
        raise ValueError("lineage capacity")
    for row in rows:
        if (
            row.system != SourceSystem.MANUAL
            or row.trust_boundary != proposal.boundary
            or row.data_classification not in classes
            or row.effective not in classes
            or not evaluate_access(
                AccessRequest(
                    data_boundary=proposal.boundary,
                    data_classification=row.effective,
                    requestor_boundaries=requestor,
                    destination=Destination.LOCAL,
                )
            ).allowed
        ):
            raise ValueError("source rights differ")


def _io[T](session: Session, call: Callable[[], T]) -> T:
    outer, nested = session.get_transaction(), session.get_nested_transaction()
    if outer is None or not outer.is_active:
        raise ValueError("live caller transaction required")
    result = call()
    if (
        session.get_transaction() is not outer
        or not outer.is_active
        or session.get_nested_transaction() is not nested
        or (nested is not None and not nested.is_active)
    ):
        raise ValueError("store changed transaction")
    _clean(session)
    return result


@dataclass(frozen=True, repr=False)
class ClaudeArtifactRootIdentity:
    """Host-pinned root observation, never owner or capture authority."""

    canonical_root: str
    device: int
    inode: int
    owner: int


def observe_claude_artifact_root(
    artifacts: LocalFilesystemArtifactStore,
) -> ClaudeArtifactRootIdentity:
    result = None
    try:
        if type(artifacts) is not LocalFilesystemArtifactStore:
            raise ValueError("concrete store required")
        with artifacts._directory_fd(()) as directory:
            metadata = os.fstat(directory)
            if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise ValueError("private root profile required")
            result = ClaudeArtifactRootIdentity(
                str(artifacts.root), metadata.st_dev, metadata.st_ino, metadata.st_uid
            )
    except Exception:  # noqa: BLE001,S110 - fixed public diagnostics only
        pass
    if result is None:
        raise ClaudeOriginalCaptureError("Claude artifact root unavailable")
    return result


def _root_check(
    artifacts: LocalFilesystemArtifactStore, expected: ClaudeArtifactRootIdentity
) -> None:
    if (
        type(expected) is not ClaudeArtifactRootIdentity
        or type(expected.canonical_root) is not str
        or not expected.canonical_root.startswith("/")
        or type(expected.device) is not int
        or expected.device < 0
        or type(expected.inode) is not int
        or expected.inode <= 0
        or type(expected.owner) is not int
        or expected.owner != os.getuid()
        or observe_claude_artifact_root(artifacts) != expected
    ):
        raise ValueError("host root identity differs")


def _artifact_profile(artifacts: LocalFilesystemArtifactStore, boundary: B, location: str) -> None:
    if type(boundary) is not B or type(location) is not str:
        raise ValueError("exact artifact profile required")
    parts = location.split("/")
    if (
        len(parts) != 2
        or not parts[1].endswith(".bin")
        or location != artifacts.location_for(parts[1][:-4])
    ):
        raise ValueError("canonical artifact location required")
    with artifacts._directory_fd((boundary.value,)) as boundary_fd:
        boundary_metadata = os.fstat(boundary_fd)
        if (
            boundary_metadata.st_uid != os.getuid()
            or stat.S_IMODE(boundary_metadata.st_mode) != 0o700
        ):
            raise ValueError("private boundary directory required")
    with artifacts._directory_fd((boundary.value, parts[0])) as directory:
        directory_metadata = os.fstat(directory)
        if (
            directory_metadata.st_uid != os.getuid()
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
        ):
            raise ValueError("private artifact directory required")
        descriptor = os.open(
            parts[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise ValueError("private artifact profile required")
        finally:
            os.close(descriptor)


def _bounded_read(
    artifacts: LocalFilesystemArtifactStore,
    expected: ClaudeArtifactRootIdentity,
    boundary: B,
    location: str,
    *,
    max_bytes: int,
) -> bytes:
    _root_check(artifacts, expected)
    _artifact_profile(artifacts, boundary, location)
    raw = artifacts.get_bounded(boundary, location, max_bytes=max_bytes)
    _artifact_profile(artifacts, boundary, location)
    _root_check(artifacts, expected)
    return raw


def _store_exact(
    artifacts: LocalFilesystemArtifactStore,
    expected: ClaudeArtifactRootIdentity,
    boundary: B,
    digest: str,
    raw: bytes,
    limit: int,
) -> str:
    location = artifacts.location_for(digest)
    try:
        previous = _bounded_read(artifacts, expected, boundary, location, max_bytes=limit)
    except FileNotFoundError:
        _root_check(artifacts, expected)
        location = artifacts.put_durable(boundary, digest, raw, max_bytes=limit)
        _artifact_profile(artifacts, boundary, location)
        _root_check(artifacts, expected)
        return location
    if previous != raw:
        raise ValueError("existing original artifact differs")
    location = artifacts.put_durable(boundary, digest, raw, max_bytes=limit)
    _artifact_profile(artifacts, boundary, location)
    _root_check(artifacts, expected)
    return location


def record_claude_original(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    expected_root: ClaudeArtifactRootIdentity,
    proposal_raw: bytes,
    original_raw: bytes,
    approved_proposal_hash: str,
    requestor_boundaries: frozenset[B],
    allowed_classifications: frozenset[C],
) -> UncommittedClaudeCustody:
    result = None
    try:
        _clean(session)
        outer = session.get_transaction()
        if outer is None or not outer.is_active:
            raise ValueError("pre-existing caller transaction required")
        _root_check(artifacts, expected_root)
        _assert_ledger_isolation(session)
        if (
            type(proposal_raw) is not bytes
            or not 0 < len(proposal_raw) <= MAX_MANIFEST_BYTES
            or type(original_raw) is not bytes
            or not 0 < len(original_raw) <= MAX_INPUT_BYTES
            or type(artifacts) is not LocalFilesystemArtifactStore
            or type(approved_proposal_hash) is not str
            or content_hash_of(proposal_raw) != approved_proposal_hash
        ):
            raise ValueError("trusted exact proposal required")
        proposal = _validated(proposal_raw, original_raw)
        if (
            type(requestor_boundaries) is not frozenset
            or type(allowed_classifications) is not frozenset
            or any(type(x) is not B for x in requestor_boundaries)
            or any(type(x) is not C for x in allowed_classifications)
            or proposal.boundary not in requestor_boundaries
            or proposal.classification not in allowed_classifications
        ):
            raise ValueError("local scope required")
        if session.get_transaction() is not outer or not outer.is_active:
            raise ValueError("caller transaction changed")
        session.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": proposal.custody_id.int % 2**63}
        )
        original_external = f"claude-original/{proposal.custody_id}"
        companion_external = (
            f"claude-original-companion/{proposal.custody_id}/{approved_proposal_hash}"
        )

        def guarded_io[T](call: Callable[[], T]) -> T:
            _root_check(artifacts, expected_root)
            before_originals = _rows(session, original_external)
            before_companions = _rows(session, companion_external)
            _original_lineage(before_originals)
            _rights(
                before_originals + before_companions,
                proposal,
                requestor_boundaries,
                allowed_classifications,
            )
            observed = _io(session, call)
            _root_check(artifacts, expected_root)
            after_originals = _rows(session, original_external)
            after_companions = _rows(session, companion_external)
            if (before_originals, before_companions) != (after_originals, after_companions):
                raise ValueError("artifact callback changed Source observation")
            _original_lineage(after_originals)
            _rights(
                after_originals + after_companions,
                proposal,
                requestor_boundaries,
                allowed_classifications,
            )
            return observed

        originals = _rows(session, original_external)
        companions = _rows(session, companion_external)
        _original_lineage(originals)
        _rights(originals + companions, proposal, requestor_boundaries, allowed_classifications)
        matches = [row for row in originals if row.content_hash == proposal.original_hash]
        if len(matches) > 1 or len(companions) > 1:
            raise ValueError("ambiguous custody")
        if matches and (
            matches[0].captured_at != proposal.captured_at
            or matches[0].data_classification != proposal.classification
            or matches[0].effective != proposal.classification
        ):
            raise ValueError("immutable original metadata differs")
        if not matches and any(
            row.captured_at > proposal.captured_at
            or not classification_covers(proposal.classification, row.effective)
            for row in originals
        ):
            raise ValueError("original revision weakens chronology or classification")
        if companions and not matches:
            raise ValueError("orphan companion provenance")
        with session.begin_nested():
            if (
                _rows(session, original_external) != originals
                or _rows(session, companion_external) != companions
            ):
                raise ValueError("sources changed before write")
            new_ids = []
            if matches:
                row = matches[0]
                original_location = row.content_location
                if type(original_location) is not str:
                    raise ValueError("original location required")
                raw = guarded_io(
                    lambda: _bounded_read(
                        artifacts,
                        expected_root,
                        proposal.boundary,
                        original_location,
                        max_bytes=proposal.original_bytes,
                    ),
                )
                if raw != original_raw:
                    raise ValueError("original readback differs")
                synced_original_location = guarded_io(
                    lambda: artifacts.put_durable(
                        proposal.boundary,
                        proposal.original_hash,
                        original_raw,
                        max_bytes=proposal.original_bytes,
                    ),
                )
                if synced_original_location != original_location:
                    raise ValueError("durable original location differs")
                original_id = row.id
            else:
                location = guarded_io(
                    lambda: _store_exact(
                        artifacts,
                        expected_root,
                        proposal.boundary,
                        proposal.original_hash,
                        original_raw,
                        proposal.original_bytes,
                    ),
                )
                returned = guarded_io(
                    lambda: _bounded_read(
                        artifacts,
                        expected_root,
                        proposal.boundary,
                        location,
                        max_bytes=proposal.original_bytes,
                    ),
                )
                if returned != original_raw:
                    raise ValueError("original readback differs")
                source, new = record_source(
                    session,
                    trust_boundary=proposal.boundary,
                    data_classification=proposal.classification,
                    system=SourceSystem.MANUAL,
                    content_hash=proposal.original_hash,
                    content_location=location,
                    external_ref=original_external,
                    captured_at=proposal.captured_at,
                )
                original_id = source.id
                if new:
                    new_ids.append(source.id)
            if type(original_id) is not UUID:
                raise ValueError("actual source UUID required")
            original_observation = _rows(session, original_external)
            if any(row not in original_observation for row in originals):
                raise ValueError("earlier original metadata changed")
            expected_count = len(originals) + (0 if matches else 1)
            pinned = [row for row in original_observation if row.id == original_id]
            if len(original_observation) != expected_count or len(pinned) != 1:
                raise ValueError("original provenance changed")
            pin = pinned[0]
            expected_location = original_location if matches else location
            if (
                pin.system != SourceSystem.MANUAL
                or pin.external_ref != original_external
                or pin.trust_boundary != proposal.boundary
                or pin.content_hash != proposal.original_hash
                or pin.content_location != expected_location
                or pin.captured_at != proposal.captured_at
                or pin.data_classification != proposal.classification
                or pin.effective != proposal.classification
            ):
                raise ValueError("original row binding differs")
            original_ref = EvidenceReference(
                source_id=original_id,
                content_hash=proposal.original_hash,
                trust_boundary=proposal.boundary,
                effective_classification=proposal.classification,
            )
            envelope = _envelope(proposal, str(original_id))
            value = json.loads(envelope)
            companion_raw = canonical_bytes(value["companion"])
            inspect_claude_custody_selection(
                companion_raw,
                original_raw,
                expected_companion_hash=content_hash_of(companion_raw),
                expected_original_reference=original_ref,
                expected_account_ref=proposal.account_ref,
                expected_exported_at=proposal.exported_at,
            )
            envelope_hash = content_hash_of(envelope)
            if companions:
                row = companions[0]
                if (
                    row.content_hash != envelope_hash
                    or row.captured_at != proposal.captured_at
                    or row.data_classification != proposal.classification
                    or row.effective != proposal.classification
                    or row.supersedes_source_id is not None
                ):
                    raise ValueError("companion is not immutable derivation")
                companion_location = row.content_location
                if type(companion_location) is not str:
                    raise ValueError("companion location required")
                observed = guarded_io(
                    lambda: _bounded_read(
                        artifacts,
                        expected_root,
                        proposal.boundary,
                        companion_location,
                        max_bytes=MAX_MANIFEST_BYTES,
                    ),
                )
                if observed != envelope:
                    raise ValueError("companion differs")
                synced_companion_location = guarded_io(
                    lambda: artifacts.put_durable(
                        proposal.boundary,
                        envelope_hash,
                        envelope,
                        max_bytes=MAX_MANIFEST_BYTES,
                    ),
                )
                if synced_companion_location != companion_location:
                    raise ValueError("durable companion location differs")
                companion_id = row.id
            else:
                location = guarded_io(
                    lambda: _store_exact(
                        artifacts,
                        expected_root,
                        proposal.boundary,
                        envelope_hash,
                        envelope,
                        MAX_MANIFEST_BYTES,
                    )
                )
                observed = guarded_io(
                    lambda: _bounded_read(
                        artifacts,
                        expected_root,
                        proposal.boundary,
                        location,
                        max_bytes=MAX_MANIFEST_BYTES,
                    ),
                )
                if observed != envelope:
                    raise ValueError("companion readback differs")
                source, new = record_source(
                    session,
                    trust_boundary=proposal.boundary,
                    data_classification=proposal.classification,
                    system=SourceSystem.MANUAL,
                    content_hash=envelope_hash,
                    content_location=location,
                    external_ref=companion_external,
                    captured_at=proposal.captured_at,
                )
                companion_id = source.id
                if new:
                    new_ids.append(source.id)
            retained_value = json.loads(observed)
            retained_companion_raw = canonical_bytes(retained_value["companion"])
            inspect_claude_custody_selection(
                retained_companion_raw,
                original_raw,
                expected_companion_hash=content_hash_of(retained_companion_raw),
                expected_original_reference=original_ref,
                expected_account_ref=proposal.account_ref,
                expected_exported_at=proposal.exported_at,
            )
            _root_check(artifacts, expected_root)
            _clean(session)
            expected_companions = companions if companions else _rows(session, companion_external)
            final_originals = _rows(session, original_external)
            final_companions = _rows(session, companion_external)
            if final_originals != original_observation or final_companions != expected_companions:
                raise ValueError("final Source columns changed")
            _rights(
                final_originals + final_companions,
                proposal,
                requestor_boundaries,
                allowed_classifications,
            )
            actual = [row for row in final_originals if row.id == original_id]
            if (
                len(actual) != 1
                or len(final_companions) != 1
                or actual[0].content_hash != proposal.original_hash
                or actual[0].captured_at != proposal.captured_at
                or final_companions[0].id != companion_id
                or final_companions[0].content_hash != envelope_hash
                or final_companions[0].captured_at != proposal.captured_at
                or final_companions[0].trust_boundary != proposal.boundary
                or final_companions[0].system != SourceSystem.MANUAL
                or final_companions[0].external_ref != companion_external
                or final_companions[0].data_classification != proposal.classification
                or final_companions[0].effective != proposal.classification
                or final_companions[0].content_location
                != (companion_location if companions else location)
                or final_companions[0].supersedes_source_id is not None
            ):
                raise ValueError("final custody changed")
            refs = UncommittedClaudeCustody(
                original_ref,
                EvidenceReference(
                    source_id=companion_id,
                    content_hash=envelope_hash,
                    trust_boundary=proposal.boundary,
                    effective_classification=proposal.classification,
                ),
                approved_proposal_hash,
                proposal.captured_at,
                tuple(new_ids),
            )
        if session.get_transaction() is not outer or not outer.is_active:
            raise ValueError("caller transaction changed")
        _clean(session)
        if (_rows(session, original_external), _rows(session, companion_external)) != (
            final_originals,
            final_companions,
        ):
            raise ValueError("Source observation changed during savepoint exit")
        _root_check(artifacts, expected_root)
        result = refs
    except Exception:  # noqa: BLE001,S110 - fixed public diagnostics only
        pass
    if result is None:
        raise ClaudeOriginalCaptureError("Claude original capture held")
    return result
