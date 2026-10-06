"""Exact retained native evidence inventory; never commit, recovery or authority.

Trusted host supplies the original approved proposal separately. Its matching
hash and USER_INSTRUCTION integrity do not authenticate a human or permit model
processing. Only original selected business sources are read. Later revisions
never replace the pinned historical bytes. SQL is read-only; caller owns session
and must roll back a held transaction if a DB failure aborted it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session, SessionTransaction, aliased
from sqlalchemy.sql.elements import ColumnElement

from zacai.connectors.gmail_wire import GmailScope
from zacai.connectors.slack_wire import HistorySelection, RepliesSelection
from zacai.ingestion.artifact_store import ArtifactStore, canonical_bytes, content_hash_of
from zacai.ingestion.native_batch_envelope import compose_native_batch_envelope
from zacai.ingestion.native_proposal_retention import load_retained_native_proposal
from zacai.ingestion.native_source_capture import (
    GmailCaptureInput,
    SlackCaptureInput,
    prepare_native_batch_proposal,
)
from zacai.ingestion.native_source_preparation import (
    NativeSourcePreparation,
    prepare_gmail_source,
    prepare_slack_sources,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation
from zacai.state import Source, SourceClassificationElevation, SourceSystem
from zacai.state_repository import source_classification_elevation_strength

MAX_REFERENCES = 74
MAX_ENVELOPE_BYTES = 256_000
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}")


class NativeBatchInventoryError(RuntimeError):
    """Fixed private-safe failure, no SQL/provider/filename cause."""


@dataclass(frozen=True, repr=False)
class NativeBatchInventory:
    batch_id: UUID
    batch_reference: EvidenceReference
    approval_reference: EvidenceReference
    proposal_digest: str
    original_observed_at: datetime
    artifact_references: tuple[tuple[EvidenceReference, ...], ...]
    hashes: tuple[tuple[UUID, str], ...]
    source_fingerprints: tuple[tuple[UUID, str], ...] = field(repr=False)
    provenance: tuple[tuple[str, SourceSystem], ...] = field(repr=False)
    processing_authorized: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)
    facts_confirmed: Literal[False] = field(default=False, init=False)
    complete_history_verified: Literal[False] = field(default=False, init=False)


def _clean(session: Session) -> None:
    if session.new or session.dirty or session.deleted:
        raise ValueError("pending unit of work")


def _time(value: datetime) -> datetime:
    if type(value) is not datetime or value.utcoffset() is None:
        raise ValueError("aware host observation required")
    return value.astimezone(UTC)


def _reference(ref: EvidenceReference) -> EvidenceReference:
    if type(ref) is not EvidenceReference:
        raise ValueError("exact evidence reference required")
    checked = EvidenceReference.model_validate(ref)
    if (
        checked.trust_boundary is not B.BRAINSTORM
        or checked.effective_classification is not C.CONFIDENTIAL
    ):
        raise ValueError("fixed source scope denied")
    return checked


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _constant(_: str) -> None:
    raise ValueError("nonfinite JSON")


def _object(raw: bytes, limit: int) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise ValueError("bounded canonical object")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    if type(value) is not dict or canonical_bytes(value) != raw:
        raise ValueError("canonical closed object required")
    return value


def _digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ValueError("digest required")
    return value


def _effective() -> ColumnElement[Any]:
    from sqlalchemy import func

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
    return func.coalesce(latest, Source.data_classification).label("effective_classification")


def _row(
    session: Session, ref: EvidenceReference, kind: SourceSystem, observed: datetime
) -> dict[str, Any]:
    _clean(session)
    with session.no_autoflush:
        rows = list(
            session.execute(
                select(*Source.__table__.columns, _effective())
                .where(Source.id == ref.source_id)
                .limit(2)
            ).mappings()
        )
    if len(rows) != 1:
        raise ValueError("missing or ambiguous selected source")
    row = dict(rows[0])
    if (
        row["system"] is not kind
        or row["trust_boundary"] is not B.BRAINSTORM
        or row["data_classification"] is not C.CONFIDENTIAL
        or row["effective_classification"] is not C.CONFIDENTIAL
        or row["content_hash"] != ref.content_hash
        or _time(row["captured_at"]) > observed
        or type(row["external_ref"]) is not str
        or not 0 < len(row["external_ref"]) <= 2048
        or type(row["content_location"]) is not str
        or not 0 < len(row["content_location"]) <= 2048
    ):
        raise ValueError("canonical selected source denied")
    return row


def _read(session: Session, artifacts: ArtifactStore, row: dict[str, Any], limit: int) -> bytes:
    _clean(session)
    raw = artifacts.get(B.BRAINSTORM, row["content_location"])
    _clean(session)
    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= limit
        or content_hash_of(raw) != row["content_hash"]
    ):
        raise ValueError("exact bounded retained bytes required")
    return raw


def _fingerprint(row: dict[str, Any]) -> str:
    # Every actual Source column is included; excerpt is hashed transiently, never
    # returned/cached as private text. UTC normalization preserves instant identity.
    values: dict[str, Any] = {}
    for column in Source.__table__.columns:
        value = row[column.name]
        if isinstance(value, datetime):
            value = _time(value).isoformat()
        elif isinstance(value, UUID):
            value = str(value)
        elif isinstance(value, Enum):
            value = value.value
        elif value is not None and type(value) is not str:
            raise ValueError("unsupported source column")
        values[column.name] = value
    return content_hash_of(canonical_bytes(values))


def _batch_unique(session: Session, external_ref: str, source_id: UUID) -> None:
    _clean(session)
    with session.no_autoflush:
        rows = list(
            session.execute(select(Source.id).where(Source.external_ref == external_ref).limit(2))
        )
    if len(rows) != 1 or rows[0][0] != source_id:
        raise ValueError("ambiguous original batch provenance")


def _keys(value: dict[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise ValueError("closed object keys differ")


def _scope(value: dict[str, Any]) -> GmailScope:
    _keys(
        value,
        {
            "account_ref",
            "expected_email",
            "message_id",
            "profile_digest",
            "wire_digest",
            "boundary",
            "classification",
            "requestor_boundaries",
            "allowed_classifications",
        },
    )
    return GmailScope(
        value["account_ref"],
        value["expected_email"],
        B(value["boundary"]),
        C(value["classification"]),
        frozenset(B(item) for item in value["requestor_boundaries"]),
        frozenset(C(item) for item in value["allowed_classifications"]),
    )


def _load(
    session: Session,
    *,
    artifacts: ArtifactStore,
    batch_reference: EvidenceReference,
    approval_reference: EvidenceReference,
    approved_proposal_raw: bytes,
    as_of: datetime,
) -> NativeBatchInventory:
    _clean(session)
    _assert_ledger_isolation(session)
    now = _time(as_of)
    batch_ref, approval_ref = _reference(batch_reference), _reference(approval_reference)
    batch = _row(session, batch_ref, SourceSystem.MANUAL, now)
    prefix = "native-source-batch/"
    if not batch["external_ref"].startswith(prefix):
        raise ValueError("exact batch source family required before artifact read")
    declared_batch_id = UUID(batch["external_ref"][len(prefix) :])
    if batch["external_ref"] != prefix + str(declared_batch_id):
        raise ValueError("canonical batch source identity required")
    _batch_unique(session, batch["external_ref"], batch_ref.source_id)
    envelope = _object(_read(session, artifacts, batch, MAX_ENVELOPE_BYTES), MAX_ENVELOPE_BYTES)
    _keys(
        envelope,
        {
            "format",
            "batch_id",
            "proposal_digest",
            "approval_reference",
            "boundary",
            "classification",
            "observed_at",
            "selections",
            "role",
            "facts_confirmed",
            "permission_granted",
            "recovery_verified",
            "complete_history_verified",
        },
    )
    batch_id = UUID(envelope["batch_id"])
    external = f"native-source-batch/{batch_id}"
    if batch["external_ref"] != external or declared_batch_id != batch_id:
        raise ValueError("batch identity differs")
    _batch_unique(session, external, batch_ref.source_id)
    observed = _time(datetime.fromisoformat(envelope["observed_at"]))
    if observed != _time(batch["captured_at"]) or observed > now:
        raise ValueError("original observation differs")
    pinned_approval = _reference(EvidenceReference.model_validate(envelope["approval_reference"]))
    if pinned_approval != approval_ref or batch_ref.source_id == approval_ref.source_id:
        raise ValueError("exact original instruction differs")
    approval = _row(session, approval_ref, SourceSystem.USER_INSTRUCTION, observed)
    _read(session, artifacts, approval, MAX_ARTIFACT_BYTES)
    proposal = _object(approved_proposal_raw, 32_000)
    proposal_digest = content_hash_of(approved_proposal_raw)
    if _digest(envelope["proposal_digest"]) != proposal_digest or proposal.get("batch_id") != str(
        batch_id
    ):
        raise ValueError("original proposal differs")
    _keys(
        proposal,
        {
            "format",
            "batch_id",
            "status",
            "boundary",
            "classification",
            "gmail",
            "slack",
            "purpose",
            "provider_calls",
            "model_calls",
            "business_fact_changes",
            "new_permission",
        },
    )
    gmail, slack, selections = proposal["gmail"], proposal["slack"], envelope["selections"]
    if (
        type(gmail) is not list
        or not 1 <= len(gmail) <= 6
        or type(slack) is not list
        or not 1 <= len(slack) <= 2
        or type(selections) is not list
        or len(selections) != len(gmail) + len(slack)
    ):
        raise ValueError("bounded selected providers required")
    slack_choices = selections[len(gmail) :]
    if (
        any(
            type(choice) is not dict
            or type(choice.get("artifacts")) is not list
            or not 2 <= len(choice["artifacts"]) <= 52
            for choice in slack_choices
        )
        or sum(len(choice["artifacts"]) - 2 for choice in slack_choices) > 50
    ):
        raise ValueError("pre-read Slack aggregate bound")
    prepared: list[NativeSourcePreparation] = []
    gm: list[GmailCaptureInput] = []
    sl: list[SlackCaptureInput] = []
    groups: list[tuple[EvidenceReference, ...]] = []
    rows = {batch_ref.source_id: batch, approval_ref.source_id: approval}
    total = 0
    for index, choice in enumerate(selections):
        if type(choice) is not dict:
            raise ValueError("closed selection required")
        _keys(
            choice,
            {
                "provider",
                "host_observed_at",
                "declared_selection_utf8",
                "declared_selection_digest",
                "artifacts",
                "next_cursor",
                "selected_page_exhausted",
                "retention_limited",
            },
        )
        is_mail = index < len(gmail)
        provider, kind = ("gmail", SourceSystem.EMAIL) if is_mail else ("slack", SourceSystem.SLACK)
        if (
            choice["provider"] != provider
            or _time(datetime.fromisoformat(choice["host_observed_at"])) != observed
        ):
            raise ValueError("selected provider or observation differs")
        artifacts_declared = choice["artifacts"]
        if type(artifacts_declared) is not list or not 2 <= len(artifacts_declared) <= 52:
            raise ValueError("bounded artifact group")
        if is_mail and len(artifacts_declared) != 3:
            raise ValueError("exact mail artifact group")
        refs: list[EvidenceReference] = []
        originals: list[bytes] = []
        for declared in artifacts_declared:
            if type(declared) is not dict:
                raise ValueError("closed artifact declaration")
            _keys(
                declared,
                {
                    "reference",
                    "system",
                    "external_ref",
                    "artifact_kind",
                    "derives_from_wire",
                    "provider_occurred_at",
                },
            )
            ref = _reference(EvidenceReference.model_validate(declared["reference"]))
            if ref.source_id in {batch_ref.source_id, approval_ref.source_id} or any(
                r.source_id == ref.source_id for r in refs
            ):
                raise ValueError("duplicate within-group or control source identity")
            row = _row(session, ref, kind, observed)
            prior = rows.get(ref.source_id)
            if prior is not None and _fingerprint(prior) != _fingerprint(row):
                raise ValueError("shared profile source changed during reads")
            if row["external_ref"] != declared["external_ref"] or declared["system"] != kind.value:
                raise ValueError("provider original metadata differs")
            raw = _read(session, artifacts, row, MAX_ARTIFACT_BYTES)
            total += len(raw)
            if total > MAX_ARTIFACT_BYTES:
                raise ValueError("total native artifact bound")
            rows[ref.source_id] = row
            refs.append(ref)
            originals.append(raw)
        if is_mail:
            declared_scope = gmail[index]
            if type(declared_scope) is not dict:
                raise ValueError("closed mail proposal")
            scope = _scope(declared_scope)
            item = GmailCaptureInput(
                scope, originals[0], originals[1], declared_scope["message_id"]
            )
            gm.append(item)
            plan = prepare_gmail_source(
                scope=scope,
                profile_response=originals[0],
                message_response=originals[1],
                expected_message_id=item.expected_message_id,
                captured_at=observed,
            )
        else:
            declared_scope = slack[index - len(gmail)]
            if type(declared_scope) is not dict:
                raise ValueError("closed Slack proposal")
            _keys(declared_scope, {"selection", "account_digest", "wire_digest"})
            value = declared_scope["selection"]
            if type(value) is not dict:
                raise ValueError("closed Slack selection")
            selection = (
                RepliesSelection.model_validate(value)
                if "parent_ts" in value
                else HistorySelection.model_validate(value)
            )
            slack_item = SlackCaptureInput(selection, originals[0], originals[1])
            sl.append(slack_item)
            plan = prepare_slack_sources(
                selection=selection,
                account_response=originals[0],
                page_response=originals[1],
                captured_at=observed,
                boundary=B.BRAINSTORM,
                classification=C.CONFIDENTIAL,
                requestor_boundaries=frozenset({B.BRAINSTORM}),
                allowed_classifications=frozenset({C.CONFIDENTIAL}),
            )
        if len(plan.artifacts) != len(refs):
            raise ValueError("reparsed record count differs")
        for actual, ref, raw in zip(plan.artifacts, refs, originals, strict=True):
            if (
                actual.original_bytes != raw
                or actual.content_hash != ref.content_hash
                or actual.external_ref != rows[ref.source_id]["external_ref"]
            ):
                raise ValueError("actual native original or derived bytes differ")
        prepared.append(plan)
        groups.append(tuple(refs))
    if (
        sum(len(p.artifacts) - 2 for p in prepared if p.provider == "slack") > 50
        or len(rows) > MAX_REFERENCES
    ):
        raise ValueError("native reference bound")
    if (
        prepare_native_batch_proposal(
            batch_id=batch_id, gmail_inputs=tuple(gm), slack_inputs=tuple(sl)
        )
        != approved_proposal_raw
    ):
        raise ValueError("exact original proposal reconstruction differs")
    raw = compose_native_batch_envelope(
        batch_id=batch_id,
        proposal_digest=proposal_digest,
        approval_reference=approval_ref,
        prepared=tuple(prepared),
        artifact_references=tuple(groups),
        observed_at=observed,
    )
    provenance: dict[str, SourceSystem] = {}
    for row in rows.values():
        external_ref, kind = row["external_ref"], row["system"]
        if external_ref in provenance and provenance[external_ref] is not kind:
            raise ValueError("conflicting source family")
        provenance[external_ref] = kind
    inventory = NativeBatchInventory(
        batch_id,
        batch_ref,
        approval_ref,
        proposal_digest,
        observed,
        tuple(groups),
        tuple(
            sorted(
                ((sid, row["content_hash"]) for sid, row in rows.items()), key=lambda p: str(p[0])
            )
        ),
        tuple(
            sorted(((sid, _fingerprint(row)) for sid, row in rows.items()), key=lambda p: str(p[0]))
        ),
        tuple(sorted(provenance.items())),
    )
    _verify_rows(
        session, artifacts=artifacts, inventory=inventory, as_of=now, expected_envelope=raw
    )
    return inventory


def _verify_rows(
    session: Session,
    *,
    artifacts: ArtifactStore,
    inventory: NativeBatchInventory,
    as_of: datetime,
    expected_envelope: bytes | None = None,
) -> None:
    _clean(session)
    _assert_ledger_isolation(session)
    now = _time(as_of)
    if (
        type(inventory) is not NativeBatchInventory
        or any(
            getattr(inventory, key) is not False
            for key in (
                "processing_authorized",
                "recovery_verified",
                "facts_confirmed",
                "complete_history_verified",
            )
        )
        or _time(inventory.original_observed_at) > now
    ):
        raise ValueError("exact historical inventory required")
    if (
        type(inventory.batch_id) is not UUID
        or type(inventory.hashes) is not tuple
        or not 2 <= len(inventory.hashes) <= MAX_REFERENCES
        or type(inventory.source_fingerprints) is not tuple
        or not 2 <= len(inventory.source_fingerprints) <= MAX_REFERENCES
        or type(inventory.provenance) is not tuple
        or not 2 <= len(inventory.provenance) <= MAX_REFERENCES
        or type(inventory.artifact_references) is not tuple
        or not 2 <= len(inventory.artifact_references) <= 8
    ):
        raise ValueError("bounded exact inventory metadata required")
    _digest(inventory.proposal_digest)
    selected = {
        _reference(inventory.batch_reference).source_id: inventory.batch_reference.content_hash,
        _reference(
            inventory.approval_reference
        ).source_id: inventory.approval_reference.content_hash,
    }
    if len(selected) != 2:
        raise ValueError("distinct control references required")
    group_keys: set[tuple[tuple[UUID, str], ...]] = set()
    for group in inventory.artifact_references:
        if type(group) is not tuple or not 2 <= len(group) <= 52:
            raise ValueError("bounded artifact reference group")
        seen = set()
        for item in group:
            ref = _reference(item)
            if (
                ref.source_id in seen
                or ref.source_id
                in {inventory.batch_reference.source_id, inventory.approval_reference.source_id}
                or (ref.source_id in selected and selected[ref.source_id] != ref.content_hash)
            ):
                raise ValueError("conflicting selected reference identity")
            seen.add(ref.source_id)
            selected[ref.source_id] = ref.content_hash
        group_key = tuple((item.source_id, item.content_hash) for item in group)
        if group_key in group_keys:
            raise ValueError("duplicate declared selected group")
        group_keys.add(group_key)
    hashes = dict(inventory.hashes)
    fingerprints = dict(inventory.source_fingerprints)
    if selected != hashes:
        raise ValueError("selected union omitted or expanded")
    if (
        not 2 <= len(hashes) <= MAX_REFERENCES
        or len(hashes) != len(inventory.hashes)
        or set(hashes) != set(fingerprints)
        or len(fingerprints) != len(inventory.source_fingerprints)
        or any(
            type(sid) is not UUID or _digest(digest) != digest for sid, digest in inventory.hashes
        )
        or any(_digest(digest) != digest for _, digest in inventory.source_fingerprints)
        or hashes.get(inventory.batch_reference.source_id) != inventory.batch_reference.content_hash
        or hashes.get(inventory.approval_reference.source_id)
        != inventory.approval_reference.content_hash
    ):
        raise ValueError("closed inventory union differs")
    other = aliased(Source)
    forbidden = []
    for external, kind in inventory.provenance:
        if (
            type(external) is not str
            or not 0 < len(external) <= 2048
            or type(kind) is not SourceSystem
        ):
            raise ValueError("closed provenance identity")
        forbidden.append(
            (other.external_ref == external)
            & or_(other.system != kind, other.trust_boundary != B.BRAINSTORM)
        )
    if not 2 <= len(forbidden) <= MAX_REFERENCES or len(dict(inventory.provenance)) != len(
        inventory.provenance
    ):
        raise ValueError("closed provenance inventory")
    # Exact retained envelope is the authority for metadata identity/roles, not
    # a caller-constructed dataclass. This is integrity, never human permission.
    batch_external = f"native-source-batch/{inventory.batch_id}"
    batch = _row(session, inventory.batch_reference, SourceSystem.MANUAL, now)
    if (
        batch["external_ref"] != batch_external
        or _time(batch["captured_at"]) != inventory.original_observed_at
    ):
        raise ValueError("exact batch identity and observation")
    _batch_unique(session, batch_external, inventory.batch_reference.source_id)
    _row(
        session,
        inventory.approval_reference,
        SourceSystem.USER_INSTRUCTION,
        inventory.original_observed_at,
    )
    retained = _read(session, artifacts, batch, MAX_ENVELOPE_BYTES)
    if expected_envelope is not None and retained != expected_envelope:
        raise ValueError("exact canonical original envelope differs")
    envelope = _object(retained, MAX_ENVELOPE_BYTES)
    _keys(
        envelope,
        {
            "format",
            "batch_id",
            "proposal_digest",
            "approval_reference",
            "boundary",
            "classification",
            "observed_at",
            "selections",
            "role",
            "facts_confirmed",
            "permission_granted",
            "recovery_verified",
            "complete_history_verified",
        },
    )
    selections = envelope["selections"]
    if (
        envelope["format"] != "zac-native-selected-batch-evidence-v1"
        or envelope["batch_id"] != str(inventory.batch_id)
        or envelope["proposal_digest"] != inventory.proposal_digest
        or envelope["boundary"] != B.BRAINSTORM.value
        or envelope["classification"] != C.CONFIDENTIAL.value
        or envelope["role"] != "CANDIDATE_CONTEXT"
        or any(
            envelope[key] is not False
            for key in (
                "facts_confirmed",
                "permission_granted",
                "recovery_verified",
                "complete_history_verified",
            )
        )
        or _reference(EvidenceReference.model_validate(envelope["approval_reference"]))
        != inventory.approval_reference
        or _time(datetime.fromisoformat(envelope["observed_at"])) != inventory.original_observed_at
        or type(selections) is not list
        or not 2 <= len(selections) <= 8
    ):
        raise ValueError("inventory differs from retained original envelope")
    retained_groups = []
    declared_roles: dict[UUID, tuple[SourceSystem, str]] = {}
    mail_groups = slack_groups = 0
    for selection in selections:
        if type(selection) is not dict or selection.get("provider") not in ("gmail", "slack"):
            raise ValueError("closed retained provider")
        if selection["provider"] == "gmail":
            if slack_groups:
                raise ValueError("original provider order differs")
            mail_groups += 1
            kind = SourceSystem.EMAIL
        else:
            slack_groups += 1
            kind = SourceSystem.SLACK
        artifacts_declared = selection.get("artifacts")
        if (
            type(artifacts_declared) is not list
            or not 2 <= len(artifacts_declared) <= 52
            or (kind is SourceSystem.EMAIL and len(artifacts_declared) != 3)
        ):
            raise ValueError("bounded original selected group")
        refs = []
        for artifact in artifacts_declared:
            if (
                type(artifact) is not dict
                or artifact.get("system") != kind.value
                or type(artifact.get("external_ref")) is not str
                or not 0 < len(artifact["external_ref"]) <= 2048
            ):
                raise ValueError("closed retained artifact role")
            ref = _reference(EvidenceReference.model_validate(artifact["reference"]))
            role = (kind, artifact["external_ref"])
            if ref.source_id in declared_roles and declared_roles[ref.source_id] != role:
                raise ValueError("conflicting retained artifact role")
            declared_roles[ref.source_id] = role
            refs.append(ref)
        retained_groups.append(tuple(refs))
    if not 1 <= mail_groups <= 6 or not 1 <= slack_groups <= 2:
        raise ValueError("closed retained provider counts")
    if tuple(retained_groups) != inventory.artifact_references:
        raise ValueError("original selected groups omitted or reordered")
    # No artifact/provider callback follows this complete actual scalar snapshot.
    foreign = select(other.id).where(or_(*forbidden)).exists().label("foreign_provenance")
    with session.no_autoflush:
        result = list(
            session.execute(
                select(*Source.__table__.columns, _effective(), foreign)
                .where(or_(Source.id.in_(tuple(hashes)), Source.external_ref == batch_external))
                .limit(MAX_REFERENCES + 1)
            ).mappings()
        )
    if len(result) != len(hashes) or {r["id"] for r in result} != set(hashes):
        raise ValueError("missing or ambiguous final selected sources")
    by_id = {row["id"]: row for row in result}
    final_batch = by_id[inventory.batch_reference.source_id]
    if (
        final_batch["system"] is not SourceSystem.MANUAL
        or final_batch["external_ref"] != batch_external
        or _time(final_batch["captured_at"]) != inventory.original_observed_at
        or by_id[inventory.approval_reference.source_id]["system"]
        is not SourceSystem.USER_INSTRUCTION
    ):
        raise ValueError("final original control roles differ")
    actual_provenance: dict[str, SourceSystem] = {}
    for actual in result:
        row = dict(actual)
        final_role = declared_roles.get(row["id"])
        if final_role is not None and (row["system"], row["external_ref"]) != final_role:
            raise ValueError("final artifact role differs from retained envelope")
        if (
            row["external_ref"] in actual_provenance
            and actual_provenance[row["external_ref"]] is not row["system"]
        ):
            raise ValueError("conflicting current selected source family")
        actual_provenance[row["external_ref"]] = row["system"]
        if (
            row["foreign_provenance"] is not False
            or row["trust_boundary"] is not B.BRAINSTORM
            or row["data_classification"] is not C.CONFIDENTIAL
            or row["effective_classification"] is not C.CONFIDENTIAL
            or row["content_hash"] != hashes[row["id"]]
            or _time(row["captured_at"]) > inventory.original_observed_at
            or _fingerprint(row) != fingerprints[row["id"]]
        ):
            raise ValueError("final source bytes metadata or access changed")
    if actual_provenance != dict(inventory.provenance):
        raise ValueError("current selected provenance omitted or expanded")
    _clean(session)


def load_native_batch_inventory(
    session: Session,
    *,
    artifacts: ArtifactStore,
    batch_reference: EvidenceReference,
    approval_reference: EvidenceReference,
    approved_proposal_raw: bytes,
    as_of: datetime,
) -> NativeBatchInventory:
    result = None
    try:
        result = _load(
            session,
            artifacts=artifacts,
            batch_reference=batch_reference,
            approval_reference=approval_reference,
            approved_proposal_raw=approved_proposal_raw,
            as_of=as_of,
        )
    except Exception:  # noqa: BLE001,S110 - sanitized outside handler
        pass
    if result is None:
        raise NativeBatchInventoryError("native retained inventory held")
    return result


def verify_native_batch_inventory_rows(
    session: Session, *, artifacts: ArtifactStore, inventory: NativeBatchInventory, as_of: datetime
) -> None:
    """Bind retained declared roles and current rows; no authority or recovery.

    This metadata verifier does not reparse native provider originals or reread
    approval artifact bytes. The loader establishes those checks separately.
    Trusted writer/store composition remains required; verifying fixed-false
    flags never authenticates approval or creates processing authority.

    Change detection for columns absent from the retained envelope (e.g. excerpt)
    requires fingerprints produced by load_native_batch_inventory. Arbitrarily
    recomputed caller fingerprints do not establish original private metadata.
    """
    verified = False
    try:
        _verify_rows(session, artifacts=artifacts, inventory=inventory, as_of=as_of)
        verified = True
    except Exception:  # noqa: BLE001,S110 - no private causes
        pass
    if not verified:
        raise NativeBatchInventoryError("native retained inventory held")


@dataclass(frozen=True, repr=False)
class NativeBatchRecoverySelection:
    """Complete metadata selection, never a protected receipt or read authority.

    Native batch integrity plus REQUIRED retained proposal. No private bytes are
    returned. Caller owns authentication, commit and actual encrypted recovery.
    Existing ordinary inventory signatures and 74-reference semantics are unchanged.
    """

    inventory: NativeBatchInventory
    proposal_reference: EvidenceReference
    hashes: tuple[tuple[UUID, str], ...]
    source_fingerprints: tuple[tuple[UUID, str], ...]
    processing_authorized: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)
    facts_confirmed: Literal[False] = field(default=False, init=False)
    complete_history_verified: Literal[False] = field(default=False, init=False)


def _selection_transactions(session: Session) -> tuple[SessionTransaction, ...]:
    outer = session.get_transaction()
    if outer is None or not outer.is_active:
        raise ValueError("live caller transaction required")
    observed = [outer]
    nested = session.get_nested_transaction()
    while nested is not None and nested is not outer:
        if not nested.is_active or nested in observed:
            raise ValueError("live nested transaction required")
        observed.append(nested)
        nested = nested.parent
    return tuple(observed)


def prepare_native_batch_recovery_selection(
    session: Session,
    *,
    artifacts: ArtifactStore,
    inventory: NativeBatchInventory,
    proposal_reference: EvidenceReference,
    approved_proposal_raw: bytes,
    as_of: datetime,
) -> NativeBatchRecoverySelection:
    """Bind an already loaded native inventory to its exact retained proposal.

    Read-only metadata preparation with a final combined full-column/ACL query
    after all store callbacks. Fingerprints compare current rows with the supplied
    loader snapshot; they are not unforgeable original-load provenance or authority.
    Proposal reads bind the supplied batch/digest claims; the later retained
    envelope verifier establishes their relationship, never owner authentication.
    Provider/approval blob presence and byte recovery remain backup/restore checks.
    The proposal's later retention time is preserved;
    it does not change original provider observation or approve processing.
    Generic Source-driven backup includes these committed Sources; no backup,
    encryption, restoration, receipt or commit occurs here. Trusted callbacks
    must not issue SQL or control the caller transaction. Session-API identity/
    liveness changes hold; Core/driver commits are not portably detected, and an
    already durable callback commit cannot be undone. Read-only intent does not
    sandbox callback writes. BaseException propagates; hosts must disable traceback
    local capture/showlocals. No callback sandbox.
    """
    result = None
    try:
        _clean(session)
        _assert_ledger_isolation(session)
        now = _time(as_of)
        if type(inventory) is not NativeBatchInventory:
            raise ValueError("exact inventory metadata required")
        if (
            type(inventory.batch_id) is not UUID
            or type(inventory.hashes) is not tuple
            or not 2 <= len(inventory.hashes) <= MAX_REFERENCES
        ):
            raise ValueError("closed bounded claimed inventory required")
        _digest(inventory.proposal_digest)
        for item in inventory.hashes:
            if type(item) is not tuple or len(item) != 2 or type(item[0]) is not UUID:
                raise ValueError("closed claimed source hash required")
            _digest(item[1])
        if (
            type(approved_proposal_raw) is not bytes
            or not 0 < len(approved_proposal_raw) <= 32_000
            or content_hash_of(approved_proposal_raw) != inventory.proposal_digest
        ):
            raise ValueError("exact original approved bytes required")
        ref = _reference(proposal_reference)
        external = f"native-source-proposal/{inventory.batch_id}"
        if ref.source_id in dict(inventory.hashes) or ref.content_hash != inventory.proposal_digest:
            raise ValueError("distinct exact proposal required")
        proposal = _row(session, ref, SourceSystem.MANUAL, now)
        if proposal["external_ref"] != external or proposal["supersedes_source_id"] is not None:
            raise ValueError("exact proposal family required")
        proposal_fingerprint = _fingerprint(proposal)
        raw = load_retained_native_proposal(
            session,
            artifacts=artifacts,
            proposal_reference=ref,
            batch_id=inventory.batch_id,
            expected_proposal_hash=inventory.proposal_digest,
            as_of=now,
        )
        if raw != approved_proposal_raw or content_hash_of(raw) != inventory.proposal_digest:
            raise ValueError("original proposal differs")
        # New composition guards every Session-API transaction boundary around
        # legacy verifier callbacks without changing that verifier's semantics.
        transactions = _selection_transactions(session)
        _verify_rows(session, artifacts=artifacts, inventory=inventory, as_of=now)
        after = _selection_transactions(session)
        if len(after) != len(transactions) or any(
            left is not right for left, right in zip(transactions, after, strict=True)
        ):
            raise ValueError("store changed caller transaction")
        hashes = dict(inventory.hashes)
        fingerprints = dict(inventory.source_fingerprints)
        hashes[ref.source_id] = ref.content_hash
        fingerprints[ref.source_id] = proposal_fingerprint
        provenance = dict(inventory.provenance)
        if external in provenance:
            raise ValueError("conflicting proposal provenance")
        provenance[external] = SourceSystem.MANUAL
        if len(hashes) > MAX_REFERENCES + 1 or set(hashes) != set(fingerprints):
            raise ValueError("bounded complete union required")
        other = aliased(Source)
        foreign = (
            select(other.id)
            .where(
                or_(
                    *[
                        (other.external_ref == name)
                        & or_(other.system != kind, other.trust_boundary != B.BRAINSTORM)
                        for name, kind in provenance.items()
                    ]
                )
            )
            .exists()
            .label("foreign_provenance")
        )
        with session.no_autoflush:
            rows = list(
                session.execute(
                    select(*Source.__table__.columns, _effective(), foreign)
                    .where(
                        or_(
                            Source.id.in_(tuple(hashes)),
                            Source.external_ref == external,
                            Source.external_ref == f"native-source-batch/{inventory.batch_id}",
                        )
                    )
                    .limit(MAX_REFERENCES + 2)
                ).mappings()
            )
        if len(rows) != len(hashes) or {row["id"] for row in rows} != set(hashes):
            raise ValueError("missing or ambiguous complete selection")
        actual_provenance: dict[str, SourceSystem] = {}
        for actual in rows:
            row = dict(actual)
            if (
                row["foreign_provenance"] is not False
                or row["trust_boundary"] is not B.BRAINSTORM
                or row["data_classification"] is not C.CONFIDENTIAL
                or row["effective_classification"] is not C.CONFIDENTIAL
                or row["content_hash"] != hashes[row["id"]]
                or _fingerprint(row) != fingerprints[row["id"]]
                or _time(row["captured_at"])
                > (now if row["id"] == ref.source_id else inventory.original_observed_at)
            ):
                raise ValueError("final complete selection changed")
            actual_provenance[row["external_ref"]] = row["system"]
        if actual_provenance != provenance:
            raise ValueError("complete selected provenance differs")
        _clean(session)
        result = NativeBatchRecoverySelection(
            inventory,
            ref,
            tuple(sorted(hashes.items(), key=lambda item: str(item[0]))),
            tuple(sorted(fingerprints.items(), key=lambda item: str(item[0]))),
        )
    except Exception:  # noqa: BLE001,S110 - fixed failure outside private handler
        pass
    if result is None:
        raise NativeBatchInventoryError("native complete recovery selection held")
    return result
