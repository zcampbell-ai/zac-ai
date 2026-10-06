"""Trusted-caller, single-writer native capture; no authority or commit issuance.

Approval row/hash checks prove referenced evidence integrity only. The trusted
host must authenticate the actual exact human decision, serialize first inserts
and consume its one attempt before effects. No public route may turn arbitrary
supplied Sources/proposal hashes into approval. Caller owns commit and recovery.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from zacai.connectors.gmail_wire import GmailScope
from zacai.connectors.slack_wire import HistorySelection, RepliesSelection
from zacai.ingestion.artifact_store import ArtifactStore, canonical_bytes, content_hash_of
from zacai.ingestion.native_batch_envelope import compose_native_batch_envelope
from zacai.ingestion.native_source_preparation import (
    SourceArtifactPlan,
    prepare_gmail_source,
    prepare_slack_sources,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceClassificationElevation, SourceSystem
from zacai.state_repository import (
    get_effective_source_classification,
    record_source,
    source_classification_elevation_strength,
)


class NativeBatchCaptureError(RuntimeError):
    """Fixed diagnostic without private cause or SQL/provider details."""


@dataclass(frozen=True, repr=False)
class GmailCaptureInput:
    scope: GmailScope
    profile_response: bytes
    message_response: bytes
    expected_message_id: str


@dataclass(frozen=True, repr=False)
class SlackCaptureInput:
    selection: HistorySelection | RepliesSelection
    account_response: bytes
    page_response: bytes


@dataclass(frozen=True, repr=False)
class NativeBatchCaptureReceipt:
    batch_reference: EvidenceReference
    approval_reference: EvidenceReference
    artifact_references: tuple[tuple[EvidenceReference, ...], ...]
    new_source_ids: frozenset[UUID]
    original_observed_at: datetime
    committed: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)
    permission_granted: Literal[False] = field(default=False, init=False)


def prepare_native_batch_proposal(*, batch_id: UUID, gmail_inputs: tuple[GmailCaptureInput, ...],
                                  slack_inputs: tuple[SlackCaptureInput, ...]) -> bytes:
    """Exact existing-wire capture snapshot, not permission to fetch those wires."""
    result = None
    try:
        if (type(batch_id) is not UUID or type(gmail_inputs) is not tuple or not 1 <= len(gmail_inputs) <= 6
            or type(slack_inputs) is not tuple or not 1 <= len(slack_inputs) <= 2):
            raise ValueError('closed batch')
        gmail: list[dict[str, object]] = []
        slack: list[dict[str, object]] = []
        for item in gmail_inputs:
            if type(item) is not GmailCaptureInput or type(item.scope) is not GmailScope:
                raise ValueError('closed mail input')
            scope = item.scope
            if scope.boundary is not B.BRAINSTORM or scope.classification is not C.CONFIDENTIAL:
                raise ValueError('fixed proposal family')
            gmail.append({'account_ref':scope.account_ref,'expected_email':scope.expected_email,
                'message_id':item.expected_message_id,'profile_digest':_hash(item.profile_response),
                'wire_digest':_hash(item.message_response),
                'boundary':scope.boundary.value,'classification':scope.classification.value,
                'requestor_boundaries':sorted(v.value for v in scope.requestor_boundaries),
                'allowed_classifications':sorted(v.value for v in scope.allowed_classifications)})
        for slack_item in slack_inputs:
            if type(slack_item) is not SlackCaptureInput or type(slack_item.selection) not in (HistorySelection, RepliesSelection):
                raise ValueError('closed Slack input')
            slack.append({'selection':slack_item.selection.model_dump(mode='json'),
                'account_digest':_hash(slack_item.account_response),'wire_digest':_hash(slack_item.page_response)})
        if len({(x['account_ref'],x['expected_email']) for x in gmail}) != 1:
            raise ValueError('one mailbox')
        if len({canonical_bytes(x.selection.account.model_dump(mode='json')) for x in slack_inputs}) != 1:
            raise ValueError('one Slack account')
        if len({x.profile_response for x in gmail_inputs}) != 1:
            raise ValueError('shared Gmail profile snapshot differs')
        if len({x.account_response for x in slack_inputs}) != 1:
            raise ValueError('shared Slack account snapshot differs')
        if len({x.expected_message_id for x in gmail_inputs}) != len(gmail_inputs):
            raise ValueError('duplicate mail selection')
        if len({canonical_bytes(x.selection.model_dump(mode='json')) for x in slack_inputs}) != len(slack_inputs):
            raise ValueError('duplicate Slack selection')
        result = canonical_bytes({'format':'zac-native-batch-capture-proposal-v1','batch_id':str(batch_id),
            'status':'PROPOSED_NOT_APPROVED','boundary':B.BRAINSTORM.value,'classification':C.CONFIDENTIAL.value,
            'gmail':gmail,'slack':slack,'purpose':'CANDIDATE_CONTEXT_ONLY','provider_calls':0,
            'model_calls':0,'business_fact_changes':False,'new_permission':False})
    except Exception:  # noqa: BLE001,S110 - sanitize outside handler
        pass
    if result is None:
        raise NativeBatchCaptureError('native batch proposal held')
    return result


def record_native_batch(session: Session, *, artifacts: ArtifactStore, proposal_raw: bytes,
                        approved_proposal_hash: str, approval_reference: EvidenceReference,
                        gmail_inputs: tuple[GmailCaptureInput, ...], slack_inputs: tuple[SlackCaptureInput, ...],
                        captured_at: datetime) -> NativeBatchCaptureReceipt:
    """Append exact evidence under caller transaction; no commit/protect/approval.

    Host authenticates approved_proposal_hash externally. Existing approval
    Source integrity is necessary but insufficient to authorize ingestion.
    Replay preserves the first batch observation and original Source timestamps.
    Same UUID cannot change proposal, input wire or approval reference.

    Requires a clean caller ORM unit of work (no pending new/dirty/deleted
    objects). On any hold the host must roll back its outer transaction before
    reuse; this uncommitted primitive does not promise connection recovery from
    a failed savepoint RELEASE. Trusted artifact callbacks that explicitly
    flush or issue direct SQL are not sandboxed by the pending-state checks.
    """
    result = None
    try:
        if (type(captured_at) is not datetime or captured_at.utcoffset() is None or type(proposal_raw) is not bytes or len(proposal_raw) > 32_000
            or type(approved_proposal_hash) is not str):
            raise ValueError('capture observation')
        _clean(session)
        payload = json.loads(proposal_raw)
        batch_id = UUID(payload['batch_id'])
        expected = prepare_native_batch_proposal(batch_id=batch_id,gmail_inputs=gmail_inputs,slack_inputs=slack_inputs)
        if proposal_raw != expected or approved_proposal_hash != content_hash_of(expected):
            raise ValueError('exact approved snapshot')
        initial_approval = _approval(session,artifacts,approval_reference)
        approval_expected = _snapshot_values(initial_approval)
        if initial_approval.captured_at > captured_at:
            raise ValueError('approval observation is future')
        ref = f'native-source-batch/{batch_id}'
        existing = _metadata(session,ref)
        observed = captured_at.astimezone(UTC)
        existing_raw = None
        if existing is not None:
            existing_raw = _bytes(session,artifacts,existing)
            if len(existing_raw) > 256_000:
                raise ValueError('metadata capacity')
            previous = json.loads(existing_raw)
            if (previous['format'] != 'zac-native-selected-batch-evidence-v1'
                or previous['role'] != 'CANDIDATE_CONTEXT'
                or any(previous[k] is not False for k in ('permission_granted','recovery_verified','facts_confirmed','complete_history_verified'))):
                raise ValueError('metadata disposition')
            observed = datetime.fromisoformat(previous['observed_at'])
            if (observed.utcoffset() is None or observed > captured_at
                or existing.captured_at != observed or previous['proposal_digest'] != approved_proposal_hash
                or previous['batch_id'] != str(batch_id)
                or previous['approval_reference'] != approval_reference.model_dump(mode='json')):
                raise ValueError('immutable batch conflict')
        if initial_approval.captured_at > observed:
            raise ValueError('approval evidence postdates original batch')
        prepared = tuple(prepare_gmail_source(scope=i.scope,profile_response=i.profile_response,
            message_response=i.message_response,expected_message_id=i.expected_message_id,captured_at=observed) for i in gmail_inputs)
        prepared += tuple(prepare_slack_sources(selection=i.selection,account_response=i.account_response,
            page_response=i.page_response,captured_at=observed,boundary=B.BRAINSTORM,classification=C.CONFIDENTIAL,
            requestor_boundaries=frozenset({B.BRAINSTORM}),allowed_classifications=frozenset({C.CONFIDENTIAL})) for i in slack_inputs)
        # Enforce batch limits without fabricating canonical Source references.
        if sum(len(i.artifacts)-2 for i in prepared if i.provider == 'slack') > 50:
            raise ValueError('message count')
        if sum(len(p.original_bytes) for i in prepared for p in i.artifacts) > 4 * 1024 * 1024:
            raise ValueError('batch bytes')
        plans = tuple(p for item in prepared for p in item.artifacts)
        shared_plans: dict[tuple[SourceSystem, str], str] = {}
        for plan in plans:
            key = (plan.system, plan.external_ref)
            if key in shared_plans and shared_plans[key] != plan.content_hash:
                raise ValueError('divergent intra-batch source identity')
            shared_plans[key] = plan.content_hash
        for plan in plans:
            _lineage(session,artifacts,plan,observed)
        locations = {(p.system,p.external_ref,p.content_hash):_put(session,artifacts,p.original_bytes) for p in plans}
        with session.begin_nested():
            _approval(session,artifacts,approval_reference)
            current = _metadata(session,ref)
            if (current is None) != (existing is None) or (current is not None and _bytes(session,artifacts,current) != existing_raw):
                raise ValueError('batch changed')
            for plan in plans:
                _lineage(session,artifacts,plan,observed)
            refs = []
            new = set()
            expected_rows = {initial_approval.id: approval_expected}
            for item in prepared:
                group = []
                for plan in item.artifacts:
                    source, was_new = record_source(session,trust_boundary=B.BRAINSTORM,data_classification=C.CONFIDENTIAL,
                        system=plan.system,external_ref=plan.external_ref,content_hash=plan.content_hash,
                        content_location=locations[(plan.system,plan.external_ref,plan.content_hash)],captured_at=observed)
                    _valid_source(session,source,plan.system,plan.external_ref,plan.content_hash)
                    expected_rows[source.id] = _snapshot_values(source)
                    if was_new:
                        new.add(source.id)
                    group.append(_reference(source))
                refs.append(tuple(group))
            raw = compose_native_batch_envelope(batch_id=batch_id,proposal_digest=approved_proposal_hash,
                approval_reference=approval_reference,prepared=prepared,artifact_references=tuple(refs),observed_at=observed)
            if len(raw) > 256_000:
                raise ValueError('metadata capacity')
            if existing_raw is not None and raw != existing_raw:
                raise ValueError('immutable envelope conflict')
            source,was_new = record_source(session,trust_boundary=B.BRAINSTORM,data_classification=C.CONFIDENTIAL,
                system=SourceSystem.MANUAL,external_ref=ref,content_hash=content_hash_of(raw),
                content_location=_put(session,artifacts,raw),captured_at=observed)
            _valid_source(session,source,SourceSystem.MANUAL,ref,content_hash_of(raw))
            if was_new:
                new.add(source.id)
            expected_rows[source.id] = _snapshot_values(source)
            # Last artifact callback precedes every final canonical class check.
            _approval(session,artifacts,approval_reference)
            _clean(session)
            _final_snapshot(session, expected_rows, plans, ref, observed)
            receipt = NativeBatchCaptureReceipt(_reference(source),approval_reference,tuple(refs),frozenset(new),observed)
        # Flush/RELEASE failures on context exit must never leave a success result.
        result = receipt
    except Exception:  # noqa: BLE001,S110 - no private DB/source cause
        pass
    if result is None:
        raise NativeBatchCaptureError('native batch capture held')
    return result


def _hash(raw: bytes) -> str:
    if type(raw) is not bytes or not 0 < len(raw) <= 4 * 1024 * 1024:
        raise ValueError('wire bound')
    return content_hash_of(raw)


def _put(session: Session, store: ArtifactStore, raw: bytes) -> str:
    digest = content_hash_of(raw)
    location = store.put(B.BRAINSTORM,digest,raw)
    _clean(session)
    returned = store.get(B.BRAINSTORM,location)
    _clean(session)
    if returned != raw:
        raise ValueError('artifact roundtrip')
    return location


def _valid_source(session: Session, source: Source, system: SourceSystem, ref: str, digest: str) -> None:
    if (source.system is not system or source.external_ref != ref or source.content_hash != digest
        or source.trust_boundary is not B.BRAINSTORM or source.data_classification is not C.CONFIDENTIAL
        or get_effective_source_classification(session,source_id=source.id) is not C.CONFIDENTIAL):
        raise ValueError('canonical source mismatch')


def _bytes(session: Session, store: ArtifactStore, source: Source) -> bytes:
    if source.content_hash is None or source.content_location is None:
        raise ValueError('missing artifact')
    raw = store.get(B.BRAINSTORM,source.content_location)
    _clean(session)
    if content_hash_of(raw) != source.content_hash:
        raise ValueError('stored source hash')
    return raw


def _metadata(session: Session, ref: str) -> Source | None:
    rows = list(session.scalars(select(Source).where(Source.external_ref == ref).limit(2)))
    if not rows:
        return None
    if len(rows) != 1:
        raise ValueError('ambiguous batch provenance')
    row = rows[0]
    if row.content_hash is None:
        raise ValueError('metadata hash')
    _valid_source(session,row,SourceSystem.MANUAL,ref,row.content_hash)
    return row


def _approval(session: Session, store: ArtifactStore, ref: EvidenceReference) -> Source:
    if type(ref) is not EvidenceReference:
        raise ValueError('approval reference type')
    ref = EvidenceReference.model_validate(ref)
    source = session.get(Source,ref.source_id)
    if (source is None or ref.trust_boundary is not B.BRAINSTORM
        or ref.effective_classification is not C.CONFIDENTIAL or source.external_ref is None):
        raise ValueError('approval evidence')
    _valid_source(session,source,SourceSystem.USER_INSTRUCTION,source.external_ref,ref.content_hash)
    _bytes(session,store,source)
    return source


def _lineage(session: Session, store: ArtifactStore, plan: SourceArtifactPlan, observed: datetime) -> None:
    # No full historical enumeration: only wrong-family existence, exact replay
    # and actual structural tips matter. Each query has a sentinel bound.
    foreign = list(session.scalars(select(Source.id).where(Source.external_ref == plan.external_ref,
        or_(Source.system != plan.system,Source.trust_boundary != B.BRAINSTORM)).limit(1)))
    if foreign:
        raise ValueError('foreign provenance')
    replay = list(session.scalars(select(Source).where(Source.external_ref == plan.external_ref,
        Source.system == plan.system,Source.trust_boundary == B.BRAINSTORM,
        Source.content_hash == plan.content_hash).limit(2)))
    if len(replay) > 1:
        raise ValueError('ambiguous exact replay')
    superseded = select(Source.supersedes_source_id).where(Source.supersedes_source_id.is_not(None)).correlate(None)
    tips = list(session.scalars(select(Source).where(Source.external_ref == plan.external_ref,
        Source.system == plan.system,Source.trust_boundary == B.BRAINSTORM,Source.id.not_in(superseded)).limit(2)))
    if len(tips) > 1:
        raise ValueError('ambiguous current tip')
    if replay:
        if replay[0].captured_at > observed:
            raise ValueError('exact replay Source postdates batch observation')
        _valid_source(session,replay[0],plan.system,plan.external_ref,plan.content_hash)
        if _bytes(session,store,replay[0]) != plan.original_bytes:
            raise ValueError('retained original artifact mismatch')
    if not tips:
        existing = list(session.scalars(select(Source.id).where(Source.external_ref == plan.external_ref).limit(1)))
        if existing:
            raise ValueError('existing lineage has no tip')
    else:
        tip = tips[0]
        if tip.content_hash is None:
            raise ValueError('tip hash')
        _valid_source(session,tip,plan.system,plan.external_ref,tip.content_hash)
        _bytes(session,store,tip)
        if not replay and tip.captured_at > observed:
            raise ValueError('new revision predates current tip')


def _reference(source: Source) -> EvidenceReference:
    if source.content_hash is None:
        raise ValueError('missing digest')
    return EvidenceReference(source_id=source.id,content_hash=source.content_hash,
        trust_boundary=B.BRAINSTORM,effective_classification=C.CONFIDENTIAL)


# Scalar values detach the expected immutable row from SQLAlchemy's identity map.
SnapshotValues = tuple[SourceSystem, B, C, str | None, str | None, str | None, datetime, UUID | None]


def _snapshot_values(source: Source) -> SnapshotValues:
    return (source.system,source.trust_boundary,source.data_classification,source.external_ref,
            source.content_hash,source.content_location,source.captured_at,source.supersedes_source_id)


def _final_snapshot(session: Session, expected: dict[UUID, SnapshotValues],
                    plans: tuple[SourceArtifactPlan, ...], metadata_ref: str, observed: datetime) -> None:
    """Callback-free scalar metadata/effective ACL snapshot, never ORM refresh.

    Raw Source updates are prohibited by the canonical append-only SQL trigger.
    This is strict current-row/corruption defense; live elevations are policy.
    The host still owns final owner/clock/commit and independent recovery.
    """
    latest = (select(SourceClassificationElevation.new_classification)
        .where(SourceClassificationElevation.source_id == Source.id)
        .order_by(
            source_classification_elevation_strength().desc(),
            SourceClassificationElevation.elevated_at.desc(),
        ).limit(1).correlate(Source).scalar_subquery())
    effective = func.coalesce(latest, Source.data_classification).label('effective_classification')
    provenance = {p.external_ref:p.system for p in plans}
    provenance[metadata_ref] = SourceSystem.MANUAL
    superseded_ids = select(Source.supersedes_source_id).where(Source.supersedes_source_id.is_not(None)).correlate(None)
    is_tip = Source.id.not_in(superseded_ids).label('is_current_tip')
    foreign_conditions = [((Source.external_ref == ref) &
        ((Source.system != system) | (Source.trust_boundary != B.BRAINSTORM))) for ref,system in provenance.items()]
    materialization_bound = len(expected) + len(provenance)
    statement = select(Source.id,Source.system,Source.trust_boundary,Source.data_classification,
        Source.external_ref,Source.content_hash,Source.content_location,Source.captured_at,
        Source.supersedes_source_id,effective,is_tip).where(or_(Source.id.in_(expected),
            (Source.external_ref.in_(provenance) & is_tip),Source.external_ref == metadata_ref,
            *foreign_conditions)).limit(materialization_bound + 1)
    with session.no_autoflush:
        rows = list(session.execute(statement))
    if len(rows) > materialization_bound or len({r[0] for r in rows}) != len(rows):
        raise ValueError('bounded current metadata snapshot')
    if sum(r[4] == metadata_ref for r in rows) != 1:
        raise ValueError('current batch metadata ambiguity')
    current = {r[0]:r for r in rows}
    for sid,values in expected.items():
        row = current.get(sid)
        if (row is None or tuple(row[1:9]) != values or row[9] is not C.CONFIDENTIAL
            or row[3] is not C.CONFIDENTIAL or row[7] > observed):
            raise ValueError('current source metadata or ACL changed')
    tips: dict[str, list[object]] = {ref:[] for ref in provenance}
    for row in rows:
        ref = row[4]
        if ref not in provenance:
            continue
        if row[1] is not provenance[ref] or row[2] is not B.BRAINSTORM:
            raise ValueError('current foreign provenance')
        if row[10]:
            tips[ref].append(row)
            if row[3] is not C.CONFIDENTIAL or row[9] is not C.CONFIDENTIAL:
                raise ValueError('current tip classification')
    if any(len(value) != 1 for value in tips.values()):
        raise ValueError('current ambiguous lineage')



def _clean(session: Session) -> None:
    """Reject unexpected pending ORM work; never flush unrelated/fact writes.

    Not a sandbox against arbitrary trusted Python issuing SQL directly. Each
    writer record_source flush finishes its own Source before the next callback.
    """
    if session.new or session.dirty or session.deleted:
        raise ValueError('native capture requires clean pending ORM state')
