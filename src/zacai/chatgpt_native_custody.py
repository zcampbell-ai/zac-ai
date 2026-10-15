"""Explicit observed native-view custody only; no processing or recovery grant.

Public proposals are comparison data. Only the original private once-use actual
POST action may enter capture. No mounted route or owner permission is created.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime
from threading import RLock
from time import monotonic as _MONOTONIC
from typing import Literal, Self
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker
from starlette.requests import Request

from zacai.chatgpt_native_source import LoadedChatGPTNativeView, load_chatgpt_native_view_pair
from zacai.chatgpt_native_view import (
    MAX_COMPANION_BYTES,
    MAX_WRAPPER_BYTES,
    ChatGPTNativeViewCompanion,
    prepare_chatgpt_native_view,
)
from zacai.claude_original_capture import (
    ClaudeArtifactRootIdentity,
    _artifact_profile,
    _root_check,
)
from zacai.gateway import ActionRequest, ActionType, GatewayOutcome, evaluate_gateway
from zacai.host_clock import HostObservedClock
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contextual_storage import _fragment_rows
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.intelligence.fragment_publication_generation import _same_output_commit_transaction
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.interfaces.named_session_binding import NamedSessionOperation, VerifiedNamedSession
from zacai.interfaces.owner_store import OwnerGrantStore
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.interfaces.private_web import _USER, _cookie
from zacai.policy import AccessRequest, Destination
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _lock
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source


class NativeViewCustodyUnavailable(ValueError):
    """Consumed attempt without acknowledged capture; no automatic retry."""


class NativeViewCustodyUncertain(NativeViewCustodyUnavailable):
    """Commit may exist; preserve custody and reconcile manually, never retry."""


class NativeViewCustodyProposalV1(Contract):
    format: Literal["zac-chatgpt-native-custody-proposal-v1"]
    capture_id: UUID
    original_reference: EvidenceReference
    companion_reference: EvidenceReference
    original_bytes: int = Field(gt=0, le=2_000_000, strict=True)
    companion: ChatGPTNativeViewCompanion
    actor_issuer: str = Field(min_length=1, max_length=255)
    actor_subject: str = Field(min_length=1, max_length=255)
    original_session_binding: Digest
    original_session_issued_at: AwareDatetime
    original_session_expires_at: AwareDatetime
    prepared_at: AwareDatetime
    expires_at: AwareDatetime
    processing_authorized: Literal[False] = False
    recovery_verified: Literal[False] = False
    current_facts_verified: Literal[False] = False

    @field_validator(
        "processing_authorized", "recovery_verified", "current_facts_verified", mode="before"
    )
    @classmethod
    def false_only(cls, value: object) -> object:
        if value is not False:
            raise ValueError("custody never grants authority")
        return value

    @model_validator(mode="after")
    def exact_pair(self) -> Self:
        refs = (self.original_reference, self.companion_reference)
        companion_raw = canonical_bytes(self.companion.model_dump(mode="json"))
        if (
            len(companion_raw) > MAX_COMPANION_BYTES
            or self.capture_id.int == 0
            or any(r.source_id.int == 0 for r in refs)
            or refs[0].source_id == refs[1].source_id
            or refs[0].trust_boundary != refs[1].trust_boundary
            or refs[0].trust_boundary not in {B.PERSONAL, B.BRAINSTORM}
            or refs[0].effective_classification not in {C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}
            or refs[1].effective_classification != refs[0].effective_classification
            or self.companion.original_reference != refs[0]
            or self.companion.original_bytes != self.original_bytes
            or content_hash_of(companion_raw) != refs[1].content_hash
            or self.companion.projection_observed_at != self.prepared_at
            or not self.original_session_issued_at
            <= self.prepared_at
            < self.expires_at
            <= self.original_session_expires_at
        ):
            raise ValueError("exact assigned whole-original custody proposal required")
        return self


def native_view_custody_proposal_digest(proposal: NativeViewCustodyProposalV1) -> str:
    result = None
    try:
        if type(proposal) is not NativeViewCustodyProposalV1:
            raise TypeError("exact native custody proposal required")
        checked = NativeViewCustodyProposalV1.model_validate(proposal.model_dump(mode="json"))
        result = content_hash_of(canonical_bytes(checked.model_dump(mode="json")))
    except BaseException:  # noqa: BLE001,S110 - fixed private-safe diagnostic.
        pass
    if result is None:
        raise NativeViewCustodyUnavailable("native custody proposal digest unavailable")
    return result


def _host(inputs: NamedOwnerHostInputs, operation: NamedSessionOperation) -> None:
    if (
        type(inputs) is not NamedOwnerHostInputs
        or type(inputs.owners) is not OwnerGrantStore
        or type(inputs.clock) is not HostObservedClock
        or type(operation) is not NamedSessionOperation
        or operation.host_clock is not inputs.clock
        or operation._source._sessions is not inputs.sessions
        or operation._source._clock is not inputs.clock
        or operation._source._owner != inputs.owner
        or getattr(inputs.owner, "__self__", None) is not inputs.owners
        or getattr(inputs.owner, "__func__", None) is not OwnerGrantStore.load
        or json.loads(operation._source._context)
        != {"origin": inputs.origin, "client_id": inputs.client_id}
    ):
        raise ValueError("actual enrolled host/operation required")


def _scope(current: VerifiedNamedSession, reference: EvidenceReference) -> None:
    if not any(
        scope.boundary is reference.trust_boundary
        and reference.effective_classification in scope.classifications
        for scope in current.principal.scopes
    ):
        raise ValueError("current exact assigned custody scope required")
    decision = evaluate_gateway(
        ActionRequest(
            action_type=ActionType.READ_DATA,
            access=AccessRequest(
                data_boundary=reference.trust_boundary,
                data_classification=reference.effective_classification,
                requestor_boundaries=frozenset({reference.trust_boundary}),
                destination=Destination.LOCAL,
            ),
            description="read and retain exact owner-selected native-view custody only",
        )
    )
    if decision.outcome is not GatewayOutcome.ALLOW:
        raise ValueError("current local custody read unavailable")


def _owner(
    inputs: NamedOwnerHostInputs,
    operation: NamedSessionOperation,
    proposal: NativeViewCustodyProposalV1,
) -> VerifiedNamedSession:
    _host(inputs, operation)
    inputs.clock()
    actual = operation.recheck(proposal.original_session_binding)
    with inputs.clock._lock:
        now = inputs.clock._last
    if (
        now is None
        or (actual.principal.identity.issuer, actual.principal.identity.subject)
        != (proposal.actor_issuer, proposal.actor_subject)
        or actual.issued_at != proposal.original_session_issued_at
        or actual.effective_expires_at != proposal.original_session_expires_at
        or not proposal.prepared_at <= now < proposal.expires_at
    ):
        raise ValueError("original signed custody owner/window unavailable")
    _scope(actual, proposal.original_reference)
    return actual


def prepare_native_view_custody_proposal(
    *,
    inputs: NamedOwnerHostInputs,
    operation: NamedSessionOperation,
    original_raw: bytes,
    expected_original_hash: str,
    capture_id: UUID,
    original_source_id: UUID,
    companion_source_id: UUID,
    boundary: B,
    whole_original_classification: C,
    expected_thread_id: str,
    selected_pointer: str,
    start: int,
    end: int,
    expires_at: datetime,
) -> NativeViewCustodyProposalV1:
    """Comparison-only exact proposal. Assigned whole scope is explicit, never inferred."""
    result = None
    try:
        _host(inputs, operation)
        inputs.clock()
        current = operation.establish()
        with inputs.clock._lock:
            at = inputs.clock._last
        if (
            type(original_raw) is not bytes
            or not 0 < len(original_raw) <= MAX_WRAPPER_BYTES
            or content_hash_of(original_raw) != expected_original_hash
            or at is None
        ):
            raise ValueError("exact whole wrapper required")
        original = EvidenceReference(
            source_id=original_source_id,
            trust_boundary=boundary,
            effective_classification=whole_original_classification,
            content_hash=expected_original_hash,
        )
        _scope(current, original)
        companion = prepare_chatgpt_native_view(
            original_raw,
            original_reference=original,
            expected_thread_id=expected_thread_id,
            selected_pointer=selected_pointer,
            start=start,
            end=end,
            observed_at=at,
        )
        reference = EvidenceReference(
            source_id=companion_source_id,
            trust_boundary=boundary,
            effective_classification=whole_original_classification,
            content_hash=content_hash_of(canonical_bytes(companion.model_dump(mode="json"))),
        )
        value = NativeViewCustodyProposalV1(
            format="zac-chatgpt-native-custody-proposal-v1",
            capture_id=capture_id,
            original_reference=original,
            companion_reference=reference,
            original_bytes=len(original_raw),
            companion=companion,
            actor_issuer=current.principal.identity.issuer,
            actor_subject=current.principal.identity.subject,
            original_session_binding=current.binding_digest,
            original_session_issued_at=current.issued_at,
            original_session_expires_at=current.effective_expires_at,
            prepared_at=at,
            expires_at=expires_at,
        )
        _owner(inputs, operation, value)
        result = value
    except BaseException:  # noqa: BLE001,S110 - fixed safe interruption diagnostic.
        pass
    if result is None:
        raise NativeViewCustodyUnavailable("native custody proposal unavailable")
    return result


@dataclass(frozen=True, repr=False)
class _NativeCustodyObservation:
    proposal_digest: str
    proposal: NativeViewCustodyProposalV1
    snapshot: NativeViewCustodyProposalV1
    inputs: NamedOwnerHostInputs
    operation: NamedSessionOperation
    observed_at: datetime


_SEAL = object()


class _PostedNativeCustody:
    def __init__(self) -> None:
        raise NativeViewCustodyUnavailable("validated original native custody action required")

    _seal: object
    _original: _PostedNativeCustody
    _observation: _NativeCustodyObservation
    _used: bool
    _lock: RLock


def observe_native_view_custody_post(
    *,
    request: Request,
    body: bytes,
    inputs: NamedOwnerHostInputs,
    operation: NamedSessionOperation,
    proposal: NativeViewCustodyProposalV1,
) -> _PostedNativeCustody:
    """Actual POST seam only; no mount, GET effects, caller approval flag or reload."""
    result = None
    try:
        _host(inputs, operation)
        digest = native_view_custody_proposal_digest(proposal)
        if (
            type(request) is not Request
            or type(body) is not bytes
            or not 0 < len(body) <= 2048
            or request.method != "POST"
            or request.url.path != "/capture-chatgpt-native-view"
            or request.scope.get("query_string", b"")
            or request.headers.getlist("host") != [urlsplit(inputs.origin).netloc]
            or request.headers.getlist("origin") != [inputs.origin]
            or request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]
        ):
            raise ValueError("closed actual native custody POST required")
        cookie = _cookie(request, _USER)
        actual = _owner(inputs, operation, proposal)
        observed = operation._source.for_cookie(cookie).establish()
        if observed != actual:
            raise ValueError("actual original cookie required")
        fields = parse_qs(body.decode("ascii"), keep_blank_values=True, strict_parsing=True)
        if set(fields) != {"action", "csrf", "proposal_digest"} or any(
            len(v) != 1 for v in fields.values()
        ):
            raise ValueError("closed custody form required")
        inputs.clock()
        actual = _owner(inputs, operation, proposal)
        with inputs.clock._lock:
            at = inputs.clock._last
        session = inputs.sessions.peek_user(cookie, at) if at is not None else None
        if (
            session is None
            or session.identity != actual.principal.identity
            or fields["action"][0] != "capture_native_view_custody"
            or fields["proposal_digest"][0] != digest
            or re.fullmatch(r"[A-Za-z0-9_-]{43}", fields["csrf"][0]) is None
            or not secrets.compare_digest(fields["csrf"][0], session.csrf)
            or at is None
        ):
            raise ValueError("original exact displayed target/CSRF required")
        token = object.__new__(_PostedNativeCustody)
        token._seal, token._original, token._used = _SEAL, token, False
        token._lock = RLock()
        snapshot = NativeViewCustodyProposalV1.model_validate(proposal.model_dump(mode="json"))
        if native_view_custody_proposal_digest(snapshot) != digest:
            raise ValueError("unchanged independent observed proposal required")
        token._observation = _NativeCustodyObservation(
            digest, proposal, snapshot, inputs, operation, at
        )
        result = token
    except BaseException:  # noqa: BLE001,S110 - fixed safe interruption diagnostic.
        pass
    if result is None:
        raise NativeViewCustodyUnavailable("validated original native custody action unavailable")
    return result


def _consume(
    action: _PostedNativeCustody, proposal: NativeViewCustodyProposalV1
) -> _NativeCustodyObservation:
    if (
        type(action) is not _PostedNativeCustody
        or action._original is not action
        or action._seal is not _SEAL
    ):
        raise ValueError("original private custody action required")
    with action._lock:
        if action._used or action._observation.proposal is not proposal:
            raise ValueError("original once-only proposal/action required")
        action._used = True  # Irreversible before owner/filesystem/canonical callbacks.
    observation = action._observation
    if native_view_custody_proposal_digest(proposal) != observation.proposal_digest:
        raise ValueError("unchanged observed custody proposal required")
    _owner(observation.inputs, observation.operation, observation.snapshot)
    return observation


def _names(proposal: NativeViewCustodyProposalV1) -> tuple[str, str]:
    return (
        f"chatgpt-native-view-original/{proposal.capture_id}",
        f"chatgpt-native-view-companion/{proposal.capture_id}",
    )


def _occupied(session: Session, proposal: NativeViewCustodyProposalV1) -> bool:
    names = _names(proposal)
    ids = (proposal.original_reference.source_id, proposal.companion_reference.source_id)
    with session.no_autoflush:
        return bool(
            session.scalar(
                select(Source.id)
                .where(
                    (Source.id.in_(ids))
                    | ((Source.system == SourceSystem.MANUAL) & Source.external_ref.in_(names))
                )
                .limit(1)
            )
        )


def _standard_factory(factory: sessionmaker[Session]) -> None:
    """Require the actual SQLAlchemy-generated standard Session subclass/options.

    Default sessionmaker.class_ is a new subclass, not Session itself. Custom
    subclasses, method overrides and nonstandard options are not admitted.
    Pure tests explicitly substitute this guard alongside physical SQL seams.
    """
    if type(factory) is not sessionmaker:
        raise ValueError("standard canonical Session factory required")
    cls = factory.class_
    if (
        cls.__bases__ != (Session,)
        or cls.__name__ != Session.__name__
        or dict(cls.__dict__) != {"__module__": Session.__module__, "__doc__": None}
        or set(factory.__dict__) != {"kw", "class_"}
        or set(factory.kw) - {"bind", "autoflush", "expire_on_commit", "future"}
        or type(factory.kw.get("autoflush")) is not bool
        or type(factory.kw.get("expire_on_commit")) is not bool
        or ("future" in factory.kw and factory.kw["future"] is not True)
    ):
        raise ValueError("standard unmodified Session factory/options required")
    engine = factory.kw.get("bind")
    if not isinstance(engine, Engine):
        raise TypeError("one local canonical engine required")
    from zacai.review_protection import assert_local_review_state_engine

    assert_local_review_state_engine(engine)


def _bound_factory(
    factory: sessionmaker[Session],
    expected_class: type[Session],
    expected_options: dict[str, object],
) -> None:
    _standard_factory(factory)
    if factory.class_ is not expected_class or factory.kw != expected_options:
        raise ValueError("original standard canonical factory changed")


def capture_native_view_pair(
    *,
    action: _PostedNativeCustody,
    proposal: NativeViewCustodyProposalV1,
    original_raw: bytes,
    factory: sessionmaker[Session],
    artifacts: LocalFilesystemArtifactStore,
    expected_root: ClaudeArtifactRootIdentity,
) -> LoadedChatGPTNativeView:
    """Consume actual custody POST, atomic pair, close/reopen. No processing proof.

    Failure consumes the attempt permanently. A possible commit requires manual
    custody reconciliation, never automatic retry. A fresh observed POST is
    a new owner action; canonical occupancy separately denies recapture. Precheck/write SQL leases contain no artifact,
    signed owner or host-clock callbacks. Fresh read-only reopen reads bytes; existing physical scalar guards apply.
    """
    result = None
    possibly_committed = False
    try:
        started = _MONOTONIC()
        o = _consume(action, proposal)
        proposal = o.snapshot  # Use only the independent observed value after callbacks.
        inputs, operation = o.inputs, o.operation
        with inputs.clock._lock:
            at = inputs.clock._last
        if at is None:
            raise ValueError("actual unchanged time required")
        deadline = started + (proposal.expires_at - at).total_seconds()
        _standard_factory(factory)
        original_class, original_options = factory.class_, dict(factory.kw)
        if type(artifacts) is not LocalFilesystemArtifactStore:
            raise ValueError("actual canonical artifact store required")
        if (
            type(original_raw) is not bytes
            or len(original_raw) != proposal.original_bytes
            or content_hash_of(original_raw) != proposal.original_reference.content_hash
        ):
            raise ValueError("exact approved whole wrapper required")
        rebuilt = prepare_chatgpt_native_view(
            original_raw,
            original_reference=proposal.original_reference,
            expected_thread_id=proposal.companion.expected_thread_id,
            selected_pointer=proposal.companion.selected_field.pointer,
            start=proposal.companion.selected_start,
            end=proposal.companion.selected_end,
            observed_at=proposal.prepared_at,
        )
        if rebuilt != proposal.companion:
            raise ValueError("exact approved companion required")
        _root_check(artifacts, expected_root)
        _owner(inputs, operation, proposal)
        _bound_factory(factory, original_class, original_options)
        with factory() as session:
            session.begin()
            entry = _physical(session)
            if _occupied(session, proposal):
                raise ValueError("occupied immutable capture cannot renew custody")
            _same(session, entry)
        companion_raw = canonical_bytes(rebuilt.model_dump(mode="json"))
        refs = (proposal.original_reference, proposal.companion_reference)
        boundary = refs[0].trust_boundary
        locations = []
        for raw, ref in zip((original_raw, companion_raw), refs, strict=True):
            _root_check(artifacts, expected_root)
            location = artifacts.put(boundary, ref.content_hash, raw)
            _owner(inputs, operation, proposal)
            returned = artifacts.get_bounded(
                boundary, location, max_bytes=2_000_000 if ref is refs[0] else 128_000
            )
            _artifact_profile(artifacts, boundary, location)
            _root_check(artifacts, expected_root)
            _owner(inputs, operation, proposal)
            if returned != raw or location != artifacts.location_for(ref.content_hash):
                raise ValueError("exact prepared artifact required")
            locations.append(location)
        inputs.clock()
        _owner(inputs, operation, proposal)
        with inputs.clock._lock:
            captured = inputs.clock._last
        if captured is None:
            raise ValueError("actual capture timestamp required")
        boundaries, labels = frozenset({boundary}), frozenset({refs[0].effective_classification})
        _bound_factory(factory, original_class, original_options)
        with factory() as session:
            session.begin()
            _lock(session, proposal.capture_id)
            entry = _physical(session)
            if _occupied(session, proposal):
                raise ValueError("capture namespace or IDs changed")
            for ref, location, namespace in zip(refs, locations, _names(proposal), strict=True):
                source, was_new = record_source(
                    session,
                    trust_boundary=boundary,
                    data_classification=ref.effective_classification,
                    system=SourceSystem.MANUAL,
                    external_ref=namespace,
                    content_hash=ref.content_hash,
                    content_location=location,
                    captured_at=captured,
                    preallocated_source_id=ref.source_id,
                )
                if source.id != ref.source_id or not was_new:
                    raise ValueError("new exact preallocated pair required")
            rows = _fragment_rows(session, refs, boundaries, labels)
            for ref, location in zip(refs, locations, strict=True):
                own = [dict(row) for row in rows if dict(row)["id"] == ref.source_id]
                if not own or any(
                    row["content_location"] != location
                    or row["captured_at"] != captured
                    or row["data_classification"] is not ref.effective_classification
                    for row in own
                ):
                    raise ValueError("exact pending capture metadata required")
            from zacai.chatgpt_native_source import _pair_snapshot

            if _pair_snapshot(session, refs, proposal.capture_id, boundaries, labels) != rows:
                raise ValueError("pending exact pair differs")
            _same(session, entry)
            if _MONOTONIC() >= deadline:
                raise ValueError("original custody deadline expired before commit")
            _same_output_commit_transaction(session, entry)
            possibly_committed = True
            session.commit()
        _owner(inputs, operation, proposal)
        _bound_factory(factory, original_class, original_options)
        with factory() as session:
            session.begin()
            entry = _physical(session)
            loaded = load_chatgpt_native_view_pair(
                session,
                artifacts=artifacts,
                capture_id=proposal.capture_id,
                original_reference=refs[0],
                companion_reference=refs[1],
                expected_companion=proposal.companion,
                authorized_boundaries=boundaries,
                allowed_classifications=labels,
            )
            baseline = _fragment_rows(session, refs, boundaries, labels)
            _same(session, entry)
        _root_check(artifacts, expected_root)
        _owner(inputs, operation, proposal)
        _bound_factory(factory, original_class, original_options)
        with factory() as session:
            session.begin()
            entry = _physical(session)
            if _fragment_rows(session, refs, boundaries, labels) != baseline:
                raise ValueError("final canonical pair changed")
            _same(session, entry)
        if _MONOTONIC() >= deadline:
            raise ValueError("original custody deadline expired before acknowledgment")
        result = loaded
    except BaseException:  # noqa: BLE001,S110 - fixed safe interruption diagnostic.
        pass
    if result is None:
        if possibly_committed:
            raise NativeViewCustodyUncertain(
                "native custody possibly committed; stop and reconcile"
            )
        raise NativeViewCustodyUnavailable(
            "native custody not acknowledged; consumed action cannot retry"
        )
    return result
