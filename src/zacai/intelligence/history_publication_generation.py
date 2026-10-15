"""Closed complete-generation custody primitives; no issued runtime authority.

Canonical claims burn the shared original generation namespace. Loading declared
bytes is not admission, observed generation, independent review or delivery.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from threading import RLock
from time import monotonic as _NATIVE_MONOTONIC
from typing import TYPE_CHECKING, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from zacai.backup_artifacts import (
    _assert_personal_custody_append_capacity,
    prepare_personal_encrypted_custody_backup_plan,
)
from zacai.contextual_authorization import _assert_fragment_generation_unconsumed
from zacai.contextual_protection import (
    PersonalFragmentCleanupUncertain,
    PersonalHistoryFragmentProtector,
)
from zacai.gateway import ActionRequest, ActionType, GatewayOutcome, evaluate_gateway
from zacai.host_clock import HostObservedClock
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contextual_generation import ContextualDraft
from zacai.intelligence.contextual_storage import (
    _fragment_rows,
    _history_external,
    load_history_contextual_packet,
)
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference, UsageObservation
from zacai.intelligence.fragment_publication_generation import (
    _same_output_commit_transaction as _same_commit,
)
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.intelligence.history_contextual_codec import (
    HistoryContextualPacketV1,
    HistoryContextualRequestV1,
    encode_history_contextual_request,
)
from zacai.intelligence.history_contextual_runtime import _route_digest
from zacai.intelligence.history_generation_review_declaration import (
    HistoryClaimV1,
    HistoryGenerationReviewDeclarationV1,
    decode_history_claim,
    encode_history_claim,
    encode_history_generation_review_declaration,
    validate_history_consent_request,
)
from zacai.intelligence.history_publication_admission import (
    AcknowledgedHistoryPublicationAdmission,
    HistoryPublicationAdmissionV1,
    _binding,
    _consume_history_admission_acknowledgment,
    _history_admission_current,
    encode_history_publication_admission,
    load_history_publication_admission,
)
from zacai.intelligence.history_review_retention import (
    HistoryDeclarationContext,
    _parts,
    history_declaration_owner,
)
from zacai.interfaces.named_session_binding import NamedSessionOperation
from zacai.policy import AccessRequest, Destination
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _lock
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source

if TYPE_CHECKING:
    from zacai.intelligence.history_contextual_runtime import (
        HistoryContextualDispatchDescriptor,
        LocalHistoryContextualRuntime,
    )
    from zacai.intelligence.history_publication_protection import (
        PersonalHistoryAdmissionReceiptV1,
        PersonalHistoryClaimReceiptV1,
        PersonalHistoryOutputReceiptV1,
        _HistoryRecoveryFields,
    )

_BOUNDARIES = frozenset({B.PERSONAL})
_LABELS = frozenset({C.HIGHLY_RESTRICTED})
MAX_SELECTED_REFS = 95
MAX_CLAIM_BYTES = 16000
MAX_ASSOCIATION_BYTES = 16000


class HistoryPublicationGenerationError(ValueError):
    """Fixed private-safe custody HOLD, not an issued approval."""


def _assert_complete_generation_union(
    declaration: HistoryGenerationReviewDeclarationV1,
    admission_reference: EvidenceReference,
    admission: HistoryPublicationAdmissionV1,
) -> tuple[EvidenceReference, ...]:
    """Bind actual present union plus FIVE distinct remaining required Sources.

    Declaration/admission plus generation claim, packet, output association,
    reviewer claim and assessment are seven own Sources. No silent clipping.
    Writer must call before irreversible burn, under its canonical parent lock.
    """
    if (
        type(declaration) is not HistoryGenerationReviewDeclarationV1
        or type(admission) is not HistoryPublicationAdmissionV1
        or type(admission_reference) is not EvidenceReference
    ):
        raise ValueError("exact complete parent and admission required")
    _binding(admission, declaration)
    _, g, q = _parts(declaration)
    validate_history_consent_request(g, q)
    if (
        admission_reference.content_hash
        != content_hash_of(encode_history_publication_admission(admission))
        or admission_reference.source_id.int == 0
        or admission_reference.trust_boundary is not B.PERSONAL
        or admission_reference.effective_classification is not C.HIGHLY_RESTRICTED
    ):
        raise ValueError("exact current admission reference required")
    selected = (*g.provenance, admission.publication_reference, admission_reference)
    if (
        len({r.source_id for r in selected}) != len(selected)
        or len(selected) + 5 > MAX_SELECTED_REFS
    ):
        raise ValueError("complete seven-Source task exceeds selected recovery capacity")
    return tuple(sorted(selected, key=lambda r: str(r.source_id)))


def _claim_prefix(generation_id: UUID) -> str:
    # Same original burn namespace as legacy and fragment consumers.
    return f"personal-history-fragment-claim/{generation_id}/"


def _claim_namespace(
    declaration: HistoryGenerationReviewDeclarationV1,
    admission: HistoryPublicationAdmissionV1,
    claim: HistoryClaimV1,
) -> str:
    _, g, _ = _parts(declaration)
    return (
        _claim_prefix(g.id)
        + "history-complete-v1/"
        + content_hash_of(encode_history_publication_admission(admission))
        + "/"
        + str(claim.attempt_id)
        + "/"
        + content_hash_of(encode_history_claim(claim))
    )


def _ids(session: Session, prefix: str) -> tuple[UUID, ...]:
    return tuple(
        session.scalars(
            select(Source.id)
            .where(
                Source.trust_boundary == B.PERSONAL,
                Source.system == SourceSystem.MANUAL,
                Source.external_ref.like(prefix + "%"),
            )
            .order_by(Source.id)
            .limit(2)
        )
    )


def _claim_binding(
    declaration: HistoryGenerationReviewDeclarationV1,
    admission_reference: EvidenceReference,
    admission: HistoryPublicationAdmissionV1,
    claim: HistoryClaimV1,
) -> tuple[EvidenceReference, ...]:
    selected = _assert_complete_generation_union(declaration, admission_reference, admission)
    if type(claim) is not HistoryClaimV1:
        raise ValueError("exact existing complete claim required")
    encode_history_claim(claim)
    _, g, q = _parts(declaration)
    route = q.route.model_dump(mode="json")
    route["capabilities"] = sorted(q.route.capabilities)
    # A2 retains the full declaration containing this consent, not a standalone
    # consent Source. Its exact canonical reference is the claim's parent.
    if (
        claim.consent_reference != admission.publication_reference
        or claim.consent_digest != admission.publication_reference.content_hash
        or claim.request_digest != g.request_digest
        or claim.task_id != g.task_id
        or claim.builder_id != g.builder_id
        or claim.original_session_binding != g.original_session_binding
        or claim.body_digest != g.body_digest
        or claim.generation_wire_format != g.generation_wire_format
        or claim.generation_wire_digest != g.generation_wire_digest
        or claim.route_digest != content_hash_of(canonical_bytes(route))
        or any(
            getattr(claim, n) != getattr(g, n)
            for n in (
                "model_digest",
                "tokenizer_digest",
                "runtime_digest",
                "template_digest",
                "renderer_digest",
                "prompt_tokens",
                "max_output_tokens",
            )
        )
        or not admission.observed_action_at <= claim.consumed_at < g.expires_at
    ):
        raise ValueError("actual full-purpose claim binding required")
    return selected


def _claim_current(
    session: Session,
    *,
    reference: EvidenceReference,
    expected_claim: HistoryClaimV1,
    expected_declaration: HistoryGenerationReviewDeclarationV1,
    admission_reference: EvidenceReference,
    expected_admission: HistoryPublicationAdmissionV1,
) -> tuple[tuple[tuple[str, object], ...], ...]:
    selected = _claim_binding(
        expected_declaration, admission_reference, expected_admission, expected_claim
    )
    raw = encode_history_claim(expected_claim)
    if (
        type(reference) is not EvidenceReference
        or reference.source_id.int == 0
        or reference.content_hash != content_hash_of(raw)
        or reference.trust_boundary is not B.PERSONAL
        or reference.effective_classification is not C.HIGHLY_RESTRICTED
        or reference.source_id in {r.source_id for r in selected}
    ):
        raise ValueError("exact distinct claim reference required")
    _history_admission_current(
        session,
        reference=admission_reference,
        expected_admission=expected_admission,
        expected_declaration=expected_declaration,
    )
    _, g, _ = _parts(expected_declaration)
    if _ids(session, _claim_prefix(g.id)) != (reference.source_id,):
        raise ValueError("one original canonical burn required")
    rows = _fragment_rows(session, (*selected, reference), _BOUNDARIES, _LABELS)
    row = next(dict(v) for v in rows if dict(v)["id"] == reference.source_id)
    if (
        row["system"] is not SourceSystem.MANUAL
        or row["external_ref"]
        != _claim_namespace(expected_declaration, expected_admission, expected_claim)
        or row["captured_at"] != expected_claim.consumed_at
        or row["lineage_id"] != reference.source_id
        or row["supersedes_source_id"] is not None
    ):
        raise ValueError("canonical claim metadata differs")
    return rows


def load_history_publication_claim(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    context: HistoryDeclarationContext,
    reference: EvidenceReference,
    expected_claim: HistoryClaimV1,
    expected_declaration: HistoryGenerationReviewDeclarationV1,
    admission_reference: EvidenceReference,
    expected_admission: HistoryPublicationAdmissionV1,
) -> HistoryClaimV1:
    result = None
    try:
        if (
            type(artifacts) is not LocalFilesystemArtifactStore
            or type(context) is not HistoryDeclarationContext
        ):
            raise ValueError("actual bounded store/context required")
        entry = _physical(session)

        def current() -> tuple[tuple[tuple[str, object], ...], ...]:
            return _claim_current(
                session,
                reference=reference,
                expected_claim=expected_claim,
                expected_declaration=expected_declaration,
                admission_reference=admission_reference,
                expected_admission=expected_admission,
            )

        before = current()
        _same(session, entry)
        load_history_publication_admission(
            session,
            artifacts=artifacts,
            context=context,
            reference=admission_reference,
            expected_admission=expected_admission,
            expected_declaration=expected_declaration,
        )
        _same(session, entry)
        # Parent body callbacks must finish before the own body current gate.
        if current() != before:
            raise ValueError("claim union changed after parent read")
        row = next(dict(v) for v in before if dict(v)["id"] == reference.source_id)
        if type(row["content_location"]) is not str:
            raise ValueError("bounded own claim location required")
        raw = artifacts.get_bounded(B.PERSONAL, row["content_location"], max_bytes=MAX_CLAIM_BYTES)
        _same(session, entry)
        if (
            raw != encode_history_claim(expected_claim)
            or content_hash_of(raw) != reference.content_hash
            or decode_history_claim(raw) != expected_claim
        ):
            raise ValueError("claim bytes differ")
        if current() != before:
            raise ValueError("claim union changed after own read")
        _same(session, entry)
        result = expected_claim
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryPublicationGenerationError("complete canonical generation claim unavailable")
    return result


class HistoryPublicationOutputAssociationV1(Contract):
    """Declared immutable origin binding; loader alone does not prove invocation."""

    format: Literal["zac-history-complete-publication-output-association-v1"] = (
        "zac-history-complete-publication-output-association-v1"
    )
    generation_id: UUID
    task_id: UUID
    builder_id: UUID
    attempt_id: UUID
    publication_reference: EvidenceReference = Field(repr=False)
    admission_reference: EvidenceReference = Field(repr=False)
    claim_reference: EvidenceReference = Field(repr=False)
    packet_reference: EvidenceReference = Field(repr=False)
    publication_digest: Digest
    admission_digest: Digest
    claim_digest: Digest
    request_digest: Digest
    generation_wire_digest: Digest
    output_digest: Digest
    usage_digest: Digest
    packet_created_at: AwareDatetime

    @model_validator(mode="after")
    def exact_references(self) -> Self:
        refs = (
            self.publication_reference,
            self.admission_reference,
            self.claim_reference,
            self.packet_reference,
        )
        if (
            any(
                v.int == 0
                for v in (self.generation_id, self.task_id, self.builder_id, self.attempt_id)
            )
            or len({r.source_id for r in refs}) != len(refs)
            or any(
                r.source_id.int == 0
                or r.trust_boundary is not B.PERSONAL
                or r.effective_classification is not C.HIGHLY_RESTRICTED
                for r in refs
            )
            or self.admission_reference.content_hash != self.admission_digest
            or self.claim_reference.content_hash != self.claim_digest
        ):
            raise ValueError("closed distinct complete output references required")
        return self

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def reviewer_authenticated(self) -> Literal[False]:
        return False


def encode_history_output_association(value: HistoryPublicationOutputAssociationV1) -> bytes:
    if type(value) is not HistoryPublicationOutputAssociationV1:
        raise ValueError("exact complete association required")
    raw = canonical_bytes(
        HistoryPublicationOutputAssociationV1.model_validate(
            value.model_dump(mode="json")
        ).model_dump(mode="json")
    )
    if not 0 < len(raw) <= MAX_ASSOCIATION_BYTES:
        raise ValueError("bounded complete association required")
    return raw


def decode_history_output_association(raw: bytes) -> HistoryPublicationOutputAssociationV1:
    from zacai.intelligence.review_context import _unique_pairs

    if type(raw) is not bytes or not 0 < len(raw) <= MAX_ASSOCIATION_BYTES:
        raise ValueError("bounded association required")
    value = HistoryPublicationOutputAssociationV1.model_validate(
        json.loads(raw, object_pairs_hook=_unique_pairs)
    )
    if encode_history_output_association(value) != raw:
        raise ValueError("canonical association required")
    return value


def _association_prefix(generation_id: UUID) -> str:
    return f"personal-history-complete-publication-output/{generation_id}/"


def _association_binding(
    value: HistoryPublicationOutputAssociationV1,
    *,
    declaration: HistoryGenerationReviewDeclarationV1,
    admission_reference: EvidenceReference,
    admission: HistoryPublicationAdmissionV1,
    claim_reference: EvidenceReference,
    claim: HistoryClaimV1,
) -> None:
    selected = _claim_binding(declaration, admission_reference, admission, claim)
    encode_history_output_association(value)
    _, g, _ = _parts(declaration)
    if (
        value.generation_id != g.id
        or value.task_id != g.task_id
        or value.builder_id != g.builder_id
        or value.attempt_id != claim.attempt_id
        or value.publication_reference != admission.publication_reference
        or value.publication_digest != admission.publication_digest
        or value.admission_reference != admission_reference
        or value.admission_digest
        != content_hash_of(encode_history_publication_admission(admission))
        or value.claim_reference != claim_reference
        or value.claim_digest != content_hash_of(encode_history_claim(claim))
        or value.request_digest != g.request_digest
        or value.generation_wire_digest != g.generation_wire_digest
        or value.packet_reference.source_id in {r.source_id for r in (*selected, claim_reference)}
        or not claim.consumed_at <= value.packet_created_at < g.expires_at
    ):
        raise ValueError("exact complete output parent/claim binding required")


def _output_current(
    session: Session,
    *,
    reference: EvidenceReference,
    value: HistoryPublicationOutputAssociationV1,
    declaration: HistoryGenerationReviewDeclarationV1,
    admission_reference: EvidenceReference,
    admission: HistoryPublicationAdmissionV1,
    claim_reference: EvidenceReference,
    claim: HistoryClaimV1,
) -> tuple[tuple[tuple[str, object], ...], ...]:
    _association_binding(
        value,
        declaration=declaration,
        admission_reference=admission_reference,
        admission=admission,
        claim_reference=claim_reference,
        claim=claim,
    )
    parent = _claim_current(
        session,
        reference=claim_reference,
        expected_claim=claim,
        expected_declaration=declaration,
        admission_reference=admission_reference,
        expected_admission=admission,
    )
    raw = encode_history_output_association(value)
    refs = (
        *_claim_binding(declaration, admission_reference, admission, claim),
        claim_reference,
        value.packet_reference,
        reference,
    )
    if (
        type(reference) is not EvidenceReference
        or reference.source_id.int == 0
        or reference.content_hash != content_hash_of(raw)
        or reference.trust_boundary is not B.PERSONAL
        or reference.effective_classification is not C.HIGHLY_RESTRICTED
        or len({r.source_id for r in refs}) != len(refs)
        or len(refs) > MAX_SELECTED_REFS
    ):
        raise ValueError("exact full output union required")
    prefix = _association_prefix(value.generation_id)
    if _ids(session, prefix) != (reference.source_id,):
        raise ValueError("unique own output association required")
    rows = _fragment_rows(session, refs, _BOUNDARIES, _LABELS)
    own = next(dict(v) for v in rows if dict(v)["id"] == reference.source_id)
    _, _, q = _parts(declaration)
    packet = next(dict(v) for v in rows if dict(v)["id"] == value.packet_reference.source_id)
    if (
        own["system"] is not SourceSystem.MANUAL
        or own["external_ref"] != prefix + reference.content_hash
        or own["captured_at"] != value.packet_created_at
        or own["lineage_id"] != reference.source_id
        or own["supersedes_source_id"] is not None
        or packet["system"] is not SourceSystem.MANUAL
        or packet["external_ref"] != _history_external(value.packet_reference.content_hash, q)
        or packet["captured_at"] != value.packet_created_at
    ):
        raise ValueError("canonical output subject metadata differs")
    if not parent:
        raise ValueError("exact current parent union required")
    return rows


def load_history_publication_output_association(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    context: HistoryDeclarationContext,
    reference: EvidenceReference,
    expected_association: HistoryPublicationOutputAssociationV1,
    expected_declaration: HistoryGenerationReviewDeclarationV1,
    admission_reference: EvidenceReference,
    expected_admission: HistoryPublicationAdmissionV1,
    claim_reference: EvidenceReference,
    expected_claim: HistoryClaimV1,
) -> tuple[HistoryContextualPacketV1, HistoryPublicationOutputAssociationV1]:
    result = None
    try:
        if (
            type(artifacts) is not LocalFilesystemArtifactStore
            or type(context) is not HistoryDeclarationContext
        ):
            raise ValueError("actual bounded output store/context required")
        entry = _physical(session)

        def current() -> tuple[tuple[tuple[str, object], ...], ...]:
            return _output_current(
                session,
                reference=reference,
                value=expected_association,
                declaration=expected_declaration,
                admission_reference=admission_reference,
                admission=expected_admission,
                claim_reference=claim_reference,
                claim=expected_claim,
            )

        before = current()
        _same(session, entry)
        load_history_publication_claim(
            session,
            artifacts=artifacts,
            context=context,
            reference=claim_reference,
            expected_claim=expected_claim,
            expected_declaration=expected_declaration,
            admission_reference=admission_reference,
            expected_admission=expected_admission,
        )
        _, _, q = _parts(expected_declaration)
        if current() != before:
            raise ValueError("output union changed after claim body")
        packet = load_history_contextual_packet(
            session,
            artifacts=artifacts,
            expected_root=context.expected_root,
            expected_account_ref=context.expected_account_ref,
            expected_exported_at=context.expected_exported_at,
            expected_packet_reference=expected_association.packet_reference,
            expected_request=q,
            authorized_boundaries=_BOUNDARIES,
            allowed_classifications=_LABELS,
        )
        _same(session, entry)
        if (
            packet.builder_id != expected_association.builder_id
            or packet.created_at != expected_association.packet_created_at
            or encode_history_contextual_request(packet.request())
            != encode_history_contextual_request(q)
        ):
            raise ValueError("actual canonical complete packet differs")
        if current() != before:
            raise ValueError("output union changed after packet body")
        row = next(dict(v) for v in before if dict(v)["id"] == reference.source_id)
        if type(row["content_location"]) is not str:
            raise ValueError("bounded association locator required")
        raw = artifacts.get_bounded(
            B.PERSONAL, row["content_location"], max_bytes=MAX_ASSOCIATION_BYTES
        )
        _same(session, entry)
        if (
            content_hash_of(raw) != reference.content_hash
            or raw != encode_history_output_association(expected_association)
            or decode_history_output_association(raw) != expected_association
        ):
            raise ValueError("exact association bytes required")
        if current() != before:
            raise ValueError("final current output union differs")
        _same(session, entry)
        result = (packet, expected_association)
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryPublicationGenerationError("paired complete output unavailable")
    return result


class CanonicalPersonalHistoryPublicationAuthorization:
    """Original acknowledged action + canonical once-use generation only.

    No mounted host/independent reviewer is activated. Result stays NEEDS_REVIEW.
    Metadata/custody constructors cannot create this original acknowledgment.
    """

    def __init__(
        self,
        *,
        factory: sessionmaker[Session],
        artifacts: LocalFilesystemArtifactStore,
        declaration: HistoryGenerationReviewDeclarationV1,
        acknowledgment: AcknowledgedHistoryPublicationAdmission,
        request: HistoryContextualRequestV1,
        protector: PersonalHistoryFragmentProtector,
        operation: NamedSessionOperation,
        clock: HostObservedClock,
        context: HistoryDeclarationContext,
    ) -> None:
        started = _NATIVE_MONOTONIC()
        if (
            type(factory) is not sessionmaker
            or type(artifacts) is not LocalFilesystemArtifactStore
            or type(declaration) is not HistoryGenerationReviewDeclarationV1
            or type(acknowledgment) is not AcknowledgedHistoryPublicationAdmission
            or type(request) is not HistoryContextualRequestV1
            or type(protector) is not PersonalHistoryFragmentProtector
            or type(operation) is not NamedSessionOperation
            or type(clock) is not HostObservedClock
            or type(context) is not HistoryDeclarationContext
            or operation.host_clock is not clock
            or protector._factory is not factory
            or protector._artifacts is not artifacts
            or protector._operation is not operation
            or protector._clock is not clock
            or factory.kw.get("bind") is not protector._engine
            or factory.kw.get("binds")
        ):
            raise HistoryPublicationGenerationError(
                "actual original complete producer graph required"
            )
        raw, g, q = _parts(declaration)
        if (
            declaration.review is None
            or declaration.review_profile_digest is None
            or encode_history_contextual_request(request) != encode_history_contextual_request(q)
        ):
            raise HistoryPublicationGenerationError("actual original full purpose request required")
        _assert_complete_generation_union(
            declaration, acknowledgment.reference, acknowledgment.admission
        )
        from zacai.intelligence.history_publication_review import _assert_complete_review_record_fit

        _assert_complete_review_record_fit(declaration)
        retained = _consume_history_admission_acknowledgment(
            acknowledgment, operation=operation, clock=clock, expected_declaration=declaration
        )
        self._factory, self._artifacts, self._declaration = factory, artifacts, declaration
        self._admission_reference, self._admission = retained.reference, retained.admission
        self._consent, self._request, self._protector = g, request, protector
        self._operation, self._clock, self._context = operation, clock, context
        self._started = started
        self._deadline_monotonic = acknowledgment.original_deadline_monotonic
        self._raw = raw
        self._request_raw = encode_history_contextual_request(request)
        self._admission_raw = encode_history_publication_admission(self._admission)
        self._original_interval = (self._started, self._deadline_monotonic)
        self._graph = (
            factory,
            artifacts,
            declaration,
            request,
            protector,
            operation,
            clock,
            context,
            protector._engine,
        )
        self._phase = "READY"
        self._lock = RLock()
        self._runtime: LocalHistoryContextualRuntime | None = None
        self._runtime_configuration: tuple[str, str, str, str, str, str] | None = None
        self._claim: HistoryClaimV1 | None = None
        self._claim_reference: EvidenceReference | None = None
        self._released: HistoryContextualDispatchDescriptor | None = None
        self._result: PersonalHistoryAssociatedOutput | None = None
        self._admission_receipt: PersonalHistoryAdmissionReceiptV1 | None = None
        self._claim_receipt: PersonalHistoryClaimReceiptV1 | None = None

    def _hold(self) -> None:
        self._phase = "HELD"
        self._released = None
        self._result = None

    def _require(self, phase: str) -> None:
        if self._phase != phase:
            raise ValueError("original complete producer phase changed")

    def _graph_check(self) -> None:
        if (
            self._graph
            != (
                self._factory,
                self._artifacts,
                self._declaration,
                self._request,
                self._protector,
                self._operation,
                self._clock,
                self._context,
                self._protector._engine,
            )
            or self._protector._factory is not self._factory
            or self._protector._artifacts is not self._artifacts
            or self._protector._operation is not self._operation
            or self._protector._clock is not self._clock
            or _parts(self._declaration)[1] != self._consent
            or encode_history_publication_admission(self._admission) != self._admission_raw
            or (self._started, self._deadline_monotonic) != self._original_interval
            or encode_history_generation_review_declaration(self._declaration) != self._raw
            or encode_history_contextual_request(self._request) != self._request_raw
        ):
            raise ValueError("original complete producer changed")
        _assert_complete_generation_union(
            self._declaration, self._admission_reference, self._admission
        )

    def _owner(self) -> datetime:
        self._graph_check()
        owner = history_declaration_owner(self._operation, self._clock, self._consent)
        decision = evaluate_gateway(
            ActionRequest(
                action_type=ActionType.SUMMARIZE_CONTENT,
                access=AccessRequest(
                    data_boundary=B.PERSONAL,
                    data_classification=C.HIGHLY_RESTRICTED,
                    requestor_boundaries=frozenset(s.boundary for s in owner.principal.scopes),
                    destination=Destination.LOCAL,
                ),
                description="bounded approved complete-history context review",
            )
        )
        if decision.outcome is not GatewayOutcome.ALLOW:
            raise ValueError("original complete owner policy denied")
        with self._clock._lock:
            now = self._clock._last
        if now is None or _NATIVE_MONOTONIC() >= self._deadline_monotonic:
            raise ValueError("original complete owner interval expired")
        self._graph_check()
        return now

    def bind_runtime(self, runtime: LocalHistoryContextualRuntime) -> None:
        from zacai.intelligence.history_contextual_runtime import LocalHistoryContextualRuntime

        failed = False
        interruption = None
        try:
            with self._lock:
                self._require("READY")
                self._phase = "BINDING"
                self._graph_check()
                if (
                    type(runtime) is not LocalHistoryContextualRuntime
                    or runtime._authorization is not None
                ):
                    raise ValueError("actual unbound complete runtime required")
                configuration = runtime.configuration()
                g = self._consent
                if runtime._route != g.route or configuration != (
                    g.model_digest,
                    g.tokenizer_digest,
                    g.template_digest,
                    g.renderer_digest,
                    g.runtime_digest,
                    _route_digest(g.route),
                ):
                    raise ValueError("actual declared complete runtime pins required")
                now = self._owner()
                self._require("BINDING")
                review = self._declaration.review
                assert review is not None
                if (
                    (g.expires_at - now).total_seconds() * 1000
                    < self._request.task.max_latency_ms + review.max_latency_ms
                ):
                    raise ValueError("original complete generation and review interval cannot fit")
                self._runtime, self._runtime_configuration = runtime, configuration
                runtime._authorization = self
                self._phase = "BOUND"
        except (KeyboardInterrupt, SystemExit) as error:
            interruption = error
            failed = True
        except Exception:  # noqa: BLE001 - permanent hold, no permission fallback
            failed = True
        if failed:
            self._hold()
            if interruption is not None:
                raise interruption
            raise HistoryPublicationGenerationError("complete runtime binding held")

    def _descriptor(
        self, request: HistoryContextualRequestV1, d: HistoryContextualDispatchDescriptor
    ) -> None:
        from zacai.intelligence.history_contextual_runtime import (
            HistoryContextualDispatchDescriptor,
        )

        if type(d) is not HistoryContextualDispatchDescriptor or d.phase not in (
            "PRE_DISPATCH",
            "RELEASE",
        ):
            raise ValueError("closed complete dispatch phase required")
        self._graph_check()
        runtime = self._runtime
        g = self._consent
        if (
            type(d) is not HistoryContextualDispatchDescriptor
            or runtime is None
            or runtime._authorization is not self
            or request is not self._request
            or runtime._prepared is None
            or runtime._attempt_id != d.attempt_id
            or runtime.configuration() != self._runtime_configuration
        ):
            raise ValueError("actual complete bound runtime descriptor required")
        retained, body, count, deadline = runtime._prepared
        if (
            d.retained_request_digest != content_hash_of(retained)
            or retained != self._request_raw
            or d.body_digest != content_hash_of(body)
            or content_hash_of(body) != g.generation_wire_digest
            or d.route_digest != _route_digest(g.route)
            or d.prompt_tokens != count
            or count != g.prompt_tokens
            or d.requested_output_tokens != g.max_output_tokens
            or deadline != d.deadline_monotonic
            or deadline > self._deadline_monotonic
            or any(
                getattr(d, n) != getattr(g, n)
                for n in (
                    "model_digest",
                    "tokenizer_digest",
                    "runtime_digest",
                    "template_digest",
                    "renderer_digest",
                )
            )
            or _NATIVE_MONOTONIC() >= deadline
        ):
            raise ValueError("complete original descriptor changed")
        if d.phase == "PRE_DISPATCH" and (
            d.output_digest is not None or d.usage_digest is not None
        ):
            raise ValueError("predispatch has no generated observations")
        if d.phase == "RELEASE" and (
            self._claim is None
            or self._claim.attempt_id != d.attempt_id
            or d.output_digest is None
            or d.usage_digest is None
        ):
            raise ValueError("original released complete attempt required")

    def _receipt_current(self, session: Session, receipt: _HistoryRecoveryFields) -> None:
        plan = prepare_personal_encrypted_custody_backup_plan(session)
        rows = json.loads(plan.rows)
        hashes = tuple(
            sorted(
                ((UUID(row["id"]), row["content_hash"]) for row in rows), key=lambda v: str(v[0])
            )
        )
        fingerprints = tuple(
            sorted(
                ((UUID(row["id"]), content_hash_of(canonical_bytes(row))) for row in rows),
                key=lambda v: str(v[0]),
            )
        )
        if (
            content_hash_of(plan.rows) != receipt.full_plan_digest
            or hashes != receipt.full_boundary_source_hashes
            or fingerprints != receipt.full_boundary_source_fingerprints
        ):
            raise ValueError("complete subject recovery plan stale")

    def _burn(
        self, d: HistoryContextualDispatchDescriptor
    ) -> tuple[HistoryClaimV1, EvidenceReference]:
        with self._factory() as session:
            session.begin()
            entry = _physical(session)
            before = _history_admission_current(
                session,
                reference=self._admission_reference,
                expected_admission=self._admission,
                expected_declaration=self._declaration,
            )
            load_history_publication_admission(
                session,
                artifacts=self._artifacts,
                context=self._context,
                reference=self._admission_reference,
                expected_admission=self._admission,
                expected_declaration=self._declaration,
            )
            if (
                _history_admission_current(
                    session,
                    reference=self._admission_reference,
                    expected_admission=self._admission,
                    expected_declaration=self._declaration,
                )
                != before
            ):
                raise ValueError("complete approval changed during claim preparation")
            _same(session, entry)
        self._require("ENTERED")
        consumed = self._owner()
        self._require("ENTERED")
        g = self._consent
        claim = HistoryClaimV1(
            consent_reference=self._admission.publication_reference,
            consent_digest=self._admission.publication_reference.content_hash,
            request_digest=g.request_digest,
            attempt_id=d.attempt_id,
            task_id=g.task_id,
            builder_id=g.builder_id,
            original_session_binding=g.original_session_binding,
            body_digest=g.body_digest,
            generation_wire_format=g.generation_wire_format,
            generation_wire_digest=g.generation_wire_digest,
            route_digest=d.route_digest,
            model_digest=d.model_digest,
            tokenizer_digest=d.tokenizer_digest,
            runtime_digest=d.runtime_digest,
            template_digest=d.template_digest,
            renderer_digest=d.renderer_digest,
            prompt_tokens=d.prompt_tokens,
            max_output_tokens=d.requested_output_tokens,
            consumed_at=consumed,
        )
        _claim_binding(self._declaration, self._admission_reference, self._admission, claim)
        raw = encode_history_claim(claim)
        location = self._artifacts.put(B.PERSONAL, content_hash_of(raw), raw)
        returned = self._artifacts.get_bounded(B.PERSONAL, location, max_bytes=MAX_CLAIM_BYTES)
        if returned != raw:
            raise ValueError("verified complete claim artifact required")
        self._owner()
        self._require("ENTERED")
        self._descriptor(self._request, d)
        assert self._admission_receipt is not None
        with self._factory() as session:
            session.begin()
            _lock(session, g.id)
            entry = _physical(session)
            _assert_complete_generation_union(
                self._declaration, self._admission_reference, self._admission
            )
            from zacai.intelligence.history_publication_review import (
                _assert_complete_review_record_fit,
            )

            _assert_complete_review_record_fit(self._declaration)
            _assert_personal_custody_append_capacity(session, 6)
            self._receipt_current(session, self._admission_receipt)
            _assert_fragment_generation_unconsumed(session, g.id)
            if (
                _history_admission_current(
                    session,
                    reference=self._admission_reference,
                    expected_admission=self._admission,
                    expected_declaration=self._declaration,
                )
                != before
            ):
                raise ValueError("complete original admission union changed")
            self._require("ENTERED")
            _same(session, entry)
            row, new = record_source(
                session,
                trust_boundary=B.PERSONAL,
                data_classification=C.HIGHLY_RESTRICTED,
                system=SourceSystem.MANUAL,
                external_ref=_claim_namespace(self._declaration, self._admission, claim),
                content_hash=content_hash_of(raw),
                content_location=location,
                captured_at=consumed,
            )
            if not new:
                raise ValueError("one new original complete burn required")
            reference = EvidenceReference(
                source_id=row.id,
                content_hash=content_hash_of(raw),
                trust_boundary=B.PERSONAL,
                effective_classification=C.HIGHLY_RESTRICTED,
            )
            _claim_current(
                session,
                reference=reference,
                expected_claim=claim,
                expected_declaration=self._declaration,
                admission_reference=self._admission_reference,
                expected_admission=self._admission,
            )
            _assert_personal_custody_append_capacity(session, 5)
            _same(session, entry)
            self._require("ENTERED")
            if _NATIVE_MONOTONIC() >= min(self._deadline_monotonic, d.deadline_monotonic):
                raise ValueError("original complete interval expired before burn commit")
            _same_commit(session, entry)
            session.commit()
        return claim, reference

    def _terminal(self, receipt: _HistoryRecoveryFields, phase: str) -> None:
        if self._claim is None or self._claim_reference is None:
            raise ValueError("actual complete burn required")
        # Subject protector finished original owner after all recovery callbacks.
        # No new caller clock/body/protection callback follows terminal checks.
        if (
            content_hash_of(self._protector._run_row(receipt.artifact_backup_run_id))
            != receipt.live_journal_digest
        ):
            raise ValueError("complete recovery journal changed")
        with self._factory() as session:
            session.begin()
            _lock(session, self._consent.id)
            entry = _physical(session)
            _claim_current(
                session,
                reference=self._claim_reference,
                expected_claim=self._claim,
                expected_declaration=self._declaration,
                admission_reference=self._admission_reference,
                expected_admission=self._admission,
            )
            self._receipt_current(session, receipt)
            _same(session, entry)
            self._require(phase)
        self._graph_check()
        if (
            self._runtime is None
            or self._runtime._prepared is None
            or _NATIVE_MONOTONIC() >= min(self._deadline_monotonic, self._runtime._prepared[3])
        ):
            raise ValueError("complete terminal original interval expired")

    def recheck_generation_dispatch(
        self, request: HistoryContextualRequestV1, d: HistoryContextualDispatchDescriptor
    ) -> None:
        from zacai.intelligence.history_publication_protection import (
            protect_history_admission,
            protect_history_claim,
        )

        uncertain = False
        failed = False
        interruption = None
        try:
            with self._lock:
                self._descriptor(request, d)
                if d.phase == "PRE_DISPATCH":
                    self._require("BOUND")
                    self._phase = "ENTERED"
                    self._admission_receipt = protect_history_admission(
                        self._protector,
                        reference=self._admission_reference,
                        expected_declaration=self._declaration,
                        expected_admission=self._admission,
                        context=self._context,
                    )
                    self._require("ENTERED")
                    self._claim, self._claim_reference = self._burn(d)
                    with self._factory() as session:
                        session.begin()
                        load_history_publication_claim(
                            session,
                            artifacts=self._artifacts,
                            context=self._context,
                            reference=self._claim_reference,
                            expected_claim=self._claim,
                            expected_declaration=self._declaration,
                            admission_reference=self._admission_reference,
                            expected_admission=self._admission,
                        )
                    self._require("ENTERED")
                    self._claim_receipt = protect_history_claim(
                        self._protector,
                        reference=self._claim_reference,
                        expected_declaration=self._declaration,
                        expected_admission=self._admission,
                        admission_reference=self._admission_reference,
                        expected_claim=self._claim,
                        context=self._context,
                    )
                    self._terminal(self._claim_receipt, "ENTERED")
                    self._phase = "CLAIMED"
                else:
                    self._require("CLAIMED")
                    self._phase = "RELEASE_ENTERED"
                    assert self._claim is not None and self._claim_reference is not None
                    proof = protect_history_claim(
                        self._protector,
                        reference=self._claim_reference,
                        expected_declaration=self._declaration,
                        expected_admission=self._admission,
                        admission_reference=self._admission_reference,
                        expected_claim=self._claim,
                        context=self._context,
                        read_existing=True,
                    )
                    if proof != self._claim_receipt:
                        raise ValueError("original complete claim proof changed")
                    self._terminal(proof, "RELEASE_ENTERED")
                    self._released = d
                    self._phase = "RELEASED"
        except PersonalFragmentCleanupUncertain:
            uncertain = True
            failed = True
        except (KeyboardInterrupt, SystemExit) as error:
            interruption = error
            failed = True
        except Exception:  # noqa: BLE001
            failed = True
        if failed:
            self._hold()
        if uncertain:
            raise PersonalFragmentCleanupUncertain(
                "PERSONAL complete generation cleanup uncertain; operator review required"
            )
        if interruption is not None:
            raise interruption
        if failed:
            raise HistoryPublicationGenerationError("complete original dispatch held")


@dataclass(frozen=True, slots=True, repr=False)
class PersonalHistoryAssociatedOutput:
    """Actual retained baseline answer; independent assessment remains required."""

    packet: HistoryContextualPacketV1
    association_reference: EvidenceReference
    association: HistoryPublicationOutputAssociationV1
    recovery_receipt: PersonalHistoryOutputReceiptV1

    @property
    def reviewer_authenticated(self) -> Literal[False]:
        return False

    @property
    def ready_to_deliver(self) -> Literal[False]:
        return False


def _output_origin(
    gate: CanonicalPersonalHistoryPublicationAuthorization,
    runtime: LocalHistoryContextualRuntime,
    request: HistoryContextualRequestV1,
    draft: ContextualDraft,
) -> UsageObservation:
    if (
        gate._phase != "OUTPUT_ENTERED"
        or gate._runtime is not runtime
        or gate._request is not request
        or gate._released is None
        or runtime._authorization is not gate
        or runtime._result is None
        or runtime._result[0] is not draft
        or runtime._released is not gate._released
        or gate._claim is None
        or gate._claim_reference is None
        or runtime._attempt_id != gate._claim.attempt_id
        or gate._released.output_digest
        != content_hash_of(canonical_bytes(draft.model_dump(mode="json")))
        or gate._released.usage_digest
        != content_hash_of(canonical_bytes(runtime._result[1].model_dump(mode="json")))
    ):
        raise ValueError("actual original complete RELEASE/result required")
    gate._graph_check()
    return runtime._result[1]


def retain_personal_history_publication_output(
    authorization: CanonicalPersonalHistoryPublicationAuthorization,
    *,
    runtime: LocalHistoryContextualRuntime,
    request: HistoryContextualRequestV1,
    draft: ContextualDraft,
) -> PersonalHistoryAssociatedOutput:
    """Once-only exact RELEASE to paired canonical output and fresh full proof.

    Artifact/owner callbacks finish outside write SQL. Preallocated Source IDs
    bind both artifacts before callback-free atomic Source retention. Failures
    remain held; orphan artifacts or possibly committed rows require reconciliation.
    Independent review is still required before owner delivery.
    """
    from uuid import uuid4

    from zacai.intelligence.history_contextual_codec import (
        MAX_PACKET_BYTES,
        encode_history_contextual_packet,
    )
    from zacai.intelligence.history_contextual_runtime import (
        _resolve_complete_draft,
    )
    from zacai.intelligence.history_publication_protection import protect_history_output

    result = None
    uncertain = False
    interruption = None
    try:
        if type(authorization) is not CanonicalPersonalHistoryPublicationAuthorization:
            raise TypeError("actual original complete issuer required")
        gate = authorization
        with gate._lock:
            gate._require("RELEASED")
            gate._phase = "OUTPUT_ENTERED"
            usage = _output_origin(gate, runtime, request, draft)
            released = gate._released
            claim, claim_ref = gate._claim, gate._claim_reference
            assert claim is not None and claim_ref is not None and released is not None
            review = _resolve_complete_draft(draft, request)
            created = gate._owner()
            packet_raw = encode_history_contextual_packet(
                review,
                request,
                builder_id=gate._consent.builder_id,
                created_at=created,
            )
            packet_digest = content_hash_of(packet_raw)
            packet_id, association_id = uuid4(), uuid4()
            packet_ref = EvidenceReference(
                source_id=packet_id,
                content_hash=packet_digest,
                trust_boundary=B.PERSONAL,
                effective_classification=C.HIGHLY_RESTRICTED,
            )
            association = HistoryPublicationOutputAssociationV1(
                generation_id=gate._consent.id,
                task_id=gate._consent.task_id,
                builder_id=gate._consent.builder_id,
                attempt_id=claim.attempt_id,
                publication_reference=gate._admission.publication_reference,
                admission_reference=gate._admission_reference,
                claim_reference=claim_ref,
                packet_reference=packet_ref,
                publication_digest=gate._admission.publication_digest,
                admission_digest=gate._admission_reference.content_hash,
                claim_digest=claim_ref.content_hash,
                request_digest=gate._consent.request_digest,
                generation_wire_digest=gate._consent.generation_wire_digest,
                output_digest=released.output_digest,
                usage_digest=released.usage_digest,
                packet_created_at=created,
            )
            association_raw = encode_history_output_association(association)
            association_hash = content_hash_of(association_raw)
            association_ref = EvidenceReference(
                source_id=association_id,
                content_hash=association_hash,
                trust_boundary=B.PERSONAL,
                effective_classification=C.HIGHLY_RESTRICTED,
            )

            def current(session: Session) -> tuple[tuple[tuple[str, object], ...], ...]:
                return _claim_current(
                    session,
                    reference=claim_ref,
                    expected_claim=claim,
                    expected_declaration=gate._declaration,
                    admission_reference=gate._admission_reference,
                    expected_admission=gate._admission,
                )

            with gate._factory() as session:
                session.begin()
                _lock(session, gate._consent.id)
                entry = _physical(session)
                baseline = current(session)
                load_history_publication_claim(
                    session,
                    artifacts=gate._artifacts,
                    context=gate._context,
                    reference=claim_ref,
                    expected_claim=claim,
                    expected_declaration=gate._declaration,
                    admission_reference=gate._admission_reference,
                    expected_admission=gate._admission,
                )
                if current(session) != baseline or _ids(
                    session, _association_prefix(gate._consent.id)
                ):
                    raise ValueError("original complete output already captured or changed")
                _assert_personal_custody_append_capacity(session, 5)
                _same(session, entry)
            gate._require("OUTPUT_ENTERED")
            packet_location = gate._artifacts.put(B.PERSONAL, packet_digest, packet_raw)
            association_location = gate._artifacts.put(
                B.PERSONAL, association_hash, association_raw
            )
            if (
                gate._artifacts.get_bounded(B.PERSONAL, packet_location, max_bytes=MAX_PACKET_BYTES)
                != packet_raw
                or gate._artifacts.get_bounded(
                    B.PERSONAL, association_location, max_bytes=MAX_ASSOCIATION_BYTES
                )
                != association_raw
            ):
                raise ValueError("prepared complete paired artifacts differ")
            gate._owner()
            _output_origin(gate, runtime, request, draft)
            with gate._factory() as session:
                session.begin()
                _lock(session, gate._consent.id)
                entry = _physical(session)
                if current(session) != baseline or _ids(
                    session, _association_prefix(gate._consent.id)
                ):
                    raise ValueError("original complete output write baseline changed")
                _assert_personal_custody_append_capacity(session, 5)
                packet_row, new_packet = record_source(
                    session,
                    trust_boundary=B.PERSONAL,
                    data_classification=C.HIGHLY_RESTRICTED,
                    system=SourceSystem.MANUAL,
                    external_ref=_history_external(packet_digest, request),
                    content_hash=packet_digest,
                    content_location=packet_location,
                    captured_at=created,
                    preallocated_source_id=packet_id,
                )
                _assert_personal_custody_append_capacity(session, 4)
                association_row, new_association = record_source(
                    session,
                    trust_boundary=B.PERSONAL,
                    data_classification=C.HIGHLY_RESTRICTED,
                    system=SourceSystem.MANUAL,
                    external_ref=_association_prefix(association.generation_id) + association_hash,
                    content_hash=association_hash,
                    content_location=association_location,
                    captured_at=created,
                    preallocated_source_id=association_id,
                )
                if (
                    not new_packet
                    or not new_association
                    or packet_row.id != packet_id
                    or association_row.id != association_id
                    or packet_row.supersedes_source_id is not None
                    or association_row.supersedes_source_id is not None
                ):
                    raise ValueError("first exact complete paired Source identities required")
                _output_current(
                    session,
                    reference=association_ref,
                    value=association,
                    declaration=gate._declaration,
                    admission_reference=gate._admission_reference,
                    admission=gate._admission,
                    claim_reference=claim_ref,
                    claim=claim,
                )
                _assert_personal_custody_append_capacity(session, 3)
                _same(session, entry)
                gate._require("OUTPUT_ENTERED")
                if _NATIVE_MONOTONIC() >= min(
                    gate._deadline_monotonic, released.deadline_monotonic
                ):
                    raise ValueError("original complete output interval expired before commit")
                _same_commit(session, entry)
                session.commit()
            gate._owner()
            with gate._factory() as session:
                session.begin()
                packet, actual_association = load_history_publication_output_association(
                    session,
                    artifacts=gate._artifacts,
                    context=gate._context,
                    reference=association_ref,
                    expected_association=association,
                    expected_declaration=gate._declaration,
                    admission_reference=gate._admission_reference,
                    expected_admission=gate._admission,
                    claim_reference=claim_ref,
                    expected_claim=claim,
                )
            if actual_association != association or packet.review != review:
                raise ValueError("actual complete paired reopen differs")
            proof = protect_history_output(
                gate._protector,
                reference=association_ref,
                expected_declaration=gate._declaration,
                expected_admission=gate._admission,
                admission_reference=gate._admission_reference,
                claim_reference=claim_ref,
                expected_claim=claim,
                expected_association=association,
                context=gate._context,
            )
            if (
                content_hash_of(gate._protector._run_row(proof.artifact_backup_run_id))
                != proof.live_journal_digest
            ):
                raise ValueError("complete output proof journal changed")
            with gate._factory() as session:
                session.begin()
                _lock(session, gate._consent.id)
                entry = _physical(session)
                _output_current(
                    session,
                    reference=association_ref,
                    value=association,
                    declaration=gate._declaration,
                    admission_reference=gate._admission_reference,
                    admission=gate._admission,
                    claim_reference=claim_ref,
                    claim=claim,
                )
                gate._receipt_current(session, proof)
                _same(session, entry)
                gate._require("OUTPUT_ENTERED")
            # Fresh proof's owner check precedes these callback-free terminal scalars.
            if (
                _output_origin(gate, runtime, request, draft) != usage
                or gate._released is not released
                or _NATIVE_MONOTONIC() >= min(gate._deadline_monotonic, released.deadline_monotonic)
            ):
                raise ValueError("original complete output final interval or origin changed")
            result = PersonalHistoryAssociatedOutput(packet, association_ref, association, proof)
            gate._result = result
            gate._phase = "OUTPUT_RETAINED"
    except PersonalFragmentCleanupUncertain:
        uncertain = True
    except (KeyboardInterrupt, SystemExit) as error:
        interruption = error
    except Exception:  # noqa: BLE001,S110
        pass
    finally:
        if (
            result is None
            and type(authorization) is CanonicalPersonalHistoryPublicationAuthorization
        ):
            authorization._hold()
    if uncertain:
        raise PersonalFragmentCleanupUncertain("PERSONAL complete output cleanup uncertain")
    if interruption is not None:
        raise interruption
    if result is None:
        raise HistoryPublicationGenerationError("complete output retention held")
    return result
