"""Finite canonical BRAINSTORM email processing host; never mounted or enabled.

Actual owner POST, exact protected consent, consumed protected one-shot claim and
protected output reuse Source/ACL/revision, physical transactions and age/State/
journal recovery. No packet relabel, PERSONAL grants or generic permission store.
All candidate flags stay false. Retained results require separate semantic review.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from threading import Lock
from typing import TYPE_CHECKING, Literal
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

from sqlalchemy.orm import Session
from starlette.requests import Request

from zacai.claude_original_read import _read_only
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.email_draft import email_task_data
from zacai.intelligence.email_generation import prepare_email_generation_request
from zacai.intelligence.email_local_wire import resolve_email_local_response
from zacai.intelligence.email_processing_runtime import FixedLocalEmailRuntimeV1
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.intelligence.local_followup_runtime import _raise_interruption
from zacai.interfaces.email_input import (
    CanonicalBrainstormEmailInput,
    EmailInputCheckpointScope,
    SavedEmailInputV1,
    _current_rows,
    _same_owner,
    load_email_instruction_subject,
)
from zacai.interfaces.email_processing_contracts import (
    ACTION,
    EmailProcessingClaimV1,
    EmailProcessingConsentV1,
    EmailProcessingManifestV1,
    EmailProcessingOutputV1,
    EmailProcessingRecordV1,
    EmailProcessingRecoveryReceiptV1,
    decode_record,
    encode_record,
    request_digest,
)
from zacai.interfaces.named_decision_capture import _find_named, _require_request_lock
from zacai.interfaces.named_session_binding import NamedSessionOperation
from zacai.interfaces.private_web import _USER, _cookie
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation, _lock
from zacai.state import SourceSystem
from zacai.state_repository import record_source

if TYPE_CHECKING:
    from zacai.interfaces.email_processing_protection import BrainstormEmailProcessingProtection

_POST_KEY = object()
_ATTEMPT_KEY = object()


class EmailProcessingError(ValueError):
    """Closed public diagnostic; hosts must disable traceback-local capture."""


@dataclass(frozen=True)
class EmailProcessingCheckpointScope:
    source_id: UUID
    record_digest: str
    captured_at: datetime


def email_processing_receipt_key(source_id: UUID, digest: str) -> str:
    return f"BRAINSTORM/state/email-processing-{source_id}/receipt-{digest}.age"


def _scope(ref: EvidenceReference, at: datetime) -> EmailProcessingCheckpointScope:
    return EmailProcessingCheckpointScope(ref.source_id, ref.content_hash, at)


def _input_scope(m: EmailProcessingManifestV1) -> EmailInputCheckpointScope:
    return EmailInputCheckpointScope(
        m.input_reference.source_id, m.input_reference.content_hash, m.input_receipt.captured_at
    )


def _namespace(value: EmailProcessingRecordV1) -> str:
    if isinstance(value, EmailProcessingConsentV1):
        return f"email-processing-consent/{value.manifest.action_id}"
    if isinstance(value, EmailProcessingClaimV1):
        return f"email-processing-claim/{value.consent_reference.source_id}"
    return f"email-processing-output/{value.claim_reference.source_id}"


def _at(value: EmailProcessingRecordV1) -> datetime:
    if isinstance(value, EmailProcessingConsentV1):
        return value.approved_at
    if isinstance(value, EmailProcessingClaimV1):
        return value.claimed_at
    return value.completed_at


def _preimages(rows: tuple[tuple[tuple[str, object], ...], ...]) -> str:
    def encode(v: object) -> object:
        if isinstance(v, Enum):
            return [type(v).__name__, v.value]
        if type(v) is UUID:
            return ["UUID", str(v)]
        if type(v) is datetime:
            return ["datetime", v.isoformat()]
        if v is None or type(v) in (str, int, float, bool):
            return v
        raise ValueError("closed Source row type required")

    return canonical_bytes({"rows": [[[k, encode(v)] for k, v in row] for row in rows]}).decode()


@dataclass(frozen=True)
class EmailProcessingInventoryV1:
    consent: EmailProcessingConsentV1 = field(repr=False)
    claim: EmailProcessingClaimV1 | None = field(repr=False)
    output: EmailProcessingOutputV1 | None = field(repr=False)
    references: tuple[EvidenceReference, ...]
    record_rows: tuple[tuple[tuple[str, object], ...], ...] = field(repr=False)


def _load_email_processing_inventory(
    session: Session, artifacts: LocalFilesystemArtifactStore, scope: EmailProcessingCheckpointScope
) -> EmailProcessingInventoryV1:
    """Closed consent -> claim -> output reads with retained preimages; no owner callbacks."""
    _assert_ledger_isolation(session)
    _read_only(session)
    entry = _physical(session)
    ref = EvidenceReference(
        source_id=scope.source_id,
        content_hash=scope.record_digest,
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.CONFIDENTIAL,
    )
    refs = [ref]
    values: list[EmailProcessingRecordV1] = []
    rows: list[tuple[tuple[tuple[str, object], ...], ...]] = []
    for _ in range(3):
        before = _current_rows(session, (ref,))
        row = dict(before[0])
        location = row["content_location"]
        if type(location) is not str:
            raise ValueError("canonical record location required")
        raw = artifacts.get_bounded(B.BRAINSTORM, location, max_bytes=256000)
        _same(session, entry)
        _read_only(session)
        if content_hash_of(raw) != ref.content_hash:
            raise ValueError("canonical record digest mismatch")
        value = decode_record(raw)
        expected_system = (
            SourceSystem.USER_INSTRUCTION
            if type(value) is EmailProcessingConsentV1
            else SourceSystem.MANUAL
        )
        if (
            row["external_ref"] != _namespace(value)
            or row["system"] is not expected_system
            or row["captured_at"] != _at(value)
            or row["supersedes_source_id"] is not None
            or _current_rows(session, (ref,)) != before
        ):
            raise ValueError("canonical record metadata changed")
        values.append(value)
        rows.append(before)
        if isinstance(value, EmailProcessingConsentV1):
            break
        ref = (
            value.consent_reference
            if isinstance(value, EmailProcessingClaimV1)
            else value.claim_reference
        )
        if ref.source_id in {r.source_id for r in refs}:
            raise ValueError("cyclic email record chain")
        refs.append(ref)
    if type(values[-1]) is not EmailProcessingConsentV1 or _at(values[0]) != scope.captured_at:
        raise ValueError("complete original email chain required")
    consent = values[-1]
    claim = next((v for v in values if type(v) is EmailProcessingClaimV1), None)
    output = next((v for v in values if type(v) is EmailProcessingOutputV1), None)
    if claim is not None and (
        claim.consent_reference != refs[-1]
        or claim.manifest_digest != consent.manifest.digest()
        or claim.attempt_id.int == 0
        or not consent.approved_at <= claim.claimed_at < consent.expires_at
    ):
        raise ValueError("claim original scope mismatch")
    if output is not None:
        if claim is None or len(values) != 3 or output.claim_reference != refs[1]:
            raise ValueError("output requires exact original claim")
        m = consent.manifest
        packet, parsed = resolve_email_local_response(
            output.response_text.encode(),
            prepare_email_generation_request(m.specification),
            m.route,
            m.model_digest,
            expected_prompt_tokens=m.full_prompt_tokens,
            elapsed_ms=output.usage.latency_ms,
            builder_id=m.builder_id,
            created_at=output.completed_at,
        )
        if (
            output.attempt_id != claim.attempt_id
            or output.body_digest != m.body_digest
            or output.packet != packet
            or output.usage != parsed.usage
            or output.reported_prompt_eval_cached_count != parsed.reported_prompt_eval_cached_count
            or not claim.claimed_at <= output.completed_at < consent.expires_at
        ):
            raise ValueError("exact invocation output binding mismatch")
    m = consent.manifest
    instruction = load_email_instruction_subject(session, artifacts, _input_scope(m))
    if (
        instruction.issuer != consent.issuer
        or instruction.subject != consent.subject
        or instruction.original_session_binding != consent.session_binding
        or instruction.original_session_issued_at != consent.original_session_issued_at
        or instruction.original_session_expires_at != consent.original_session_expires_at
    ):
        raise ValueError("email processing cannot adopt another original input session")
    input_refs = (m.input_reference, *instruction.selection.references())
    if _preimages(_current_rows(session, input_refs)) != m.source_preimages_json:
        raise ValueError("admitted input preimages changed")
    complete = (*refs, *input_refs)
    if len({r.source_id for r in complete}) != len(complete):
        raise ValueError("distinct email custody chain required")
    for r, before in zip(refs, rows, strict=True):
        if _current_rows(session, (r,)) != before:
            raise ValueError("record preimages changed during callbacks")
    _same(session, entry)
    _read_only(session)
    record_rows = _current_rows(session, tuple(refs))
    return EmailProcessingInventoryV1(consent, claim, output, complete, record_rows)


def load_email_processing_inventory(
    session: Session, artifacts: LocalFilesystemArtifactStore, scope: EmailProcessingCheckpointScope
) -> EmailProcessingInventoryV1:
    interruption: type[BaseException] | None = None
    exit_code: int | None = 1
    try:
        return _load_email_processing_inventory(session, artifacts, scope)
    except BaseException as error:  # noqa: BLE001 - close artifact/private diagnostics
        interruption = type(error)
        if isinstance(error, SystemExit):
            exit_code = error.code if error.code is None or type(error.code) is int else 1
    _raise_interruption(interruption, exit_code)
    raise EmailProcessingError("email canonical processing inventory unavailable")


@dataclass(frozen=True)
class _EmailProcessingPost:
    consent: EmailProcessingConsentV1 = field(repr=False)
    operation: NamedSessionOperation = field(repr=False)
    _key: object = field(repr=False)
    _once: list[bool] = field(default_factory=lambda: [False], repr=False)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def consume(self) -> None:
        with self._lock:
            if self._key is not _POST_KEY or self._once[0]:
                raise ValueError("observed email processing action consumed")
            self._once[0] = True


def observe_email_processing_post(
    request: Request,
    *,
    body: bytes,
    operation: NamedSessionOperation,
    manifest: EmailProcessingManifestV1,
) -> _EmailProcessingPost:
    """Exact original authenticated processing action; no shaped-input grant."""
    interruption: type[BaseException] | None = None
    exit_code: int | None = 1
    try:
        if (
            type(request) is not Request
            or type(operation) is not NamedSessionOperation
            or type(manifest) is not EmailProcessingManifestV1
            or type(body) is not bytes
            or not 0 < len(body) <= 2000
            or request.method != "POST"
            or request.url.path != "/generate-caz-email"
            or request.scope.get("query_string", b"")
            or request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]
        ):
            raise ValueError("closed email processing POST required")
        origin = json.loads(operation._source._context)["origin"]
        if request.headers.getlist("host") != [urlsplit(origin).netloc] or request.headers.getlist(
            "origin"
        ) != [origin]:
            raise ValueError("original same-origin action required")
        cookie = _cookie(request, _USER)
        first = operation.establish()
        if not _same_owner(first, operation._source.for_cookie(cookie).establish()):
            raise ValueError("actual original cookie required")
        current = operation._source._sessions.peek_user(cookie, operation.host_clock())
        values = parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=True)
        if (
            current is None
            or set(values) != {"csrf", "action_id", "manifest_digest", "action"}
            or any(len(v) != 1 for v in values.values())
            or not secrets.compare_digest(values["csrf"][0], current.csrf)
            or values["action_id"][0] != str(manifest.action_id)
            or values["manifest_digest"][0] != manifest.digest()
            or values["action"][0] != ACTION
        ):
            raise ValueError("exact original processing action required")
        final = operation.recheck(first.binding_digest)
        if not _same_owner(first, final) or not any(
            s.boundary is B.BRAINSTORM and C.CONFIDENTIAL in s.classifications
            for s in final.principal.scopes
        ):
            raise ValueError("original business owner unavailable")
        now = operation.host_clock()
        consent = EmailProcessingConsentV1(
            manifest=manifest,
            action_text=ACTION,
            issuer=final.principal.identity.issuer,
            subject=final.principal.identity.subject,
            session_binding=final.binding_digest,
            original_session_issued_at=final.issued_at,
            original_session_expires_at=final.effective_expires_at,
            approved_at=now,
            expires_at=min(now + timedelta(minutes=10), final.effective_expires_at),
        )
        return _EmailProcessingPost(consent, operation, _POST_KEY)
    except BaseException as error:  # noqa: BLE001 - no private interruption arguments
        interruption = type(error)
        if isinstance(error, SystemExit):
            exit_code = error.code if error.code is None or type(error.code) is int else 1
    _raise_interruption(interruption, exit_code)
    raise EmailProcessingError("email processing action not observed")


@dataclass(frozen=True)
class _EmailAttempt:
    consent: EmailProcessingConsentV1 = field(repr=False)
    consent_reference: EvidenceReference
    consent_receipt: EmailProcessingRecoveryReceiptV1 = field(repr=False)
    claim: EmailProcessingClaimV1 = field(repr=False)
    claim_reference: EvidenceReference
    claim_receipt: EmailProcessingRecoveryReceiptV1 = field(repr=False)
    started: float
    record_preimages_json: str = field(repr=False)
    _key: object = field(repr=False)
    _once: list[bool] = field(default_factory=lambda: [False], repr=False)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def consume(self) -> None:
        with self._lock:
            if self._key is not _ATTEMPT_KEY or self._once[0]:
                raise ValueError("actual live attempt consumed")
            self._once[0] = True


@dataclass(frozen=True)
class RetainedEmailInvocationV1:
    reference: EvidenceReference
    record: EmailProcessingOutputV1 = field(repr=False)
    receipt: EmailProcessingRecoveryReceiptV1 = field(repr=False)
    fresh_input_observed_at: datetime
    ready_to_deliver: Literal[False] = field(default=False, init=False)


class CanonicalBrainstormEmailProcessing:
    """Closed host composition, original session, no service registration or send."""

    def __init__(
        self,
        *,
        inputs: CanonicalBrainstormEmailInput,
        protection: BrainstormEmailProcessingProtection,
        runtime: FixedLocalEmailRuntimeV1,
    ) -> None:
        from zacai.interfaces.email_processing_protection import BrainstormEmailProcessingProtection

        if (
            type(inputs) is not CanonicalBrainstormEmailInput
            or type(protection) is not BrainstormEmailProcessingProtection
            or type(runtime) is not FixedLocalEmailRuntimeV1
            or protection._operation is not inputs._operation
            or protection._protector is not inputs._protection._protector
            or protection._binding != inputs._protection._binding
        ):
            raise EmailProcessingError("concrete email processing composition rejected")
        self._inputs, self._protection, self._runtime = inputs, protection, runtime
        self._factory, self._artifacts, self._operation = (
            inputs._factory,
            inputs._artifacts,
            inputs._operation,
        )
        self._clock = self._operation.host_clock
        self._attempt: _EmailAttempt | None = None
        self._published: EmailProcessingManifestV1 | None = None
        self._fresh_observed: datetime | None = None

    def _fresh_inputs(self, manifest: EmailProcessingManifestV1) -> SavedEmailInputV1:
        fresh = self._inputs.load(_input_scope(manifest), manifest.input_receipt)
        original, observed = manifest.specification, fresh.specification
        # Retain both actual observations. Compare every task field except the
        # newer read observation; dispatch ALWAYS uses the protected original spec.
        a, b = email_task_data(original.task()), email_task_data(observed.task())
        old_event, new_event = a["event"], b["event"]
        old_at, new_at = original.task().event.observed_at, observed.task().event.observed_at
        if new_at < old_at:
            raise ValueError("input observation moved backward")
        a["event"] = {k: v for k, v in old_event.items() if k != "observed_at"}
        b["event"] = {k: v for k, v in new_event.items() if k != "observed_at"}
        if (
            a != b
            or original.recipient != observed.recipient
            or original.sources != observed.sources
        ):
            raise ValueError("underlying admitted instruction/evidence/recipient/budgets changed")
        self._fresh_observed = new_at
        return fresh

    def prepare(
        self, saved: SavedEmailInputV1, *, action_id: UUID, builder_id: UUID
    ) -> EmailProcessingManifestV1:
        result = None
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            if self._published is not None or type(saved) is not SavedEmailInputV1:
                raise ValueError("one finite published action per host required")
            scope = EmailInputCheckpointScope(
                saved.reference.source_id,
                saved.reference.content_hash,
                saved.recovery_receipt.captured_at,
            )
            with self._factory() as session:
                original = load_email_instruction_subject(session, self._artifacts, scope)
                preimages = _current_rows(
                    session, (saved.reference, *original.selection.references())
                )
            fresh = self._inputs.load(scope, saved.recovery_receipt)
            if fresh.instruction != original:
                raise ValueError("input changed during preparation")
            # Saved input may have been reopened since its initial observation:
            # preparation admits this actual fresh complete envelope, once.
            request = prepare_email_generation_request(fresh.specification)
            body, count, pins = self._runtime.prepare(request)
            self._inputs._owner(fresh.instruction)
            with self._factory() as session:
                rows = _current_rows(
                    session, (fresh.reference, *fresh.instruction.selection.references())
                )
                if rows != preimages:
                    raise ValueError("loaded input changed after tokenizer callback")
            result = EmailProcessingManifestV1(
                action_id=action_id,
                builder_id=builder_id,
                input_reference=fresh.reference,
                input_receipt=fresh.recovery_receipt,
                specification=fresh.specification,
                source_preimages_json=_preimages(rows),
                route=self._runtime.route,
                model_digest=self._runtime.model_digest,
                tokenizer_digest=pins.tokenizer_digest,
                implementation_digest=pins.implementation_digest,
                request_digest=request_digest(fresh.specification),
                body_digest=content_hash_of(body),
                schema_digest=content_hash_of(request.schema_json.encode()),
                full_prompt_tokens=count,
            )
            self._fresh_inputs(result)
            self._rows(result)
            self._published = result
        except BaseException as error:  # noqa: BLE001 - sanitize cancellation outside handler
            result = None
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        if result is None:
            raise EmailProcessingError("email processing manifest unavailable")
        return result

    def _owner(self, consent: EmailProcessingConsentV1) -> None:
        active = self._operation.recheck(consent.session_binding)
        if (
            active.principal.identity.issuer != consent.issuer
            or active.principal.identity.subject != consent.subject
            or active.issued_at != consent.original_session_issued_at
            or active.effective_expires_at != consent.original_session_expires_at
            or not consent.approved_at <= self._clock() < consent.expires_at
        ):
            raise ValueError("original email processing owner/window unavailable")

    def _rows(self, m: EmailProcessingManifestV1) -> None:
        with self._factory() as session:
            instruction = load_email_instruction_subject(session, self._artifacts, _input_scope(m))
            if (
                _preimages(
                    _current_rows(session, (m.input_reference, *instruction.selection.references()))
                )
                != m.source_preimages_json
            ):
                raise ValueError("original admitted source rows changed")

    def _write(
        self, value: EmailProcessingRecordV1, *, lock_id: UUID, consent: EmailProcessingConsentV1
    ) -> EvidenceReference:
        raw = encode_record(value)
        digest = content_hash_of(raw)
        # Artifact callbacks finish before the last original owner/row checks.
        location = self._artifacts.put(B.BRAINSTORM, digest, raw)
        if self._artifacts.get_bounded(B.BRAINSTORM, location, max_bytes=256000) != raw:
            raise ValueError("canonical processing artifact readback mismatch")
        self._owner(consent)
        with self._factory() as session:
            _lock(session, lock_id)
            entry = _physical(session)
            if _find_named(session, _namespace(value)) is not None:
                raise ValueError("email processing record already committed")
            instruction = load_email_instruction_subject(
                session, self._artifacts, _input_scope(consent.manifest)
            )
            refs = (consent.manifest.input_reference, *instruction.selection.references())
            if _preimages(_current_rows(session, refs)) != consent.manifest.source_preimages_json:
                raise ValueError("admitted rows changed before commit")
            # Parent record rows are validated under the same lock before writes.
            if not isinstance(value, EmailProcessingConsentV1):
                parent = (
                    value.consent_reference
                    if isinstance(value, EmailProcessingClaimV1)
                    else value.claim_reference
                )
                parent_at = (
                    consent.approved_at
                    if type(value) is EmailProcessingClaimV1
                    else self._attempt.claim.claimed_at
                    if self._attempt
                    else None
                )
                if parent_at is None:
                    raise ValueError("actual live claim required")
                inventory = load_email_processing_inventory(
                    session, self._artifacts, _scope(parent, parent_at)
                )
                if inventory.consent != consent:
                    raise ValueError("original parent consent changed")
            _same(session, entry)
            _require_request_lock(session, lock_id)
            # No external callbacks after final read; clock watermark was updated
            # by original owner check, physical PG constraints serialize only this action.
            with self._clock._lock:
                final = self._clock._last
            if final is None or not consent.approved_at <= _at(value) <= final < consent.expires_at:
                raise ValueError("original action expired before write")
            source, _ = record_source(
                session,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.CONFIDENTIAL,
                system=SourceSystem.USER_INSTRUCTION
                if type(value) is EmailProcessingConsentV1
                else SourceSystem.MANUAL,
                external_ref=_namespace(value),
                content_hash=digest,
                content_location=location,
                captured_at=_at(value),
            )
            source_id = source.id
            session.commit()
        return EvidenceReference(
            source_id=source_id,
            content_hash=digest,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.CONFIDENTIAL,
        )

    def record(
        self, post: _EmailProcessingPost
    ) -> tuple[EvidenceReference, EmailProcessingRecoveryReceiptV1]:
        result = None
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            if (
                type(post) is not _EmailProcessingPost
                or post.operation is not self._operation
                or self._published is None
                or post.consent.manifest != self._published
            ):
                raise ValueError("actual published processing action required")
            post.consume()
            c = post.consent
            self._owner(c)
            self._fresh_inputs(c.manifest)
            ref = self._write(c, lock_id=c.manifest.action_id, consent=c)
            receipt = self._protection.protect(_scope(ref, c.approved_at))
            self._protection.recheck(_scope(ref, c.approved_at), receipt)
            self._owner(c)
            with self._factory() as session:
                if (
                    load_email_processing_inventory(
                        session, self._artifacts, _scope(ref, c.approved_at)
                    ).consent
                    != c
                ):
                    raise ValueError("consent changed after protection")
            result = (ref, receipt)
        except BaseException as error:  # noqa: BLE001 - sanitize cancellation outside handler
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        if result is None:
            raise EmailProcessingError("email consent unavailable; pending custody may remain")
        return result

    def _deadline(self, attempt: _EmailAttempt) -> float:
        # Pair the trusted side-effect-free wall observation with an earlier
        # monotonic anchor: clock-read latency consumes, never renews permission.
        paired = time.perf_counter()
        now = self._clock()
        monotonic = time.perf_counter()
        elapsed = (monotonic - attempt.started) * 1000
        if (
            not attempt.started <= paired <= monotonic
            or not 0 <= elapsed < attempt.consent.manifest.specification.task().max_latency_ms
            or not attempt.consent.approved_at
            <= now
            < min(attempt.consent.expires_at, attempt.consent.original_session_expires_at)
        ):
            raise ValueError("original email attempt deadline exhausted")
        permission_end = min(
            attempt.consent.expires_at, attempt.consent.original_session_expires_at
        )
        deadline = min(
            attempt.started + attempt.consent.manifest.specification.task().max_latency_ms / 1000,
            paired + (permission_end - now).total_seconds(),
        )
        if not monotonic < deadline:
            raise ValueError("original email attempt deadline exhausted")
        return deadline

    def _gate(self, attempt: _EmailAttempt) -> None:
        if attempt is not self._attempt or attempt._key is not _ATTEMPT_KEY:
            raise ValueError("actual protected live attempt required")
        c = attempt.consent
        self._owner(c)
        self._fresh_inputs(c.manifest)
        self._protection.recheck(
            _scope(attempt.consent_reference, c.approved_at), attempt.consent_receipt
        )
        self._protection.recheck(
            _scope(attempt.claim_reference, attempt.claim.claimed_at), attempt.claim_receipt
        )
        self._owner(c)
        self._final_rows(attempt)
        self._deadline(attempt)

    def _final_rows(self, attempt: _EmailAttempt) -> None:
        # No artifact/owner/tokenizer/clock callback in this final release query.
        m = attempt.consent.manifest
        input_ids = {str(r.source_id) for r in m.specification.task().event.provenance}
        if str(m.input_reference.source_id) not in input_ids:
            raise ValueError("original input provenance absent")
        refs = m.specification.task().event.provenance
        with self._factory() as session:
            if _preimages(_current_rows(session, refs)) != m.source_preimages_json:
                raise ValueError("admitted input rows changed after callbacks")
            if (
                _preimages(
                    _current_rows(session, (attempt.consent_reference, attempt.claim_reference))
                )
                != attempt.record_preimages_json
            ):
                raise ValueError("verified canonical consent/claim row preimages changed")
            for ref, at, kind, namespace in (
                (
                    attempt.consent_reference,
                    attempt.consent.approved_at,
                    SourceSystem.USER_INSTRUCTION,
                    _namespace(attempt.consent),
                ),
                (
                    attempt.claim_reference,
                    attempt.claim.claimed_at,
                    SourceSystem.MANUAL,
                    _namespace(attempt.claim),
                ),
            ):
                row = dict(_current_rows(session, (ref,))[0])
                if (
                    row["captured_at"] != at
                    or row["system"] is not kind
                    or row["external_ref"] != namespace
                ):
                    raise ValueError("original attempt canonical rows changed")

    def generate(
        self,
        consent_reference: EvidenceReference,
        consent_receipt: EmailProcessingRecoveryReceiptV1,
    ) -> RetainedEmailInvocationV1:
        result = None
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            if self._attempt is not None or self._published is None:
                raise ValueError("one finite attempt per admitted host required")
            started = time.perf_counter()
            scope = _scope(consent_reference, consent_receipt.captured_at)
            self._protection.recheck(scope, consent_receipt)
            with self._factory() as session:
                inventory = load_email_processing_inventory(session, self._artifacts, scope)
            c = inventory.consent
            if (
                inventory.claim is not None
                or inventory.output is not None
                or c.manifest != self._published
            ):
                raise ValueError("exact original consent required")
            self._owner(c)
            self._fresh_inputs(c.manifest)
            claim = EmailProcessingClaimV1(
                consent_reference=consent_reference,
                manifest_digest=c.manifest.digest(),
                attempt_id=uuid4(),
                claimed_at=self._clock(),
            )
            ref = self._write(claim, lock_id=consent_reference.source_id, consent=c)
            receipt = self._protection.protect(_scope(ref, claim.claimed_at))
            self._protection.recheck(_scope(ref, claim.claimed_at), receipt)
            with self._factory() as session:
                reopened = load_email_processing_inventory(
                    session, self._artifacts, _scope(ref, claim.claimed_at)
                )
            if reopened.claim != claim or reopened.consent != c:
                raise ValueError("protected claim changed before attempt")
            attempt = _EmailAttempt(
                c,
                consent_reference,
                consent_receipt,
                claim,
                ref,
                receipt,
                started,
                _preimages(reopened.record_rows),
                _ATTEMPT_KEY,
            )
            self._attempt = attempt
            self._gate(attempt)
            raw = self._runtime._invoke(self, attempt)
            completed = self._clock()
            elapsed = (time.perf_counter() - started) * 1000
            packet, parsed = resolve_email_local_response(
                raw,
                prepare_email_generation_request(c.manifest.specification),
                c.manifest.route,
                c.manifest.model_digest,
                expected_prompt_tokens=c.manifest.full_prompt_tokens,
                elapsed_ms=elapsed,
                builder_id=c.manifest.builder_id,
                created_at=completed,
            )
            output = EmailProcessingOutputV1(
                claim_reference=ref,
                attempt_id=claim.attempt_id,
                body_digest=c.manifest.body_digest,
                response_text=raw.decode(),
                packet=packet,
                usage=parsed.usage,
                reported_prompt_eval_cached_count=parsed.reported_prompt_eval_cached_count,
                completed_at=completed,
            )
            self._gate(attempt)
            output_ref = self._write(output, lock_id=consent_reference.source_id, consent=c)
            output_receipt = self._protection.protect(_scope(output_ref, completed))
            self._protection.recheck(_scope(output_ref, completed), output_receipt)
            self._owner(c)
            with self._factory() as session:
                actual = load_email_processing_inventory(
                    session, self._artifacts, _scope(output_ref, completed)
                )
            self._owner(c)
            self._final_rows(attempt)
            with self._factory() as session:
                record_refs = tuple(
                    r
                    for r in actual.references
                    if r.source_id
                    not in {p.source_id for p in c.manifest.specification.task().event.provenance}
                )
                if _current_rows(session, record_refs) != actual.record_rows:
                    raise ValueError("output chain changed after final owner callback")
            self._deadline(attempt)
            if actual.output != output or self._fresh_observed is None:
                raise ValueError("protected output changed before release")
            result = RetainedEmailInvocationV1(
                output_ref, output, output_receipt, self._fresh_observed
            )
        except BaseException as error:  # noqa: BLE001 - sanitize cancellation outside handler
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        if result is None:
            raise EmailProcessingError(
                "email generation unavailable; committed attempt cannot replay"
            )
        return result

    def reconcile(
        self, reference: EvidenceReference, captured_at: datetime
    ) -> EmailProcessingRecoveryReceiptV1:
        """Original-session pending custody only. Never issues an attempt or processes."""
        result = None
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            scope = _scope(reference, captured_at)
            with self._factory() as session:
                original = load_email_processing_inventory(session, self._artifacts, scope)
            self._owner(original.consent)
            self._fresh_inputs(original.consent.manifest)
            receipt = self._protection.protect(scope)
            self._protection.recheck(scope, receipt)
            self._owner(original.consent)
            with self._factory() as session:
                current = load_email_processing_inventory(session, self._artifacts, scope)
            self._owner(original.consent)
            with self._factory() as session:
                record_refs = tuple(
                    r
                    for r in original.references
                    if r.source_id
                    not in {
                        p.source_id
                        for p in original.consent.manifest.specification.task().event.provenance
                    }
                )
                if (
                    current != original
                    or _current_rows(session, record_refs) != original.record_rows
                ):
                    raise ValueError("original pending record changed during reconciliation")
                if (
                    _preimages(
                        _current_rows(
                            session, original.consent.manifest.specification.task().event.provenance
                        )
                    )
                    != original.consent.manifest.source_preimages_json
                ):
                    raise ValueError("input changed after reconciliation callbacks")
            result = receipt
        except BaseException as error:  # noqa: BLE001 - sanitize cancellation outside handler
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        if result is None:
            raise EmailProcessingError("email processing custody reconciliation held")
        return result

    def load_output(
        self, reference: EvidenceReference, receipt: EmailProcessingRecoveryReceiptV1
    ) -> RetainedEmailInvocationV1:
        """Authenticated protected output for separate human review, no acceptance grant."""
        result = None
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            scope = _scope(reference, receipt.captured_at)
            self._protection.recheck(scope, receipt)
            with self._factory() as session:
                original = load_email_processing_inventory(session, self._artifacts, scope)
            if original.output is None or original.claim is None:
                raise ValueError("protected output required")
            self._owner(original.consent)
            self._fresh_inputs(original.consent.manifest)
            self._protection.recheck(scope, receipt)
            self._owner(original.consent)
            with self._factory() as session:
                record_refs = tuple(
                    r
                    for r in original.references
                    if r.source_id
                    not in {
                        p.source_id
                        for p in original.consent.manifest.specification.task().event.provenance
                    }
                )
                if (
                    _current_rows(session, record_refs) != original.record_rows
                    or _preimages(
                        _current_rows(
                            session, original.consent.manifest.specification.task().event.provenance
                        )
                    )
                    != original.consent.manifest.source_preimages_json
                ):
                    raise ValueError("output/input preimages changed after review read callbacks")
            if self._fresh_observed is None:
                raise ValueError("actual fresh read required")
            result = RetainedEmailInvocationV1(
                reference, original.output, receipt, self._fresh_observed
            )
        except BaseException as error:  # noqa: BLE001 - sanitize cancellation outside handler
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        if result is None:
            raise EmailProcessingError("protected email output unavailable for owner review")
        return result
